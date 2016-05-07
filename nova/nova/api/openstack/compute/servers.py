# coding=utf-8
# Copyright 2010 OpenStack Foundation
# Copyright 2011 Piston Cloud Computing, Inc
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64
import re

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging as messaging
from oslo_utils import strutils
from oslo_utils import timeutils
from oslo_utils import uuidutils
import six
import stevedore
import webob
from webob import exc

from nova.api.openstack import api_version_request
from nova.api.openstack import common
from nova.api.openstack.compute.schemas import servers as schema_servers
from nova.api.openstack.compute.views import servers as views_servers
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.api import validation
from nova import compute
from nova.compute import flavors
from nova import exception
from nova.i18n import _
from nova.i18n import _LW
from nova.image import glance
from nova import objects
from nova import utils

ALIAS = 'servers'

CONF = cfg.CONF
CONF.import_opt('enable_instance_password',
                'nova.api.openstack.compute.legacy_v2.servers')
CONF.import_opt('network_api_class', 'nova.network')
CONF.import_opt('reclaim_instance_interval', 'nova.compute.manager')
CONF.import_opt('extensions_blacklist', 'nova.api.openstack',
                group='osapi_v21')
CONF.import_opt('extensions_whitelist', 'nova.api.openstack',
                group='osapi_v21')

LOG = logging.getLogger(__name__)
authorize = extensions.os_compute_authorizer(ALIAS)


class ServersController(wsgi.Controller):
    """The Server API base controller class for the OpenStack API."""

    EXTENSION_CREATE_NAMESPACE = 'nova.api.v21.extensions.server.create'
    EXTENSION_DESERIALIZE_EXTRACT_SERVER_NAMESPACE = (
        'nova.api.v21.extensions.server.create.deserialize')

    EXTENSION_REBUILD_NAMESPACE = 'nova.api.v21.extensions.server.rebuild'
    EXTENSION_DESERIALIZE_EXTRACT_REBUILD_NAMESPACE = (
        'nova.api.v21.extensions.server.rebuild.deserialize')

    EXTENSION_UPDATE_NAMESPACE = 'nova.api.v21.extensions.server.update'

    EXTENSION_RESIZE_NAMESPACE = 'nova.api.v21.extensions.server.resize'

    _view_builder_class = views_servers.ViewBuilderV21

    schema_server_create = schema_servers.base_create
    schema_server_update = schema_servers.base_update
    schema_server_rebuild = schema_servers.base_rebuild
    schema_server_resize = schema_servers.base_resize

    schema_server_create_v20 = schema_servers.base_create_v20
    schema_server_update_v20 = schema_servers.base_update_v20
    schema_server_rebuild_v20 = schema_servers.base_rebuild_v20

    @staticmethod
    def _add_location(robj):
        # Just in case...
        if 'server' not in robj.obj:
            return robj

        link = filter(lambda l: l['rel'] == 'self',
                      robj.obj['server']['links'])
        if link:
            robj['Location'] = utils.utf8(link[0]['href'])

        # Convenience return
        return robj

    def __init__(self, **kwargs):
        def _check_load_extension(required_function):

            def check_whiteblack_lists(ext):
                # Check whitelist is either empty or if not then the extension
                # is in the whitelist
                if (not CONF.osapi_v21.extensions_whitelist or
                        ext.obj.alias in CONF.osapi_v21.extensions_whitelist):

                    # Check the extension is not in the blacklist
                    extensions_blacklist = CONF.osapi_v21.extensions_blacklist
                    if ext.obj.alias not in extensions_blacklist:
                        return True
                    else:
                        LOG.warning(_LW("Not loading %s because it is "
                                        "in the blacklist"), ext.obj.alias)
                        return False
                else:
                    LOG.warning(
                        _LW("Not loading %s because it is not in the "
                            "whitelist"), ext.obj.alias)
                    return False

            def check_load_extension(ext):
                if isinstance(ext.obj, extensions.V21APIExtensionBase):
                    # Filter out for the existence of the required
                    # function here rather than on every request. We
                    # don't have a new abstract base class to reduce
                    # duplication in the extensions as they may want
                    # to implement multiple server (and other) entry
                    # points if hasattr(ext.obj, 'server_create'):
                    if hasattr(ext.obj, required_function):
                        LOG.debug('extension %(ext_alias)s detected by '
                                  'servers extension for function %(func)s',
                                  {'ext_alias': ext.obj.alias,
                                   'func': required_function})
                        return check_whiteblack_lists(ext)
                    else:
                        LOG.debug(
                            'extension %(ext_alias)s is missing %(func)s',
                            {'ext_alias': ext.obj.alias,
                            'func': required_function})
                        return False
                else:
                    return False
            return check_load_extension

        self.extension_info = kwargs.pop('extension_info')
        super(ServersController, self).__init__(**kwargs)
        self.compute_api = compute.API(skip_policy_check=True)

        # Look for implementation of extension point of server creation
        self.create_extension_manager = \
          stevedore.enabled.EnabledExtensionManager(
              namespace=self.EXTENSION_CREATE_NAMESPACE,
              check_func=_check_load_extension('server_create'),
              invoke_on_load=True,
              invoke_kwds={"extension_info": self.extension_info},
              propagate_map_exceptions=True)
        if not list(self.create_extension_manager):
            LOG.debug("Did not find any server create extensions")

        # Look for implementation of extension point of server rebuild
        self.rebuild_extension_manager = \
            stevedore.enabled.EnabledExtensionManager(
                namespace=self.EXTENSION_REBUILD_NAMESPACE,
                check_func=_check_load_extension('server_rebuild'),
                invoke_on_load=True,
                invoke_kwds={"extension_info": self.extension_info},
                propagate_map_exceptions=True)
        if not list(self.rebuild_extension_manager):
            LOG.debug("Did not find any server rebuild extensions")

        # Look for implementation of extension point of server update
        self.update_extension_manager = \
            stevedore.enabled.EnabledExtensionManager(
                namespace=self.EXTENSION_UPDATE_NAMESPACE,
                check_func=_check_load_extension('server_update'),
                invoke_on_load=True,
                invoke_kwds={"extension_info": self.extension_info},
                propagate_map_exceptions=True)
        if not list(self.update_extension_manager):
            LOG.debug("Did not find any server update extensions")

        # Look for implementation of extension point of server resize
        self.resize_extension_manager = \
            stevedore.enabled.EnabledExtensionManager(
                namespace=self.EXTENSION_RESIZE_NAMESPACE,
                check_func=_check_load_extension('server_resize'),
                invoke_on_load=True,
                invoke_kwds={"extension_info": self.extension_info},
                propagate_map_exceptions=True)
        if not list(self.resize_extension_manager):
            LOG.debug("Did not find any server resize extensions")

        # Look for API schema of server create extension
        self.create_schema_manager = \
            stevedore.enabled.EnabledExtensionManager(
                namespace=self.EXTENSION_CREATE_NAMESPACE,
                check_func=_check_load_extension('get_server_create_schema'),
                invoke_on_load=True,
                invoke_kwds={"extension_info": self.extension_info},
                propagate_map_exceptions=True)
        if list(self.create_schema_manager):
            self.create_schema_manager.map(self._create_extension_schema,
                                           self.schema_server_create, '2.1')
            self.create_schema_manager.map(self._create_extension_schema,
                                           self.schema_server_create_v20,
                                           '2.0')
        else:
            LOG.debug("Did not find any server create schemas")

        # Look for API schema of server update extension
        self.update_schema_manager = \
            stevedore.enabled.EnabledExtensionManager(
                namespace=self.EXTENSION_UPDATE_NAMESPACE,
                check_func=_check_load_extension('get_server_update_schema'),
                invoke_on_load=True,
                invoke_kwds={"extension_info": self.extension_info},
                propagate_map_exceptions=True)
        if list(self.update_schema_manager):
            self.update_schema_manager.map(self._update_extension_schema,
                                           self.schema_server_update, '2.1')
            self.update_schema_manager.map(self._update_extension_schema,
                                           self.schema_server_update_v20,
                                           '2.0')
        else:
            LOG.debug("Did not find any server update schemas")

        # Look for API schema of server rebuild extension
        self.rebuild_schema_manager = \
            stevedore.enabled.EnabledExtensionManager(
                namespace=self.EXTENSION_REBUILD_NAMESPACE,
                check_func=_check_load_extension('get_server_rebuild_schema'),
                invoke_on_load=True,
                invoke_kwds={"extension_info": self.extension_info},
                propagate_map_exceptions=True)
        if list(self.rebuild_schema_manager):
            self.rebuild_schema_manager.map(self._rebuild_extension_schema,
                                            self.schema_server_rebuild, '2.1')
            self.rebuild_schema_manager.map(self._rebuild_extension_schema,
                                            self.schema_server_rebuild_v20,
                                            '2.0')
        else:
            LOG.debug("Did not find any server rebuild schemas")

        # Look for API schema of server resize extension
        self.resize_schema_manager = \
            stevedore.enabled.EnabledExtensionManager(
                namespace=self.EXTENSION_RESIZE_NAMESPACE,
                check_func=_check_load_extension('get_server_resize_schema'),
                invoke_on_load=True,
                invoke_kwds={"extension_info": self.extension_info},
                propagate_map_exceptions=True)
        if list(self.resize_schema_manager):
            self.resize_schema_manager.map(self._resize_extension_schema,
                                           self.schema_server_resize, '2.1')
        else:
            LOG.debug("Did not find any server resize schemas")

    @extensions.expected_errors((400, 403))
    def index(self, req):
        """Returns a list of server names and ids for a given user."""
        context = req.environ['nova.context']
        authorize(context, action="index")
        try:
            servers = self._get_servers(req, is_detail=False)
        except exception.Invalid as err:
            raise exc.HTTPBadRequest(explanation=err.format_message())
        return servers

    @extensions.expected_errors((400, 403))
    def detail(self, req):
        """Returns a list of server details for a given user."""
        ### 1.从req中获取context，并验证是否有'detail'的权限
        context = req.environ['nova.context']
        authorize(context, action="detail")
        try:
            ### 2.调用_get_servers()函数，is_detail直接指定为True
            servers = self._get_servers(req, is_detail=True)
        except exception.Invalid as err:
            raise exc.HTTPBadRequest(explanation=err.format_message())
        return servers

    def _get_servers(self, req, is_detail):
        """Returns a list of servers, based on any search options specified."""

        ### 1.从req中获取传入的search_opts和context
        search_opts = {}
        search_opts.update(req.GET)

        context = req.environ['nova.context']

        ### 2.移除非法的查询参数
        ###     如果调用者是admin，则仅移除'sort_key', 'sort_dir', 'limit', 'marker'这四个值
        ###     否则仅允许有如下查询参数，其余查询参数均会被舍弃
        ###         ('reservation_id', 'name', 'status', 'image', 'flavor',
        ###         'ip', 'changes-since', 'all_tenants')(如果API的版本不低于2.4，则还允许'ip6')
        remove_invalid_options(context, search_opts,
                self._get_server_search_options(req))

        # Verify search by 'status' contains a valid status.
        # Convert it to filter by vm_state or task_state for compute_api.
        ### 3.如果search_opts中存在key'status'，用具体的'vm_state'和'task_state'代替它，步骤如下：
        ###     从search_opts中移除'status'，第二个参数'None'是防止search_opts中没有'status'这个key
        ###     从req中直接获取具体的'status'的值，根据'status'和'vm_state'+'task_state'的对应关系，获取传入的'status'值对应的
        ###         具体的'vm_state'和'task_state'，如果req中有'status'这个key，但是获取的'vm_state','task_state'同时为空，
        ###         直接返回[]，否则将'vm_state'和'task_state'(如果有需要)加入到search_opts中
        search_opts.pop('status', None)
        if 'status' in req.GET.keys():
            ### 通过url传过来的值中可能有多个"status='xxx'"，将它们全部取出
            statuses = req.GET.getall('status')
            states = common.task_and_vm_state_from_status(statuses)
            vm_state, task_state = states
            if not vm_state and not task_state:
                return {'servers': []}
            search_opts['vm_state'] = vm_state
            # When we search by vm state, task state will return 'default'.
            # So we don't need task_state search_opt.
            if 'default' not in task_state:
                search_opts['task_state'] = task_state

        ### 4.将search_opts中可能存在的'changes-since'的值规范化，使之与数据库中的时间格式一致
        if 'changes-since' in search_opts:
            try:
                parsed = timeutils.parse_isotime(search_opts['changes-since'])
            except ValueError:
                msg = _('Invalid changes-since value')
                raise exc.HTTPBadRequest(explanation=msg)
            search_opts['changes-since'] = parsed

        # By default, compute's get_all() will return deleted instances.
        # If an admin hasn't specified a 'deleted' search option, we need
        # to filter out deleted instances by setting the filter ourselves.
        # ... Unless 'changes-since' is specified, because 'changes-since'
        # should return recently deleted images according to the API spec.

        ### 5.当'deleted'不存在于search_opts中，如果'changes-since'也不在search_opts中，
        ###     则search_opts['deleted']默认为False
        ###   如果'deleted'存在于search_opts中，则确保search_opts['deleted']值为bool类型，默认为False
        if 'deleted' not in search_opts:
            if 'changes-since' not in search_opts:
                # No 'changes-since', so we only want non-deleted servers
                search_opts['deleted'] = False
        else:
            # Convert deleted filter value to a valid boolean.
            # Return non-deleted servers if an invalid value
            # is passed with deleted filter.
            search_opts['deleted'] = strutils.bool_from_string(
                search_opts['deleted'], default=False)

        ### 6.当只想查询处于'deleted'状态的虚拟机时，判断是否为admin用户在操作，
        ###   如果是，则将search_opts['deleted']设置为True，如果不是，则拒绝此次查询
        ###   只有admin用户可以查询已被删除的虚拟机
        if search_opts.get("vm_state") == ['deleted']:
            if context.is_admin:
                search_opts['deleted'] = True
            else:
                msg = _("Only administrators may list deleted instances")
                raise exc.HTTPForbidden(explanation=msg)

        # If tenant_id is passed as a search parameter this should
        # imply that all_tenants is also enabled unless explicitly
        # disabled. Note that the tenant_id parameter is filtered out
        # by remove_invalid_options above unless the requestor is an
        # admin.

            # TODO(gmann): 'all_tenants' flag should not be required while
        # searching with 'tenant_id'. Ref bug# 1185290
        # +microversions to achieve above mentioned behavior by
        # uncommenting below code.

        # if 'tenant_id' in search_opts and 'all_tenants' not in search_opts:
            # We do not need to add the all_tenants flag if the tenant
            # id associated with the token is the tenant id
            # specified. This is done so a request that does not need
            # the all_tenants flag does not fail because of lack of
            # policy permission for compute:get_all_tenants when it
            # doesn't actually need it.
            # if context.project_id != search_opts.get('tenant_id'):
            #    search_opts['all_tenants'] = 1

        ### 7.确保all_tenants的值为bool值，当'all_tenants'的值为空字符串
        ###   因为'all_tenants'的值已被取出，从search_opts中移除它的值
        all_tenants = common.is_all_tenants(search_opts)
        # use the boolean from here on out so remove the entry from search_opts
        # if it's present
        search_opts.pop('all_tenants', None)

        elevated = None
        ### 8.'all_tenants'为True时，验证是否有获取所有租户的虚拟机信息的权限
        ###     context.elevated()将权限直接提升至'admin'
        ###   'all_tenants'为False时，将'project_id'和'user_id'放入到search_opts中
        if all_tenants:
            if is_detail:
                authorize(context, action="detail:get_all_tenants")
            else:
                authorize(context, action="index:get_all_tenants")
            elevated = context.elevated()
        else:
            if context.project_id:
                search_opts['project_id'] = context.project_id
            else:
                search_opts['user_id'] = context.user_id

        ### 9.从req中获取limit，maker，sort_keys，sort_dirs的值
        ###   limit最大默认为1000，sort_keys默认为'created_at', sort_dirs默认为'desc'
        limit, marker = common.get_limit_and_marker(req)
        sort_keys, sort_dirs = common.get_sort_params(req.params)

        ### 10.将此处的expected_attrs与ViewBuilder中的_show_expected_attrs合并
        ###    处理后的expected_attrs的值为['flavor', 'info_cache', 'metadata', 'pci_devices'](已经过排序)
        expected_attrs = ['pci_devices']
        if is_detail:
            # merge our expected attrs with what the view builder needs for
            # showing details
            expected_attrs = self._view_builder.get_show_expected_attrs(
                                                                expected_attrs)

        ### 11.调用compute_api中的get_all()函数来获取虚拟机的信息
        try:
            instance_list = self.compute_api.get_all(elevated or context,
                    search_opts=search_opts, limit=limit, marker=marker,
                    want_objects=True, expected_attrs=expected_attrs,
                    sort_keys=sort_keys, sort_dirs=sort_dirs)
        except exception.MarkerNotFound:
            msg = _('marker [%s] not found') % marker
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.FlavorNotFound:
            LOG.debug("Flavor '%s' could not be found ",
                      search_opts['flavor'])
            instance_list = objects.InstanceList()

        ### 12.通过_view_builder构建返回值
        if is_detail:
            ### 将instance_list中每个虚拟机对应的最新的一条错误记录放入到instance.fault中
            instance_list.fill_faults()
            response = self._view_builder.detail(req, instance_list)
        else:
            response = self._view_builder.index(req, instance_list)

        ### 缓存虚拟机信息
        req.cache_db_instances(instance_list)
        return response

    def _get_server(self, context, req, instance_uuid, is_detail=False):
        """Utility function for looking up an instance by uuid.

        :param context: request context for auth
        :param req: HTTP request. The instance is cached in this request.
        :param instance_uuid: UUID of the server instance to get
        :param is_detail: True if you plan on showing the details of the
            instance in the response, False otherwise.
        """
        expected_attrs = ['flavor', 'pci_devices']
        if is_detail:
            expected_attrs = self._view_builder.get_show_expected_attrs(
                                                            expected_attrs)
        instance = common.get_instance(self.compute_api, context,
                                       instance_uuid,
                                       expected_attrs=expected_attrs)
        req.cache_db_instance(instance)
        return instance

    def _check_string_length(self, value, name, max_length=None):
        try:
            if isinstance(value, six.string_types):
                ### 去掉value中的空白字符
                value = value.strip()
            utils.check_string_length(value, name, min_length=1,
                                      max_length=max_length)
        except exception.InvalidInput as e:
            raise exc.HTTPBadRequest(explanation=e.format_message())

    def _get_requested_networks(self, requested_networks):
        """Create a list of requested networks from the networks attribute."""
        networks = []
        network_uuids = []
        for network in requested_networks:
            request = objects.NetworkRequest()
            try:
                # fixed IP address is optional
                # if the fixed IP address is not provided then
                # it will use one of the available IP address from the network
                request.address = network.get('fixed_ip', None)
                request.port_id = network.get('port', None)

                if request.port_id:
                    request.network_id = None
                    if not utils.is_neutron():
                        # port parameter is only for neutron v2.0
                        msg = _("Unknown argument: port")
                        raise exc.HTTPBadRequest(explanation=msg)
                    if request.address is not None:
                        msg = _("Specified Fixed IP '%(addr)s' cannot be used "
                                "with port '%(port)s': port already has "
                                "a Fixed IP allocated.") % {
                                    "addr": request.address,
                                    "port": request.port_id}
                        raise exc.HTTPBadRequest(explanation=msg)
                else:
                    request.network_id = network['uuid']

                if (not request.port_id and
                        not uuidutils.is_uuid_like(request.network_id)):
                    br_uuid = request.network_id.split('-', 1)[-1]
                    if not uuidutils.is_uuid_like(br_uuid):
                        msg = _("Bad networks format: network uuid is "
                                "not in proper format "
                                "(%s)") % request.network_id
                        raise exc.HTTPBadRequest(explanation=msg)

                # duplicate networks are allowed only for neutron v2.0
                if (not utils.is_neutron() and request.network_id and
                        request.network_id in network_uuids):
                    expl = (_("Duplicate networks"
                              " (%s) are not allowed") %
                            request.network_id)
                    raise exc.HTTPBadRequest(explanation=expl)
                network_uuids.append(request.network_id)
                networks.append(request)
            except KeyError as key:
                expl = _('Bad network format: missing %s') % key
                raise exc.HTTPBadRequest(explanation=expl)
            except TypeError:
                expl = _('Bad networks format')
                raise exc.HTTPBadRequest(explanation=expl)

        return objects.NetworkRequestList(objects=networks)

    # NOTE(vish): Without this regex, b64decode will happily
    #             ignore illegal bytes in the base64 encoded
    #             data.
    B64_REGEX = re.compile('^(?:[A-Za-z0-9+\/]{4})*'
                           '(?:[A-Za-z0-9+\/]{2}=='
                           '|[A-Za-z0-9+\/]{3}=)?$')

    def _decode_base64(self, data):
        data = re.sub(r'\s', '', data)
        if not self.B64_REGEX.match(data):
            return None
        try:
            return base64.b64decode(data)
        except TypeError:
            return None

    @extensions.expected_errors(404)
    def show(self, req, id):
        """Returns server details by server id."""
        context = req.environ['nova.context']
        authorize(context, action="show")
        instance = self._get_server(context, req, id, is_detail=True)
        return self._view_builder.show(req, instance)

    @wsgi.response(202)
    @extensions.expected_errors((400, 403, 409, 413))
    @validation.schema(schema_server_create_v20, '2.0', '2.0')
    @validation.schema(schema_server_create, '2.1')
    def create(self, req, body):
        """Creates a new server for a given user."""

        context = req.environ['nova.context']
        server_dict = body['server']
        password = self._get_server_admin_password(server_dict)
        name = common.normalize_name(server_dict['name'])

        # Arguments to be passed to instance create function
        create_kwargs = {}

        # Query extensions which want to manipulate the keyword
        # arguments.
        # NOTE(cyeoh): This is the hook that extensions use
        # to replace the extension specific code below.
        # When the extensions are ported this will also result
        # in some convenience function from this class being
        # moved to the extension
        if list(self.create_extension_manager):
            self.create_extension_manager.map(self._create_extension_point,
                                              server_dict, create_kwargs, body)

        availability_zone = create_kwargs.get("availability_zone")

        target = {
            'project_id': context.project_id,
            'user_id': context.user_id,
            'availability_zone': availability_zone}
        authorize(context, target, 'create')

        # TODO(Shao He, Feng) move this policy check to os-availabilty-zone
        # extension after refactor it.
        if availability_zone:
            _dummy, host, node = self.compute_api._handle_availability_zone(
                context, availability_zone)
            if host or node:
                authorize(context, {}, 'create:forced_host')

        block_device_mapping = create_kwargs.get("block_device_mapping")
        # TODO(Shao He, Feng) move this policy check to os-block-device-mapping
        # extension after refactor it.
        if block_device_mapping:
            authorize(context, target, 'create:attach_volume')

        image_uuid = self._image_from_req_data(server_dict, create_kwargs)

        # NOTE(cyeoh): Although an extension can set
        # return_reservation_id in order to request that a reservation
        # id be returned to the client instead of the newly created
        # instance information we do not want to pass this parameter
        # to the compute create call which always returns both. We use
        # this flag after the instance create call to determine what
        # to return to the client
        return_reservation_id = create_kwargs.pop('return_reservation_id',
                                                  False)

        requested_networks = None
        if ('os-networks' in self.extension_info.get_extensions()
                or utils.is_neutron()):
            requested_networks = server_dict.get('networks')

        if requested_networks is not None:
            requested_networks = self._get_requested_networks(
                requested_networks)

        if requested_networks and len(requested_networks):
            authorize(context, target, 'create:attach_network')

        try:
            flavor_id = self._flavor_id_from_req_data(body)
        except ValueError:
            msg = _("Invalid flavorRef provided.")
            raise exc.HTTPBadRequest(explanation=msg)

        try:
            inst_type = flavors.get_flavor_by_flavor_id(
                    flavor_id, ctxt=context, read_deleted="no")

            (instances, resv_id) = self.compute_api.create(context,
                            inst_type,
                            image_uuid,
                            display_name=name,
                            display_description=name,
                            metadata=server_dict.get('metadata', {}),
                            admin_password=password,
                            requested_networks=requested_networks,
                            check_server_group_quota=True,
                            **create_kwargs)
        except (exception.QuotaError,
                exception.PortLimitExceeded) as error:
            raise exc.HTTPForbidden(
                explanation=error.format_message(),
                headers={'Retry-After': 0})
        except exception.ImageNotFound:
            msg = _("Can not find requested image")
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.FlavorNotFound:
            msg = _("Invalid flavorRef provided.")
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.KeypairNotFound:
            msg = _("Invalid key_name provided.")
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.ConfigDriveInvalidValue:
            msg = _("Invalid config_drive provided.")
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.ExternalNetworkAttachForbidden as error:
            raise exc.HTTPForbidden(explanation=error.format_message())
        except messaging.RemoteError as err:
            msg = "%(err_type)s: %(err_msg)s" % {'err_type': err.exc_type,
                                                 'err_msg': err.value}
            raise exc.HTTPBadRequest(explanation=msg)
        except UnicodeDecodeError as error:
            msg = "UnicodeError: %s" % error
            raise exc.HTTPBadRequest(explanation=msg)
        except (exception.ImageNotActive,
                exception.FlavorDiskTooSmall,
                exception.FlavorMemoryTooSmall,
                exception.InvalidMetadata,
                exception.InvalidRequest,
                exception.InvalidVolume,
                exception.MultiplePortsNotApplicable,
                exception.InvalidFixedIpAndMaxCountRequest,
                exception.InstanceUserDataMalformed,
                exception.InstanceUserDataTooLarge,
                exception.PortNotFound,
                exception.FixedIpAlreadyInUse,
                exception.SecurityGroupNotFound,
                exception.PortRequiresFixedIP,
                exception.NetworkRequiresSubnet,
                exception.NetworkNotFound,
                exception.NetworkDuplicated,
                exception.InvalidBDMSnapshot,
                exception.InvalidBDMVolume,
                exception.InvalidBDMImage,
                exception.InvalidBDMBootSequence,
                exception.InvalidBDMLocalsLimit,
                exception.InvalidBDMVolumeNotBootable,
                exception.AutoDiskConfigDisabledByImage,
                exception.ImageNUMATopologyIncomplete,
                exception.ImageNUMATopologyForbidden,
                exception.ImageNUMATopologyAsymmetric,
                exception.ImageNUMATopologyCPUOutOfRange,
                exception.ImageNUMATopologyCPUDuplicates,
                exception.ImageNUMATopologyCPUsUnassigned,
                exception.ImageNUMATopologyMemoryOutOfRange) as error:
            raise exc.HTTPBadRequest(explanation=error.format_message())
        except (exception.PortInUse,
                exception.InstanceExists,
                exception.NetworkAmbiguous,
                exception.NoUniqueMatch) as error:
            raise exc.HTTPConflict(explanation=error.format_message())

        # If the caller wanted a reservation_id, return it
        if return_reservation_id:
            # NOTE(cyeoh): In v3 reservation_id was wrapped in
            # servers_reservation but this is reverted for V2 API
            # compatibility. In the long term with the tasks API we
            # will probably just drop the concept of reservation_id
            return wsgi.ResponseObject({'reservation_id': resv_id})

        req.cache_db_instances(instances)
        server = self._view_builder.create(req, instances[0])

        if CONF.enable_instance_password:
            server['server']['adminPass'] = password

        robj = wsgi.ResponseObject(server)

        return self._add_location(robj)

    # NOTE(gmann): Parameter 'req_body' is placed to handle scheduler_hint
    # extension for V2.1. No other extension supposed to use this as
    # it will be removed soon.
    def _create_extension_point(self, ext, server_dict,
                                create_kwargs, req_body):
        handler = ext.obj
        LOG.debug("Running _create_extension_point for %s", ext.obj)

        handler.server_create(server_dict, create_kwargs, req_body)

    def _rebuild_extension_point(self, ext, rebuild_dict, rebuild_kwargs):
        handler = ext.obj
        LOG.debug("Running _rebuild_extension_point for %s", ext.obj)

        handler.server_rebuild(rebuild_dict, rebuild_kwargs)

    def _resize_extension_point(self, ext, resize_dict, resize_kwargs):
        handler = ext.obj
        LOG.debug("Running _resize_extension_point for %s", ext.obj)

        handler.server_resize(resize_dict, resize_kwargs)

    def _update_extension_point(self, ext, update_dict, update_kwargs):
        handler = ext.obj
        LOG.debug("Running _update_extension_point for %s", ext.obj)
        handler.server_update(update_dict, update_kwargs)

    def _create_extension_schema(self, ext, create_schema, version):
        handler = ext.obj
        LOG.debug("Running _create_extension_schema for %s", ext.obj)

        schema = handler.get_server_create_schema(version)
        if ext.obj.name == 'SchedulerHints':
            # NOTE(oomichi): The request parameter position of scheduler-hint
            # extension is different from the other extensions, so here handles
            # the difference.
            create_schema['properties'].update(schema)
        else:
            create_schema['properties']['server']['properties'].update(schema)

    def _update_extension_schema(self, ext, update_schema, version):
        handler = ext.obj
        LOG.debug("Running _update_extension_schema for %s", ext.obj)

        schema = handler.get_server_update_schema(version)
        update_schema['properties']['server']['properties'].update(schema)

    def _rebuild_extension_schema(self, ext, rebuild_schema, version):
        handler = ext.obj
        LOG.debug("Running _rebuild_extension_schema for %s", ext.obj)

        schema = handler.get_server_rebuild_schema(version)
        rebuild_schema['properties']['rebuild']['properties'].update(schema)

    def _resize_extension_schema(self, ext, resize_schema, version):
        handler = ext.obj
        LOG.debug("Running _resize_extension_schema for %s", ext.obj)

        schema = handler.get_server_resize_schema(version)
        resize_schema['properties']['resize']['properties'].update(schema)

    def _delete(self, context, req, instance_uuid):
        authorize(context, action='delete')
        instance = self._get_server(context, req, instance_uuid)
        if CONF.reclaim_instance_interval:
            try:
                self.compute_api.soft_delete(context, instance)
            except exception.InstanceInvalidState:
                # Note(yufang521247): instance which has never been active
                # is not allowed to be soft_deleted. Thus we have to call
                # delete() to clean up the instance.
                self.compute_api.delete(context, instance)
        else:
            self.compute_api.delete(context, instance)

    @extensions.expected_errors((400, 404))
    @validation.schema(schema_server_update_v20, '2.0', '2.0')
    @validation.schema(schema_server_update, '2.1')
    def update(self, req, id, body):
        """Update server then pass on to version-specific controller."""

        ### 从req中获取context，并验证用户是否有update的权限
        ctxt = req.environ['nova.context']
        update_dict = {}
        authorize(ctxt, action='update')

        ### 如果需要修改虚拟机的名称
        ###     将'name'对应为'display_name'
        ###     将传入的名称规范化（去掉名称开头和结尾的空白字符）
        if 'name' in body['server']:
            update_dict['display_name'] = common.normalize_name(
                body['server']['name'])

        ### self.update_extension_manager:
        ###     <stevedore.enabled.EnabledExtensionManager object at 0x5b40750>
        ### EnabledExtensionManager.__dict__:
        ###     {
        ###         'check_func': <function check_load_extension at 0x60e9668>,
        ###         'namespace': 'nova.api.v21.extensions.server.update',
        ###         '_on_load_failure_callback': None,
        ###         'extensions': [
        ###             <stevedore.extension.Extension object at 0x68e2a10>,
        ###             <stevedore.extension.Extension object at 0x68e2a90>
        ###         ],
        ###         'propagate_map_exceptions': True,
        ###         '_extensions_by_name': None
        ###     }
        ### 上面的两个extension的值如下：
        ###     {
        ###         'obj': <Extension: name=DiskConfig, alias=os-disk-config, version=1>,
        ###         'entry_point': EntryPoint.parse('disk_config = nova.api.openstack.compute.disk_config:DiskConfig'),
        ###         'name': 'disk_config',
        ###         'plugin': <class 'nova.api.openstack.compute.disk_config.DiskConfig'>
        ###     }
        ###     {
        ###         'obj': <Extension: name=AccessIPs, alias=os-access-ips, version=1>,
        ###         'entry_point': EntryPoint.parse('access_ips = nova.api.openstack.compute.access_ips:AccessIPs'),
        ###         'name': 'access_ips',
        ###         'plugin': <class 'nova.api.openstack.compute.access_ips.AccessIPs'>
        ###     }
        if list(self.update_extension_manager):
            ### def map(self, func, *args, **kwds):
            ###     if not self.extensions
            ###         raise NoMatches('No %s extensions found' % self.namespace)
            ###     response = []
            ###     for e in self.extensions:
            ###         ### def _invoke_one_plugin(self, response_callback, func, e, args, kwds):
            ###         ###     try:
            ###         ###         response_callback(func(e, *args, **kwds))
            ###         ###     except Exception as err:
            ###         ###         if self.propagate_map_exceptions:
            ###         ###             raise
            ###         ###         else:
            ###         ###             LOG.error('error calling %r: %s', e.name, err)
            ###         ###             LOG.exception(err)
            ###         self._invoke_one_plugin(response.append, func, e, args, kwds)
            ###     return response
            ### def _update_extension_point(self, ext, update_dict, update_kwargs):
            ###     handler = ext.obj
            ###     LOG.debug("Running _update_extension_point for %s", ext.obj)
            ###     handler.server_update(update_dict, update_kwargs)

            ### 对于disk_config:
            ###     def server_create(self, server_dict, create_kwargs,
            ###                       body_deprecated_param=None):
            ###         ### API_DISK_CONFIG = "OS-DCF:diskConfig"
            ###         if API_DISK_CONFIG in server_dict:
            ###             api_value = server_dict[API_DISK_CONFIG]
            ###             ### def disk_config_from_api(value):
            ###             ###     if value == 'AUTO':
            ###             ###         return True
            ###             ###     elif value == 'MANUAL':
            ###             ###         return False
            ###             ###     else:
            ###             ###         msg = _("%s must be either 'MANUAL' or 'AUTO'.") % API_DISK_CONFIG
            ###             ###        raise exc.HTTPBadRequest(explanation=msg)
            ###             internal_value = disk_config_from_api(api_value)
            ###             ### INTERNAL_DISK_CONFIG = "auto_disk_config"
            ###             create_kwargs[INTERNAL_DISK_CONFIG] = internal_value

            ###    server_update = server_create

            ### 对于access_ips:
            ###     def server_create(self, server_dict, create_kwargs,
            ###                       body_deprecated_param=None):
            ###         if AccessIPs.v4_key in server_dict:
            ###             access_ip_v4 = server_dict.get(AccessIPs.v4_key)
            ###             if access_ip_v4:
            ###                 create_kwargs['access_ip_v4'] = access_ip_v4
            ###             else:
            ###                 create_kwargs['access_ip_v4'] = None
            ###         if AccessIPs.v6_key in server_dict:
            ###             access_ip_v6 = server_dict.get(AccessIPs.v6_key)
            ###             if access_ip_v6:
            ###                 create_kwargs['access_ip_v6'] = access_ip_v6
            ###             else:
            ###                 create_kwargs['access_ip_v6'] = None

            ###     server_update = server_create
            self.update_extension_manager.map(self._update_extension_point,
                                              body['server'], update_dict)

        ### 通过传入的ID获取虚拟机，将需要修改的信息更新到虚拟机中，保存虚拟机
        instance = self._get_server(ctxt, req, id, is_detail=True)
        try:
            # NOTE(mikal): this try block needs to stay because save() still
            # might throw an exception.
            instance.update(update_dict)
            instance.save()
            ### 通过_view_builder构造虚拟机的信息，并返回
            return self._view_builder.show(req, instance,
                                           extend_address=False)
        except exception.InstanceNotFound:
            msg = _("Instance could not be found")
            raise exc.HTTPNotFound(explanation=msg)

    # NOTE(gmann): Returns 204 for backwards compatibility but should be 202
    # for representing async API as this API just accepts the request and
    # request hypervisor driver to complete the same in async mode.
    @wsgi.response(204)
    @extensions.expected_errors((400, 404, 409))
    @wsgi.action('confirmResize')
    def _action_confirm_resize(self, req, id, body):
        context = req.environ['nova.context']
        authorize(context, action='confirm_resize')
        instance = self._get_server(context, req, id)
        try:
            self.compute_api.confirm_resize(context, instance)
        except exception.InstanceUnknownCell as e:
            raise exc.HTTPNotFound(explanation=e.format_message())
        except exception.MigrationNotFound:
            msg = _("Instance has not been resized.")
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'confirmResize', id)

    @wsgi.response(202)
    @extensions.expected_errors((400, 404, 409))
    @wsgi.action('revertResize')
    def _action_revert_resize(self, req, id, body):
        context = req.environ['nova.context']
        authorize(context, action='revert_resize')
        instance = self._get_server(context, req, id)
        try:
            self.compute_api.revert_resize(context, instance)
        except exception.InstanceUnknownCell as e:
            raise exc.HTTPNotFound(explanation=e.format_message())
        except exception.MigrationNotFound:
            msg = _("Instance has not been resized.")
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.FlavorNotFound:
            msg = _("Flavor used by the instance could not be found.")
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'revertResize', id)

    @wsgi.response(202)
    @extensions.expected_errors((404, 409))
    @wsgi.action('reboot')
    @validation.schema(schema_servers.reboot)
    def _action_reboot(self, req, id, body):

        reboot_type = body['reboot']['type'].upper()
        context = req.environ['nova.context']
        authorize(context, action='reboot')
        instance = self._get_server(context, req, id)

        try:
            self.compute_api.reboot(context, instance, reboot_type)
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'reboot', id)

    def _resize(self, req, instance_id, flavor_id, **kwargs):
        """Begin the resize process with given instance/flavor."""
        context = req.environ["nova.context"]
        authorize(context, action='resize')
        instance = self._get_server(context, req, instance_id)

        try:
            self.compute_api.resize(context, instance, flavor_id, **kwargs)
        except exception.InstanceUnknownCell as e:
            raise exc.HTTPNotFound(explanation=e.format_message())
        except exception.QuotaError as error:
            raise exc.HTTPForbidden(
                explanation=error.format_message(),
                headers={'Retry-After': 0})
        except exception.FlavorNotFound:
            msg = _("Unable to locate requested flavor.")
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.CannotResizeToSameFlavor:
            msg = _("Resize requires a flavor change.")
            raise exc.HTTPBadRequest(explanation=msg)
        except (exception.CannotResizeDisk,
                exception.AutoDiskConfigDisabledByImage) as e:
            raise exc.HTTPBadRequest(explanation=e.format_message())
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'resize', instance_id)
        except exception.ImageNotAuthorized:
            msg = _("You are not authorized to access the image "
                    "the instance was started with.")
            raise exc.HTTPUnauthorized(explanation=msg)
        except exception.ImageNotFound:
            msg = _("Image that the instance was started "
                    "with could not be found.")
            raise exc.HTTPBadRequest(explanation=msg)
        except (exception.NoValidHost,
                exception.AutoDiskConfigDisabledByImage) as e:
            raise exc.HTTPBadRequest(explanation=e.format_message())
        except exception.Invalid:
            msg = _("Invalid instance image.")
            raise exc.HTTPBadRequest(explanation=msg)

    @wsgi.response(204)
    @extensions.expected_errors((404, 409))
    def delete(self, req, id):
        """Destroys a server."""
        try:
            self._delete(req.environ['nova.context'], req, id)
        except exception.InstanceNotFound:
            msg = _("Instance could not be found")
            raise exc.HTTPNotFound(explanation=msg)
        except exception.InstanceUnknownCell as e:
            raise exc.HTTPNotFound(explanation=e.format_message())
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'delete', id)

    def _image_uuid_from_href(self, image_href):
        # If the image href was generated by nova api, strip image_href
        # down to an id and use the default glance connection params
        image_uuid = image_href.split('/').pop()

        if not uuidutils.is_uuid_like(image_uuid):
            msg = _("Invalid imageRef provided.")
            raise exc.HTTPBadRequest(explanation=msg)

        return image_uuid

    def _image_from_req_data(self, server_dict, create_kwargs):
        """Get image data from the request or raise appropriate
        exceptions.

        The field imageRef is mandatory when no block devices have been
        defined and must be a proper uuid when present.
        """
        image_href = server_dict.get('imageRef')

        if not image_href and create_kwargs.get('block_device_mapping'):
            return ''
        elif image_href:
            return self._image_uuid_from_href(six.text_type(image_href))
        else:
            msg = _("Missing imageRef attribute")
            raise exc.HTTPBadRequest(explanation=msg)

    def _flavor_id_from_req_data(self, data):
        flavor_ref = data['server']['flavorRef']
        return common.get_id_from_href(flavor_ref)

    @wsgi.response(202)
    @extensions.expected_errors((400, 401, 403, 404, 409))
    @wsgi.action('resize')
    @validation.schema(schema_server_resize)
    def _action_resize(self, req, id, body):
        """Resizes a given instance to the flavor size requested."""
        resize_dict = body['resize']
        flavor_ref = str(resize_dict["flavorRef"])

        resize_kwargs = {}

        if list(self.resize_extension_manager):
            self.resize_extension_manager.map(self._resize_extension_point,
                                              resize_dict, resize_kwargs)

        self._resize(req, id, flavor_ref, **resize_kwargs)

    @wsgi.response(202)
    @extensions.expected_errors((400, 403, 404, 409, 413))
    @wsgi.action('rebuild')
    @validation.schema(schema_server_rebuild_v20, '2.0', '2.0')
    @validation.schema(schema_server_rebuild, '2.1')
    def _action_rebuild(self, req, id, body):
        """Rebuild an instance with the given attributes."""
        rebuild_dict = body['rebuild']

        ### 1.获取传入参数中的image的uuid
        image_href = rebuild_dict["imageRef"]
        image_href = self._image_uuid_from_href(image_href)

        ### 2.从传入的参数中获取password，没有传入则随机生成一个
        password = self._get_server_admin_password(rebuild_dict)

        ### 3.从请求中获取context
        ###   通过context验证是否有权限进行'rebuild'
        ###   获取instance
        context = req.environ['nova.context']
        authorize(context, action='rebuild')
        instance = self._get_server(context, req, id)

        attr_map = {
            'name': 'display_name',
            'metadata': 'metadata',
        }

        rebuild_kwargs = {}

        ### self.rebuild_extension_manager:
        ###     <stevedore.enabled.EnabledExtensionManager object at 0x6887450>
        ### list(self.rebuild_extension_manager):
        ###     [
        ###         <stevedore.extension.Extension object at 0xaaaaaaa>,
        ###         <stevedore.extension.Extension object at 0xbbbbbbb>,
        ###         <stevedore.extension.Extension object at 0xccccccc>,
        ###         <stevedore.extension.Extension object at 0xddddddd>，
        ###     ]
        if list(self.rebuild_extension_manager):
            self.rebuild_extension_manager.map(self._rebuild_extension_point,
                                               rebuild_dict, rebuild_kwargs)

        ### request_attribute   instance_attribute
        ### 'name'              'display_name'
        ### 'metadata'          'metadata'
        for request_attribute, instance_attribute in attr_map.items():
            try:
                if request_attribute == 'name':
                    rebuild_kwargs[instance_attribute] = common.normalize_name(
                        rebuild_dict[request_attribute])
                else:
                    rebuild_kwargs[instance_attribute] = rebuild_dict[
                        request_attribute]
            except (KeyError, TypeError):
                pass

        try:
            self.compute_api.rebuild(context,
                                     instance,
                                     image_href,
                                     password,
                                     **rebuild_kwargs)
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'rebuild', id)
        except exception.InstanceNotFound:
            msg = _("Instance could not be found")
            raise exc.HTTPNotFound(explanation=msg)
        except exception.InstanceUnknownCell as e:
            raise exc.HTTPNotFound(explanation=e.format_message())
        except exception.ImageNotFound:
            msg = _("Cannot find image for rebuild")
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.QuotaError as error:
            raise exc.HTTPForbidden(explanation=error.format_message())
        except (exception.ImageNotActive,
                exception.FlavorDiskTooSmall,
                exception.FlavorMemoryTooSmall,
                exception.InvalidMetadata,
                exception.AutoDiskConfigDisabledByImage) as error:
            raise exc.HTTPBadRequest(explanation=error.format_message())

        instance = self._get_server(context, req, id, is_detail=True)

        view = self._view_builder.show(req, instance, extend_address=False)

        # Add on the admin_password attribute since the view doesn't do it
        # unless instance passwords are disabled
        if CONF.enable_instance_password:
            view['server']['adminPass'] = password

        robj = wsgi.ResponseObject(view)
        return self._add_location(robj)

    @wsgi.response(202)
    @extensions.expected_errors((400, 403, 404, 409))
    @wsgi.action('createImage')
    @common.check_snapshots_enabled
    @validation.schema(schema_servers.create_image, '2.0', '2.0')
    @validation.schema(schema_servers.create_image, '2.1')
    def _action_create_image(self, req, id, body):
        """Snapshot a server instance."""
        context = req.environ['nova.context']
        authorize(context, action='create_image')

        entity = body["createImage"]
        image_name = common.normalize_name(entity["name"])
        metadata = entity.get('metadata', {})

        common.check_img_metadata_properties_quota(context, metadata)

        instance = self._get_server(context, req, id)

        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
                    context, instance.uuid)

        try:
            if self.compute_api.is_volume_backed_instance(context, instance,
                                                          bdms):
                authorize(context, action="create_image:allow_volume_backed")
                image = self.compute_api.snapshot_volume_backed(
                                                       context,
                                                       instance,
                                                       image_name,
                                                       extra_properties=
                                                       metadata)
            else:
                image = self.compute_api.snapshot(context,
                                                  instance,
                                                  image_name,
                                                  extra_properties=metadata)
        except exception.InstanceUnknownCell as e:
            raise exc.HTTPNotFound(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                        'createImage', id)
        except exception.Invalid as err:
            raise exc.HTTPBadRequest(explanation=err.format_message())

        # build location of newly-created image entity
        image_id = str(image['id'])
        image_ref = glance.generate_image_url(image_id)

        resp = webob.Response(status_int=202)
        resp.headers['Location'] = image_ref
        return resp

    def _get_server_admin_password(self, server):
        """Determine the admin password for a server on creation."""
        try:
            password = server['adminPass']
        except KeyError:
            password = utils.generate_password()
        return password

    def _get_server_search_options(self, req):
        """Return server search options allowed by non-admin."""
        opt_list = ('reservation_id', 'name', 'status', 'image', 'flavor',
                    'ip', 'changes-since', 'all_tenants')
        req_ver = req.api_version_request
        if req_ver > api_version_request.APIVersionRequest("2.4"):
            opt_list += ('ip6',)
        return opt_list

    def _get_instance(self, context, instance_uuid):
        try:
            attrs = ['system_metadata', 'metadata']
            return objects.Instance.get_by_uuid(context, instance_uuid,
                                                expected_attrs=attrs)
        except exception.InstanceNotFound as e:
            raise webob.exc.HTTPNotFound(explanation=e.format_message())

    @wsgi.response(202)
    @extensions.expected_errors((404, 409))
    @wsgi.action('os-start')
    def _start_server(self, req, id, body):
        """Start an instance."""
        ### 1.获取context, instance并验证是否有start权限
        context = req.environ['nova.context']
        instance = self._get_instance(context, id)
        authorize(context, instance, 'start')
        LOG.debug('start instance', instance=instance)
        try:
            ### 2.调用nova.compute.api.API()中的start()函数
            self.compute_api.start(context, instance)
        except (exception.InstanceNotReady, exception.InstanceIsLocked) as e:
            raise webob.exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceUnknownCell as e:
            raise exc.HTTPNotFound(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                'start', id)

    @wsgi.response(202)
    @extensions.expected_errors((404, 409))
    @wsgi.action('os-stop')
    def _stop_server(self, req, id, body):
        """Stop an instance."""
        ### 1.获取context, instance并验证是否有stop权限
        context = req.environ['nova.context']
        instance = self._get_instance(context, id)
        authorize(context, instance, 'stop')
        LOG.debug('stop instance', instance=instance)
        try:
            ### 2.调用nova.compute.api.API()中的stop()函数
            self.compute_api.stop(context, instance)
        except (exception.InstanceNotReady, exception.InstanceIsLocked) as e:
            raise webob.exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceUnknownCell as e:
            raise exc.HTTPNotFound(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                'stop', id)


def remove_invalid_options(context, search_options, allowed_search_options):
    """Remove search options that are not valid for non-admin API/context."""
    if context.is_admin:
        # Only remove parameters for sorting and pagination
        for key in ('sort_key', 'sort_dir', 'limit', 'marker'):
            search_options.pop(key, None)
        return
    # Otherwise, strip out all unknown options
    unknown_options = [opt for opt in search_options
                        if opt not in allowed_search_options]
    LOG.debug("Removing options '%s' from query",
              ", ".join(unknown_options))
    for opt in unknown_options:
        search_options.pop(opt, None)


class Servers(extensions.V21APIExtensionBase):
    """Servers."""

    name = "Servers"
    alias = ALIAS
    version = 1

    def get_resources(self):
        member_actions = {'action': 'POST'}
        collection_actions = {'detail': 'GET'}
        resources = [
            extensions.ResourceExtension(
                ALIAS,
                ServersController(extension_info=self.extension_info),
                member_name='server', collection_actions=collection_actions,
                member_actions=member_actions)]

        return resources

    def get_controller_extensions(self):
        return []
