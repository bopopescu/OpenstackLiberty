# coding=utf-8
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""
WSGI middleware for OpenStack API controllers.
"""

from oslo_config import cfg
from oslo_log import log as logging
import routes
import six
import stevedore
import webob.dec
import webob.exc

from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova import exception
from nova.i18n import _
from nova.i18n import _LC
from nova.i18n import _LE
from nova.i18n import _LI
from nova.i18n import _LW
from nova.i18n import translate
from nova import notifications
from nova import utils
from nova import wsgi as base_wsgi


api_opts = [
        cfg.BoolOpt('enabled',
                    default=True,
                    help='DEPRECATED: Whether the V2.1 API is enabled or not. '
                    'This option will be removed in the near future.',
                    deprecated_for_removal=True, deprecated_group='osapi_v21'),
        cfg.ListOpt('extensions_blacklist',
                    default=[],
                    help='DEPRECATED: A list of v2.1 API extensions to never '
                    'load. Specify the extension aliases here. '
                    'This option will be removed in the near future. '
                    'After that point you have to run all of the API.',
                    deprecated_for_removal=True, deprecated_group='osapi_v21'),
        cfg.ListOpt('extensions_whitelist',
                    default=[],
                    help='DEPRECATED: If the list is not empty then a v2.1 '
                    'API extension will only be loaded if it exists in this '
                    'list. Specify the extension aliases here. '
                    'This option will be removed in the near future. '
                    'After that point you have to run all of the API.',
                    deprecated_for_removal=True, deprecated_group='osapi_v21')
]
api_opts_group = cfg.OptGroup(name='osapi_v21', title='API v2.1 Options')

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
CONF.register_group(api_opts_group)
CONF.register_opts(api_opts, api_opts_group)

# List of v21 API extensions which are considered to form
# the core API and so must be present
# TODO(cyeoh): Expand this list as the core APIs are ported to v21
API_V21_CORE_EXTENSIONS = set(['os-consoles',
                               'extensions',
                               'os-flavor-extra-specs',
                               'os-flavor-manage',
                               'flavors',
                               'ips',
                               'os-keypairs',
                               'os-flavor-access',
                               'server-metadata',
                               'servers',
                               'versions'])


class FaultWrapper(base_wsgi.Middleware):
    """Calls down the middleware stack, making exceptions into faults."""

    _status_to_type = {}

    @staticmethod
    def status_to_type(status):
        if not FaultWrapper._status_to_type:
            for clazz in utils.walk_class_hierarchy(webob.exc.HTTPError):
                FaultWrapper._status_to_type[clazz.code] = clazz
        return FaultWrapper._status_to_type.get(
                                  status, webob.exc.HTTPInternalServerError)()

    def _error(self, inner, req):
        LOG.exception(_LE("Caught error: %s"), six.text_type(inner))

        safe = getattr(inner, 'safe', False)
        headers = getattr(inner, 'headers', None)
        status = getattr(inner, 'code', 500)
        if status is None:
            status = 500

        msg_dict = dict(url=req.url, status=status)
        LOG.info(_LI("%(url)s returned with HTTP %(status)d"), msg_dict)
        outer = self.status_to_type(status)
        if headers:
            outer.headers = headers
        # NOTE(johannes): We leave the explanation empty here on
        # purpose. It could possibly have sensitive information
        # that should not be returned back to the user. See
        # bugs 868360 and 874472
        # NOTE(eglynn): However, it would be over-conservative and
        # inconsistent with the EC2 API to hide every exception,
        # including those that are safe to expose, see bug 1021373
        if safe:
            user_locale = req.best_match_language()
            inner_msg = translate(inner.message, user_locale)
            outer.explanation = '%s: %s' % (inner.__class__.__name__,
                                            inner_msg)

        notifications.send_api_fault(req.url, status, inner)
        return wsgi.Fault(outer)

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        try:
            ### self.application: <oslo_middleware.sizelimit.RequestBodySizeLimiter object at 0x6ac9dd0>
            return req.get_response(self.application)
        except Exception as ex:
            return self._error(ex, req)


class LegacyV2CompatibleWrapper(base_wsgi.Middleware):

    def _filter_request_headers(self, req):
        """For keeping same behavior with v2 API, ignores microversions
        HTTP header X-OpenStack-Nova-API-Version in the request.
        """

        if wsgi.API_VERSION_REQUEST_HEADER in req.headers:
            del req.headers[wsgi.API_VERSION_REQUEST_HEADER]
        return req

    def _filter_response_headers(self, response):
        """For keeping same behavior with v2 API, filter out microversions
        HTTP header and microversions field in header 'Vary'.
        """

        if wsgi.API_VERSION_REQUEST_HEADER in response.headers:
            del response.headers[wsgi.API_VERSION_REQUEST_HEADER]

        if 'Vary' in response.headers:
            vary_headers = response.headers['Vary'].split(',')
            filtered_vary = []
            for vary in vary_headers:
                vary = vary.strip()
                if vary == wsgi.API_VERSION_REQUEST_HEADER:
                    continue
                filtered_vary.append(vary)
            if filtered_vary:
                response.headers['Vary'] = ','.join(filtered_vary)
            else:
                del response.headers['Vary']
        return response

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        req.set_legacy_v2()
        req = self._filter_request_headers(req)
        response = req.get_response(self.application)
        return self._filter_response_headers(response)


class APIMapper(routes.Mapper):
    def routematch(self, url=None, environ=None):
        if url == "":
            result = self._match("", environ)
            return result[0], result[1]
        return routes.Mapper.routematch(self, url, environ)

    def connect(self, *args, **kargs):
        # NOTE(vish): Default the format part of a route to only accept json
        #             and xml so it doesn't eat all characters after a '.'
        #             in the url.
        kargs.setdefault('requirements', {})
        if not kargs['requirements'].get('format'):
            kargs['requirements']['format'] = 'json|xml'
        return routes.Mapper.connect(self, *args, **kargs)


class ProjectMapper(APIMapper):
    def resource(self, member_name, collection_name, **kwargs):
        if 'parent_resource' not in kwargs:
            kwargs['path_prefix'] = '{project_id}/'
        else:
            parent_resource = kwargs['parent_resource']
            p_collection = parent_resource['collection_name']
            p_member = parent_resource['member_name']
            kwargs['path_prefix'] = '{project_id}/%s/:%s_id' % (p_collection,
                                                                p_member)
        # member_name: server
        # collection_name: servers
        # kwargs:
        #     {
        #         'member': {'action': 'POST'},
        #         'controller': <nova.api.openstack.wsgi.ResourceV21 object at 0x82b4610>,
        #         'collection': {'detail': 'GET'},
        #         'path_prefix': '{project_id:[0-9a-f\\-]+}/'
        #     }
        routes.Mapper.resource(self, member_name,
                                     collection_name,
                                     **kwargs)


class PlainMapper(APIMapper):
    def resource(self, member_name, collection_name, **kwargs):
        if 'parent_resource' in kwargs:
            parent_resource = kwargs['parent_resource']
            p_collection = parent_resource['collection_name']
            p_member = parent_resource['member_name']
            kwargs['path_prefix'] = '%s/:%s_id' % (p_collection, p_member)
        routes.Mapper.resource(self, member_name,
                                     collection_name,
                                     **kwargs)


class APIRouter(base_wsgi.Router):
    """Routes requests on the OpenStack API to the appropriate controller
    and method.
    """
    ExtensionManager = None  # override in subclasses

    @classmethod
    def factory(cls, global_config, **local_config):
        """Simple paste factory, :class:`nova.wsgi.Router` doesn't have one."""
        return cls()

    def __init__(self, ext_mgr=None, init_only=None):
        if ext_mgr is None:
            if self.ExtensionManager:
                ext_mgr = self.ExtensionManager()
            else:
                raise Exception(_("Must specify an ExtensionManager class"))

        mapper = ProjectMapper()
        self.resources = {}
        self._setup_routes(mapper, ext_mgr, init_only)
        self._setup_ext_routes(mapper, ext_mgr, init_only)
        self._setup_extensions(ext_mgr)
        super(APIRouter, self).__init__(mapper)

    def _setup_ext_routes(self, mapper, ext_mgr, init_only):
        for resource in ext_mgr.get_resources():
            LOG.debug('Extending resource: %s',
                      resource.collection)

            if init_only is not None and resource.collection not in init_only:
                continue

            inherits = None
            if resource.inherits:
                inherits = self.resources.get(resource.inherits)
                if not resource.controller:
                    resource.controller = inherits.controller
            wsgi_resource = wsgi.Resource(resource.controller,
                                          inherits=inherits)
            self.resources[resource.collection] = wsgi_resource
            kargs = dict(
                controller=wsgi_resource,
                collection=resource.collection_actions,
                member=resource.member_actions)

            if resource.parent:
                kargs['parent_resource'] = resource.parent

            mapper.resource(resource.collection, resource.collection, **kargs)

            if resource.custom_routes_fn:
                resource.custom_routes_fn(mapper, wsgi_resource)

    def _setup_extensions(self, ext_mgr):
        for extension in ext_mgr.get_controller_extensions():
            collection = extension.collection
            controller = extension.controller

            msg_format_dict = {'collection': collection,
                               'ext_name': extension.extension.name}
            if collection not in self.resources:
                LOG.warning(_LW('Extension %(ext_name)s: Cannot extend '
                                'resource %(collection)s: No such resource'),
                            msg_format_dict)
                continue

            LOG.debug('Extension %(ext_name)s extended resource: '
                      '%(collection)s',
                      msg_format_dict)

            resource = self.resources[collection]
            resource.register_actions(controller)
            resource.register_extensions(controller)

    def _setup_routes(self, mapper, ext_mgr, init_only):
        raise NotImplementedError()


class APIRouterV21(base_wsgi.Router):
    """Routes requests on the OpenStack v2.1 API to the appropriate controller
    and method.
    """

    @classmethod
    def factory(cls, global_config, **local_config):
        """Simple paste factory, :class:`nova.wsgi.Router` doesn't have one."""
        ### cls: <class 'nova.api.openstack.compute.APIRouterV21'>
        ### global_config: {'__file__': '/etc/nova/api-paste.ini', 'here': '/etc/nova'}
        ### local_config: {}
        ### 初始化一个APIRouterV21类的对象并返回
        return cls()

    @staticmethod
    def api_extension_namespace():
        return 'nova.api.v21.extensions'

    def __init__(self, init_only=None, v3mode=False):
        """
        1.检查配置文件中是否启用了APIv2.1(osapi_v21.enabled, 默认为True, 此参数即将被舍弃)
        2.检查配置文件中是否配置了extensions_blacklist或extensions_whitelist,
            如果配置了,警告说在M版本中必须运行API的全部extensions
        3.获取配置文件中extensions_whitelist和extensions_blacklist的交集,
            如果交集中有元素,则警告Extensions同时存在于blacklist和whitelist中
        4.构造一个stevedore.enabled.EnabledExtensionManager的对象,
            构造参数如下:
                namespace='nova.api.v21.extensions',
                check_func=_check_load_extension,
                invoke_on_load=True,
                invoke_kwds={"extension_info": self.loaded_extension_info}
                    (self.loaded_extension_info = extension_info.LoadedExtensionInfo())
        5.检查传入的v3mode参数,v3mode为True时, mapper = PlainMapper(), 否则mapper = ProjectMapper()
        6.检查self.api_extension_manager的extensions是否非空
            如果非空, 执行如下操作:
                self._register_resources_check_inherits(mapper)
                    遍历self.api_extension_manager中所有的extension
                    遍历每个extension中的所有的resource
                    根据extension中是否存在inherits属性的值不为空的resource,
                        将extensions分成两组, 分别调用_register_resources_list函数
                            即对于每个extension执行_register_resources(ext, mapper)操作
        """
        def _check_load_extension(ext):
            if (self.init_only is None or ext.obj.alias in
                self.init_only) and isinstance(ext.obj,
                                               extensions.V21APIExtensionBase):

                # Check whitelist is either empty or if not then the extension
                # is in the whitelist
                if (not CONF.osapi_v21.extensions_whitelist or
                        ext.obj.alias in CONF.osapi_v21.extensions_whitelist):

                    # Check the extension is not in the blacklist
                    blacklist = CONF.osapi_v21.extensions_blacklist
                    if ext.obj.alias not in blacklist:
                        return self._register_extension(ext)
            return False

        ### CONF.osapi_v21.enabled: True
        if not CONF.osapi_v21.enabled:
            LOG.info(_LI("V2.1 API has been disabled by configuration"))
            LOG.warning(_LW("In the M release you must run the v2.1 API."))
            return

        ### CONF.osapi_v21.extensions_blacklist: []
        ### CONF.osapi_v21.extensions_whitelist: []
        if (CONF.osapi_v21.extensions_blacklist or
                CONF.osapi_v21.extensions_whitelist):
            LOG.warning(
                _LW('In the M release you must run all of the API. '
                'The concept of API extensions will be removed from '
                'the codebase to ensure there is a single Compute API.'))

        ### self.init_only: None
        self.init_only = init_only
        LOG.debug("v21 API Extension Blacklist: %s",
                  CONF.osapi_v21.extensions_blacklist)
        LOG.debug("v21 API Extension Whitelist: %s",
                  CONF.osapi_v21.extensions_whitelist)

        ### CONF.osapi_v21.extensions_whitelist: []
        ### CONF.osapi_v21.extensions_blacklist: []
        ### 获取上述两个list的交集
        in_blacklist_and_whitelist = set(
            CONF.osapi_v21.extensions_whitelist).intersection(
                CONF.osapi_v21.extensions_blacklist)
        if len(in_blacklist_and_whitelist) != 0:
            LOG.warning(_LW("Extensions in both blacklist and whitelist: %s"),
                        list(in_blacklist_and_whitelist))

        ### namespace: 'nova.api.v21.extensions'
        ### check_fun: <function _check_load_extension at 0x5907f50>
        ### self.loaded_extension_info: <nova.api.openstack.compute.extension_info.LoadedExtensionInfo object at 0x55b0150>
        self.api_extension_manager = stevedore.enabled.EnabledExtensionManager(
            namespace=self.api_extension_namespace(),
            check_func=_check_load_extension,
            invoke_on_load=True,
            invoke_kwds={"extension_info": self.loaded_extension_info})

        ### v3mode: False
        if v3mode:
            mapper = PlainMapper()
        else:
            mapper = ProjectMapper()

        self.resources = {}

        ### list(self.api_extension_manager) 是依靠类的__iter__函数, 等于list(self.extensions)
        ### self.api_extension_manager: <stevedore.enabled.EnabledExtensionManager object at 0x57a51d0>
        ### mapper: <nova.api.openstack.ProjectMapper object at 0x57a5210>
        if list(self.api_extension_manager):
            self._register_resources_check_inherits(mapper)
            self.api_extension_manager.map(self._register_controllers)

        ### 检查是否缺少了核心的extension
        ### 操作如下：
        ###     使用定义的核心extensions减去已定义的extensions
        ###     如果得到的结果不为空list，则说明有核心extension缺失了
        missing_core_extensions = self.get_missing_core_extensions(
            self.loaded_extension_info.get_extensions().keys())
        if not self.init_only and missing_core_extensions:
            LOG.critical(_LC("Missing core API extensions: %s"),
                         missing_core_extensions)
            raise exception.CoreAPIMissing(
                missing_apis=missing_core_extensions)

        ### Loaded extensions:
        ###     [
        ###         'extensions', 'flavors', 'image-metadata', 'image-size',
        ###         'images', 'ips', 'limits', 'os-access-ips', 'os-admin-actions',
        ###         'os-admin-password', 'os-agents', 'os-aggregates', 'os-assisted-volume-snapshots',
        ###         'os-attach-interfaces', 'os-availability-zone', 'os-baremetal-nodes',
        ###         'os-block-device-mapping', 'os-cells', 'os-certificates', 'os-cloudpipe',
        ###         'os-config-drive', 'os-console-auth-tokens', 'os-console-output',
        ###         'os-consoles', 'os-create-backup', 'os-deferred-delete', 'os-disk-config',
        ###         'os-evacuate', 'os-extended-availability-zone', 'os-extended-server-attributes',
        ###         'os-extended-status', 'os-extended-volumes', 'os-fixed-ips', 'os-flavor-access',
        ###         'os-flavor-extra-specs', 'os-flavor-manage', 'os-flavor-rxtx', 'os-floating-ip-dns',
        ###         'os-floating-ip-pools', 'os-floating-ips', 'os-floating-ips-bulk', 'os-fping',
        ###         'os-hide-server-addresses', 'os-hosts', 'os-hypervisors', 'os-instance-actions',
        ###         'os-instance-usage-audit-log', 'os-keypairs', 'os-lock-server', 'os-migrate-server',
        ###         'os-migrations', 'os-multinic', 'os-multiple-create', 'os-networks',
        ###         'os-networks-associate', 'os-pause-server', 'os-personality',
        ###         'os-preserve-ephemeral-rebuild', 'os-quota-class-sets', 'os-quota-sets',
        ###         'os-remote-consoles', 'os-rescue', 'os-scheduler-hints', 'os-security-group-default-rules',
        ###         'os-security-groups', 'os-server-diagnostics', 'os-server-external-events',
        ###         'os-server-groups', 'os-server-password', 'os-server-usage', 'os-services',
        ###         'os-shelve', 'os-simple-tenant-usage', 'os-suspend-server', 'os-tenant-networks',
        ###         'os-used-limits', 'os-user-data', 'os-virtual-interfaces', 'os-volumes', 'server-metadata',
        ###         'server-migrations', 'servers', 'versions'
        ###      ]
        ###
        LOG.info(_LI("Loaded extensions: %s"),
                 sorted(self.loaded_extension_info.get_extensions().keys()))
        super(APIRouterV21, self).__init__(mapper)

    def _register_resources_list(self, ext_list, mapper):
        for ext in ext_list:
            self._register_resources(ext, mapper)

    def _register_resources_check_inherits(self, mapper):
        ### mapper: <nova.api.openstack.ProjectMapper object at 0x57a5210>

        ext_has_inherits = []
        ext_no_inherits = []

        ### self.api_extension_manager: <stevedore.enabled.EnabledExtensionManager object at 0x57a51d0>
        ### ext: <stevedore.extension.Extension object at 0x6de4f50>
        ### ext.__dict__:
        ###     {
        ###         'obj': <Extension: name=Cells, alias=os-cells, version=1>,
        ###         'entry_point': EntryPoint.parse('cells = nova.api.openstack.compute.cells:Cells'),
        ###         'name': 'cells',
        ###         'plugin': <class 'nova.api.openstack.compute.cells.Cells'>
        ###     }
        for ext in self.api_extension_manager:
            for resource in ext.obj.get_resources():
                if resource.inherits:
                    ext_has_inherits.append(ext)
                    break
            else:
                ext_no_inherits.append(ext)

        self._register_resources_list(ext_no_inherits, mapper)
        self._register_resources_list(ext_has_inherits, mapper)

    @staticmethod
    def get_missing_core_extensions(extensions_loaded):
        ### API_V21_CORE_EXTENSIONS:
        ###     [
        ###         'os-consoles', 'extensions', 'os-flavor-extra-specs', 'os-flavor-manage',
        ###         'flavors', 'ips', 'os-keypairs', 'os-flavor-access', 'server-metadata',
        ###         'servers', 'versions'
        ###     ]
        extensions_loaded = set(extensions_loaded)
        missing_extensions = API_V21_CORE_EXTENSIONS - extensions_loaded
        return list(missing_extensions)

    @property
    def loaded_extension_info(self):
        raise NotImplementedError()

    def _register_extension(self, ext):
        raise NotImplementedError()

    def _register_resources(self, ext, mapper):
        """Register resources defined by the extensions

        Extensions define what resources they want to add through a
        get_resources function

        1.遍历extension的所有resource
        2.对于每个resource:
            如果resource的inherits属性不为空,
                从self.resources中获取resource.inherits所指定的resource
                如果resource的controller属性为空,则将inherits指定的resource的controller赋值给它
        3.使用resource的controller和inherits对应的resource构造一个wsgi.ResourceV21对象,
            并将其添加到self.resources中, key为resource.collection
        4.构造kargs, 其值如下:
            {
                'controller': wsgi_resource                 --- wsgi.ResourceV21()
                'collection': resource.collection_actions   --- eg: {'detail': 'GET'}
                'member': resource.member_actions           --- eg: {'action': 'POST'}
                'parent_resource': resource.parent          --- 如果resource.parent为空, 则字典没有此key
            }
        5.执行mapper.resource(member_name, resource.collection,**kargs)
            根据kwargs现有属性
            def resource(self, member_name, collection_name, **kwargs):
                if 'parent_resource' not in kwargs:
                    kwargs['path_prefix'] = '{project_id}/'
                else:
                    parent_resource = kwargs['parent_resource']
                    p_collection = parent_resource['collection_name']
                    p_member = parent_resource['member_name']
                    kwargs['path_prefix'] = '{project_id}/%s/:%s_id' % (p_collection,
                                                                        p_member)
                routes.Mapper.resource(self, member_name,
                                             collection_name,
                                             **kwargs)
        6.如果resource.custom_routes_fn属性不为空,
            执行resource.custom_routes_fn(mapper, wsgi_resource)
        """

        ### ext.obj: <Extension: name=Servers, alias=servers, version=1>
        handler = ext.obj
        LOG.debug("Running _register_resources on %s", ext.obj)

        ### get_resources =['servers']
        for resource in handler.get_resources():
            LOG.debug('Extended resource: %s', resource.collection)

            inherits = None
            ### resource.inherits = None
            if resource.inherits:
                inherits = self.resources.get(resource.inherits)
                if not resource.controller:
                    resource.controller = inherits.controller
            ### resource.controller: <nova.api.openstack.compute.servers.ServersController object at 0x85d4b90>
            ### inherits: None
            wsgi_resource = wsgi.ResourceV21(resource.controller,
                                             inherits=inherits)
            self.resources[resource.collection] = wsgi_resource
            ### wsgi_resource: <nova.api.openstack.wsgi.ResourceV21 object at 0x86d4690>
            ### resource.collection_actions: {'detail': 'GET'}
            ### resource.member_actions: {'action': 'POST'}
            kargs = dict(
                controller=wsgi_resource,
                collection=resource.collection_actions,
                member=resource.member_actions)

            ### resource.parent: None
            if resource.parent:
                kargs['parent_resource'] = resource.parent

            # non core-API plugins use the collection name as the
            # member name, but the core-API plugins use the
            # singular/plural convention for member/collection names
            ### resource.member_name: 'server'
            ### resource.collection: 'servers'
            if resource.member_name:
                member_name = resource.member_name
            else:
                member_name = resource.collection
            mapper.resource(member_name, resource.collection,
                            **kargs)

            ### resource.custom_routes_fn: None
            if resource.custom_routes_fn:
                    resource.custom_routes_fn(mapper, wsgi_resource)

    def _register_controllers(self, ext):
        """Register controllers defined by the extensions

        Extensions define what resources they want to add through
        a get_controller_extensions function
        """

        handler = ext.obj
        LOG.debug("Running _register_controllers on %s", ext.obj)

        for extension in handler.get_controller_extensions():
            ext_name = extension.extension.name
            collection = extension.collection
            controller = extension.controller

            if collection not in self.resources:
                LOG.warning(_LW('Extension %(ext_name)s: Cannot extend '
                                'resource %(collection)s: No such resource'),
                            {'ext_name': ext_name, 'collection': collection})
                continue

            LOG.debug('Extension %(ext_name)s extending resource: '
                      '%(collection)s',
                      {'ext_name': ext_name, 'collection': collection})

            resource = self.resources[collection]
            resource.register_actions(controller)
            resource.register_extensions(controller)
