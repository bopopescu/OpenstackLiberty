# coding=utf-8
# Copyright (c) 2014 IBM Corp.
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

"""Middleware that ensures x-compute-request-id

Using this middleware provides a convenient way to attach the
x-compute-request-id to only v2 responses. Previously, this header was set in
api/openstack/wsgi.py

Responses for v2.1 API are taken care of by the request_id middleware provided
in oslo.
"""

### api-paste.ini
### [composite:openstack_compute_api_v21]
### use = call:nova.api.auth:pipeline_factory_v21
### noauth2 = compute_req_id faultwrap sizelimit noauth2 osapi_compute_app_v21
### keystone = compute_req_id faultwrap sizelimit authtoken keystonecontext osapi_compute_app_v21


from oslo_context import context
from oslo_middleware import base
import webob.dec


ENV_REQUEST_ID = 'openstack.request_id'
HTTP_RESP_HEADER_REQUEST_ID = 'x-compute-request-id'


class ComputeReqIdMiddleware(base.Middleware):

    @webob.dec.wsgify
    def __call__(self, req):
        """
            参数req:
            {
                'environ': {
                    'SCRIPT_NAME': '/v2',
                    'webob.adhoc_attrs': {
                        'response': <Response at 0x74efa10 200 OK>
                        },
                    'REQUEST_METHOD': 'GET',
                    'PATH_INFO': '/0d6ef9bd028641a8ae239c9c1b1f088f/cloudos-servers/detail',
                    'SERVER_PROTOCOL': 'HTTP/1.0',
                    'QUERY_STRING': 'all_tenants=True',
                    'HTTP_X_AUTH_TOKEN': '42ab4a87008648b5b10e40690aff8fe3',
                    'HTTP_USER_AGENT': 'python-novaclient',
                    'HTTP_CONNECTION': 'keep-alive',
                    'REMOTE_PORT': '48695',
                    'SERVER_NAME': '192.168.65.18',
                    'REMOTE_ADDR': '192.168.65.18',
                    'eventlet.input': <eventlet.wsgi.Input object at 0x7114350>,
                    'wsgi.url_scheme': 'http',
                    'SERVER_PORT': '8774',
                    'wsgi.input': <eventlet.wsgi.Input object at 0x7114350>,
                    'HTTP_HOST': '192.168.65.18:8774',
                    'HTTP_X_AUTH_PROJECT_ID': 'service',
                    'wsgi.multithread': True,
                    'eventlet.posthooks': [],
                    'HTTP_ACCEPT': 'application/json',
                    'wsgi.version': (1, 0),
                    'RAW_PATH_INFO': '/v2/0d6ef9bd028641a8ae239c9c1b1f088f/cloudos-servers/detail',
                    'GATEWAY_INTERFACE': 'CGI/1.1',
                    'wsgi.run_once': False,
                    'wsgi.errors': <open file '<stderr>', mode 'w' at 0x7fd45b2bc1e0>,
                    'wsgi.multiprocess': False,
                    'CONTENT_TYPE': 'text/plain',
                    'HTTP_ACCEPT_ENCODING': 'gzip, deflate',
                    'nova.best_content_type': 'application/json'
                    }
                }
        """

        ### def generate_request_id():
        ###    return b'req-' + str(uuid.uuid4()).encode('ascii')
        req_id = context.generate_request_id()
        req.environ[ENV_REQUEST_ID] = req_id

        ### get_response = Request.send
        ### self.application = <nova.api.openstack.FaultWrapper object at 0x7096250>
        response = req.get_response(self.application)

        if HTTP_RESP_HEADER_REQUEST_ID not in response.headers:
            response.headers.add(HTTP_RESP_HEADER_REQUEST_ID, req_id)

        """
            response示例：
                200 OK
                Content-Type: application/json
                Content-Length: 15282
                x-compute-request-id: req-b6e5f0cb-e354-4f33-8ced-f85f83ab8372
        """
        return response


def send(self, application=None, catch_exc_info=False):
        """
        Like ``.call_application(application)``, except returns a
        response object with ``.status``, ``.headers``, and ``.body``
        attributes.

        This will use ``self.ResponseClass`` to figure out the class
        of the response object to return.

        If ``application`` is not given, this will send the request to
        ``self.make_default_send_app()``
        """
        if application is None:
            application = self.make_default_send_app()
        if catch_exc_info:
            status, headers, app_iter, exc_info = self.call_application(
                application, catch_exc_info=True)
            del exc_info
        else:
            status, headers, app_iter = self.call_application(
                application, catch_exc_info=False)
        return self.ResponseClass(
            status=status, headerlist=list(headers), app_iter=app_iter)

get_response = send