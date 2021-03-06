# Copyright 2011 United States Government as represented by the
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

"""Unit tests for `wsgi`."""

import os.path
import platform
import socket
import tempfile
import testtools

import eventlet
import eventlet.wsgi
import mock
import requests
import webob

from oslo_config import cfg
from oslo_config import fixture as config
from oslo_service import _options
from oslo_service import sslutils
from oslo_service import wsgi
from oslo_utils import netutils
from oslotest import base as test_base
from oslotest import moxstubout


SSL_CERT_DIR = os.path.normpath(os.path.join(
                                os.path.dirname(os.path.abspath(__file__)),
                                'ssl_cert'))
CONF = cfg.CONF


class WsgiTestCase(test_base.BaseTestCase):
    """Base class for WSGI tests."""

    def setUp(self):
        super(WsgiTestCase, self).setUp()
        self.conf_fixture = self.useFixture(config.Config())
        self.conf_fixture.register_opts(_options.wsgi_opts)
        self.conf = self.conf_fixture.conf
        self.config = self.conf_fixture.config
        self.conf(args=[], default_config_files=[])


class TestLoaderNothingExists(WsgiTestCase):
    """Loader tests where os.path.exists always returns False."""

    def setUp(self):
        super(TestLoaderNothingExists, self).setUp()
        mox_fixture = self.useFixture(moxstubout.MoxStubout())
        self.stubs = mox_fixture.stubs
        self.stubs.Set(os.path, 'exists', lambda _: False)

    def test_relpath_config_not_found(self):
        self.config(api_paste_config='api-paste.ini')
        self.assertRaises(
            wsgi.ConfigNotFound,
            wsgi.Loader,
            self.conf
        )

    def test_asbpath_config_not_found(self):
        self.config(api_paste_config='/etc/openstack-srv/api-paste.ini')
        self.assertRaises(
            wsgi.ConfigNotFound,
            wsgi.Loader,
            self.conf
        )


class TestLoaderNormalFilesystem(WsgiTestCase):
    """Loader tests with normal filesystem (unmodified os.path module)."""

    _paste_config = """
[app:test_app]
use = egg:Paste#static
document_root = /tmp
    """

    def setUp(self):
        super(TestLoaderNormalFilesystem, self).setUp()
        self.paste_config = tempfile.NamedTemporaryFile(mode="w+t")
        self.paste_config.write(self._paste_config.lstrip())
        self.paste_config.seek(0)
        self.paste_config.flush()

        self.config(api_paste_config=self.paste_config.name)
        self.loader = wsgi.Loader(CONF)

    def test_config_found(self):
        self.assertEqual(self.paste_config.name, self.loader.config_path)

    def test_app_not_found(self):
        self.assertRaises(
            wsgi.PasteAppNotFound,
            self.loader.load_app,
            "nonexistent app",
        )

    def test_app_found(self):
        url_parser = self.loader.load_app("test_app")
        self.assertEqual("/tmp", url_parser.directory)

    def tearDown(self):
        self.paste_config.close()
        super(TestLoaderNormalFilesystem, self).tearDown()


class TestWSGIServer(WsgiTestCase):
    """WSGI server tests."""

    def setUp(self):
        super(TestWSGIServer, self).setUp()

    def test_no_app(self):
        server = wsgi.Server(self.conf, "test_app", None)
        self.assertEqual("test_app", server.name)

    def test_custom_max_header_line(self):
        self.config(max_header_line=4096)  # Default value is 16384
        wsgi.Server(self.conf, "test_custom_max_header_line", None)
        self.assertEqual(self.conf.max_header_line,
                         eventlet.wsgi.MAX_HEADER_LINE)

    def test_start_random_port(self):
        server = wsgi.Server(self.conf, "test_random_port", None,
                             host="127.0.0.1", port=0)
        server.start()
        self.assertNotEqual(0, server.port)
        server.stop()
        server.wait()

    @testtools.skipIf(not netutils.is_ipv6_enabled(), "no ipv6 support")
    def test_start_random_port_with_ipv6(self):
        server = wsgi.Server(self.conf, "test_random_port", None,
                             host="::1", port=0)
        server.start()
        self.assertEqual("::1", server.host)
        self.assertNotEqual(0, server.port)
        server.stop()
        server.wait()

    @testtools.skipIf(platform.mac_ver()[0] != '',
                      'SO_REUSEADDR behaves differently '
                      'on OSX, see bug 1436895')
    def test_socket_options_for_simple_server(self):
        # test normal socket options has set properly
        self.config(tcp_keepidle=500)
        server = wsgi.Server(self.conf, "test_socket_options", None,
                             host="127.0.0.1", port=0)
        server.start()
        sock = server._socket
        self.assertEqual(1, sock.getsockopt(socket.SOL_SOCKET,
                                            socket.SO_REUSEADDR))
        self.assertEqual(1, sock.getsockopt(socket.SOL_SOCKET,
                                            socket.SO_KEEPALIVE))
        if hasattr(socket, 'TCP_KEEPIDLE'):
            self.assertEqual(self.conf.tcp_keepidle,
                             sock.getsockopt(socket.IPPROTO_TCP,
                                             socket.TCP_KEEPIDLE))
        self.assertFalse(server._server.dead)
        server.stop()
        server.wait()
        self.assertTrue(server._server.dead)

    def test_server_pool_waitall(self):
        # test pools waitall method gets called while stopping server
        server = wsgi.Server(self.conf, "test_server", None, host="127.0.0.1")
        server.start()
        with mock.patch.object(server._pool,
                               'waitall') as mock_waitall:
            server.stop()
            server.wait()
            mock_waitall.assert_called_once_with()

    def test_uri_length_limit(self):
        eventlet.monkey_patch(os=False, thread=False)
        server = wsgi.Server(self.conf, "test_uri_length_limit", None,
                             host="127.0.0.1", max_url_len=16384, port=33337)
        server.start()
        self.assertFalse(server._server.dead)

        uri = "http://127.0.0.1:%d/%s" % (server.port, 10000 * 'x')
        resp = requests.get(uri, proxies={"http": ""})
        eventlet.sleep(0)
        self.assertNotEqual(resp.status_code,
                            requests.codes.REQUEST_URI_TOO_LARGE)

        uri = "http://127.0.0.1:%d/%s" % (server.port, 20000 * 'x')
        resp = requests.get(uri, proxies={"http": ""})
        eventlet.sleep(0)
        self.assertEqual(resp.status_code,
                         requests.codes.REQUEST_URI_TOO_LARGE)
        server.stop()
        server.wait()

    def test_reset_pool_size_to_default(self):
        server = wsgi.Server(self.conf, "test_resize", None,
                             host="127.0.0.1", max_url_len=16384)
        server.start()

        # Stopping the server, which in turn sets pool size to 0
        server.stop()
        self.assertEqual(server._pool.size, 0)

        # Resetting pool size to default
        server.reset()
        server.start()
        self.assertEqual(server._pool.size, CONF.wsgi_default_pool_size)

    def test_client_socket_timeout(self):
        self.config(client_socket_timeout=5)

        # mocking eventlet spawn method to check it is called with
        # configured 'client_socket_timeout' value.
        with mock.patch.object(eventlet,
                               'spawn') as mock_spawn:
            server = wsgi.Server(self.conf, "test_app", None,
                                 host="127.0.0.1", port=0)
            server.start()
            _, kwargs = mock_spawn.call_args
            self.assertEqual(self.conf.client_socket_timeout,
                             kwargs['socket_timeout'])
            server.stop()

    def test_wsgi_keep_alive(self):
        self.config(wsgi_keep_alive=False)

        # mocking eventlet spawn method to check it is called with
        # configured 'wsgi_keep_alive' value.
        with mock.patch.object(eventlet,
                               'spawn') as mock_spawn:
            server = wsgi.Server(self.conf, "test_app", None,
                                 host="127.0.0.1", port=0)
            server.start()
            _, kwargs = mock_spawn.call_args
            self.assertEqual(self.conf.wsgi_keep_alive,
                             kwargs['keepalive'])
            server.stop()


class TestWSGIServerWithSSL(WsgiTestCase):
    """WSGI server with SSL tests."""

    def setUp(self):
        super(TestWSGIServerWithSSL, self).setUp()
        self.conf_fixture.register_opts(_options.ssl_opts,
                                        sslutils.config_section)
        cert_file_name = os.path.join(SSL_CERT_DIR, 'certificate.crt')
        key_file_name = os.path.join(SSL_CERT_DIR, 'privatekey.key')
        eventlet.monkey_patch(os=False, thread=False)

        self.config(cert_file=cert_file_name,
                    key_file=key_file_name,
                    group=sslutils.config_section)

    def test_ssl_server(self):
        def test_app(env, start_response):
            start_response('200 OK', {})
            return ['PONG']

        fake_ssl_server = wsgi.Server(self.conf, "fake_ssl", test_app,
                                      host="127.0.0.1", port=0, use_ssl=True)
        fake_ssl_server.start()
        self.assertNotEqual(0, fake_ssl_server.port)

        cli = eventlet.connect(("localhost", fake_ssl_server.port))
        ca_certs_name = os.path.join(SSL_CERT_DIR, 'ca.crt')
        cli = eventlet.wrap_ssl(cli, ca_certs=ca_certs_name)

        cli.write('POST / HTTP/1.1\r\nHost: localhost\r\n'
                  'Connection: close\r\nContent-length:4\r\n\r\nPING')
        response = cli.read(8192)
        self.assertEqual(response[-4:], "PONG")

        fake_ssl_server.stop()
        fake_ssl_server.wait()

    def test_two_servers(self):
        def test_app(env, start_response):
            start_response('200 OK', {})
            return ['PONG']

        fake_ssl_server = wsgi.Server(self.conf, "fake_ssl", test_app,
                                      host="127.0.0.1", port=0, use_ssl=True)
        fake_ssl_server.start()
        self.assertNotEqual(0, fake_ssl_server.port)

        fake_server = wsgi.Server(self.conf, "fake", test_app,
                                  host="127.0.0.1", port=0)
        fake_server.start()
        self.assertNotEqual(0, fake_server.port)

        cli = eventlet.connect(("localhost", fake_ssl_server.port))
        cli = eventlet.wrap_ssl(cli,
                                ca_certs=os.path.join(SSL_CERT_DIR, 'ca.crt'))

        cli.write('POST / HTTP/1.1\r\nHost: localhost\r\n'
                  'Connection: close\r\nContent-length:4\r\n\r\nPING')
        response = cli.read(8192)
        self.assertEqual(response[-4:], "PONG")

        cli = eventlet.connect(("localhost", fake_server.port))

        cli.sendall('POST / HTTP/1.1\r\nHost: localhost\r\n'
                    'Connection: close\r\nContent-length:4\r\n\r\nPING')
        response = cli.recv(8192)
        self.assertEqual(response[-4:], "PONG")

        fake_ssl_server.stop()
        fake_ssl_server.wait()

    @testtools.skipIf(platform.mac_ver()[0] != '',
                      'SO_REUSEADDR behaves differently '
                      'on OSX, see bug 1436895')
    def test_socket_options_for_ssl_server(self):
        # test normal socket options has set properly
        self.config(tcp_keepidle=500)
        server = wsgi.Server(self.conf, "test_socket_options", None,
                             host="127.0.0.1", port=0, use_ssl=True)
        server.start()
        sock = server._socket
        self.assertEqual(1, sock.getsockopt(socket.SOL_SOCKET,
                                            socket.SO_REUSEADDR))
        self.assertEqual(1, sock.getsockopt(socket.SOL_SOCKET,
                                            socket.SO_KEEPALIVE))
        if hasattr(socket, 'TCP_KEEPIDLE'):
            self.assertEqual(CONF.tcp_keepidle,
                             sock.getsockopt(socket.IPPROTO_TCP,
                                             socket.TCP_KEEPIDLE))
        server.stop()
        server.wait()

    @testtools.skipIf(not netutils.is_ipv6_enabled(), "no ipv6 support")
    def test_app_using_ipv6_and_ssl(self):
        greetings = 'Hello, World!!!'

        @webob.dec.wsgify
        def hello_world(req):
            return greetings

        server = wsgi.Server(self.conf, "fake_ssl",
                             hello_world,
                             host="::1",
                             port=0,
                             use_ssl=True)

        server.start()

        response = requests.get('https://[::1]:%d/' % server.port,
                                verify=os.path.join(SSL_CERT_DIR, 'ca.crt'))
        self.assertEqual(greetings, response.text)

        server.stop()
        server.wait()
