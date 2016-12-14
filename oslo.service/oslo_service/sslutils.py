# coding=utf-8
# Copyright 2013 IBM Corp.
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

import copy
import os
import ssl

from oslo_service._i18n import _
from oslo_service import _options

# ssl Secure Sockets Layer 安全套接层
config_section = 'ssl'


# ssl_opts = [
#     cfg.StrOpt('version',
#                help='SSL version to use (valid only if SSL enabled). '
#                     'Valid values are TLSv1 and SSLv23. SSLv2, SSLv3, '
#                     'TLSv1_1, and TLSv1_2 may be available on some '
#                     'distributions.'
#                ),
#     cfg.StrOpt('ciphers',
#                help='Sets the list of available ciphers. value should be a '
#                     'string in the OpenSSL cipher list format.'
#                ),
# ]
def list_opts():
    """Entry point for oslo-config-generator."""
    return [(config_section, copy.deepcopy(_options.ssl_opts))]


# 判断能否使用SSL, 步骤如下:
### 1.如果配置文件的SSL段中配置了cert_file或者key_file, 则use_ssl=True
### 2.根据配置文件, 如果cert_file, ca_file, key_file这三个key有value, 则判断value指定的路径是否存在, 不存在则报错
### 3.如果使用SSL, 则需要同时配置cert_file和key_file
### 4.返回use_ssl的值
def is_enabled(conf):
    # config_section = 'ssl'
    conf.register_opts(_options.ssl_opts, config_section)

    #     cfg.StrOpt('cert_file',
    #                help="Certificate file to use when starting "
    #                     "the server securely.",
    #                deprecated_group='DEFAULT',
    #                deprecated_name='ssl_cert_file'),
    cert_file = conf.ssl.cert_file

    #     cfg.StrOpt('key_file',
    #                help="Private key file to use when starting "
    #                     "the server securely.",
    #                deprecated_group='DEFAULT',
    #                deprecated_name='ssl_key_file'),
    key_file = conf.ssl.key_file

    #     cfg.StrOpt('ca_file',
    #                help="CA certificate file to use to verify "
    #                     "connecting clients.",
    #                deprecated_group='DEFAULT',
    #                deprecated_name='ssl_ca_file'),
    ca_file = conf.ssl.ca_file
    use_ssl = cert_file or key_file

    if cert_file and not os.path.exists(cert_file):
        raise RuntimeError(_("Unable to find cert_file : %s") % cert_file)

    if ca_file and not os.path.exists(ca_file):
        raise RuntimeError(_("Unable to find ca_file : %s") % ca_file)

    if key_file and not os.path.exists(key_file):
        raise RuntimeError(_("Unable to find key_file : %s") % key_file)

    if use_ssl and (not cert_file or not key_file):
        raise RuntimeError(_("When running server in SSL mode, you must "
                             "specify both a cert_file and key_file "
                             "option value in your configuration file"))

    return use_ssl


def wrap(conf, sock):
    conf.register_opts(_options.ssl_opts, config_section)
    ssl_kwargs = {
        'server_side': True,
        'certfile': conf.ssl.cert_file,
        'keyfile': conf.ssl.key_file,
        'cert_reqs': ssl.CERT_NONE,
    }

    if conf.ssl.ca_file:
        ssl_kwargs['ca_certs'] = conf.ssl.ca_file
        ssl_kwargs['cert_reqs'] = ssl.CERT_REQUIRED

    return ssl.wrap_socket(sock, **ssl_kwargs)
