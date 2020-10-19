# Copyright 2012 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011,2012 Akira YOSHIYAMA <akirayoshiyama@gmail.com>
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This source code is based ./auth_token.py and ./ec2_token.py.
# See them for their copyright.

"""
S3 Token Middleware

This WSGI component:

* Gets a request from the swift3 middleware with an S3 Authorization
  access key.
* Validates s3 token in Keystone.
* Transforms the account name to AUTH_%(tenant_name).
* Optionally can retrieve and cache secret from keystone
  to validate signature locally

"""

import base64
import json

from keystoneclient.v3 import client as keystone_client
from keystoneauth1 import session as keystone_session
from keystoneauth1 import loading as keystone_loading
import requests
import httplib
import six
from six.moves import urllib

from swift.common.swob import Request, HTTPBadRequest, HTTPUnauthorized, \
    HTTPException, HTTPServiceUnavailable
from swift.common.utils import config_true_value, split_path, get_logger, \
    cache_from_env
from swift.common.wsgi import ConfigFileError

from swift3.utils import is_valid_ipv6


PROTOCOL_NAME = 'S3 Token Authentication'

# Headers to purge if they came from (or may have come from) the client
KEYSTONE_AUTH_HEADERS = (
    'X-Identity-Status', 'X-Service-Identity-Status',
    'X-Domain-Id', 'X-Service-Domain-Id',
    'X-Domain-Name', 'X-Service-Domain-Name',
    'X-Project-Id', 'X-Service-Project-Id',
    'X-Project-Name', 'X-Service-Project-Name',
    'X-Project-Domain-Id', 'X-Service-Project-Domain-Id',
    'X-Project-Domain-Name', 'X-Service-Project-Domain-Name',
    'X-User-Id', 'X-Service-User-Id',
    'X-User-Name', 'X-Service-User-Name',
    'X-User-Domain-Id', 'X-Service-User-Domain-Id',
    'X-User-Domain-Name', 'X-Service-User-Domain-Name',
    'X-Roles', 'X-Service-Roles',
    'X-Is-Admin-Project',
    'X-Service-Catalog',
    # Deprecated headers, too...
    'X-Tenant-Id',
    'X-Tenant-Name',
    'X-Tenant',
    'X-User',
    'X-Role',
)


def parse_v2_response(token):
    access_info = token['access']
    headers = {
        'X-Identity-Status': 'Confirmed',
        'X-Roles': ','.join(r['name']
                            for r in access_info['user']['roles']),
        'X-User-Id': access_info['user']['id'],
        'X-User-Name': access_info['user']['name'],
        'X-Tenant-Id': access_info['token']['tenant']['id'],
        'X-Tenant-Name': access_info['token']['tenant']['name'],
        'X-Project-Id': access_info['token']['tenant']['id'],
        'X-Project-Name': access_info['token']['tenant']['name'],
    }
    return (
        headers,
        access_info['token'].get('id'),
        access_info['token']['tenant'])


def parse_v3_response(token):
    token = token['token']
    headers = {
        'X-Identity-Status': 'Confirmed',
        'X-Roles': ','.join(r['name']
                            for r in token['roles']),
        'X-User-Id': token['user']['id'],
        'X-User-Name': token['user']['name'],
        'X-User-Domain-Id': token['user']['domain']['id'],
        'X-User-Domain-Name': token['user']['domain']['name'],
        'X-Tenant-Id': token['project']['id'],
        'X-Tenant-Name': token['project']['name'],
        'X-Project-Id': token['project']['id'],
        'X-Project-Name': token['project']['name'],
        'X-Project-Domain-Id': token['project']['domain']['id'],
        'X-Project-Domain-Name': token['project']['domain']['name'],
    }
    return headers, None, token['project']


class S3Token(object):
    """Middleware that handles S3 authentication."""

    def __init__(self, app, conf):
        """Common initialization code."""
        self._app = app
        self._logger = get_logger(
            conf, log_route=conf.get('log_name', 's3token'))
        self._logger.debug('Starting the %s component', PROTOCOL_NAME)
        self._timeout = float(conf.get('http_timeout', '10.0'))
        if not (0 < self._timeout <= 60):
            raise ValueError('http_timeout must be between 0 and 60 seconds')
        self._reseller_prefix = conf.get('reseller_prefix', 'AUTH_')
        self._delay_auth_decision = config_true_value(
            conf.get('delay_auth_decision'))

        # where to find the auth service (we use this to validate tokens)
        self._request_uri = conf.get('auth_uri')
        if not self._request_uri:
            self._logger.warning(
                "Use of the auth_host, auth_port, and auth_protocol "
                "configuration options was deprecated in the Newton release "
                "in favor of auth_uri. These options may be removed in a "
                "future release.")
            auth_host = conf.get('auth_host')
            if not auth_host:
                raise ConfigFileError('Either auth_uri or auth_host required')
            elif is_valid_ipv6(auth_host):
                # Note(timburke) it is an IPv6 address, so it needs to be
                # wrapped with '[]' to generate a valid IPv6 URL, based on
                # http://www.ietf.org/rfc/rfc2732.txt
                auth_host = '[%s]' % auth_host
            auth_port = int(conf.get('auth_port', 35357))
            auth_protocol = conf.get('auth_protocol', 'https')

            self._request_uri = '%s://%s:%s' % (auth_protocol, auth_host,
                                                auth_port)
        self._request_uri = self._request_uri.rstrip('/')
        parsed = urllib.parse.urlsplit(self._request_uri)
        if not parsed.scheme or not parsed.hostname:
            raise ConfigFileError(
                'Invalid auth_uri; must include scheme and host')
        if parsed.scheme not in ('http', 'https'):
            raise ConfigFileError(
                'Invalid auth_uri; scheme must be http or https')
        if parsed.query or parsed.fragment or '@' in parsed.netloc:
            raise ConfigFileError('Invalid auth_uri; must not include '
                                  'username, query, or fragment')
        self._request_uri += '/v%s/s3tokens' % conf.get('auth_version', '2.0')
        self._max_attempts = 1 + int(conf.get('max_retries', 1))

        # SSL
        insecure = config_true_value(conf.get('insecure'))
        cert_file = conf.get('certfile')
        key_file = conf.get('keyfile')

        if insecure:
            self._verify = False
        elif cert_file and key_file:
            self._verify = (cert_file, key_file)
        elif cert_file:
            self._verify = cert_file
        else:
            self._verify = None

        self.session = requests.Session()

        self._secret_cache_duration = int(conf.get('secret_cache_duration', 0))
        if self._secret_cache_duration > 0:
            try:
                auth_plugin = keystone_loading.get_plugin_loader(
                    conf.get('auth_type'))
                available_auth_options = auth_plugin.get_options()
                auth_options = {}
                for option in available_auth_options:
                    name = option.name.replace('-', '_')
                    value = conf.get(name)
                    if value:
                        auth_options[name] = value

                auth = auth_plugin.load_from_options(**auth_options)
                session = keystone_session.Session(auth=auth)
                self.keystoneclient = keystone_client.Client(session=session)
                self._logger.info("Caching s3tokens for %s seconds",
                                  self._secret_cache_duration)
            except Exception:
                self._logger.warning("Unable to load keystone auth_plugin. "
                                     "Secret caching will be unavailable.",
                                     exc_info=True)
                self.keystoneclient = None
                self._secret_cache_duration = 0

    def _deny_request(self, code):
        error_cls, message = {
            'AccessDenied': (HTTPUnauthorized, 'Access denied'),
            'InvalidURI': (HTTPBadRequest,
                           'Could not parse the specified URI'),
            'ServiceUnavailable': (HTTPServiceUnavailable,
                                   'Service unavailable'),
        }[code]
        resp = error_cls(content_type='text/xml')
        error_msg = ('<?xml version="1.0" encoding="UTF-8"?>\r\n'
                     '<Error>\r\n  <Code>%s</Code>\r\n  '
                     '<Message>%s</Message>\r\n</Error>\r\n' %
                     (code, message))
        if six.PY3:
            error_msg = error_msg.encode()
        resp.body = error_msg
        return resp

    def _json_request(self, creds_json, tx_id):
        headers = {
            'Content-Type': 'application/json',
            'X-Trans-Id': tx_id
        }
        for attempt in range(self._max_attempts):
            try:
                response = self.session.post(
                    self._request_uri, headers=headers,
                    data=creds_json, verify=self._verify,
                    timeout=self._timeout)
            except requests.exceptions.Timeout as e:
                self._logger.info('HTTP timeout: %s', e)
                raise self._deny_request('ServiceUnavailable')
            except httplib.BadStatusLine as e:
                # See https://github.com/requests/requests/issues/2364
                self._logger.warning('HTTP request raised %s', e)
                if attempt + 1 >= self._max_attempts:
                    raise self._deny_request('ServiceUnavailable')
                self._logger.warning('retrying (%d/%d)',
                                     attempt + 1, self._max_attempts - 1)
                continue
            except requests.exceptions.RequestException as e:
                self._logger.warning('HTTP connection exception: %s', e)
                # Sometimes, we don't get httplib.BadStatusLine,
                # but a RequestException with a nested ProtocolError
                # with BadStatusLine as message.
                if 'BadStatusLine' in str(e) and \
                        attempt + 1 < self._max_attempts:
                    self._logger.warning('retrying (%d/%d)',
                                         attempt + 1, self._max_attempts - 1)
                    continue
                raise self._deny_request('InvalidURI')

            if response.status_code >= 500:
                self._logger.warning(
                    'Keystone reply error: status=%s reason=%s',
                    response.status_code, response.reason)
                if attempt + 1 >= self._max_attempts:
                    raise self._deny_request('ServiceUnavailable')
                self._logger.warning('retrying (%d/%d)',
                                     attempt + 1, self._max_attempts - 1)
                continue
            elif response.status_code < 200 or response.status_code >= 300:
                self._logger.debug('Keystone reply error: status=%s reason=%s',
                                   response.status_code, response.reason)
                raise self._deny_request('AccessDenied')
            break

        return response

    def __call__(self, environ, start_response):
        """Handle incoming request. authenticate and send downstream."""
        req = Request(environ)
        self._logger.debug('Calling S3Token middleware.')

        # Always drop auth headers if we're first in the pipeline
        if 'keystone.token_info' not in req.environ:
            req.headers.update({h: None for h in KEYSTONE_AUTH_HEADERS})

        try:
            parts = split_path(req.path, 1, 4, True)
            version, account, container, obj = parts
        except ValueError:
            msg = 'Not a path query: %s, skipping.' % req.path
            self._logger.debug(msg)
            return self._app(environ, start_response)

        # Read request signature and access id.
        s3_auth_details = req.environ.get('swift3.auth_details')
        if not s3_auth_details:
            msg = 'No authorization deatils from Swift3. skipping.'
            self._logger.debug(msg)
            return self._app(environ, start_response)

        access = s3_auth_details['access_key']
        if isinstance(access, six.binary_type):
            access = access.decode('utf-8')

        signature = s3_auth_details['signature']
        if isinstance(signature, six.binary_type):
            signature = signature.decode('utf-8')

        string_to_sign = s3_auth_details['string_to_sign']
        if isinstance(string_to_sign, six.text_type):
            string_to_sign = string_to_sign.encode('utf-8')
        token = base64.urlsafe_b64encode(string_to_sign).encode('ascii')

        # NOTE(chmou): This is to handle the special case with nova
        # when we have the option s3_affix_tenant. We will force it to
        # connect to another account than the one
        # authenticated. Before people start getting worried about
        # security, I should point that we are connecting with
        # username/token specified by the user but instead of
        # connecting to its own account we will force it to go to an
        # another account. In a normal scenario if that user don't
        # have the reseller right it will just fail but since the
        # reseller account can connect to every account it is allowed
        # by the swift_auth middleware.
        force_tenant = None
        if ':' in access:
            access, force_tenant = access.split(':')

        # Authenticate request.
        creds = {'credentials': {'access': access,
                                 'token': token,
                                 'signature': signature}}

        memcache_client = None
        memcache_token_key = 's3secret/%s' % access
        if self._secret_cache_duration > 0:
            memcache_client = cache_from_env(environ)
        cached_auth_data = None

        if memcache_client:
            cached_auth_data = memcache_client.get(memcache_token_key)
            if cached_auth_data:
                headers, token_id, tenant, secret = cached_auth_data
                if six.PY2 and isinstance(secret, six.text_type):
                    secret = secret.encode('utf-8')
                if s3_auth_details['check_signature'](secret):
                    self._logger.debug("Cached creds valid")
                else:
                    self._logger.debug("Cached creds invalid")
                    cached_auth_data = None

        if not cached_auth_data:
            creds_json = json.dumps(creds)
            self._logger.debug('Connecting to Keystone sending this JSON: %s',
                               creds_json)
            # NOTE(vish): We could save a call to keystone by having
            #             keystone return token, tenant, user, and roles
            #             from this call.
            #
            # NOTE(chmou): We still have the same problem we would need to
            #              change token_auth to detect if we already
            #              identified and not doing a second query and just
            #              pass it through to swiftauth in this case.
            try:
                # NB: requests.Response, not swob.Response
                tx_id = environ.get('swift.trans_id', 'UNKNOWN')
                resp = self._json_request(creds_json, tx_id)
            except HTTPException as e_resp:
                if self._delay_auth_decision:
                    msg = ('Received error, deferring rejection based on '
                           'error: %s')
                    self._logger.debug(msg, e_resp.status)
                    return self._app(environ, start_response)
                else:
                    msg = 'Received error, rejecting request with error: %s'
                    self._logger.debug(msg, e_resp.status)
                    # NB: swob.Response, not requests.Response
                    return e_resp(environ, start_response)

            self._logger.debug('Keystone Reply: Status: %d, Output: %s',
                               resp.status_code, resp.content)

            try:
                token = resp.json()
                if 'access' in token:
                    headers, token_id, tenant = parse_v2_response(token)
                elif 'token' in token:
                    headers, token_id, tenant = parse_v3_response(token)
                else:
                    raise ValueError
                if memcache_client:
                    user_id = headers.get('X-User-Id')
                    if not user_id:
                        raise ValueError
                    try:
                        cred_ref = self.keystoneclient.ec2.get(
                            user_id=user_id,
                            access=access)
                        memcache_client.set(
                            memcache_token_key,
                            (headers, token_id, tenant, cred_ref.secret),
                            time=self._secret_cache_duration)
                        self._logger.debug("Cached keystone credentials")
                    except Exception:
                        self._logger.warning("Unable to cache secret",
                                             exc_info=True)

                # Populate the environment similar to auth_token,
                # so we don't have to contact Keystone again.
                #
                # Note that although the strings are unicode following json
                # deserialization, Swift's HeaderEnvironProxy handles ensuring
                # they're stored as native strings
                req.environ['keystone.token_info'] = token
            except (ValueError, KeyError, TypeError):
                if self._delay_auth_decision:
                    error = ('Error on keystone reply: %d %s - '
                             'deferring rejection downstream')
                    self._logger.debug(error, resp.status_code, resp.content)
                    return self._app(environ, start_response)
                else:
                    error = ('Error on keystone reply: %d %s - '
                             'rejecting request')
                    self._logger.debug(error, resp.status_code, resp.content)
                    return self._deny_request('InvalidURI')(
                        environ, start_response)

        req.headers.update(headers)
        req.headers['X-Auth-Token'] = token_id
        tenant_to_connect = force_tenant or tenant['id']
        if six.PY2 and isinstance(tenant_to_connect, six.text_type):
            tenant_to_connect = tenant_to_connect.encode('utf-8')
        self._logger.debug('Connecting with tenant: %s', tenant_to_connect)
        new_tenant_name = '%s%s' % (self._reseller_prefix, tenant_to_connect)
        environ['PATH_INFO'] = environ['PATH_INFO'].replace(account,
                                                            new_tenant_name)
        return self._app(environ, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return S3Token(app, conf)
    return auth_filter
