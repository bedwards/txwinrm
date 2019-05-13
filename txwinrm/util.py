
##############################################################################
#
# Copyright (C) Zenoss, Inc. 2013-2019, all rights reserved.
#
# This content is made available according to terms specified in the LICENSE
# file at the top-level directory of this package.
#
##############################################################################

import os
import re
import base64
import logging
import httplib
from datetime import datetime
from collections import namedtuple
from xml.etree import cElementTree as ET
from xml.etree.ElementTree import ParseError
from twisted.internet import reactor, defer
from twisted.internet.protocol import Protocol
from twisted.web.client import Agent
from twisted.internet.error import ConnectError
from twisted.internet.ssl import ClientContextFactory
from twisted.web.http_headers import Headers
from twisted.internet.threads import deferToThread
from . import constants as c
from twisted_utils import add_timeout

from .krb5 import kinit, ccname, add_trusted_realm, config

# ZEN-15434 lazy import to avoid segmentation fault during install
kerberos = None

log = logging.getLogger('winrm')
_XML_WHITESPACE_PATTERN = re.compile(r'>\s+<')
_AGENT = None
_MAX_PERSISTENT_PER_HOST = 200
_CACHED_CONNECTION_TIMEOUT = 24000
_CONNECT_TIMEOUT = 500
_NANOSECONDS_PATTERN = re.compile(r'\.(\d{6})(\d{3})')
_REQUEST_TEMPLATE_NAMES = (
    'enumerate', 'pull',
    'create', 'command', 'send', 'receive', 'signal', 'delete',
    'subscribe', 'event_pull', 'unsubscribe', 'enum_shells', 'pull_shells')
_REQUEST_TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'request')
_REQUEST_TEMPLATES = {}
_CONTENT_TYPE = {'Content-Type': ['application/soap+xml;charset=UTF-8']}
_MAX_KERBEROS_RETRIES = 3
_MARKER = object()
_ENCRYPTED_CONTENT_TYPE = {
    "Content-Type": [
        "multipart/encrypted;"
        "protocol=\"application/HTTP-Kerberos-session-encrypted\";"
        "boundary=\"Encrypted Boundary\""]}
_BODY = """--Encrypted Boundary
Content-Type: application/HTTP-Kerberos-session-encrypted
OriginalContent: type=application/soap+xml;charset=UTF-8;Length={original_length}
--Encrypted Boundary
Content-Type: application/octet-stream
{emsg}--Encrypted Boundary
"""

_KRB_INTERNAL_CACHE_ERR = 'Internal credentials cache error while storing '\
    'credentials while getting initial credentials'


def _has_get_attr(obj, attr_name):
    attr_value = getattr(obj, attr_name, _MARKER)
    if attr_value is _MARKER:
        return False, None
    return True, attr_value


class MyWebClientContextFactory(object):

    def __init__(self):
        self._options = ClientContextFactory()

    def getContext(self, hostname, port):
        return self._options.getContext()


def _get_agent():
    context_factory = MyWebClientContextFactory()
    try:
        # HTTPConnectionPool has been present since Twisted version 12.1
        from twisted.web.client import HTTPConnectionPool
        pool = HTTPConnectionPool(reactor, persistent=True)
        pool.maxPersistentPerHost = _MAX_PERSISTENT_PER_HOST
        pool.cachedConnectionTimeout = _CACHED_CONNECTION_TIMEOUT
        agent = Agent(reactor, context_factory,
                      connectTimeout=_CONNECT_TIMEOUT, pool=pool)
    except ImportError:
        from _zenclient import ZenAgent
        agent = ZenAgent(reactor, context_factory, persistent=True, maxConnectionsPerHostName=1)
    return agent


class _StringProducer(object):
    """
    The length attribute must be a non-negative integer or the constant
    twisted.web.iweb.UNKNOWN_LENGTH. If the length is known, it will be used to
    specify the value for the Content-Length header in the request. If the
    length is unknown the attribute should be set to UNKNOWN_LENGTH. Since more
    servers support Content-Length, if a length can be provided it should be.
    """

    def __init__(self, body):
        self._body = body
        self.length = len(body)

    def startProducing(self, consumer):
        """
        This method is used to associate a consumer with the producer. It
        should return a Deferred which fires when all data has been produced.
        """
        consumer.write(self._body)
        return defer.succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass


def _parse_error_message(xml_str):
    if not xml_str:
        return ""
    try:
        elem = ET.fromstring(xml_str)
        text = elem.findtext('.//{' + c.XML_NS_SOAP_1_2 + '}Text').strip()
        detail = elem.findtext('.//{' + c.XML_NS_SOAP_1_2 + '}Detail/*/*').strip()
    except ParseError:
        return "Malformed XML: {}".format(xml_str)
    except Exception:
        return "Unexpected Response ({})".format(xml_str)
    return "{0} {1}".format(text, detail)


class _ErrorReader(Protocol):

    def __init__(self, gssclient=None):
        self.d = defer.Deferred()
        self._data = []
        self.gssclient = gssclient

    def dataReceived(self, data):
        self._data.append(data)

    def connectionLost(self, reason):
        if self.gssclient:
            try:
                body = self.gssclient.decrypt_body(''.join(self._data))
            except Exception as e:
                body = 'There was a problem decrypting an error message: {}.'\
                       ' Check WinRM logs on {}'.format(e.message, self.gssclient._conn_info.hostname)
        else:
            body = ''.join(self._data)
        message = _parse_error_message(body)
        self.d.callback(message)


class RequestError(Exception):
    pass


class ForbiddenError(RequestError):
    pass


class UnauthorizedError(RequestError):
    pass


def _get_request_template(name):
    if name not in _REQUEST_TEMPLATE_NAMES:
        raise Exception('Invalid request template name: {0}'.format(name))
    if name not in _REQUEST_TEMPLATES:
        path = os.path.join(_REQUEST_TEMPLATE_DIR, '{0}.xml'.format(name))
        with open(path) as f:
            _REQUEST_TEMPLATES[name] = \
                _XML_WHITESPACE_PATTERN.sub('><', f.read()).strip()
    return _REQUEST_TEMPLATES[name]


def _get_basic_auth_header(conn_info):
    authstr = "{0}:{1}".format(conn_info.username, conn_info.password)
    return 'Basic {0}'.format(base64.encodestring(authstr).strip())


GSS_SEM = defer.DeferredSemaphore(1)


class AuthGSSClient(object):
    """Client for working with the gss api.

    The Generic Security Services (GSS) API allows Kerberos implementations to
    be API compatible. Instances of this class operate on a context for GSSAPI
    client-side authentication with the given service principal.

    GSSAPI Function Result Codes:
        -1 : Error
        0  : GSSAPI step continuation (only returned by 'Step' function)
        1  : GSSAPI step complete, or function return OK
    """

    def __init__(self, service, conn_info):
        """Initialize AuthGSSClient.

        @param service: a string containing the service principal in the form
            'type@fqdn' (e.g. 'imap@mail.apple.com').
        """
        # ZEN-15434 Lazy import.  import causes segmentation fault because of
        # differing versions of the kerberos.so file.  Only import here
        global kerberos
        if not kerberos:
            import kerberos
        self._service = service
        self._conn_info = update_conn_info(None, conn_info)
        self._username = self._conn_info.username
        self._password = self._conn_info.password
        self._realm = self._conn_info.username.split('@')[1].upper()
        self._dcip = self._conn_info.dcip
        self._include_dir = self._conn_info.include_dir
        gssflags = kerberos.GSS_C_CONF_FLAG | kerberos.GSS_C_MUTUAL_FLAG |\
            kerberos.GSS_C_SEQUENCE_FLAG | kerberos.GSS_C_INTEG_FLAG

        os.environ['KRB5CCNAME'] = ccname(self._conn_info.username)
        if self._conn_info.trusted_realm and self._conn_info.trusted_kdc:
            add_trusted_realm(self._conn_info.trusted_realm,
                              self._conn_info.trusted_kdc)
        if hasattr(kerberos, 'authGSSClientWrapIov'):
            result_code, self._context = kerberos.authGSSClientInit(
                service,
                gssflags=gssflags)
        else:
            result_code, self._context = kerberos.authGSSClientInit(service)
        if result_code != kerberos.AUTH_GSS_COMPLETE:
            raise Exception('kerberos authGSSClientInit failed')

    def __del__(self):
        if self._context is not None:
            if not kerberos:
                return
            result_code = kerberos.authGSSClientClean(self._context)

            if result_code != kerberos.AUTH_GSS_COMPLETE:
                raise Exception('kerberos authGSSClientClean failed')

    def _step(self, challenge=''):
        """Process a single GSSAPI client-side step.

        Uses the supplied server data. Run through a deferToThread
        so we do not block.

        @param challenge: a string containing the base64-encoded server data
            (which may be empty for the first step).
        @return:          a result code
        """
        log.debug('{} GSSAPI step challenge="{}"'.format(
            self._conn_info.hostname, challenge))

        def gss_step_sem():
            os.environ['KRB5CCNAME'] = ccname(self._conn_info.username)
            log.debug('set KRB5CCNAME to {}'.format(os.environ['KRB5CCNAME']))
            return kerberos.authGSSClientStep(self._context, challenge)

        return deferToThread(gss_step_sem)

    @defer.inlineCallbacks
    def get_base64_client_data(self, challenge=''):
        """Get authorization token.

        @return: a string containing the base64-encoded client data to be sent
            to the server.
        """
        result_code = None
        for i in xrange(_MAX_KERBEROS_RETRIES):
            try:
                result_code = yield self._step(challenge)
                break
            except kerberos.GSSError as e:
                msg = e.args[1][0]
                if msg == 'Cannot determine realm for numeric host address':
                    raise Exception(msg)
                elif msg == 'Server not found in Kerberos database':
                    raise Exception(
                        msg + ': Attempted to get ticket for {}. Ensure'
                        ' reverse DNS is correct.'.format(self._service))
                log.debug('{} {}. Calling kinit.'.format(
                    self._conn_info.hostname, msg))
                kinit_result = yield kinit(
                    self._username,
                    self._password,
                    self._dcip,
                    includedir=self._include_dir,
                    disable_rdns=self._conn_info.disable_rdns)
                if kinit_result:
                    # this error is ok.  it just means more
                    # than one process is calling kinit
                    if _KRB_INTERNAL_CACHE_ERR not in kinit_result:
                        kinit_result = kinit_result.strip()
                        extra = ''
                        if 'Realm not local to KDC while getting initial '\
                                'credentials' in kinit_result:
                            extra = ' Make sure all KDCs are valid: {}'.format(
                                ','.join(config.realms[self._realm]))
                        raise Exception(kinit_result + extra)

        if result_code != kerberos.AUTH_GSS_CONTINUE:
            raise Exception('failed to obtain service principal ticket ({0}).'
                            .format(result_code))
        base64_client_data = kerberos.authGSSClientResponse(self._context)
        defer.returnValue(base64_client_data)

    @defer.inlineCallbacks
    def get_username(self, challenge):
        """
        Get the user name of the principal authenticated via the now complete
        GSSAPI client-side operations.

        @param challenge: a string containing the base64-encoded server data
        @return:          a string containing the user name.
        """
        result_code = yield self._step(challenge)
        if result_code != kerberos.AUTH_GSS_COMPLETE:
            raise Exception('kerberos authGSSClientStep failed ({0}). '
                            'challenge={1}'
                            .format(result_code, challenge))
        defer.returnValue(kerberos.authGSSClientUserName(self._context))

    def encrypt_body(self, body):
        # get original length of body. wrap will encrypt in place
        orig_len = len(body)
        # encode before sending to wrap func
        ebody = base64.b64encode(body)
        # wrap it up
        try:
            rc, pad_len = kerberos.authGSSClientWrapIov(self._context, ebody, 1)
            if rc is not kerberos.AUTH_GSS_COMPLETE:
                log.debug("%s Unable to encrypt message body", self._conn_info.hostname)
                return
        except AttributeError:
            # must be on centos 5, encryption not possible
            return body
        except kerberos.GSSError as e:
            msg = e.args[1][0]
            raise Exception(msg)

        # get wrapped request which is in b64 encoding
        ewrap = kerberos.authGSSClientResponse(self._context)
        # decode wrapped request
        payload = bytes(base64.b64decode(ewrap))
        # add carriage returns to body
        body = _BODY.replace('\n', '\r\n')
        body = bytes(body.format(original_length=orig_len + pad_len, emsg=payload))
        return body

    def decrypt_body(self, body):
        try:
            b_start = body.index("Content-Type: application/octet-stream") + \
                len("Content-Type: application/octet-stream\r\n")
        except ValueError:
            # Unencrypted data, return body
            return body
        b_end = body.index("--Encrypted Boundary", b_start)
        ebody = body[b_start:b_end]
        ebody = base64.b64encode(ebody)
        try:
            rc = kerberos.authGSSClientUnwrapIov(self._context, ebody)
        except kerberos.GSSError as e:
            msg = e.args[1][0]
            raise Exception(msg)
        if rc is not kerberos.AUTH_GSS_COMPLETE:
            log.debug("%s Unable to decrypt message body", self._conn_info.hostname)
            return
        ewrap = kerberos.authGSSClientResponse(self._context)
        body = base64.b64decode(ewrap)
        return body

    def cleanup(self):
        kerberos.authGSSClientClean(self._context)
        self._context = None

    def context_lifetime(self):
        try:
            return kerberos.getGSSClientContextLifetime(self._context)
        except Exception:
            return 0


def get_auth_details(auth_header=''):
    auth_details = ''
    for field in auth_header.split(','):
        try:
            kind, details = field.strip().split(' ', 1)
            if kind.lower() == 'kerberos':
                auth_details = details.strip()
                break
        except ValueError:
            continue
    return auth_details


@defer.inlineCallbacks
def _authenticate_with_kerberos(conn_info, url, agent, gss_client=None):
    service = '{0}@{1}'.format(conn_info.service.upper(), conn_info.hostname)
    if gss_client is None:
        gss_client = AuthGSSClient(
            service,
            conn_info)

    try:
        base64_client_data = yield gss_client.get_base64_client_data()
    except Exception as e:
        log.debug('{} error in get_base64_client_data: {}'.format(
            conn_info.hostname, e))
        raise e
    auth = 'Kerberos {0}'.format(base64_client_data)
    k_headers = Headers(_CONTENT_TYPE)
    k_headers.addRawHeader('Authorization', auth)
    k_headers.addRawHeader('Content-Length', '0')
    log.debug('%s sending auth data', conn_info.hostname)
    response = yield agent.request('POST', url, k_headers, None)
    log.debug('%s received authorization response code %d', conn_info.hostname,
              response.code)
    err_msg = None
    try:
        auth_header = response.headers.getRawHeaders('WWW-Authenticate')[0]
        auth_details = get_auth_details(auth_header)
    except Exception:
        auth_details = None
        err_msg = 'No WWW-Authenticate header found in authentication '\
                  'response.  Be sure Windows Management Framework is '\
                  'up to date.'
        log.debug(err_msg)

    if response.code == httplib.UNAUTHORIZED:
        try:
            if auth_details:
                yield gss_client._step(auth_details)
        except kerberos.GSSError as e:
            msg = "Unauthorized: Received kerberos error during "\
                "authentication of connection {0}: {1}.".format(
                    e.args[1][1], e.args[1][0])
            raise Exception(msg)
        raise UnauthorizedError(
            "Unauthorized to use winrm on {}. Must be Administrator or "
            "user given permissions to use winrm".format(
                conn_info.hostname))
    elif response.code == httplib.FORBIDDEN:
        raise ForbiddenError(
            "Forbidden. Check WinRM port and version.")
    elif response.code != httplib.OK:
        proto = _StringProtocol()
        response.deliverBody(proto)
        xml_str = yield proto.d
        xml_str = gss_client.decrypt_body(xml_str)
        raise Exception(
            "status code {0} received on initial winrm connection {1}"
            .format(response.code, xml_str or err_msg))
    if not auth_details:
        raise Exception(
            'negotiate not found in WWW-Authenticate header: {0}'
            .format(auth_header))
    k_username = yield gss_client.get_username(auth_details)
    log.debug('{} kerberos auth successful for user: {} / {} '
              .format(conn_info.hostname, conn_info.username, k_username))
    defer.returnValue(gss_client)


def update_conn_info(old_conn_info, new_conn_info):
    if old_conn_info is None or not hasattr(old_conn_info, 'connect_timeout'):
        return(ConnectionInfo(hostname=new_conn_info.hostname,
                              auth_type=new_conn_info.auth_type,
                              username=new_conn_info.username,
                              password=new_conn_info.password,
                              scheme=new_conn_info.scheme,
                              port=new_conn_info.port,
                              connectiontype=new_conn_info.connectiontype,
                              keytab=new_conn_info.keytab,
                              dcip=new_conn_info.dcip,
                              timeout=new_conn_info.timeout,
                              trusted_realm=new_conn_info.trusted_realm,
                              trusted_kdc=new_conn_info.trusted_kdc,
                              ipaddress=new_conn_info.ipaddress,
                              service=new_conn_info.service,
                              envelope_size=new_conn_info.envelope_size,
                              code_page=new_conn_info.code_page,
                              locale=new_conn_info.locale,
                              include_dir=new_conn_info.include_dir,
                              disable_rdns=new_conn_info.disable_rdns,
                              connect_timeout=new_conn_info.connect_timeout))
    else:
        return(old_conn_info._replace(hostname=new_conn_info.hostname,
                                      auth_type=new_conn_info.auth_type,
                                      username=new_conn_info.username,
                                      password=new_conn_info.password,
                                      scheme=new_conn_info.scheme,
                                      port=new_conn_info.port,
                                      connectiontype=new_conn_info.connectiontype,
                                      keytab=new_conn_info.keytab,
                                      dcip=new_conn_info.dcip,
                                      timeout=new_conn_info.timeout,
                                      trusted_realm=new_conn_info.trusted_realm,
                                      trusted_kdc=new_conn_info.trusted_kdc,
                                      ipaddress=new_conn_info.ipaddress,
                                      service=new_conn_info.service,
                                      envelope_size=new_conn_info.envelope_size,
                                      code_page=new_conn_info.code_page,
                                      locale=new_conn_info.locale,
                                      include_dir=new_conn_info.include_dir,
                                      disable_rdns=new_conn_info.disable_rdns,
                                      connect_timeout=new_conn_info.connect_timeout))


class ConnectionInfo(namedtuple(
    'ConnectionInfo', [
        'hostname',
        'auth_type',
        'username',
        'password',
        'scheme',
        'port',
        'connectiontype',
        'keytab',
        'dcip',
        'timeout',
        'trusted_realm',
        'trusted_kdc',
        'ipaddress',
        'service',
        'envelope_size',
        'code_page',
        'locale',
        'include_dir',
        'disable_rdns',
        'connect_timeout'])):
    def __new__(cls, hostname, auth_type, username, password, scheme, port,
                connectiontype, keytab, dcip, timeout=60, trusted_realm='',
                trusted_kdc='', ipaddress='', service='', envelope_size=512000,
                code_page=65001, locale='en-US', include_dir=None,
                disable_rdns=False, connect_timeout=60):
        if not ipaddress:
            ipaddress = hostname
        if not service:
            service = scheme
        try:
            connect_timeout = int(connect_timeout)
        except Exception:
            raise
        return super(ConnectionInfo, cls).__new__(cls, hostname, auth_type,
                                                  username, password, scheme,
                                                  port, connectiontype, keytab,
                                                  dcip, timeout,
                                                  trusted_realm, trusted_kdc,
                                                  ipaddress, service,
                                                  envelope_size, code_page,
                                                  locale, include_dir,
                                                  disable_rdns,
                                                  int(connect_timeout))


def verify_include_dir(conn_info):
    has_include_dir, include_dir = _has_get_attr(conn_info, 'include_dir')
    if has_include_dir and include_dir:
        if not os.path.exists(include_dir):
            raise Exception("includedir must be a valid location")


def verify_code_page(conn_info):
    has_code_page, code_page = _has_get_attr(conn_info, 'code_page')
    if not has_code_page or not isinstance(code_page, int):
        raise Exception("code_page must be an integer")


def verify_envelope_size(conn_info):
    has_envelope_size, envelope_size = _has_get_attr(conn_info, 'envelope_size')
    if not has_envelope_size or not isinstance(envelope_size, int):
        raise Exception("envelope_size must be an integer")


def verify_hostname(conn_info):
    has_hostname, hostname = _has_get_attr(conn_info, 'hostname')
    if not has_hostname or not hostname:
        raise Exception("hostname is not resolvable")


def verify_ipaddress(conn_info):
    has_ipaddress, ipaddress = _has_get_attr(conn_info, 'ipaddress')
    if not has_ipaddress or not ipaddress:
        raise Exception("ipaddress missing")


def verify_auth_type(conn_info):
    has_auth_type, auth_type = _has_get_attr(conn_info, 'auth_type')
    if not has_auth_type or auth_type not in ('basic', 'kerberos'):
        raise Exception(
            "auth_type must be basic or kerberos: {0}".format(auth_type))


def verify_username(conn_info):
    has_username, username = _has_get_attr(conn_info, 'username')
    if not has_username or not username:
        raise Exception("username missing")


def verify_password(conn_info):
    has_password, password = _has_get_attr(conn_info, 'password')
    if not has_password or not password:
        raise Exception("password missing")


def verify_scheme(conn_info):
    has_scheme, scheme = _has_get_attr(conn_info, 'scheme')
    if not has_scheme or scheme not in ['http', 'https']:
        raise Exception(
            "scheme must be http or https: {0}"
            .format(scheme))


def verify_service(conn_info):
    has_service, service = _has_get_attr(conn_info, 'service')
    if not has_service:
        # if not supplied, default to scheme
        has_service, service = _has_get_attr(conn_info, 'scheme')
    if not has_service or service not in ['http', 'https', 'wsman']:
        raise Exception(
            "service must be http, https, or wsman: {0}"
            .format(service))


def verify_port(conn_info):
    has_port, port = _has_get_attr(conn_info, 'port')
    if not has_port or not port or not isinstance(port, int):
        raise Exception("illegal value for port: {0}".format(port))


def verify_connectiontype(conn_info):
    has_connectiontype, connectiontype = _has_get_attr(conn_info, 'connectiontype')
    if not has_connectiontype or not connectiontype:
        raise Exception("connectiontype missing")


def verify_timeout(conn_info):
    has_timeout, timeout = _has_get_attr(conn_info, 'timeout')
    if not has_timeout:
        raise Exception("timeout missing")
    if not timeout:
        conn_info.timeout = 60


def verify_conn_info(conn_info):
    verify_hostname(conn_info)
    verify_ipaddress(conn_info)
    verify_auth_type(conn_info)
    verify_username(conn_info)
    verify_password(conn_info)
    verify_scheme(conn_info)
    verify_port(conn_info)
    verify_connectiontype(conn_info)
    verify_timeout(conn_info)
    verify_include_dir(conn_info)


class RequestSender(object):

    def __init__(self, conn_info):
        verify_conn_info(conn_info)
        self._conn_info = update_conn_info(None, conn_info)
        self._url = None
        self._headers = None
        self.gssclient = None
        self.agent = None
        self.authorized = False
        self._lifetime_limit = 5

    @defer.inlineCallbacks
    def _get_url_and_headers(self):
        url = "{c.scheme}://{c.ipaddress}:{c.port}/wsman".format(c=self._conn_info)
        if self.agent is None:
            self.agent = _get_agent()
        if self._conn_info.auth_type == 'basic':
            headers = Headers(_CONTENT_TYPE)
            headers.addRawHeader('Connection', self._conn_info.connectiontype)
            if not self.authorized:
                headers.addRawHeader(
                    'Authorization', _get_basic_auth_header(self._conn_info))
                self.authorized = True
        elif self.is_kerberos():
            if self.gssclient:
                # check to see if our ticket is going to expire soon
                # go ahead and kill the connection
                # defer until it does expire and reinit
                lifetime = self.gssclient.context_lifetime()
                if lifetime <= self._lifetime_limit:
                    d = defer.Deferred()
                    yield self.close_connections()
                    try:
                        yield add_timeout(d, lifetime)
                    except Exception:
                        pass
                    self.agent = _get_agent()
            headers = Headers(_ENCRYPTED_CONTENT_TYPE)
            headers.addRawHeader('Connection', self._conn_info.connectiontype)
            if self.gssclient is None:
                try:
                    self.gssclient = yield _authenticate_with_kerberos(self._conn_info, url, self.agent)
                except kerberos.GSSError as e:
                    if 'The referenced context has expired' in e.args[0][0]:
                        log.debug('found The referenced context has expired, starting over')
                        self._token = self._gssclient = yield _authenticate_with_kerberos(self._conn_info, self._url, self.agent)
        else:
            raise Exception('unknown auth type: {0}'.format(self._conn_info.auth_type))
        defer.returnValue((url, headers))

    @defer.inlineCallbacks
    def _set_url_and_headers(self):
        self._url, self._headers = yield self._get_url_and_headers()

    @property
    def hostname(self):
        return self._conn_info.hostname

    def is_kerberos(self):
        return self._conn_info.auth_type == 'kerberos'

    def decrypt_body(self, body):
        return self.gssclient.decrypt_body(body)

    @defer.inlineCallbacks
    def send_request(self, request_template_name, **kwargs):
        log.debug('sending request on {}: {} {}'.format(self._conn_info.hostname,
                  request_template_name, kwargs))
        self._lifetime_limit = kwargs.get('lifetime_limit', 5)
        if self.agent is None:
            self.agent = _get_agent()
        kwargs['envelope_size'] = getattr(self._conn_info, 'envelope_size', 512000)
        kwargs['locale'] = getattr(self._conn_info, 'locale', 'en-US')
        kwargs['code_page'] = getattr(self._conn_info, 'code_page', 65001)
        if not self._url or self._conn_info.auth_type == 'kerberos':
            yield self._set_url_and_headers()
        request = _get_request_template(request_template_name).format(**kwargs)
        if self.is_kerberos():
            encrypted_request = self.gssclient.encrypt_body(request)
            if not encrypted_request.startswith("--Encrypted Boundary"):
                self._headers.setRawHeaders('Content-Type', _CONTENT_TYPE['Content-Type'])
            body_producer = _StringProducer(encrypted_request)
        else:
            body_producer = _StringProducer(request)

        @defer.inlineCallbacks
        def reset_agent_resend(sender, request, body_producer):
            log.debug('resetting connection on {} and resending last request: {}'.format(
                      self._conn_info.hostname,
                      request))
            yield self.close_connections()
            yield sender._set_url_and_headers()
            if sender.is_kerberos():
                try:
                    encrypted_request = sender.gssclient.encrypt_body(request)
                    if not encrypted_request.startswith("--Encrypted Boundary"):
                        sender._headers.setRawHeaders('Content-Type', _CONTENT_TYPE['Content-Type'])
                    body_producer = _StringProducer(encrypted_request)
                except Exception as e:
                    raise e
            try:
                response = yield sender.agent.request(
                    'POST', sender._url, sender._headers, body_producer)
            except Exception as e:
                raise e
            defer.returnValue(response)

        try:
            response = yield self.agent.request(
                'POST', self._url, self._headers, body_producer)
        except ConnectError:
            # network timeout.  could be stale connection, so let's reset
            log.debug('{} received ConnectError'.format(self._conn_info.hostname))
            response = yield reset_agent_resend(self, request, body_producer)
        except Exception as e:
            raise e

        log.debug('{} received response {} {}'.format(self._conn_info.hostname,
                  response.code, request_template_name))
        if response.code == httplib.UNAUTHORIZED or response.code == httplib.BAD_REQUEST:
            # check to see if we need to re-authorize due to lost connection or bad request error
            log.debug('{} received UNAUTHORIZED or BAD_REQUEST'.format(self._conn_info.hostname))
            response = yield reset_agent_resend(self, request, body_producer)
            if response.code == httplib.UNAUTHORIZED:
                if self.is_kerberos():
                    auth_header = response.headers.getRawHeaders('WWW-Authenticate')[0]
                    auth_details = get_auth_details(auth_header)
                    try:
                        if auth_details:
                            yield self.gssclient._step(auth_details)
                    except kerberos.GSSError as e:
                        msg = "HTTP Unauthorized received.  "\
                            "Kerberos error code {0}: {1}.".format(e.args[1][1], e.args[1][0])
                        raise Exception(msg)
                raise UnauthorizedError(
                    "HTTP Unauthorized received: Check username and password")
        if response.code == httplib.FORBIDDEN:
            raise ForbiddenError(
                "Forbidden: Check WinRM port and version")
        elif response.code != httplib.OK:
            if self.is_kerberos():
                reader = _ErrorReader(self.gssclient)
            else:
                reader = _ErrorReader()
            response.deliverBody(reader)
            message = yield reader.d
            if 'maximum number of concurrent operations for this user has been exceeded' in message:
                message += '  To fix this, increase the MaxConcurrentOperationsPerUser WinRM'\
                           ' Configuration option to 4294967295 and restart the winrm service.'
            raise RequestError("HTTP status: {0}. {1}".format(
                response.code, message))
        defer.returnValue(response)

    @defer.inlineCallbacks
    def close_connections(self):
        # close connections
        # return a Deferred()
        if self.agent and hasattr(self.agent, 'closeCachedConnections'):
            # twisted 11 has no return and is part of the Agent
            self.agent.closeCachedConnections()
        elif self.agent:
            # twisted 12 returns a Deferred from the pool
            yield self.agent._pool.closeCachedConnections()
            self.agent._pool = None
        if self.gssclient is not None:
            self.gssclient.cleanup()
            self.gssclient = None
        self.agent = None
        self._url = None
        self.authorized = False
        defer.returnValue(None)

    def update_conn_info(self, conn_info):
        self._conn_info = update_conn_info(self._conn_info, conn_info)


class _StringProtocol(Protocol):

    def __init__(self):
        self.d = defer.Deferred()
        self._data = []

    def dataReceived(self, data):
        self._data.append(data)

    def connectionLost(self, reason):
        self.d.callback(''.join(self._data))


class EtreeRequestSender(object):
    """A request sender that returns an etree element"""

    def __init__(self, sender):
        self._sender = sender

    def update_conn_info(self, conn_info):
        self._sender.update_conn_info(conn_info)

    @defer.inlineCallbacks
    def send_request(self, request_template_name, **kwargs):
        resp = yield self._sender.send_request(
            request_template_name, **kwargs)
        proto = _StringProtocol()
        resp.deliverBody(proto)
        body = yield proto.d
        if self._sender.is_kerberos():
            xml_str = self._sender.gssclient.decrypt_body(body)
        else:
            xml_str = yield body
        if log.isEnabledFor(logging.DEBUG):
            try:
                import xml.dom.minidom
                xml = xml.dom.minidom.parseString(xml_str)
                log.debug(xml.toprettyxml())
            except Exception:
                log.debug('Could not prettify response XML: "{0}"'.format(xml_str))
        defer.returnValue(ET.fromstring(xml_str))

    @defer.inlineCallbacks
    def close_connections(self):
        closed = yield self._sender.close_connections()
        defer.returnValue(closed)


def create_etree_request_sender(conn_info):
    sender = RequestSender(conn_info)
    return EtreeRequestSender(sender)


TZOFFSET_PATTERN = re.compile(r'[-+]\d+:\d\d$')


def get_datetime(text):
    """
    Parse the date from a WinRM response and return a datetime object.
    """
    text2 = TZOFFSET_PATTERN.sub('Z', text)
    if text2.endswith('Z'):
        if '.' in text2:
            format = "%Y-%m-%dT%H:%M:%S.%fZ"
            date_string = _NANOSECONDS_PATTERN.sub(r'.\g<1>', text2)
        else:
            format = "%Y-%m-%dT%H:%M:%SZ"
            date_string = text2
    else:
        format = '%m/%d/%Y %H:%M:%S.%f'
        date_string = text2
    return datetime.strptime(date_string, format)
