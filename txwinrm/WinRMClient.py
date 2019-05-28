##############################################################################
#
# Copyright (C) Zenoss, Inc. 2016-2017, all rights reserved.
#
# This content is made available according to terms specified in the LICENSE
# file at the top-level directory of this package.
#
##############################################################################

import logging
import time
from collections import namedtuple
from httplib import (
    BAD_REQUEST,
    UNAUTHORIZED,
    FORBIDDEN,
    OK,
    INTERNAL_SERVER_ERROR
)

from twisted.internet import reactor
from twisted.internet.defer import (
    inlineCallbacks,
    returnValue,
    DeferredSemaphore,
    Deferred,
)
from twisted.internet.error import TimeoutError

try:
    from twisted.web.client import ResponseFailed
    ResponseFailed
except ImportError:
    class ResponseFailed(Exception):
        pass

from . import constants as c
from .util import (
    _authenticate_with_kerberos,
    _get_agent,
    verify_conn_info,
    _CONTENT_TYPE,
    _ENCRYPTED_CONTENT_TYPE,
    Headers,
    _get_basic_auth_header,
    _get_request_template,
    _StringProducer,
    UnauthorizedError,
    ForbiddenError,
    RequestError,
    _ErrorReader,
    _StringProtocol,
    ET,
    update_conn_info
)
from .shell import (
    _build_command_line_elem,
    _build_ps_command_line_elem,
    _find_command_id,
    _MAX_REQUESTS_PER_COMMAND,
    _find_stream,
    _find_exit_code,
    CommandResponse,
    _stripped_lines,
    _find_shell_id
)
from .enumerate import (
    DEFAULT_RESOURCE_URI,
    SaxResponseHandler,
    _MAX_REQUESTS_PER_ENUMERATION,
    ItemsAccumulator
)
from .SessionManager import SESSION_MANAGER, Session, copy
from .twisted_utils import add_timeout, with_timeout
kerberos = None
LOG = logging.getLogger('winrm')
KRB5_SEM = DeferredSemaphore(1)


class ShellException(Exception):
    pass


class ResponseError(Exception):
    pass


class RetryRequest(Exception):
    pass


def create_shell_from_elem(elem):
    accumulator = ItemsAccumulator()
    accumulator.new_item()
    for item in ['ShellId', 'Owner', 'ClientIP', 'ShellRunTime',
                 'ShellInactivity', 'IdleTimeOut']:
        xpath = './/{{{}}}{}'.format(c.XML_NS_MSRSP, item)
        try:
            accumulator.add_property(item, elem.findtext(xpath).strip())
        except AttributeError as e:
            if item == 'ShellId':
                raise Exception('Invalid response from create shell request:'
                                ' {}'.format(e))
            # as long as we have a valid ShellId we should be fine
            accumulator.add_property(item, '')
    return accumulator.items[0]


def t_print(thing):
    print '{}  {}'.format(time.strftime('%H:%M:%S'), thing)


class _StringReader(_StringProtocol):

    def __init__(self, gssclient=None):
        self.d = Deferred()
        self._data = []
        self.gssclient = gssclient

    def dataReceived(self, data):
        self._data.append(data)

    def connectionLost(self, reason):
        if self.gssclient:
            try:
                body = self.gssclient.decrypt_body(''.join(self._data))
            except Exception as e:
                body = 'There was a problem decrypting data received: {}.'\
                       ' Check WinRM logs on {}'.format(
                            e.message, self.gssclient._conn_info.hostname)
        else:
            body = ''.join(self._data)
        self.d.callback(body)


class WinRMConnection(object):
    """Class to hold connection objects for WinRM communications."""

    def __init__(self, conn_info):
        """Initialize a WinRMConnection."""
        # twisted agent to send http/https requests
        self._agent = _get_agent(conn_info.connect_timeout)

        # connection info.  see util.ConnectionInfo
        self._conn_info = conn_info

        # url for connection
        self._url = "{c.scheme}://{c.ipaddress}:{c.port}/wsman".format(
            c=self._conn_info)

        # our kerberos context for encryption/decryption
        # if using domain authentication
        self._gssclient = None

    @inlineCallbacks
    def run_authenticate(self):
        """Initialize kerberos connection."""
        self._gssclient = yield with_timeout(
            fn=_authenticate_with_kerberos,
            args=(self._conn_info,
                  self._url,
                  self._agent),
            kwargs={},
            seconds=self._conn_info.connect_timeout)

    @inlineCallbacks
    def init_connection(self):
        """Initialize kerberos connection."""
        LOG.debug('authenticate with kerberos')
        try:
            yield self.run_authenticate()
        except Exception as e:
            if isinstance(e, kerberos.GSSError) and 'The referenced '\
                    'context has expired' in e.args[0][0]:
                LOG.debug('found The referenced context has expired,'
                          ' starting over')
                yield self.run_authenticate()
            else:
                raise e

    @inlineCallbacks
    def close_cached_connections(self, agent=None):
        """Close connections so we do not end up with orphans.

        nothing to return
        """
        if not agent:
            agent = self._agent
        if agent and hasattr(agent, 'closeCachedConnections'):
            # twisted 11 has no return and is part of the Agent
            agent.closeCachedConnections()
        elif agent:
            # twisted 12 has a pool
            yield agent._pool.closeCachedConnections()
        returnValue(None)

    @inlineCallbacks
    def close_connection(self):
        if self._gssclient is not None:
            self._gssclient.cleanup()
            self._gssclient = None
        yield self.close_cached_connections(self._agent)
        if self._agent and hasattr(self._agent, 'pool'):
            self._agent._pool = None
        self._agent = None
        returnValue(None)

    @inlineCallbacks
    def send_request(self, request):
        response = yield self._send_request(request)
        if self._gssclient:
            proto = _StringReader(self._gssclient)
        else:
            proto = _StringReader()
        response.deliverBody(proto)
        xml_str = yield proto.d
        if LOG.isEnabledFor(logging.DEBUG):
            try:
                import xml.dom.minidom
                xml = xml.dom.minidom.parseString(xml_str)
                LOG.debug(xml.toprettyxml())
            except Exception:
                LOG.debug('Could not prettify response XML: "{0}"'.format(
                    xml_str))
        if 'integrity check' in xml_str:
            raise Exception(xml_str)
        ret_str = ET.fromstring(xml_str)
        returnValue(ret_str)

    @inlineCallbacks
    def _send_request(self, request):
        LOG.debug('{} sending request: {} {}'.format(
            self._conn_info.hostname,
            request.request_template_name,
            request.kwargs))
        request.prep_request(self._gssclient)
        try:
            response = yield self._agent.request(
                'POST',
                self._url,
                request.headers,
                request.body_producer)
        except Exception as e:
            LOG.debug('{} exception sending request: {}'.format(
                self._conn_info.hostname, e))
            raise e
        LOG.debug('{} received response {} {}'.format(
            self._conn_info.hostname,
            response.code,
            request.request_template_name))
        if response.code != OK:
            # only send errors to _handle_response
            yield self._handle_response(response, request)
        returnValue(response)

    @inlineCallbacks
    def _handle_response(self, response, request):
        """Handle errors from winrm.

        in some cases we may want to retry the request.
        """
        if response.code == FORBIDDEN:
            raise ForbiddenError(
                "Forbidden: Check WinRM port and version")
        if self._gssclient:
            reader = _ErrorReader(self._gssclient)
        else:
            reader = _ErrorReader()
        response.deliverBody(reader)
        message = yield reader.d
        retry = any([response.code == UNAUTHORIZED,
                     response.code == BAD_REQUEST,
                     'unexpected response' in message.lower()])
        if all([retry, not request.retry, self._gssclient]):
            raise RetryRequest()
        if response.code == UNAUTHORIZED:
            if self._gssclient:
                raise UnauthorizedError(
                    "Unauthorized to use winrm on {}. User must be "
                    "Administrator or given permissions to use the "
                    " winrm service".format(
                        self._conn_info.hostname))
            else:
                raise UnauthorizedError(
                    "Unauthorized to use winrm on {}. Check username"
                    " and password".format(
                        self._conn_info.hostname))
        if response.code == INTERNAL_SERVER_ERROR:
            if 'maximum number of concurrent operations for this user has '\
                    'been exceeded' in message:
                message += '  To fix this, increase the MaxConcurrentOperati'\
                           'onsPerUser WinRM Configuration option to 4294967'\
                           '295 and restart the winrm service.'
                raise RequestError("{}: HTTP status: {}. {}.".format(
                    self._conn_info.ipaddress, response.code, message))
        raise RequestError("{}: HTTP status: {}. {}.".format(
            self._conn_info.ipaddress, response.code, message))


class Request(object):
    """Class used for WinRM requests."""

    def __init__(self, client, request_template_name, **kwargs):
        """Initialize Request."""
        self.client = client
        self._conn_info = client._conn_info
        self.request_template_name = request_template_name
        self.kwargs = kwargs
        kwargs['envelope_size'] = client._conn_info.envelope_size
        kwargs['locale'] = client._conn_info.locale
        kwargs['code_page'] = client._conn_info.code_page
        self.request = _get_request_template(request_template_name).format(
            **kwargs)
        self.headers = None
        self.is_kerberos = self._conn_info.auth_type == 'kerberos'
        self.retry = False
        self.body_producer = None

    def _set_headers(self):
        if self.headers:
            return self.headers
        if self._conn_info.auth_type == 'basic':
            self.headers = Headers(_CONTENT_TYPE)
            self.headers.addRawHeader('Connection',
                                      self._conn_info.connectiontype)
            self.headers.addRawHeader(
                'Authorization', _get_basic_auth_header(self._conn_info))
        elif self.is_kerberos:
            self.headers = Headers(_ENCRYPTED_CONTENT_TYPE)
            self.headers.addRawHeader('Connection',
                                      self._conn_info.connectiontype)
        return self.headers

    def prep_request(self, gssclient):
        """Prepare request and body_producer."""
        self._set_headers()
        if not self.is_kerberos:
            self.body_producer = _StringProducer(self.request)
            return
        encrypted_request = gssclient.encrypt_body(self.request)
        if not encrypted_request.startswith("--Encrypted Boundary"):
            self._headers.setRawHeaders(
                'Content-Type',
                _CONTENT_TYPE['Content-Type'])
        self.body_producer = _StringProducer(encrypted_request)


class WinRMClient(object):
    """Base winrm client class.

    Contains core functionality for various types of winrm based clients
    """

    def __init__(self, conn_info, lifetime_limit=5):
        """Base WinRMClient for working with windows."""
        global kerberos
        if not kerberos:
            import kerberos

        verify_conn_info(conn_info)
        self.key = None
        self._conn_info = update_conn_info(None, conn_info)
        self.ps_script = None
        self._lifetime_limit = lifetime_limit

        # WinRMConnection for the client.
        self._connection = None

        # set to True if the subclassed client will handle the response
        self._get_raw = False

        self._request_d = None

    def is_kerberos(self):
        """Test if this is a kerberos connection."""
        return self._conn_info.auth_type == 'kerberos'

    @inlineCallbacks
    def init_connection(self):
        """Initialize a WinRMConnection.

        Obtain a kerberos ticket and connect to server if kerberos
        """
        connection = WinRMConnection(self._conn_info)
        if self.is_kerberos() and connection._gssclient is None:
            yield connection.init_connection()
        returnValue(connection)

    def close_connection(self, connection):
        """Close a connection and reset."""
        if not connection:
            connection = self._connection
        self._connection = None
        if not connection:
            return
        reactor.callWhenRunning(connection.close_connection)

    @inlineCallbacks
    def check_lifetime(self, connection):
        """Check to see if our ticket is going to expire soon."""
        lifetime = connection._gssclient.context_lifetime()
        if lifetime <= self._lifetime_limit:
            # go ahead and kill the connection
            # defer until it does expire and reinit
            def expire_ticket(seconds):
                self.close_connection(connection)
                d = Deferred()
                reactor.callLater(seconds, d.callback, None)
                return d
            try:
                yield expire_ticket(lifetime)
            except Exception:
                pass
            connection = yield self.init_connection()
        returnValue(connection)

    @inlineCallbacks
    def connection(self):
        """Return client's WinRMConnection.

        If no current connection, create one.
        If kerberos, then check the ticket lifetime so that we don't
        use an expiring ticket.
        """
        connection = yield self.init_connection()
        if self.is_kerberos():
            connection = yield self.check_lifetime(connection)
        returnValue(connection)

    @inlineCallbacks
    def send_request(self, request, **kwargs):
        """Send a request through a WinRMConnection.

        wait for any previous request to finish
        """
        if self._request_d and not self._request_d.called:
            # wait for previous request to finish
            yield self._request_d
        self._request_d = self._send_request(self._connection,
                                             request,
                                             **kwargs)
        response = yield self._request_d
        self._request_d = None
        returnValue(response)

    @inlineCallbacks
    def _send_request(self, connection, request, **kwargs):
        """Send a request through a WinRMConnection."""
        # if we do not have a current connection, create a new one
        if not connection:
            connection = yield self.connection()

        req = Request(self, request, **kwargs)
        if self._get_raw:
            # just get the raw response and allow client to decrypt and parse
            response_d = connection._send_request(req)
        else:
            response_d = connection.send_request(req)
        try:
            response = yield add_timeout(response_d,
                                         self._conn_info.timeout + 1)
        except Exception as e:
            retry = isinstance(e, kerberos.GSSError) and\
                'The referenced context has expired' in e.args[0][0]
            if any([isinstance(e, RetryRequest),
                    retry]):
                LOG.debug('{} retring request {}'.format(
                    self._conn_info.hostname, req.request_template_name))
                self.close_connection(connection)
                connection = yield self.connection()
                req.retry = True
                if self._get_raw:
                    response_d = connection._send_request(req)
                else:
                    response_d = connection.send_request(req)
                try:
                    response = yield add_timeout(response_d,
                                                 self._conn_info.timeout + 1)
                    returnValue(response)
                except Exception as e:
                    self.close_connection(connection)
                    raise e
            elif isinstance(e, TimeoutError):
                # either we timed out sending or receiving response
                self.close_connection(connection)
                LOG.debug('{} request {} timed out.'.format(
                    self._conn_info.hostname, req.request_template_name))
            raise e
        # save current connection
        self._connection = connection
        returnValue(response)

    @inlineCallbacks
    def _create_shell(self):
        elem = yield self.send_request('create')
        returnValue(_find_shell_id(elem))

    @inlineCallbacks
    def _delete_shell(self, shell_id):
        yield self.send_request('delete', shell_id=shell_id)
        returnValue(None)

    @inlineCallbacks
    def _signal_terminate(self, shell_id, command_id):
        yield self.send_request('signal',
                                shell_id=shell_id,
                                command_id=command_id,
                                signal_code=c.SHELL_SIGNAL_TERMINATE)
        returnValue(None)

    @inlineCallbacks
    def _signal_ctrl_c(self, shell_id, command_id):
        yield self.send_request('signal',
                                shell_id=shell_id,
                                command_id=command_id,
                                signal_code=c.SHELL_SIGNAL_CTRL_C)
        returnValue(None)

    @inlineCallbacks
    def _send_command(self, shell_id, command_line):
        if self.ps_script is not None:
            command_line_elem = _build_ps_command_line_elem(command_line,
                                                            self.ps_script)
        else:
            command_line_elem = _build_command_line_elem(command_line)
        LOG.debug('{} WinRMClient._send_command: sending command request '
                  '(shell_id={}, command_line_elem={})'.format(
                      self._conn_info.hostname, shell_id, command_line_elem))
        command_elem = yield self.send_request(
            'command', shell_id=shell_id, command_line_elem=command_line_elem,
            timeout=self._conn_info.timeout)
        returnValue(command_elem)

    @inlineCallbacks
    def _send_receive(self, shell_id, command_id):
        receive_elem = yield self.send_request(
            'receive', shell_id=shell_id, command_id=command_id,
            timeout=self._conn_info.timeout)
        returnValue(receive_elem)


class SingleCommandClient(WinRMClient):
    """Client to send a single command to a winrm device."""

    def __init__(self, conn_info):
        super(SingleCommandClient, self).__init__(conn_info)

    @inlineCallbacks
    def run_command(self, command_line, ps_script=None):
        r"""Run a single command.

        If running a powershell script, send it in separately with ps_script in
        "& {<actual script here>}" format
        e.g. command_line='powershell -NoLogo -NonInteractive -NoProfile
        -Command', ps_script='"& {get-counter -counter \\\"\memory\pages
        output/sec\\\" }"'
        """
        self.ps_script = ps_script
        try:
            shell_id = yield self._create_shell()
        except Exception as e:
            raise e
        cmd_response = None
        cmd_response = yield self._run_command(shell_id, command_line)
        self.close_connection(self._connection)
        returnValue(cmd_response)

    @inlineCallbacks
    def _run_command(self, shell_id, command_line):
        try:
            command_elem = yield self._send_command(shell_id, command_line)
        except Exception as e:
            raise e
        command_id = _find_command_id(command_elem)
        stdout_parts = []
        stderr_parts = []
        for i in xrange(_MAX_REQUESTS_PER_COMMAND):
            try:
                receive_elem = yield self._send_receive(shell_id, command_id)
            except Exception as e:
                if isinstance(e, kerberos.GSSError) and 'The referenced '\
                        'context has expired' in e.args[0][0]:
                    LOG.debug('found The referenced context has expired,'
                              ' try to receive again')
                    continue
                raise e
            stdout_parts.extend(
                _find_stream(receive_elem, command_id, 'stdout'))
            stderr_parts.extend(
                _find_stream(receive_elem, command_id, 'stderr'))
            exit_code = _find_exit_code(receive_elem, command_id)
            if exit_code is not None:
                break
        else:
            raise Exception("Reached max requests per command.")
        try:
            yield self._signal_terminate(shell_id, command_id)
        except Exception as e:
            raise e
        stdout = _stripped_lines(stdout_parts)
        stderr = _stripped_lines(stderr_parts)
        try:
            yield self._delete_shell(shell_id)
        except Exception as e:
            raise e
        returnValue(CommandResponse(stdout, stderr, exit_code))


class LongCommandClient(WinRMClient):
    """Client to run a long running command on a winrm device."""

    def __init__(self, conn_info):
        super(LongCommandClient, self).__init__(conn_info)
        self._shells = []
        self._exit_codes = {}

    @inlineCallbacks
    def start(self, command_line, ps_script=None):
        r"""Start long running command.

        If running a powershell script, send it in separately with ps_script in
        "& {<actual script here>}" format
        e.g. command_line='powershell -NoLogo -NonInteractive -NoProfile
        -Command', ps_script='"& {get-counter -counter \\\"\memory\pages
        output/sec\\\" }"'

        Return a shell id, command id tuple on success
        """
        LOG.debug("{} LongRunningCommand run_command: {}".format(
            self._conn_info.hostname, command_line))
        self.key = (self._conn_info.ipaddress, command_line + str(ps_script))
        self.ps_script = ps_script
        try:
            shell_id = yield self._create_shell()
        except Exception:
            raise
        try:
            command_elem = yield self._send_command(
                shell_id,
                command_line)
        except Exception:
            # try to delete the shell
            yield self._delete_shell(shell_id)
            raise
        command_id = _find_command_id(command_elem)
        shell_cmd = (shell_id, command_id)
        self._shells.append(shell_cmd)
        returnValue(shell_cmd)

    @inlineCallbacks
    def receive(self, shell_cmd=None):
        """Receive data from running command.

        shell_cmd is shell and command id pair from which to receive output
        if not supplied, assume the first pair in the _shells list.
        """
        if not shell_cmd:
            try:
                shell_cmd = self._shells[0]
            except IndexError:
                raise ShellException('No shell and command id from which to '
                                     'receive output.')
        receive_elem = yield self._send_receive(*shell_cmd)
        stdout_parts = _find_stream(receive_elem, shell_cmd[1], 'stdout')
        stderr_parts = _find_stream(receive_elem, shell_cmd[1], 'stderr')
        exit_code = _find_exit_code(receive_elem, shell_cmd[1])
        self._exit_codes[shell_cmd] = exit_code
        stdout = _stripped_lines(stdout_parts)
        stderr = _stripped_lines(stderr_parts)
        returnValue(CommandResponse(stdout, stderr, exit_code))

    @inlineCallbacks
    def stop(self, shell_cmd=None):
        """Stop running command.

        shell_cmd is shell and command id pair to stop
        if not supplied, assume the first pair in the _shells list.
        """
        if not shell_cmd:
            try:
                shell_cmd = self._shells[0]
            except IndexError:
                # nothing to stop or delete, return None
                returnValue(None)
        try:
            self._shells.remove(shell_cmd)
        except ValueError:
            pass
        try:
            yield self._signal_ctrl_c(shell_cmd)
        except Exception as e:
            if 'internal error' in e.message or 'integrity' in e.message:
                # problem stopping command
                # continue so we can try to delete the shell
                pass
        response = None
        try:
            exit_code = self._exit_codes.pop(shell_cmd)
        except KeyError:
            exit_code = None
        if exit_code is None and shell_cmd:
            # no exit code, so let's receive data
            try:
                response = yield self.receive(shell_cmd)
            except Exception as e:
                if 'internal error' in e.message\
                        or 'integrity' in e.message\
                        or isinstance(e, TimeoutError):
                    pass
                else:
                    raise e
        try:
            yield self._signal_terminate(*shell_cmd)
        except Exception as e:
            if 'internal error' in e.message\
                    or 'integrity' in e.message:
                pass
            else:
                raise e
        try:
            yield self._delete_shell(shell_cmd[0])
        except Exception as e:
            if 'internal error' in e.message\
                    or 'integrity' in e.message:
                pass
            else:
                raise e
        returnValue(response)


class EnumerateClient(WinRMClient):
    """Client to send a single wmi query(WQL) to a winrm device.

    Sends enumerate requests to a host running the WinRM service and returns
    a list of items.
    """

    def __init__(self, conn_info):
        super(EnumerateClient, self).__init__(conn_info)
        self._handler = SaxResponseHandler(self)
        self._hostname = self._conn_info.ipaddress
        self.key = (self._conn_info.ipaddress, 'enumerate')
        self._gssclient = None
        self._get_raw = True

    def decrypt_body(self, body):
        """Used by SaxResponseHandler to decrypt response."""
        return self._connection._gssclient.decrypt_body(body)

    @inlineCallbacks
    def enumerate(self, wql, resource_uri=DEFAULT_RESOURCE_URI):
        """Runs a remote WQL query."""
        request_template_name = 'enumerate'
        enumeration_context = None
        items = []
        try:
            for i in xrange(_MAX_REQUESTS_PER_ENUMERATION):
                LOG.debug('{0} "{1}" {2}'.format(
                    self._hostname, wql, request_template_name))
                response = yield self.send_request(
                    request_template_name,
                    resource_uri=resource_uri,
                    wql=wql,
                    enumeration_context=enumeration_context)
                LOG.debug("{0} {1} HTTP status: {2}".format(
                    self._hostname, wql, response.code))
                enumeration_context, new_items = \
                    yield self._handler.handle_response(response)
                items.extend(new_items)
                if not enumeration_context:
                    break
                request_template_name = 'pull'
            else:
                raise Exception("Reached max requests per enumeration.")
        except (ResponseFailed, RequestError, Exception) as e:
            if isinstance(e, ResponseFailed):
                for reason in e.reasons:
                    LOG.error('{0} {1}'.format(self._hostname, reason.value))
            else:
                LOG.debug('{0} {1}'.format(self._hostname, e))
            raise e
        returnValue(items)

    @inlineCallbacks
    def do_collect(self, enum_infos):
        """Run enumerations in the session's semaphore.

        Windows must finish an enumeration before a new
        command or enumeration can start
        """
        items = {}
        for enum_info in enum_infos:
            try:
                items[enum_info] = yield self.enumerate(
                    enum_info.wql,
                    enum_info.resource_uri)
            except RequestError as e:
                LOG.debug('{0} {1}'.format(self._hostname, e))
                # only raise Unauthorized or Forbidden.  no need to continue
                # Simple RequestError could just be missing wmi class
                if isinstance(e, UnauthorizedError) or\
                        isinstance(e, ForbiddenError):
                    self.close_connection(self._connection)
                    raise e
            except Exception as e:
                # Fail the collection for general errors.
                self.close_connection(self._connection)
                raise e

        self.close_connection(self._connection)
        returnValue(items)


class AssociatorClient(EnumerateClient):
    r"""WinRM Client used to find associated wmi classes.

    this client can return wmi classes that are associated with
        another wmi class through a single property.
        First a regular wmi query is run to select objects from a class.
            e.g. 'select * from Win32_NetworkAdapter'
        Next we will loop through the results and run the associator query
        using a specific property of the object as input to return
        a result class.
            e.g. for interface in interfaces:
                "ASSOCIATORS OF {Win32_NetworkAdapter.DeviceID=interface.\
                DeviceID} WHERE ResultClass=Win32_PnPEntity'
    """

    @inlineCallbacks
    def associate(self,
                  seed_class,
                  associations,
                  where=None,
                  resource_uri=DEFAULT_RESOURCE_URI,
                  fields=['*']):
        """Method to retrieve associated wmi classes based upon a
        property from a given class

        seed_class - wmi class which will be initially queried
        associations - list of dicts containing parameters for
            the 'ASSOCIATORS of {A}' wql statement.  We dequeue the
            dicts and can search results from previous wql query to
            search for nested associations.
                search_class - initial class to associate with
                search_property - property on search_class to match
                return_class - class which will be returned
                where_type - keyword of association type:
                    AssocClass = AssocClassName
                    RequiredAssocQualifier = QualifierName
                    RequiredQualifier = QualifierName
                    ResultClass = ClassName
                    ResultRole = PropertyName
                    Role = PropertyName
        where - wql where clause to narrow scope of initial query
        resource_uri - uri of resource.  this will be the same for both
            input and result classes.  Limitation of WQL
        fields - fields to return from seed_class on initial query

        returns dict of seed_class and all return_class results
            mapped by search_property

        see https://msdn.microsoft.com/en-us/library/aa384793(v=vs.85).aspx
        """
        associations_copy = copy.deepcopy(associations)
        items = {}
        wql = 'Select {} from {}'.format(','.join(fields), seed_class)
        if where:
            wql += ' where {}'.format(where)
        EnumInfo = namedtuple('EnumInfo', ['wql', 'resource_uri'])
        enum_info = EnumInfo(wql, resource_uri)
        results = yield self.do_collect([enum_info])

        try:
            input_results = results[enum_info]
        except KeyError:
            raise Exception('No results for seed class {}.'.format(seed_class))

        items[seed_class] = input_results
        while associations_copy:
            association = associations_copy.pop(0)
            associate_results = []
            prop_results = {}
            for item in input_results:
                try:
                    prop = getattr(item, association['search_property'])
                except AttributeError:
                    continue
                else:
                    wql = "ASSOCIATORS of {{{}.{}='{}'}} WHERE {}={}".format(
                        association['search_class'],
                        association['search_property'],
                        prop,
                        association['where_type'],
                        association['return_class'])
                    enum_info = EnumInfo(wql, resource_uri)
                    result = yield self.do_collect([enum_info])
                    associate_results.extend(result[enum_info])
                    prop_results[prop] = result[enum_info]

            items[association['return_class']] = prop_results
            input_results = associate_results
        returnValue(items)
