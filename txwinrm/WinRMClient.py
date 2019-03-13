##############################################################################
#
# Copyright (C) Zenoss, Inc. 2016-2017, all rights reserved.
#
# This content is made available according to terms specified in the LICENSE
# file at the top-level directory of this package.
#
##############################################################################

import logging
from collections import namedtuple
from httplib import BAD_REQUEST, UNAUTHORIZED, FORBIDDEN, OK

from twisted.internet.defer import (
    inlineCallbacks,
    returnValue,
    DeferredSemaphore,
    Deferred
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
    get_auth_details,
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


def create_shell_from_elem(elem):
    accumulator = ItemsAccumulator()
    accumulator.new_item()
    for item in ['ShellId', 'Owner', 'ClientIP', 'ShellRunTime', 'ShellInactivity', 'IdleTimeOut']:
        xpath = './/{{{}}}{}'.format(c.XML_NS_MSRSP, item)
        try:
            accumulator.add_property(item, elem.findtext(xpath).strip())
        except AttributeError as e:
            if item == 'ShellId':
                raise Exception('Invalid response from create shell request: {}'.format(e))
            # as long as we have a valid ShellId we should be fine
            accumulator.add_property(item, '')
    return accumulator.items[0]


class WinRMSession(Session):
    '''
    Session class to keep track of single winrm connection
    '''
    def __init__(self):
        super(WinRMSession, self).__init__()

        # twisted agent to send http/https requests
        self._agent = None

        # our kerberos context for encryption/decryption
        self._gssclient = None

        # url for session
        self._url = None

        # headers to use for requests
        self._headers = None

        # connection info.  see util.ConnectionInfo
        self._conn_info = None

        # DeferredSemaphore so that we complete one transaction/conversation
        # at a time.  Windows cannot handle mixed transaction types on one
        # connection.
        self.sem = DeferredSemaphore(1)

        # unused.  reserved for possible future use
        self._refresh_dc = None

        self.set_lifetime_limit(5)

    def set_lifetime_limit(self, lifetime_limit):
        # amount of time to compare against context lifetime
        # if kerberos context lifetime is <=, then let it expire and reset
        self._lifetime_limit = lifetime_limit

    def semrun(self, fn, *args, **kwargs):
        """Run fn(*args, **kwargs) under a DeferredSemaphore with a timeout."""
        return self.sem.run(
            with_timeout,
            fn=fn,
            args=args,
            kwargs=kwargs,
            seconds=self._conn_info.timeout)

    def is_kerberos(self):
        return self._conn_info.auth_type == 'kerberos'

    def decrypt_body(self, body):
        return self._gssclient.decrypt_body(body)

    def _set_headers(self):
        if self._headers:
            return self._headers
        if self._conn_info.auth_type == 'basic':
            self._headers = Headers(_CONTENT_TYPE)
            self._headers.addRawHeader('Connection', self._conn_info.connectiontype)
            self._headers.addRawHeader(
                'Authorization', _get_basic_auth_header(self._conn_info))
        elif self.is_kerberos():
            self._headers = Headers(_ENCRYPTED_CONTENT_TYPE)
            self._headers.addRawHeader('Connection', self._conn_info.connectiontype)
        return self._headers

    def update_conn_info(self, client):
        self._conn_info = update_conn_info(self._conn_info, client._conn_info)

    @inlineCallbacks
    def _deferred_login(self, client=None):
        if self._agent is None:
            self._agent = _get_agent()
        if self._gssclient:
            returnValue(self._gssclient)
        if client:
            self.update_conn_info(client)
        self._url = "{c.scheme}://{c.ipaddress}:{c.port}/wsman".format(
            c=self._conn_info)
        if self.is_kerberos():
            try:
                # run through single semaphore so that we can allow
                # for multiple users. gss uses KRB5CCNAME to determine
                # cache to use, so we must make sure that the env variable
                # is not overwritten.
                self._token = self._gssclient = yield KRB5_SEM.run(
                    with_timeout,
                    fn=_authenticate_with_kerberos,
                    args=(self._conn_info,
                          self._url,
                          self._agent),
                    kwargs={},
                    seconds=self._conn_info.timeout)
            except Exception as e:
                global kerberos
                import kerberos
                if isinstance(e, kerberos.GSSError) and 'The referenced '\
                        'context has expired' in e.args[0][0]:
                    LOG.debug('found The referenced context has expired,'
                              ' starting over')
                    self._token = self._gssclient = yield KRB5_SEM.run(
                        with_timeout,
                        fn=_authenticate_with_kerberos,
                        args=(self._conn_info,
                              self._url,
                              self._agent),
                        kwargs={},
                        seconds=self._conn_info.timeout)
                else:
                    raise
            returnValue(self._gssclient)
        else:
            returnValue('basic_auth_token')

    @inlineCallbacks
    def close_cached_connections(self):
        # close connections so we do not end up with orphans
        # return a Deferred()
        if self._agent and hasattr(self._agent, 'closeCachedConnections'):
            # twisted 11 has no return and is part of the Agent
            self._agent.closeCachedConnections()
        elif self._agent:
            # twisted 12 has a pool
            yield self._agent._pool.closeCachedConnections()
        returnValue(None)

    @inlineCallbacks
    def _deferred_logout(self):
        # close connections so they don't timeout
        # gssclient will no longer be valid so get rid of it
        # set token to None so the next client will reinitialize
        #   the connection
        yield self._reset_all()

    @inlineCallbacks
    def _reset_all(self):
        self._token = None
        self._login_d = None
        if self._gssclient is not None:
            self._gssclient.cleanup()
            self._gssclient = None
        yield self.close_cached_connections()
        if self._agent:
            self._agent._pool = None
            self._agent = None
        self._headers = None
        self._url = None
        returnValue(None)

    @inlineCallbacks
    def handle_response(self, request, response, client):
        if response.code != OK:
            # first get the error message out of the response so we
            # don't encounter Decrypt Integrity Check errors
            if self.is_kerberos():
                reader = _ErrorReader(self._gssclient)
            else:
                reader = _ErrorReader()
            response.deliverBody(reader)
            message = yield reader.d
            if 'maximum number of concurrent operations for this user has '\
                    'been exceeded' in message:
                message += '  To fix this, increase the MaxConcurrentOperati'\
                           'onsPerUser WinRM Configuration option to 4294967'\
                           '295 and restart the winrm service.'
            if response.code == UNAUTHORIZED or response.code == BAD_REQUEST:
                # check to see if we need to re-authorize due to
                # lost connection or bad request error
                # only retry if using kerberos
                yield self._reset_all()
                if client.is_kerberos():
                    yield SESSION_MANAGER.init_connection(client, WinRMSession)
                    try:
                        yield self._set_headers()
                        encrypted_request = self._gssclient.encrypt_body(
                            request)
                        if not encrypted_request.startswith(
                                "--Encrypted Boundary"):
                            self._headers.setRawHeaders(
                                'Content-Type', _CONTENT_TYPE['Content-Type'])
                        body_producer = _StringProducer(encrypted_request)
                        response = yield self._agent.request(
                            'POST', self._url, self._headers, body_producer)
                    except Exception:
                        raise
            if response.code == UNAUTHORIZED:
                raise UnauthorizedError(
                    "Unauthorized to use winrm on {}. Must be Administrator"
                    " or user given permissions to use winrm".format(
                        client._conn_info.hostname))
            else:
                raise RequestError("{}: HTTP status: {}. {}.".format(
                    client._conn_info.ipaddress, response.code, message))
        if response.code == FORBIDDEN:
            raise ForbiddenError(
                "Forbidden: Check WinRM port and version")
        returnValue(response)

    @inlineCallbacks
    def send_request(self, request_template_name, client, envelope_size=None, **kwargs):
        response = yield self._send_request(
            request_template_name, client, envelope_size=envelope_size, **kwargs)
        proto = _StringProtocol()
        response.deliverBody(proto)
        body = yield proto.d
        if self.is_kerberos():
            xml_str = self._gssclient.decrypt_body(body)
        else:
            xml_str = yield body
        if LOG.isEnabledFor(logging.DEBUG):
            try:
                import xml.dom.minidom
                xml = xml.dom.minidom.parseString(xml_str)
                LOG.debug(xml.toprettyxml())
            except Exception:
                LOG.debug('Could not prettify response XML: "{0}"'.format(xml_str))
        returnValue(ET.fromstring(xml_str))

    @inlineCallbacks
    def _send_request(self, request_template_name, client, envelope_size=None,
                      locale=None, code_page=None, **kwargs):
        try:
            self._logout_dc.cancel()
            self._logout_dc = None
        except Exception:
            pass
        if client.is_kerberos():
            # lazy import
            global kerberos
            if not kerberos:
                import kerberos
            # check to see if our ticket is going to expire soon
            # go ahead and kill the connection
            # defer until it does expire and reinit
            lifetime = self._gssclient.context_lifetime()
            if lifetime <= self._lifetime_limit:
                d = Deferred()
                yield self._reset_all()
                try:
                    yield add_timeout(d, lifetime)
                except Exception:
                    pass
        if self._token is None:
            yield client.init_connection()
        if self._login_d and not self._login_d.called:
            # check for a reconnection attempt so we do not send any requests
            # to a dead connection
            self._token = yield self._login_d
        kwargs['envelope_size'] = envelope_size or self._conn_info.envelope_size
        kwargs['locale'] = locale or self._conn_info.locale
        kwargs['code_page'] = code_page or self._conn_info.code_page
        LOG.debug('{} sending request: {} {}'.format(
            self._conn_info.hostname, request_template_name, kwargs))
        request = _get_request_template(request_template_name).format(**kwargs)
        self._headers = self._set_headers()
        if self.is_kerberos():
            encrypted_request = self._gssclient.encrypt_body(request)
            if not encrypted_request.startswith("--Encrypted Boundary"):
                self._headers.setRawHeaders('Content-Type', _CONTENT_TYPE['Content-Type'])
            body_producer = _StringProducer(encrypted_request)
        else:
            body_producer = _StringProducer(request)
        try:
            response = yield self._agent.request(
                'POST', self._url, self._headers, body_producer)
        except Exception as e:
            LOG.debug('{} exception sending request: {}'.format(self._conn_info.hostname, e))
            raise
        LOG.debug('{} received response {} {}'.format(
            self._conn_info.hostname, response.code, request_template_name))
        response = yield self.handle_response(request, response, client)
        returnValue(response)


class WinRMClient(object):
    """Base winrm client class

    Contains core functionality for various types of winrm based clients
    """
    def __init__(self, conn_info, lifetime_limit=5):
        verify_conn_info(conn_info)
        self.key = None
        self._conn_info = update_conn_info(None, conn_info)
        self.ps_script = None
        self._lifetime_limit = lifetime_limit

    def is_connected(self):
        if self.session() and self.session()._agent:
            return True
        else:
            return False

    def session(self):
        return SESSION_MANAGER.get_connection(self.key)

    @inlineCallbacks
    def init_connection(self):
        """Initialize a connection through the session_manager"""
        try:
            yield add_timeout(SESSION_MANAGER.init_connection(self, WinRMSession),
                              seconds=self._conn_info.connect_timeout,
                              exception_class=TimeoutError)
        except Exception:
            self.close_connection(immediately=True)
            raise
        self.session().set_lifetime_limit(self._lifetime_limit)
        returnValue(None)

    def is_kerberos(self):
        return self._conn_info.auth_type == 'kerberos'

    def decrypt_body(self, body):
        return self.session().decrypt_body(body)

    @inlineCallbacks
    def send_request(self, request, **kwargs):
        session = self.session()
        if session is None or session._token is None\
                or (session.is_kerberos() and session._gssclient is None):
            yield self.init_connection()

        if not self.session():
            raise Exception('Could not connect to device {}'.format(self._conn_info.hostname))
        response = yield self.session().send_request(request, self, **kwargs)
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

    def close_connection(self, immediately=False):
        SESSION_MANAGER.close_connection(self, immediately)

    @inlineCallbacks
    def close_cached_connections(self):
        yield self.session().close_cached_connections()


class SingleCommandClient(WinRMClient):
    """Client to send a single command to a winrm device"""
    def __init__(self, conn_info):
        super(SingleCommandClient, self).__init__(conn_info)

    @inlineCallbacks
    def run_command(self, command_line, ps_script=None):
        """Run a single command in the session's semaphore.  Windows must finish
        a command conversation before a new command or enumeration can start

        If running a powershell script, send it in separately with ps_script in
        "& {<actual script here>}" format
        e.g. command_line='powershell -NoLogo -NonInteractive -NoProfile -Command',
        ps_script='"& {get-counter -counter \\\"\memory\pages output/sec\\\" }"'
        """
        cmd_response = None
        self.ps_script = ps_script
        if ps_script:
            self.key = (self._conn_info.ipaddress, 'short', self.ps_script)
        else:
            self.key = (self._conn_info.ipaddress, 'short', command_line)
        yield self.init_connection()
        try:
            run_cmd_d = self.run_single_command(command_line)
            cmd_response = yield add_timeout(run_cmd_d, self._conn_info.timeout)
        except Exception as e:
            if isinstance(e, TimeoutError):
                yield self.close_cached_connections()
            self.close_connection()
            raise
        returnValue(cmd_response)

    @inlineCallbacks
    def run_single_command(self, command_line):
        """
        Run a single command line in a remote shell like the winrs application
        on Windows. Returns a dictionary with the following
        structure:
            CommandResponse
                .stdout = [<non-empty, stripped line>, ...]
                .stderr = [<non-empty, stripped line>, ...]
                .exit_code = <int>
        """
        shell_id = yield self._create_shell()
        cmd_response = None
        try:
            cmd_response = yield self._run_command(shell_id, command_line)
        except TimeoutError:
            yield self.close_cached_connections()
        self.close_connection()
        returnValue(cmd_response)

    @inlineCallbacks
    def _run_command(self, shell_id, command_line):
        command_elem = yield self._send_command(shell_id, command_line)
        command_id = _find_command_id(command_elem)
        stdout_parts = []
        stderr_parts = []
        for i in xrange(_MAX_REQUESTS_PER_COMMAND):
            receive_elem = yield self._send_receive(shell_id, command_id)
            stdout_parts.extend(
                _find_stream(receive_elem, command_id, 'stdout'))
            stderr_parts.extend(
                _find_stream(receive_elem, command_id, 'stderr'))
            exit_code = _find_exit_code(receive_elem, command_id)
            if exit_code is not None:
                break
        else:
            raise Exception("Reached max requests per command.")
        yield self._signal_terminate(shell_id, command_id)
        stdout = _stripped_lines(stdout_parts)
        stderr = _stripped_lines(stderr_parts)
        yield self._delete_shell(shell_id)
        returnValue(CommandResponse(stdout, stderr, exit_code))


class LongCommandClient(WinRMClient):
    """Client to run a long running command on a winrm device"""
    def __init__(self, conn_info):
        super(LongCommandClient, self).__init__(conn_info)
        self._shells = []
        self._exit_codes = {}

    @inlineCallbacks
    def start(self, command_line, ps_script=None):
        """Start long running command.

        If running a powershell script, send it in separately with ps_script in
        "& {<actual script here>}" format
        e.g. command_line='powershell -NoLogo -NonInteractive -NoProfile -Command',
        ps_script='"& {get-counter -counter \\\"\memory\pages output/sec\\\" }"'

        Return a shell id, command id tuple on success

        """
        LOG.debug("{} LongRunningCommand run_command: {}".format(
            self._conn_info.hostname, command_line))
        self.key = (self._conn_info.ipaddress, command_line + str(ps_script))
        self.ps_script = ps_script
        if not self.is_connected():
            yield self.init_connection()
        try:
            shell_id = yield self._create_shell()
        except TimeoutError:
            self.close_cached_connections()
            raise
        try:
            command_elem = yield self._send_command(shell_id,
                                                    command_line)
        except TimeoutError:
            yield self._delete_shell(shell_id)
            self.close_cached_connections()
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
        try:
            receive_elem = yield self._send_receive(*shell_cmd)
        except TimeoutError:
            self.close_connection()
            raise
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
                self.close_connection()
                returnValue(None)
        yield self._signal_ctrl_c(*shell_cmd)
        response = None
        try:
            exit_code = self._exit_codes.pop(shell_cmd)
        except KeyError:
            exit_code = None
        if exit_code is None:
            # no exit code, so let's receive data
            try:
                response = yield self.receive()
            except TimeoutError:
                pass
        yield self._signal_terminate(*shell_cmd)
        yield self._delete_shell(shell_cmd[0])
        self.close_connection()
        try:
            self._shells.remove(shell_cmd)
        except ValueError:
            pass
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

    @inlineCallbacks
    def enumerate(self, wql, resource_uri=DEFAULT_RESOURCE_URI):
        """Runs a remote WQL query."""
        if not self.is_connected():
            yield self.init_connection()
        request_template_name = 'enumerate'
        enumeration_context = None
        items = []
        try:
            for i in xrange(_MAX_REQUESTS_PER_ENUMERATION):
                LOG.debug('{0} "{1}" {2}'.format(
                    self._hostname, wql, request_template_name))
                response = yield self.session()._send_request(
                    request_template_name,
                    self,
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
            raise
        returnValue(items)

    @inlineCallbacks
    def do_collect(self, enum_infos):
        """Run enumerations in the session's semaphore.  Windows must finish
        an enumeration before a new command or enumeration can start
        """
        items = {}
        yield self.init_connection()
        for enum_info in enum_infos:
            try:
                items[enum_info] = yield self.session().semrun(
                    self.enumerate,
                    enum_info.wql,
                    enum_info.resource_uri)
            except RequestError as e:
                LOG.debug('{0} {1}'.format(self._hostname, e))
                # only raise Unauthorized or Forbidden.  no need to continue
                # Simple RequestError could just be missing wmi class
                if isinstance(e, UnauthorizedError) or isinstance(e, ForbiddenError):
                    self.close_connection()
                    raise
            except Exception:
                # Fail the collection for general errors.
                self.close_connection()
                raise

        self.close_connection()
        returnValue(items)


class AssociatorClient(EnumerateClient):
    """WinRM Client that can return wmi classes that are associated with
        another wmi class through a single property.
        First a regular wmi query is run to select objects from a class.
            e.g. 'select * from Win32_NetworkAdapter'
        Next we will loop through the results and run the associator query
        using a specific property of the object as input to return
        a result class.
            e.g. for interface in interfaces:
                "ASSOCIATORS OF {Win32_NetworkAdapter.DeviceID=interface.DeviceID} WHERE ResultClass=Win32_PnPEntity'
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
