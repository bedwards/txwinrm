##############################################################################
#
# Copyright (C) Zenoss, Inc. 2013-2018, all rights reserved.
#
# This content is made available according to terms specified in the LICENSE
# file at the top-level directory of this package.
#
##############################################################################

import logging
import time

from collections import namedtuple
from twisted.internet import defer, reactor
from .enumerate import (
    DEFAULT_RESOURCE_URI,
    SaxResponseHandler,
    _MAX_REQUESTS_PER_ENUMERATION,
)
from .WinRMClient import EnumerateClient, WinRMClient
from .util import (
    ConnectionInfo,
    ForbiddenError,
    RequestError,
    UnauthorizedError,
)
from .twisted_utils import add_timeout
from .krb5 import klist


EnumInfo = namedtuple('EnumInfo', ['wql', 'resource_uri'])
log = logging.getLogger('winrm')


def create_enum_info(wql, resource_uri=DEFAULT_RESOURCE_URI):
    return EnumInfo(wql, resource_uri)


def t_print(thing):
    print '{}  {}'.format(time.strftime('%H:%M:%S'), thing)


class WinrmCollectClient(WinRMClient):

    def __init__(self, conn_info):
        super(WinrmCollectClient, self).__init__(conn_info)
        self._handler = SaxResponseHandler(self)
        self._hostname = self._conn_info.ipaddress
        self.key = (self._conn_info.ipaddress, 'enumerate')

    def decrypt_body(self, body):
        """Used by SaxResponseHandler to decrypt response."""
        return self._connection._gssclient.decrypt_body(body)

    @defer.inlineCallbacks
    def test_context_lifetime(self, enum_infos):
        """Test expired context handling.

        we do not want to use an expiring context(spn). this test
        will wait until there's less than 60s left for the conext lifetime
        then set the limit to 60s, and allow the expiring mechanism in the
        session handle the expiration and obtain a new connection.

        for quicker testing, change the lifetime of the spn on windows
        AD to be 10 minutes in group policy
        """
        t_print('init_connection')
        connection = yield self.connection()
        lifetime = connection._gssclient.context_lifetime()
        t_print('lifetime left: {}s'.format(lifetime))
        if lifetime >= 5:
            t_print('kill connection')
            self.close_connection(connection)
            d = defer.Deferred()
            try:
                t_print('sleep {} seconds'.format(lifetime - 5))
                yield add_timeout(d, lifetime - 5)
            except Exception:
                pass

        request_template_name = 'enumerate'
        enumeration_context = None
        items = []
        self._get_raw = True
        for enum_info in enum_infos:
            try:
                for i in xrange(_MAX_REQUESTS_PER_ENUMERATION):
                    log.debug('{0} "{1}" {2}'.format(
                        self._hostname, enum_info.wql, request_template_name))
                    response = yield self.send_request(
                        request_template_name,
                        resource_uri=DEFAULT_RESOURCE_URI,
                        wql=enum_info.wql,
                        enumeration_context=enumeration_context)
                    log.debug("{0} {1} HTTP status: {2}".format(
                        self._hostname, enum_info.wql, response.code))
                    enumeration_context, new_items = \
                        yield self._handler.handle_response(response)
                    items.extend(new_items)
                    if not enumeration_context:
                        break
                    request_template_name = 'pull'
                else:
                    raise Exception("Reached max requests per enumeration.")
            except Exception as e:
                log.debug('{0} {1}'.format(self._hostname, e))
                raise
        lifetime = self._connection._gssclient.context_lifetime()
        t_print('new connection lifetime left: {}s'.format(lifetime))
        defer.returnValue(items)

    @defer.inlineCallbacks
    def do_collect(self, enum_infos):
        """
        conn_info has the following attributes
            hostname
            auth_type: basic or kerberos
            username
            password
            scheme: http (https coming soon)
            port: int
        """
        client = EnumerateClient(self._conn_info)
        items = {}
        for enum_info in enum_infos:
            try:
                items[enum_info] = yield client.enumerate(
                    enum_info.wql, enum_info.resource_uri)
            except (UnauthorizedError, ForbiddenError):
                # Fail the collection for general errors.
                raise
            except RequestError:
                # Store empty results for other query-specific errors.
                continue

        defer.returnValue(items)

    @defer.inlineCallbacks
    def test_user_in_klist(self):
        t_print('init_connection')
        connection = yield self.connection()
        results = 'Default principal: a@b'
        t_print('user should not be found results:\n{}'.format(results))
        if connection._gssclient.user_in_klist(results):
            print 'found {} in klist results'.format(self._conn_info.username)
        else:
            print 'did not find {} in klist results'.format(self._conn_info.username)
        results = yield klist(['-A'])
        t_print('user should be found results:\n{}'.format(results))
        if connection._gssclient.user_in_klist(results):
            print 'found {} in klist results'.format(self._conn_info.username)
        else:
            print 'did not find {} in klist results'.format(self._conn_info.username)
        defer.returnValue(None)

# ----- An example of useage...


if __name__ == '__main__':
    from pprint import pprint
    import logging
    logging.basicConfig()
    # log.setLevel(level=logging.DEBUG)

    @defer.inlineCallbacks
    def do_example_collect():
        connectiontype = 'Keep-Alive'
        # enter your information here
        conn_info = ConnectionInfo(
            "",  # hostname
            "kerberos",
            "",  # domain user here
            "",  # password here
            "http",
            5985,
            connectiontype,
            "",  # keytab unused
            '',  # kdc
            ipaddress='',  # ipaddress if no dns
        )
        winrm = WinrmCollectClient(conn_info)
        wql1 = create_enum_info(
            'Select Caption, DeviceID, Name From Win32_Processor')
        wql2 = create_enum_info(
            'select Name, Label, Capacity from Win32_Volume')
        items = []
        # items = yield winrm.test_context_lifetime([wql1, wql2])
        items = yield winrm.do_collect([wql1, wql2])
        # yield winrm.test_user_in_klist()
        if items:
            t_print('results')
            pprint(items)
        reactor.stop()

    reactor.callWhenRunning(do_example_collect)
    reactor.run()
