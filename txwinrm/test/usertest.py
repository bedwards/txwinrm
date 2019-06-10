##############################################################################
#
# Copyright (C) Zenoss, Inc. 2019, all rights reserved.
#
# This content is made available according to terms specified in the LICENSE
# file at the top-level directory of this package.
#
##############################################################################

"""Functional test for ensuring the correct user in multi-user environment

this test will create 2 clients to two different devices, run a simple
enumeration against both, then assert the user is correct for the kerberos
context.

to test:
edit the usertest.ini config with two different users in the same domain
for two devices.
to run:
    python -m txwinrm.test.usertest
"""

import logging
from ConfigParser import RawConfigParser
from kerberos import authGSSClientUserName
from collections import namedtuple
from twisted.internet import defer
from ..enumerate import DEFAULT_RESOURCE_URI
from ..WinRMClient import EnumerateClient
from ..util import (
    ConnectionInfo,
    ForbiddenError,
    RequestError,
    UnauthorizedError,
)

logging.basicConfig()
EnumInfo = namedtuple('EnumInfo', ['wql', 'resource_uri'])
log = logging.getLogger('winrm')


def create_enum_info(wql, resource_uri=DEFAULT_RESOURCE_URI):
    return EnumInfo(wql, resource_uri)


class WinrmCollectClient(object):

    @defer.inlineCallbacks
    def do_collect(self, conn_info, enum_infos):
        """
        conn_info has the following attributes
            hostname
            auth_type: basic or kerberos
            username
            password
            scheme: http (https coming soon)
            port: int
        """
        client = EnumerateClient(conn_info)
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

        try:
            assert(conn_info.username.lower() == authGSSClientUserName(
                client._connection._gssclient._context).lower())
        except Exception:
            print 'ERROR: Expected and Actual usernames do not match for host'\
                  ' {}'.format(conn_info.hostname)
            print 'Expected username: {}, Actual username {}'.format(
                conn_info.username,
                authGSSClientUserName(client._connection._gssclient._context))
        else:
            print 'Expected and Actual usernames match for host {}: {}'\
                .format(conn_info.hostname, conn_info.username)
        defer.returnValue(None)


@defer.inlineCallbacks
def user_run():
    client1 = WinrmCollectClient()
    client2 = WinrmCollectClient()
    connectiontype = 'Keep-Alive'
    parser = RawConfigParser(allow_no_value=True)
    parser.read('./txwinrm/test/usertest.ini')
    setup = {}
    debug = parser.get('options', 'debug')
    if debug.lower() == 'true':
        log.setLevel(level=logging.DEBUG)
    for k, v in parser.items('setup'):
        server, option = k.split('.')
        if server not in setup.keys():
            setup[server] = {option: v}
        else:
            setup[server][option] = v
    conn_infos = []
    for server in setup.iteritems():
        conn_infos.append(ConnectionInfo(
            server[1]['hostname'], "kerberos",
            server[1]['username'], server[1]['password'],
            "http", 5985, connectiontype, "", parser.get('kdc', 'kdc'),
            ipaddress=server[1]['ipaddress']))

    @defer.inlineCallbacks
    def do_example_collect(winrm, conn_info):
        wql1 = create_enum_info(
            'Select name from Win32_computersystem')
        yield winrm.do_collect(conn_info, [wql1])

    d1 = do_example_collect(client1, conn_infos[0])
    d2 = do_example_collect(client2, conn_infos[1])
    deferreds = [d1, d2]
    try:
        yield defer.DeferredList(deferreds, consumeErrors=True)
    finally:
        reactor.stop()


if __name__ == '__main__':
    from twisted.internet import reactor
    reactor.callWhenRunning(user_run)
    reactor.run()
