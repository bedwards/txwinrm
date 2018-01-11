##############################################################################
#
# Copyright (C) Zenoss, Inc. 2013, all rights reserved.
#
# This content is made available according to terms specified in the LICENSE
# file at the top-level directory of this package.
#
##############################################################################

"""
Use twisted web client to enumerate/pull WQL query.
"""

import sys
from collections import namedtuple
from twisted.internet import defer
from . import app
from .WinRMClient import EnumerateClient, DEFAULT_RESOURCE_URI

EnumInfo = namedtuple('EnumInfo', ['wql', 'resource_uri'])


def create_enum_info(wql, resource_uri=DEFAULT_RESOURCE_URI):
    return EnumInfo(wql, resource_uri)


class WinrmStrategy(object):

    def __init__(self):
        self._item_count = 0

    @property
    def count_summary(self):
        return '{0} items'.format(self._item_count)

    def _print_items(self, query_results, hostname, wql, include_header):
        if include_header:
            print '\n', hostname, "==>", wql
            indent = '  '
        else:
            indent = ''
        for key, items in query_results.iteritems():
            is_first_item = True
            print '\n{}'.format(key)
            for item in items:
                if is_first_item:
                    is_first_item = False
                else:
                    print '{0}{1}'.format(indent, '-' * 4)
                for name, value in vars(item).iteritems():
                    self._item_count += 1
                    text = value
                    if isinstance(value, list):
                        text = ', '.join(value)
                    print '{0}{1} = {2}'.format(indent, name, text)

    def act(self, good_conn_infos, args, config):
        include_header = len(config.conn_infos) > 1
        ds = []
        for conn_info in good_conn_infos:
            client = EnumerateClient(conn_info)
            wqls = []
            for wql in config.wqls:
                wqls.append(create_enum_info(wql, config.resource_uri))
            d = client.do_collect(wqls)
            d.addCallback(
                self._print_items, conn_info.hostname, wql, include_header)
            ds.append(d)
        return defer.DeferredList(ds, consumeErrors=True)


class WinrmUtility(app.ConfigDrivenUtility):

    def add_args(self, parser):
        parser.add_argument("--filter", "-f", help='wmi queries separated by ";"')
        parser.add_argument("--resource_uri",
                            help='resource uri to find wmi class.  e.g. {}'.format(DEFAULT_RESOURCE_URI),
                            default=DEFAULT_RESOURCE_URI)

    def check_args(self, args):
        legit = args.config or args.filter
        if not legit:
            print >>sys.stderr, "ERROR: You must specify a config file with " \
                                "-c or specify a WQL filter with -f"
        return legit

    def add_config(self, parser, config):
        config.wqls = parser.options('wqls')
        config.wqls = parser.options('resource_uri')

    def adapt_args_to_config(self, args, config):
        config.wqls = args.filter.split(';')
        config.resource_uri = args.resource_uri


if __name__ == '__main__':
    app.main(WinrmUtility(WinrmStrategy()))
