##############################################################################
#
# Copyright (C) Zenoss, Inc. 2013, all rights reserved.
#
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
#
##############################################################################

import logging

import collections
import os
import re

from twisted.internet import defer, reactor
from twisted.internet.protocol import ProcessProtocol
LOG = logging.getLogger('txwinrm.krb5')


__all__ = [
    'kinit',
    'ccname',
]


KRB5_CONF_TEMPLATE = (
    "# This file is managed by the txwinrm python module.\n"
    "# NOTE: Any changes to the logging, libdefaults, domain_realm\n"
    "# sections of this file will be overwritten.\n"
    "#\n"
    "\n"
    "{includedir}\n"
    "[logging]\n"
    " default = FILE:/var/log/krb5libs.log\n"
    " kdc = FILE:/var/log/krb5kdc.log\n"
    " admin_server = FILE:/var/log/kadmind.log\n"
    "\n"
    "[libdefaults]\n"
    " default_realm = EXAMPLE.COM\n"
    " dns_lookup_realm = false\n"
    " dns_lookup_kdc = false\n"
    " ticket_lifetime = 24h\n"
    " renew_lifetime = 7d\n"
    " forwardable = true\n"
    "{disable_rdns}"
    "\n"
    "[realms]\n"
    "{realms_text}"
    "\n"
    "[domain_realm]\n"
    "{domain_realm_text}"
)

INCLUDEDIR_TEMPLATE = (
    "includedir {includedir}\n"
)

KDC_TEMPLATE = (
    "  kdc = {kdc}"
)

REALM_TEMPLATE = (
    " {realm} = {{\n"
    "{kdcs}\n"
    "  admin_server = {admin_server}\n"
    " }}\n"
)

DOMAIN_REALM_TEMPLATE = (
    " .{domain} = {realm}\n"
    " {domain} = {realm}\n"
)


class Config(object):
    """Manages KRB5_CONFIG."""

    def __init__(self):
        """Initialize instance with data from KRB5_CONFIG."""
        self.path = self.get_path()
        self.includedirs = set()
        self.disable_rdns = False
        self.realms, self.admin_servers = self.load()

        # For further usage by kerberos python module.
        os.environ['KRB5_CONFIG'] = self.path

    def add_includedir(self, includedir):
        self.includedirs.add(includedir)
        self.save()

    def remove_includedir(self, includedir):
        self.includedirs.discard(includedir)
        self.save()

    def add_kdc(self, realm, kdcs, disable_rdns=False):
        """Add realm and KDC to KRB5_CONFIG.
        Allow for comma separated string of kdcs with regex
        Use + or nothing to add, - to remove, * for admin_server
        Assume first entry to be the admin_server if not specified
        Example:
        '10.10.10.10,*10.10.10.20, +10.10.10.30, -10.10.10.40'
        10.10.10.10 is a kdc, add it
        10.10.10.20 is a kdc and admin_server
        10.10.10.30 is a kdc, add it
        10.10.10.40 is no longer a kdc or was mistyped, remove it
        """
        if not kdcs or not kdcs.strip():
            return

        # reload currently saved copy
        self.realms, self.admin_servers = self.load()
        valid_kdcs = []
        remove_kdcs = []
        admin_server = None
        for kdc in kdcs.split(','):
            kdc = kdc.strip()
            match = re.match('^([\+\-\*])(.*)', kdc)
            if match and match.group(1) == '+':
                valid_kdcs.append(match.group(2).strip())
            elif match and match.group(1) == '-':
                remove_kdcs.append(match.group(2).strip())
            elif match and match.group(1) == '*':
                admin_server = match.group(2).strip()
                valid_kdcs.append(admin_server)
            elif kdc:
                valid_kdcs.append(kdc)

        if not admin_server and valid_kdcs:
            admin_server = valid_kdcs[0]

        new_kdcs = self.realms[realm].symmetric_difference(set(valid_kdcs))
        bad_kdcs = self.realms[realm].intersection(set(remove_kdcs))
        if (not new_kdcs and not bad_kdcs and
                admin_server == self.admin_servers[realm] and
                self.disable_rdns == disable_rdns):
            # nothing to do
            return

        self.disable_rdns = disable_rdns
        self.realms[realm] = self.realms[realm].union(new_kdcs) - bad_kdcs
        self.admin_servers[realm] = admin_server
        self.save()

    def get_path(self):
        """Return the path to krb5.conf.

        Order of preference:
            1. $KRB5_CONFIG
            2. $ZENHOME/var/krb5.conf
            3. $HOME/.txwinrm/krb5.conf
            4. /etc/krb5.conf
        """
        if 'KRB5_CONFIG' in os.environ:
            return os.environ['KRB5_CONFIG']

        if 'ZENHOME' in os.environ:
            return os.path.join(os.environ['ZENHOME'], 'var', 'krb5.conf')

        if 'HOME' in os.environ:
            return os.path.join(os.environ['HOME'], '.txwinrm', 'krb5.conf')

        return os.path.join('/etc', 'krb5.conf')

    def get_ccname(self, username):
        """Return KRB5CCNAME environment for username.

        We use a separate credential cache for each username because
        kinit causes all previous credentials to be destroyed when a new
        one is initialized.

        https://groups.google.com/forum/#!topic/comp.protocols.kerberos/IjtK9Mo39qc
        """
        if 'ZENHOME' in os.environ:
            return os.path.join(
                os.environ['ZENHOME'], 'var', 'krb5cc', username)

        if 'HOME' in os.environ:
            return os.path.join(
                os.environ['HOME'], '.txwinrm', 'krb5cc', username)

        return ''

    def load(self):
        """Load current realms from KRB5_CONFIG file."""
        realm_kdcs = collections.defaultdict(set)
        realm_adminservers = {}
        if not self.includedirs:
            self.includedirs = set()

        if not os.path.isfile(self.path):
            return realm_kdcs, realm_adminservers

        with open(self.path, 'r') as krb5_conf:
            in_realms_section = False
            in_realm = None

            for line in krb5_conf:
                if line.strip().startswith('[realms]'):
                    in_realms_section = True
                elif line.strip().startswith('['):
                    in_realms_section = False
                elif line.strip().startswith('includedir'):
                    match = re.search(r'includedir (\S+)', line)
                    if match:
                        self.includedirs.add(match.group(1))
                elif line.strip().startswith('rdns'):
                    try:
                        self.disable_rdns = True if line.split('=')[1].strip() == 'false' else False
                    except Exception:
                        self.disable_rdns = False
                elif in_realms_section:
                    line = line.strip()
                    if not line:
                        continue

                    match = re.search(r'(\S+)\s+=\s+{', line)
                    if match:
                        in_realm = match.group(1)
                        continue

                    if in_realm:
                        match = re.search(r'kdc\s+=\s+(\S+)', line)
                        if match:
                            realm_kdcs[in_realm].add(match.group(1))

                        match = re.search(r'admin_server\s+=\s+(\S+)', line)
                        if match:
                            realm_adminservers[in_realm] = match.group(1)

        return realm_kdcs, realm_adminservers

    def save(self):
        """Save current realm KDCs to KRB5_CONFIG."""
        realms_list = []
        domain_realm_list = []
        includedir_list = []

        for realm, kdcs in self.realms.iteritems():
            if not kdcs:
                continue

            kdc_list = []
            for kdc in kdcs:
                kdc_list.append(KDC_TEMPLATE.format(kdc=kdc))

            realms_list.append(
                REALM_TEMPLATE.format(
                    realm=realm.upper(),
                    kdcs='\n'.join(kdc_list),
                    admin_server=self.admin_servers[realm.upper()]))

            domain_realm_list.append(
                DOMAIN_REALM_TEMPLATE.format(
                    domain=realm.lower(), realm=realm.upper()))

        dirname = os.path.dirname(self.path)
        if not os.path.isdir(dirname):
            os.makedirs(dirname)

        # create config dir for user supplied options
        includedir = os.path.join(dirname, 'config')
        if not os.path.isdir(includedir):
            os.makedirs(includedir)
        self.includedirs.add(includedir)

        for includedir in tuple(self.includedirs):
            includedir_list.append(
                INCLUDEDIR_TEMPLATE.format(
                    includedir=includedir))

        disable_rdns = ' rdns = false\n' if self.disable_rdns else ''
        try:
            with open(self.path, 'w') as krb5_conf:
                krb5_conf.write(
                    KRB5_CONF_TEMPLATE.format(
                        disable_rdns=disable_rdns,
                        includedir=''.join(includedir_list),
                        realms_text=''.join(realms_list),
                        domain_realm_text=''.join(domain_realm_list)))
        except IOError as e:
            pass

# Singleton. Loads from KRB5_CONFIG on import.
config = Config()


class KinitProcessProtocol(ProcessProtocol):
    """Communicates with kinit command.

    The only thing we do is answer the password prompt. We don't even
    care about the output.
    """

    def __init__(self, password):
        self._password = password
        self.d = defer.Deferred()
        self._data = ''
        self._error = ''

    def errReceived(self, data):
        self._error += data

    def outReceived(self, data):
        self._data += data
        if 'Password for' in self._data and ':' in self._data:
            self.transport.write('{0}\n'.format(self._password))
            self._data = ''
        elif 'Password expired' in data:
            # strip off '\nEnter new password:'
            self._error = data.split('\n')[0]
            self.transport.signalProcess('KILL')

    def processEnded(self, reason):
        self.d.callback(self._error if self._error else None)


@defer.inlineCallbacks
def kinit(username, password, kdc, includedir=None, disable_rdns=False):
    """Perform kerberos initialization."""
    kinit = None
    for path in ('/usr/bin/kinit', '/usr/kerberos/bin/kinit'):
        if os.path.isfile(path):
            kinit = path
            break

    if not kinit:
        raise Exception("krb5-workstation is not installed")

    try:
        user, realm = username.split('@')
    except ValueError:
        raise Exception("kerberos username must be in user@domain format")

    realm = realm.upper()

    global config

    if includedir:
        config.add_includedir(includedir)
    config.add_kdc(realm, kdc, disable_rdns)

    ccname = config.get_ccname(username)
    dirname = os.path.dirname(ccname)
    if not os.path.isdir(dirname):
        os.makedirs(dirname)

    kinit_args = [kinit, '{}@{}'.format(user, realm)]
    kinit_env = {
        'KRB5_CONFIG': config.path,
        'KRB5CCNAME': ccname,
    }

    protocol = KinitProcessProtocol(password)

    reactor.spawnProcess(protocol, kinit, kinit_args, kinit_env)

    results = yield protocol.d
    if 'Included profile file could not be read while initializing Kerberos 5 library' in results:
        config.remove_includedir(includedir)
        retry_protocol = KinitProcessProtocol(password)
        reactor.spawnProcess(retry_protocol, kinit, kinit_args, kinit_env)
        results = yield retry_protocol.d
    defer.returnValue(results)


def ccname(username):
    """Return KRB5CCNAME value for username."""
    return config.get_ccname(username)


def add_trusted_realm(realm, kdc, disable_rdns=False):
    """Add a trusted realm for cross realm authentication"""
    trusted_realm = realm.upper()
    global config
    config.add_kdc(trusted_realm, kdc, disable_rdns)
