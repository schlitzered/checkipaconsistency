#  -*- coding: utf-8 -*-
"""
FreeIPA Server module

Author: Peter Pakos <peter.pakos@wandisco.com>

Copyright (C) 2017 WANdisco

This file is part of checkipaconsistency.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from __future__ import print_function
import ldap
import dns.resolver


class FreeIPAServer(object):
    def __init__(self, host, domain, binddn, bindpw):

        self._users = None
        self._susers = None
        self._pusers = None
        self._hosts = None
        self._services = None
        self._ugroups = None
        self._hgroups = None
        self._ngroups = None
        self._hbac = None
        self._sudo = None
        self._zones = None
        self._certs = None
        self._conflicts = None
        self._ghosts = None
        self._bind = None
        self._msdcs = None
        self._replicas = None
        self._healthy_agreements = False

        self._binddn = binddn
        self._bindpw = bindpw
        self._domain = domain
        self._url = 'ldaps://' + host
        self.hostname_short = host.replace('.{0}'.format(domain), '')
        self._conn = self._get_conn()

        if not self._conn:
            return

        self._fqdn = self._get_fqdn()
        self.hostname_short = self._fqdn.replace('.{0}'.format(domain), '')


        self._base_dn = 'dc=' + self._domain.replace('.', ',dc=')

        context = self._get_context()
        if self._base_dn != context:
            exit(1)

    @property
    def users(self):
        if not self._users:
            self._users = self._get_users(user_base='active')
        return self._users

    @property
    def susers(self):
        if not self._susers:
            self._susers = self._get_users(user_base='stage')
        return self._susers

    @property
    def pusers(self):
        if not self._pusers:
            self._pusers = self._get_users(user_base='preserved')
        return self._pusers

    @property
    def hosts(self):
        if not self._hosts:
            self._hosts = self._get_hosts()
        return self._hosts

    @property
    def services(self):
        if not self._services:
            self._services = self._get_services()
        return self._services

    @property
    def ugroups(self):
        if not self._ugroups:
            self._ugroups = self._get_groups()
        return self._ugroups

    @property
    def hgroups(self):
        if not self._hgroups:
            self._hgroups = self._get_hostgroups()
        return self._hgroups

    @property
    def ngroups(self):
        if not self._ngroups:
            self._ngroups = self._count_netgroups()
        return self._ngroups

    @property
    def hbac(self):
        if not self._hbac:
            self._hbac = self._get_hbac_rules()
        return self._hbac

    @property
    def sudo(self):
        if not self._sudo:
            self._sudo = self._get_sudo_rules()
        return self._sudo

    @property
    def zones(self):
        if not self._zones:
            self._zones = self._get_dns_zones()
        return self._zones

    @property
    def certs(self):
        if not self._certs:
            self._certs = self._get_certificates()
        return self._certs

    @property
    def conflicts(self):
        if not self._conflicts:
            self._conflicts = self._get_ldap_conflicts()
        return self._conflicts

    @property
    def ghosts(self):
        if not self._ghosts:
            self._ghosts = self._get_ghost_replicas()
        return self._ghosts

    @property
    def bind(self):
        if not self._bind:
            self._bind = self._get_anon_bind()
        return self._bind

    @property
    def msdcs(self):
        if not self._msdcs:
            self._msdcs = self._get_ms_adtrust()
        return self._msdcs

    @property
    def replicas(self):
        if not self._replicas:
            self._replicas, self._healthy_agreements = self._replication_agreements()
        return self._replicas

    @property
    def healthy_agreements(self):
        if not self._healthy_agreements:
            self._replicas, self._healthy_agreements = self._replication_agreements()
        return self._healthy_agreements

    @staticmethod
    def _get_ldap_msg(e):
        msg = e
        if hasattr(e, 'message'):
            msg = e.message
            if 'desc' in e.message:
                msg = e.message['desc']
            elif hasattr(e, 'args'):
                msg = e.args[0]['desc']
        return msg

    def _get_conn(self):
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

        try:
            conn = ldap.initialize(self._url)
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 3)
            conn.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)
            conn.simple_bind_s(self._binddn, self._bindpw)
        except (
            ldap.SERVER_DOWN,
            ldap.NO_SUCH_OBJECT,
            ldap.INVALID_CREDENTIALS
        ):
            return False
        return conn

    def _search(self, base, fltr, attrs=None, scope=ldap.SCOPE_SUBTREE):
        try:
            return self._conn.search_s(base, scope, fltr, attrs)
        except (ldap.NO_SUCH_OBJECT, ldap.SERVER_DOWN) as e:
            return False
        except ldap.REFERRAL:
            exit(1)

    def _get_fqdn(self):
        results = self._search(
            'cn=config',
            '(objectClass=*)',
            ['nsslapd-localhost'],
            scope=ldap.SCOPE_BASE
        )

        if not results and type(results) is not list:
            r = None
        else:
            dn, attrs = results[0]
            r = attrs['nsslapd-localhost'][0].decode('utf-8')

        return r

    def _get_context(self):
        results = self._search(
            'cn=config',
            '(objectClass=*)',
            ['nsslapd-defaultnamingcontext'],
            scope=ldap.SCOPE_BASE
        )

        if not results and type(results) is not list:
            r = None
        else:
            dn, attrs = results[0]
            r = attrs['nsslapd-defaultnamingcontext'][0].decode('utf-8')

        return r

    def _get_users(self, user_base):
        if user_base == 'active':
            user_base = 'cn=users,cn=accounts,{0}'.format(self._base_dn)
        elif user_base == 'stage':
            user_base = 'cn=staged users,cn=accounts,cn=provisioning,{0}'.format(self._base_dn)
        elif user_base == 'preserved':
            user_base = 'cn=deleted users,cn=accounts,cn=provisioning,{0}'.format(self._base_dn)
        results = self._search(
            user_base,
            '(objectClass=person)'
        )

        return results

    def _get_groups(self):
        results = self._search(
            'cn=groups,cn=accounts,{0}'.format(self._base_dn),
            '(objectClass=ipausergroup)'
        )

        return results

    def _get_hosts(self):
        results = self._search(
            'cn=computers,cn=accounts,{0}'.format(self._base_dn),
            '(fqdn=*)'
        )

        return results

    def _get_services(self):
        results = self._search(
            'cn=services,cn=accounts,{0}'.format(self._base_dn),
            '(krbprincipalname=*)'
        )

        return results

    def _count_netgroups(self):
        results = self._search(
            'cn=ng,cn=alt,{0}'.format(self._base_dn),
            '(ipaUniqueID=*)',
            None,
            scope=ldap.SCOPE_ONELEVEL
        )

        return results

    def _get_hostgroups(self):
        results = self._search(
            'cn=hostgroups,cn=accounts,{0}'.format(self._base_dn),
            '(objectClass=ipahostgroup)'
        )
        return results

    def _get_hbac_rules(self):
        results = self._search(
            'cn=hbac,{0}'.format(self._base_dn),
            '(ipaUniqueID=*)',
            scope=ldap.SCOPE_ONELEVEL
        )
        return results

    def _get_sudo_rules(self):
        results = self._search(
            'cn=sudorules,cn=sudo,{0}'.format(self._base_dn),
            '(ipaUniqueID=*)',
            scope=ldap.SCOPE_ONELEVEL
        )
        return results

    def _get_dns_zones(self):
        results = self._search(
            'cn=dns,{0}'.format(self._base_dn),
            '(|(objectClass=idnszone)(objectClass=idnsforwardzone))',
            scope=ldap.SCOPE_ONELEVEL
        )
        return results

    def _get_certificates(self):
        results = self._search(
            'ou=certificateRepository,ou=ca,o=ipaca',
            '(certStatus=*)',
            ['subjectName'],
            scope=ldap.SCOPE_ONELEVEL
        )
        return results

    def _get_ldap_conflicts(self):
        results = self._search(
            self._base_dn,
            '(|(nsds5ReplConflict=*)(&(objectclass=ldapsubentry)(nsds5ReplConflict=*)))',
            ['nsds5ReplConflict']
        )

        return results

    def _get_ghost_replicas(self):
        results = self._search(
            self._base_dn,
            '(&(objectclass=nstombstone)(nsUniqueId=ffffffff-ffffffff-ffffffff-ffffffff))',
            ['nscpentrywsi']
        )

        r = 0

        if type(results) == list and len(results) > 0:
            dn, attrs = results[0]

            for attr in attrs['nscpentrywsi']:
                if 'replica ' in str(attr) and 'ldap' not in str(attr):
                    r += 1

        return r

    def _get_anon_bind(self):
        results = self._search(
            'cn=config',
            '(objectClass=*)',
            ['nsslapd-allow-anonymous-access'],
            scope=ldap.SCOPE_BASE
        )
        dn, attrs = results[0]
        state = attrs['nsslapd-allow-anonymous-access'][0].decode('utf-8')

        if state in ['on', 'off', 'rootdse']:
            r = str(state).upper()
        else:
            r = 'ERROR'

        return r

    def _get_ms_adtrust(self):
        record = '_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.{0}'.format(self._domain)

        r = False

        try:
            answers = dns.resolver.resolve(record, 'SRV')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return r

        for answer in answers:
            if self._fqdn in answer.to_text():
                r = True
                return r

        return r

    def _replication_agreements(self):
        msg = []
        healthy = True
        suffix = self._base_dn.replace('=', '\\3D').replace(',', '\\2C')
        results = self._search(
            'cn=replica,cn={0},cn=mapping tree,cn=config'.format(suffix),
            '(objectClass=*)',
            ['nsDS5ReplicaHost', 'nsds5replicaLastUpdateStatus'],
            scope=ldap.SCOPE_ONELEVEL
        )

        for result in results:
            dn, attrs = result
            host = attrs['nsDS5ReplicaHost'][0].decode('utf-8')
            host = host.replace('.{0}'.format(self._domain), '')
            status = attrs['nsds5replicaLastUpdateStatus'][0].decode('utf-8')
            status = status.replace('Error ', '').partition(' ')[0].strip('()')
            if status not in ['0', '18']:
                healthy = False
            msg.append('{0} {1}'.format(host, status))

        r1 = '\n'.join(msg)
        r2 = healthy
        return r1, r2
