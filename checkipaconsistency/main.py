#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Tool to check consistency across FreeIPA servers

Author: Peter Pakos <peter.pakos@wandisco.com>

Copyright (C) 2017 WANdisco

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

import json
import os
import sys
import argparse
from prettytable import PrettyTable
import dns.resolver

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

import yaml
from .__version__ import __version__
from .freeipaserver import FreeIPAServer


class Checks(object):
    def __init__(self):
        pass


class Main(object):
    def __init__(self):
        self._app_name = os.path.basename(sys.modules['__main__'].__file__)
        self._app_dir = os.path.dirname(os.path.realpath(__file__))
        self._parse_args()

        self._domain = None
        self._hosts = []
        self._binddn = 'cn=Directory Manager'
        self._bindpw = None
        self._data = dict()

        self._load_config()

        if self._args.domain:
            self._domain = self._args.domain

        if not self._domain:
            exit(1)

        if self._args.hosts:
            self._hosts = self._args.hosts

        for i, host in enumerate(self._hosts):
            if not host or ' ' in host:
                exit(1)

        if not self._hosts:
            record = '_ldap._tcp.{0}'.format(self._domain)
            answers = []

            try:
                answers = dns.resolver.resolve(record, 'SRV')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                exit(1)

            for answer in answers:
                self._hosts.append(str(answer).split(' ')[3].rstrip('.'))

        if self._args.binddn:
            self._binddn = self._args.binddn

        if not self._binddn:
            exit(1)

        if self._args.bindpw:
            self._bindpw = self._args.bindpw

        if not self._bindpw:
            exit(1)

        self._servers = dict()
        for host in self._hosts:
            self._servers[host] = FreeIPAServer(host, self._domain, self._binddn, self._bindpw)

        self._checks = {
            'users': {
                'display_name': 'Active Users',
                'duplicates': True,
                'check_missing_dn': True
            },
            'susers': {
                'display_name': 'Stage Users',
                'duplicates': True,
                'check_missing_dn': True
            },
            'pusers': {
                'display_name': 'Preserved Users',
                'duplicates': True,
                'check_missing_dn': True
            },
            'hosts': {
                'display_name': 'Hosts',
                'duplicates': True,
                'check_missing_dn': True
            },
            'services': {
                'display_name': 'Services',
                'duplicates': True,
                'check_missing_dn': True
            },
            'ugroups': {
                'display_name': 'User Groups',
                'duplicates': True,
                'check_missing_dn': True
            },
            'hgroups': {
                'display_name': 'Host Groups',
                'duplicates': True,
                'check_missing_dn': True
            },
            'ngroups': {
                'display_name': 'Netgroups',
                'duplicates': True,
                'check_missing_dn': True
            },
            'hbac': {
                'display_name': 'HBAC Rules',
                'duplicates': 'cn',
                'check_missing_dn': True
            },
            'sudo': {
                'display_name': 'SUDO Rules',
                'duplicates': 'cn',
                'check_missing_dn': True
            },
            'zones': {
                'display_name': 'DNS Zones',
            },
            'certs': {
                'display_name': 'Certificates',
                'check_missing_dn': True
            },
            'conflicts': {
                'display_name': 'LDAP Conflicts'
            },
            'ghosts': {
                'display_name': 'Ghost Replicas'
            },
            'bind': {
                'display_name': 'Anonymous BIND'
            },
            'msdcs': {
                'display_name': 'Microsoft ADTrust'
            },
            'replicas': {
                'display_name': 'Replication Status'
            }
        }

    def _parse_args(self):
        parser = argparse.ArgumentParser(description='Tool to check consistency across FreeIPA servers', add_help=False)
        parser.add_argument('-H', '--hosts', nargs='*', dest='hosts', help='list of IPA servers')
        parser.add_argument('-d', '--domain', nargs='?', dest='domain', help='IPA domain')
        parser.add_argument('-D', '--binddn', nargs='?', dest='binddn', help='Bind DN (default: cn=Directory Manager)')
        parser.add_argument('-W', '--bindpw', nargs='?', dest='bindpw', help='Bind password')
        parser.add_argument('--help', action='help', help='show this help message and exit')
        parser.add_argument('--version', action='version',
                            version='{0} {1}'.format(os.path.basename(sys.argv[0]), __version__))
        parser.add_argument('--debug', action='store_true', dest='debug', help='debugging mode')
        parser.add_argument('--verbose', action='store_true', dest='verbose', help='verbose mode')
        parser.add_argument('--quiet', action='store_true', dest='quiet', help='do not log to console')
        parser.add_argument('-l', '--log-file', nargs='?', dest='log_file', default=None,
                            help='log to file (./{0}.log by default)'.format(self._app_name))
        parser.add_argument('--no-header', action='store_true', dest='disable_header', help='disable table header')
        parser.add_argument('--no-border', action='store_true', dest='disable_border', help='disable table border')
        parser.add_argument('-o', '--output', nargs='?', dest='output', help='output type', default='cli',
                            choices=['cli', 'json', 'yaml'])

        args = parser.parse_args()

        if args.log_file is None:
            args.log_file = self._app_name + '.log'

        self._args = args

    def _load_config(self):
        config = configparser.ConfigParser()
        file_dir = os.path.expanduser(os.environ.get('XDG_CONFIG_HOME', '~/.config'))

        if not os.path.exists(file_dir):
            os.makedirs(file_dir)

        config_file = os.path.join(
            file_dir,
            os.path.splitext(__name__)[0]
        )

        if not os.path.isfile(config_file):
            config.add_section('IPA')
            config.set('IPA', 'DOMAIN', 'ipa.example.com')
            config.set('IPA', 'HOSTS', 'ipa01, ipa02, ipa03, ipa04, ipa05, ipa06')
            config.set('IPA', 'BINDDN', 'cn=Directory Manager')
            config.set('IPA', 'BINDPW', 'example123')
            with open(config_file, 'w') as cfgfile:
                config.write(cfgfile)
            return

        config.read(config_file)

        if not config.has_section('IPA'):
            return

        if config.has_option('IPA', 'DOMAIN'):
            self._domain = config.get('IPA', 'DOMAIN')

        if config.has_option('IPA', 'HOSTS'):
            self._hosts = config.get('IPA', 'HOSTS')
            self._hosts = self._hosts.replace(',', ' ').split()

        if config.has_option('IPA', 'BINDDN'):
            self._binddn = config.get('IPA', 'BINDDN')

        if config.has_option('IPA', 'BINDPW'):
            self._bindpw = config.get('IPA', 'BINDPW')

    def run(self):
        self._compute_data()
        if self._args.output == 'json':
            print(json.dumps(self._data, indent=4, sort_keys=True))
        elif self._args.output == 'yaml':
            print(yaml.dump(self._data))
        elif self._args.output == 'cli':
            self._output_cli()

    def _compute_data(self):
        self._data['checks'] = dict()
        self._data['meta'] = dict()
        self._data['meta']['servers'] = dict()
        for server, payload in self._servers.items():
            self._data['meta']['servers'][server] = payload.hostname_short
        for check, check_payload in self._checks.items():
            _check_result = dict()
            _check_result['display_name'] = check_payload['display_name']
            _check_result['servers'] = dict()
            _numbers = list()
            for server, payload in self._servers.items():
                data = getattr(payload, check)
                _check_result['servers'][server] = dict()
                if isinstance(data, list):
                    _check_result['servers'][server]['result'] = len(data)
                    _numbers.append(len(data))
                else:
                    _check_result['servers'][server]['result'] = data
                    _numbers.append(data)
            _check_result['status_item_count'] = self._check_item_count(check, _numbers)
            self._data['checks'][check] = _check_result
            if check_payload.get('check_missing_dn', False):
                self._check_missing_dn(check=check)
            if check_payload.get('duplicates', False):
                self._duplicates(
                    check=check,
                    identifier=check_payload.get('duplicates')
                )

    def _output_cli(self):
        table_header = list()
        table_header.append('FreeIPA servers:')
        for payload in self._data['meta']['servers'].values():
            table_header.append(payload)
        table_header.append('COUNT')
        table = PrettyTable(
            table_header,
            header=not self._args.disable_header,
            border=not self._args.disable_border
        )
        table.align = 'l'

        for check, payload in self._data['checks'].items():
            data = list()
            data.append(payload['display_name'])
            for server in self._data['meta']['servers'].keys():
                data.append(payload['servers'][server]['result'])
            if payload['status_item_count']:
                data.append('OK')
            else:
                data.append('FAIL')

            table.add_row(data)

        print(table)

        self._output_cli_missing_dn()
        self._output_cli_duplicates()

    def _output_cli_missing_dn(self):
        print("Missing DN´s...")
        print("")

        for check, payload in self._data['checks'].items():
            if payload.get('status_missing_dn', None) is None:
                continue
            status_ok = payload.get('status_missing_dn')
            display_name = payload['display_name']
            if status_ok:
                print("status for {0} is ok".format(display_name))
                print("")
                continue
            print("status for {0} shows issues".format(display_name))
            print("")
            for server in self._data['meta']['servers'].keys():
                print("server {0} is missing these dn´s:".format(server))
                for dn in payload['missing_dn']:
                    print(dn)
                print("")
            print("")

    def _output_cli_duplicates(self):
        print("Duplicate objects...")
        print("")

        for check, payload in self._data['checks'].items():
            if payload.get('status_duplicates', None) is None:
                continue
            status_ok = payload.get('status_duplicates')
            display_name = payload['display_name']
            if status_ok:
                print("status for {0} is ok".format(display_name))
                print("")
                continue
            print("status for {0} shows issues".format(display_name))
            print("")
            print("found the following duplicates")
            servers = list()
            for server in self._data['meta']['servers'].keys():
                servers.append(server)
            servers.sort()
            for item, item_payload in payload['duplicates'].items():
                print("{0} item {1} has multiple version".format(check, item))
                for dn, dn_values in item_payload.items():
                    print("dn {0} with ipaUniqueID´s: {1}".format(dn, dn_values))
                for server in servers:
                    _ids = payload['servers'][server]['duplicates'][item]
                    print("{0} knows the following ipaUniqueId´s: {1}".format(server, _ids))
            print("")

    @staticmethod
    def _check_item_count(check, check_results):
        if check in ['conflicts', 'ghosts']:
            if check_results.count(check_results[0]) == len(check_results) and check_results[0] == 0:
                return True
            else:
                return False
        elif check == 'replicas':
            for lines in check_results:
                for line in lines.splitlines():
                    _, state = line.split()
                    state = int(state)
                    if state not in [0, 1]:
                        return False
            return True
        else:
            if check_results.count(check_results[0]) == len(check_results) and None not in check_results:
                return True
            else:
                return False

    def _duplicates(self, check, identifier):
        all_identifiers = dict()

        for server, payload in self._servers.items():
            data = getattr(payload, check)
            for item in data:
                dn = str(item[0])
                if isinstance(identifier, str):
                    _identifier = str(item[1]['cn'][0])
                else:
                    _identifier = str(item[0])
                uniq_id = str(item[1]['ipaUniqueID'][0])
                if _identifier not in all_identifiers:
                    all_identifiers[_identifier] = dict()
                    all_identifiers[_identifier]['identifiers'] = set()
                    all_identifiers[_identifier]['servers'] = dict()
                    all_identifiers[_identifier]['dn'] = dict()
                all_identifiers[_identifier]['identifiers'].add(uniq_id)
                if server not in all_identifiers[_identifier]['servers']:
                    all_identifiers[_identifier]['servers'][server] = set()
                all_identifiers[_identifier]['servers'][server].add(uniq_id)
                if dn not in all_identifiers[_identifier]['dn']:
                    all_identifiers[_identifier]['dn'][dn] = set()
                all_identifiers[_identifier]['dn'][dn].add(uniq_id)

        self._data['checks'][check]['duplicates'] = dict()
        self._data['checks'][check]['status_duplicates'] = True

        for _identifier, payload in all_identifiers.items():
            if len(payload['identifiers']) > 1:
                self._data['checks'][check]['status_duplicates'] = False
                for server, server_values in payload['servers'].items():
                    if 'duplicates' not in self._data['checks'][check]['servers'][server]:
                        self._data['checks'][check]['servers'][server]['duplicates'] = dict()
                    self._data['checks'][check]['servers'][server]['duplicates'][_identifier] = list(server_values)
                for dn, dn_values in payload['dn'].items():
                    if _identifier not in self._data['checks'][check]['duplicates']:
                        self._data['checks'][check]['duplicates'][_identifier] = dict()
                    self._data['checks'][check]['duplicates'][_identifier][dn] = list(dn_values)

    def _check_missing_dn(self, check):
        status_ok = True
        all_dns = set()
        servers = dict()
        for server, payload in self._servers.items():
            data = getattr(payload, check)
            server_items = set()
            for item in data:
                server_items.add(item[0])
                all_dns.add(item[0])
            servers[server] = server_items

        for server, items in servers.items():
            delta = all_dns.difference(items)
            if delta:
                status_ok = False
            self._data['checks'][check]['servers'][server]['missing_dn'] = list(delta)
        self._data['checks'][check]['status_missing_dn'] = status_ok


def main():
    try:
        Main().run()
    except KeyboardInterrupt:
        print('\nTerminating...')
        exit(130)
