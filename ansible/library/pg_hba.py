#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

'''
This module is used to manage postgres pg_hba files with Ansible.
'''

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: pg_hba
short_description: Adds, removes or modifies an rule in a pg_hba file.
description:
   - The fundamental function of the module is to create, or delete lines in pg_hba files.
   - The lines in the file should be in a typical pg_hba form and lines should be unique per key (type, databases, users, source).
     If they are not unique and the SID is 'the one to change', only one for C(state=present) or none for C(state=absent) of the SID's will remain.
extends_documentation_fragment: files
version_added: "2.6"
options:
  backup:
    description:
      - If set, create a backup of the C(pg_hba) file before it is modified.
        The location of the backup is returned in the (backup) variable by this module.
    default: false
    type: bool
  create:
    description:
      - Create an C(pg_hba) file if none exists.
      - When set to false, an error is raised when the C(pg_hba) file doesn't exist.
    default: false
    type: bool
  contype:
    description:
      - Type of the rule. Use emptystring C('') if you don't want to change file, but only want to read contents.
    choices: [ "local", "host", "hostssl", "hostnossl", "" ]
  databases:
    description:
      - Databases this line applies to.
    default: "all"
  dest:
    description:
      - Path to C(pg_hba) file to modify.
    required: true
  method:
    description:
      - Authentication method to be used.
    default: "md5"
    choices: [ "trust", "reject", "md5", "password", "gss", "sspi", "krb5", "ident", "peer", "ldap", "radius", "cert", "pam" ]
  netmask:
    description:
      - The netmask of the source address.
    default: ""
  options:
    description:
      - Additional options for the authentication I(method).
    default: ""
  order:
    description:
      - The entries will be written out in a specific order.
      - With this option you can control by wich field they are ordered first, second and last.
      - s=source, d=databases, u=users.
    default: "sdu"
    choices: [ "sdu", "sud", "dsu", "dus", "usd", "uds" ]
  src:
    description:
      - The source address/net where the connections could come from.
      - Will not be used for entries of I(type)=C(local).
      - You can also use keywords C(all), C(samehost), and C(samenet).
    default: "samehost"
    aliases: [ 'source' ]
  state:
    description:
      - The lines will be added/modified when C(state=present) and removed when C(state=absent).
    default: present
    choices: [ "present", "absent" ]
  users:
    description:
      - Users this line applies to.
    default: "all"

notes:
   - The default authentication assumes that on the host, you are either logging in as or
     sudo'ing to an account with appropriate permissions to read and modify the file.
   - This module also returns the pg_hba info. You can use this module to only retrieve it by only specifying I(dest).
     The info kan be found in the returned data under key pg_hba, being a list, containing a dict per rule.
   - This module will sort resulting C(pg_hba) files if a rule change is required.
     This could give unexpected results with manual created hba files, if it was improperly sorted.
     For example a rule was created for a net first and for a ip in that net range next.
     In that situation, the 'ip specific rule' will never hit, it is in the C(pg_hba) file obsolete.
     After the C(pg_hba) file is rewritten by the M(pg_hba) module, the ip specific rule will be sorted above the range rule.
     And then it will hit, which will give unexpected results.
   - With the 'order' parameter you can control which field is used to sort first, next and last.
   - The module supports a check mode and a diff mode.

requirements:
    - "ipaddress"

author: Sebastiaan Mannem (github.com/sebasmannem)
'''

EXAMPLES = '''
- name: Grant user joe from network 192.168.0.0/24 access to database sales using md5 password authentication.
  pg_hba:
    user=joe
    source=192.168.0.100/24
    database=sales
    method=md5

- name: Grant user repmgr from host 192.168.0.100/32 access for replication without password.
  pg_hba:
    user=repmgr
    source=192.168.0.100
    database=replication
    method=trust
'''

RETURN = '''
msgs:
    description: List of textual messages what was done
    returned: always
    type: list
    sample:
       "msgs": [
          "Removing",
          "Changed",
          "Writing"
        ]
backup_file:
    description: File that the original pg_hba file was backed up to
    returned: changed
    type: string
    sample: /tmp/pg_hba_jxobj_p
pg_hba:
    description: List of the pg_hba rules as they are configured in the specified hba file
    returned: always
    type: list
    sample:
      "pg_hba": [
         {
            "db": "all",
            "method": "md5",
            "src": "samehost",
            "type": "host",
            "usr": "all"
         }
      ]
'''

import os
import re
try:
    import ipaddress
    HAS_IPADDRESS = True
except ImportError:
    HAS_IPADDRESS = False
import copy
from ansible.module_utils.basic import AnsibleModule, tempfile, shutil

PG_HBA_METHODS = ["trust", "reject", "md5", "password", "gss", "sspi", "krb5", "ident", "peer",
                  "ldap", "radius", "cert", "pam"]
PG_HBA_TYPES = ["local", "host", "hostssl", "hostnossl"]
PG_HBA_ORDERS = ["sdu", "sud", "dsu", "dus", "usd", "uds"]
PG_HBA_HDR = ['type', 'db', 'usr', 'src', 'mask', 'method', 'options']

WHITESPACES_RE = re.compile(r'\s+')


class PgHbaError(Exception):
    '''
    This exception is raised when parsing the pg_hba file ends in an error.
    '''
    pass


class PgHba(object):
    """
    PgHba object to read/write entries to/from.
    pg_hba_file - the pg_hba file almost always /etc/pg_hba
    """
    def __init__(self, pg_hba_file=None, order="sdu", backup=False, create=False):
        if order not in PG_HBA_ORDERS:
            msg = "invalid order setting {0} (should be one of '{1}')."
            raise PgHbaError(msg.format(order, "', '".join(PG_HBA_ORDERS)))
        self.pg_hba_file = pg_hba_file
        self.rules = None
        self.comment = None
        self.order = order
        self.backup = backup
        self.last_backup = None
        self.create = create
        self.unchanged()
        # self.databases will be update by add_rule and gives some idea of the number of databases
        # (at least that are handled by this pg_hba)
        self.databases = set(['postgres', 'template0', 'template1'])

        # self.databases will be update by add_rule and gives some idea of the number of users
        # (at least that are handled by this pg_hba) since this migth also be groups with multiple
        # users, this migth be totally off, but at least it is some info...
        self.users = set(['postgres'])

        self.read()

    def unchanged(self):
        '''
        This method resets self.diff to a empty default
        '''
        self.diff = {'before': {'file': self.pg_hba_file, 'pg_hba': []},
                     'after': {'file': self.pg_hba_file, 'pg_hba': []}}

    def read(self):
        '''
        Read in the pg_hba from the system
        '''
        self.rules = {}
        self.comment = []
        # read the pg_hbafile
        try:
            file = open(self.pg_hba_file, 'r')
            for line in file:
                line = line.strip()
                # uncomment
                if '#' in line:
                    line, comment = line.split('#', 1)
                    self.comment.append('#' + comment)
                rule = self.line_to_rule(line)
                if rule:
                    self.add_rule(rule)
            file.close()
            self.unchanged()
        except IOError:
            if not self.create:
                raise PgHbaError("pg_hba file '{0}' doesn't exist. "
                                 "Use create option to autocreate.".format(self.pg_hba_file))

    def line_to_rule(self, line):
        '''
        split into sid, home, enabled
        '''
        if WHITESPACES_RE.sub('', line) == '':
            # empty line. skip this one...
            return None
        cols = WHITESPACES_RE.split(line)
        if len(cols) < 4:
            msg = "File {0} has a rule with too few columns: {1}."
            raise PgHbaError(msg.format(self.pg_hba_file, line))
        if cols[0] not in PG_HBA_TYPES:
            msg = "File {0} contains an rule of unknown type: {1}."
            raise PgHbaError(msg.format(self.pg_hba_file, line))
        if cols[0] == 'local':
            if cols[3] not in PG_HBA_METHODS:
                raise PgHbaError("File {0} contains an rule of 'local' type where 4th column '{1}' "
                                 "isn't a valid auth-method.".format(self.pg_hba_file, cols[3]))
            cols.insert(3, None)
            cols.insert(3, None)
        else:
            if len(cols) < 6:
                cols.insert(4, None)
            elif cols[5] not in PG_HBA_METHODS:
                cols.insert(4, None)
            if len(cols) < 7:
                cols.insert(7, None)
            if cols[5] not in PG_HBA_METHODS:
                raise PgHbaError("File {0} contains an rule '{1}' "
                                 "that has no valid method.".format(self.pg_hba_file, line))
        rule = dict(zip(PG_HBA_HDR, cols[:7]))
        clean_empty_rule_keys(rule)
        rule['line'] = line
        return rule

    def rule2weight(self, rule):
        '''
        For networks, every 1 in 'netmask in binary' makes the subnet more specific.
        Therefore I chose to use prefix as the weight.
        So a single IP (/32) should have twice the weight of a /16 network.
        To keep everything in the same weight scale,
        - for ipv6, we use a weight scale of 0 (all possible ipv6 addresses) to 128 (single ip)
        - for ipv4, we use a weight scale of 0 (all possible ipv6 addresses) to 128 (single ip)
        Therefore for ipv6, we use prefixlen (0-32) * 4 (0-128) for weight
        '''
        if rule['type'] == 'local':
            # local is always 'this server' and therefore considered /32
            srcweight = 128  # (local is considered one ip address which has a weight of 128)
        else:
            sourceobj = rule2source_ipnw(rule)
            if isinstance(sourceobj, ipaddress.IPv4Network):
                srcweight = sourceobj.prefixlen * 4
            elif isinstance(sourceobj, ipaddress.IPv6Network):
                srcweight = sourceobj.prefixlen
            elif isinstance(sourceobj, str):
                # You can also write all to match any IP address,
                # samehost to match any of the server's own IP addresses,
                # or samenet to match any address in any subnet that the server is connected to.
                if sourceobj == 'all':
                    # (all is considered the full range of all ips, which has a weight of 0)
                    srcweight = 0
                elif sourceobj == 'samehost':
                    # (samehost is considered one ip address which has a weight of 128)
                    srcweight = 128
                elif sourceobj == 'samenet':
                    # Might write some fancy code to determine all prefix's
                    # from all interfaces and find a sane value for this one.
                    # For now, let's assume /24...
                    srcweight = 96
                elif sourceobj[0] == '.':
                    # suffix matching (domain name), let's asume a very large scale
                    # and therefore a very low weight.
                    # (ipv4 /16 is considered equivalent to ipv6 /64)
                    srcweight = 64
                else:
                    # hostname, let's asume only one host matches
                    # (ipv4 /32 is considered equivalent to ipv6 /128)
                    srcweight = 128

        # One little thing: for db and user weight, higher weight means less specific and thus
        # lower in the file. Since prefix is higher for more specific, I inverse the output to
        # align with how dbweight and userweight works...
        srcweight = 128 - srcweight  # (higher prefix should be lower weight)

        if rule['db'] == 'all':
            dbweight = len(self.databases) + 1
        elif rule['db'] == 'replication':
            dbweight = 0
        elif rule['db'] in ['samerole', 'samegroup']:
            dbweight = 1
        else:
            dbweight = 1 + rule['db'].count(',')

        if rule['usr'] == 'all':
            uweight = len(self.users) + 1
        else:
            uweight = 1

        ret = []
        for character in self.order:
            if character == 'u':
                ret.append(uweight)
            elif character == 's':
                ret.append(srcweight)
            elif character == 'd':
                ret.append(dbweight)

        return tuple(ret)

    def is_empty(self):
        '''
        This methid can be used to check if a PgHba object is empty (no rules).
        '''
        return bool(len(self.rules) == 0)

    def write(self):
        '''
        This method writes the PgHba rules (back) to a file.
        '''
        if not self.changed():
            return

        if self.pg_hba_file:
            if self.backup and os.path.isfile(self.pg_hba_file):
                __backup_file_h, self.last_backup = tempfile.mkstemp(prefix='pg_hba')
                shutil.copy(self.pg_hba_file, self.last_backup)
            fileh = open(self.pg_hba_file, 'w')
        else:
            filed, __path = tempfile.mkstemp(prefix='pg_hba')
            fileh = os.fdopen(filed, 'w')

        fileh.write(self.render())
        self.unchanged()
        fileh.close()

    def add_rule(self, rule):
        '''
        This method can be used to add a rule to the list of rules in this PgHba object
        '''
        key = rule2key(rule)
        try:
            oldrule = self.rules[key]
            ekeys = set(list(oldrule.keys()) + list(rule.keys()))
            ekeys.remove('line')
            for k in ekeys:
                if oldrule[k] != rule[k]:
                    raise Exception('')
        except Exception:
            self.rules[key] = rule
            self.diff['after']['pg_hba'].append(rule['line'])
            if rule['db'] not in ['all', 'samerole', 'samegroup', 'replication']:
                databases = set(rule['db'].split(','))
                self.databases.update(databases)
            if rule['usr'] != 'all':
                user = rule['usr']
                if user[0] == '+':
                    user = user[1:]
                self.users.add(user)

    def remove_rule(self, rule):
        '''
        This method can be used to find and remove a rule. It doesn't look for the exact rule, only
        the rule with the same key.
        '''
        keys = rule2key(rule)
        try:
            del self.rules[keys]
            self.diff['before']['pg_hba'].append(rule['line'])
        except KeyError:
            pass

    def get_rules(self, with_lines=False):
        '''
        This method returns all the rules of the PgHba object
        '''
        for rule in sorted(self.rules.values(), key=self.rule2weight):
            rule = copy.copy(rule)
            if not with_lines and 'line' in rule:
                del rule['line']
            yield rule

    def render(self):
        '''
        This method renders the content of the PgHba rules and commentsselfself.
        The returning value can be used directly to write to a new file.
        '''
        comment = '\n'.join(self.comment)
        rule_lines = '\n'.join([r['line'] for r in self.get_rules(with_lines=True)])
        result = comment + '\n' + rule_lines
        # End it properly with a linefeed (if not already).
        if result and result[-1] not in ['\n', '\r']:
            result += '\n'
        return result

    def changed(self):
        '''
        This method can be called to detect if the PgHba file has been changed.
        '''
        return bool(self.diff['before']['pg_hba'] or self.diff['after']['pg_hba'])


def clean_empty_rule_keys(rule):
    '''
    This method is used to clean keys without values in a rule dictionary.
    '''
    keys = [key for key in rule.keys()]
    for k in keys:
        if not rule[k]:
            del rule[k]


def rule2source_ipnw(rule):
    '''
    This method is used to get the source of a rul as an ipaddress object if possible.
    '''
    if '/' not in rule['src'] and 'mask' in rule.keys():
        if ':' in rule['mask']:
            # ipaddress module cannot work with ipv6 netmask, so lets convert it to prefixlen
            binvalue = "{0:b}".format(int(ipaddress.IPv6Address(u'{0}'.format(rule['mask']))))
            if '01' in binvalue:
                msg = 'IPv6 mask {} contains 1 after 0 and cannot be converted to prefixlen'
                raise ValueError(msg.format(rule['mask']))
            prefixlen = binvalue.count('1')
            sourcenw = '{0}/{1}'.format(rule['src'], prefixlen)
        else:
            sourcenw = '{0}/{1}'.format(rule['src'], rule['mask'])
    else:
        sourcenw = rule['src']

    try:
        return ipaddress.ip_network(u'{0}'.format(sourcenw), strict=False)
    except ValueError:
        return rule['src']


def rule2key(rule):
    '''
    This method can be used to get the ey from a rule.
    '''
    if rule['type'] == 'local':
        source = 'local'
    else:
        source = str(rule2source_ipnw(rule))
    return (source, rule['db'], rule['usr'])


def new_rules(contype, databases, users, source, netmask, method, options):
    '''
    This function can be called with a comma seperated list of databases and a comma seperated list
    of users and it will act as a generator that returns a expanded list of rules one by one.
    '''
    if method not in PG_HBA_METHODS:
        msg = "invalid method {0} (should be one of '{1}')."
        raise PgHbaError(msg.format(method, "', '".join(PG_HBA_METHODS)))
    if contype not in PG_HBA_TYPES:
        msg = "invalid connection type {0} (should be one of '{1}')."
        raise PgHbaError(msg.format(contype, "', '".join(PG_HBA_TYPES)))
    # Add the job
    rule = dict(zip(PG_HBA_HDR, [contype, databases, users, source, netmask, method, options]))

    for database in databases.split(','):
        for usr in users.split(','):

            rule = dict(zip(PG_HBA_HDR, [contype, database, usr, source, netmask, method, options]))

            if contype == 'local':
                del rule['src']
                del rule['mask']
            elif '/' in source:
                del rule['mask']
            else:
                rule['src'] = str(rule2source_ipnw(rule))
                del rule['mask']

            clean_empty_rule_keys(rule)

            line = [rule[k] for k in PG_HBA_HDR if k in rule.keys()]
            rule['line'] = "\t".join(line)
            yield rule


def main():
    '''
    This function is the main function of this module
    '''
    module = AnsibleModule(
        argument_spec=dict(
            contype=dict(type='str', default=None, choices=PG_HBA_TYPES + ['']),
            create=dict(type='bool', default=False),
            databases=dict(type='str', default='all'),
            dest=dict(type='path', required=True),
            method=dict(type='str', default='md5', choices=PG_HBA_METHODS),
            netmask=dict(type='str', default=''),
            options=dict(type='str', default=''),
            order=dict(type='str', default="sdu", choices=PG_HBA_ORDERS),
            state=dict(type='str', default="present", choices=["absent", "present"]),
            src=dict(type='str', default='samehost', aliases=['source']),
            users=dict(type='str', default='all')
        ),
        add_file_common_args=True,
        supports_check_mode=True
    )
    if not HAS_IPADDRESS:
        module.fail_json(msg='Missing required libraries.')

    contype = module.params["contype"]
    create = module.params["create"]
    if module.check_mode:
        backup = False
    else:
        backup = module.params['backup']
    databases = module.params["databases"]
    dest = module.params["dest"]

    method = module.params["method"]
    netmask = module.params["netmask"]
    options = module.params["options"]
    order = module.params["order"]
    source = module.params["src"]
    state = module.params["state"]
    users = module.params["users"]

    ret = {'msgs': []}

    pg_hba = PgHba(dest, order, backup=backup, create=create)

    if contype:
        for rule in new_rules(contype, databases, users, source, netmask, method, options):
            if state == "present":
                ret['msgs'].append('Adding')
                pg_hba.add_rule(rule)
            else:
                ret['msgs'].append('Removing')
                pg_hba.remove_rule(rule)

        file_args = module.load_file_common_arguments(module.params)
        ret['changed'] = changed = pg_hba.changed()
        if changed:
            ret['msgs'].append('Changed')
            ret['diff'] = pg_hba.diff

        if not module.check_mode:
            ret['msgs'].append('Writing')
            pg_hba.write()
            module.set_fs_attributes_if_different(file_args, True, pg_hba.diff, expand=False)
            if pg_hba.last_backup:
                ret['backup_file'] = pg_hba.last_backup

    ret['pg_hba'] = [rule for rule in pg_hba.get_rules()]
    module.exit_json(**ret)


if __name__ == '__main__':
    main()
