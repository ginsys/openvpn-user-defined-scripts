#!/usr/bin/env python

# (c) 2014, Serge van Ginderachter <serge@vanginderachter.be>

# This is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with the source. If not, see <http://www.gnu.org/licenses/>.


import os
import sys
import yaml
import ldap
import syslog

# --------------------------------------------------------------------------- #
# configuration defaults
# --------------------------------------------------------------------------- #

DEFAULTS = {'libdir': '/var/lib/openvpn',
            }

# --------------------------------------------------------------------------- #
# OpenVPN User Defined Script base class
# --------------------------------------------------------------------------- #


class OpenVPNScript(object):

    # utilities

    def env(self, var):
        return os.getenv(var, "")

    def log(self, msg=''):
        if msg != '':
            sys.stdout.write(self.script_path + ': ' + str(msg) + '\n')
            syslog.openlog(ident='openvpn ' + self.name + ' ' + self.instance,
                           logoption=0, facility=syslog.LOG_DAEMON)
            syslog.syslog(syslog.LOG_INFO, msg)
            syslog.closelog()

    def exit0(self, msg=''):
        if msg != '':
            sys.stdout.write(self.script_path + ': ' + str(msg) + '\n')
            syslog.openlog(ident='openvpn ' + self.name + ' ' + self.instance,
                           logoption=0, facility=syslog.LOG_DAEMON)
            syslog.syslog(syslog.LOG_INFO, msg)
            syslog.closelog()
        sys.exit(0)

    def exit1(self, msg=''):
        if msg != '':
            sys.stderr.write(self.script_path + ': ' + str(msg) + '\n')
            syslog.openlog(ident='openvpn ' + self.name + ' ' + self.instance,
                           logoption=0, facility=syslog.LOG_DAEMON)
            syslog.syslog(syslog.LOG_ERR, msg)
            syslog.closelog()
        self.exit_error(msg)
        sys.exit(1)

# --------------------------------------------------------------------------- #
# Utilities
# --------------------------------------------------------------------------- #

    def ldap_bind(self, userDN, userpass):

        con = ldap.initialize(uri='ldap://' +
                              self.config['ldap_host'] + ':' +
                              str(self.config['ldap_port']))
        con.simple_bind_s(userDN, userpass)
        return con

    def ldap_search_user(self, con, uid):

        attrs = []
        base_dn = self.config['ldap_user_baseDN']
        ldap_filter = '(%s)' % self.config['ldap_user_searchfilter'].replace(
            '%u', uid)

        results = con.search_s(base_dn, ldap.SCOPE_SUBTREE, ldap_filter, attrs)
        # results is a list of a set of userdn + dict of attributes
        if len(results) >= 1:
            return results[0]
        else:
            return (None, None)

    def ldap_memberof(self, con, userDN, groupDN):

        member_attr = self.config['groupmember_attr']

        base_dn = self.config['ldap_group_baseDN']
        ldap_filter = '(%s)' % groupDN.split(',')[0]
        attrs = [member_attr]

        results = con.search_s(base_dn, ldap.SCOPE_SUBTREE, ldap_filter, attrs)
        # results is a list of a set of groupdn + dict of attributes

        if len(results) >= 1:
            found_groupDN, attributes = results[0]
            if found_groupDN == groupDN and member_attr in attributes:
                members = attributes[member_attr]
                if userDN in members:
                    return True
        return False


# --------------------------------------------------------------------------- #
# Constructor
# --------------------------------------------------------------------------- #

    def __init__(self, args):

        self.script_type = self.env('script_type')
        self.args = args

        self.script_path = args[0]
        self.name = os.path.basename(
            self.script_path).replace(
            '.py',
            '').replace(
            '.pyc',
            '')

        # we need at least one argument, confirming the openvpn instance
        if len(args) >= 2:
            self.instance = args[1]
        else:
            self.instance = None

        # remainder args are script specific from openvpn
        self.script_args = args[2:]

        # config is at same location as script
        self.config_path = self.script_path.replace(
            '.py', '').replace('.pyc', '') + '.yml'
        if not os.path.isfile(self.config_path):
            self.exit1('configfile %s not found' % self.config_path)
        self.load_config()

        if self.instance not in self.instances:
            self.exit1(
                'instance %s not found in config file %s' %
                (self.instance, self.config_path))

        self.db_file = self.name + '_' + self.instance + '.db'
        self.db_path = os.path.join(self.config['libdir'], self.db_file)
        self.log('persistance db file: ' + self.db_path)

# --------------------------------------------------------------------------- #

    def check_config(self):
        # check specifics in child classes
        pass

    def exit_error(self, msg=None):
        # implement specific action on error if exit 1 is nog enough
        pass

    def load_config(self):
        # read config file
        try:
            with open(self.config_path) as f:
                self.config = yaml.safe_load(f.read())
        except Exception as e:
            self.exit1(str(e))

        if 'libdir' not in self.config:
            self.config['libdir'] = DEFAULTS['libdir']
        if ('groups' not in self.config or
                not isinstance(self.config['groups'], dict)):
            self.exit1('missing groups config or groups is not a dictionary')
        if ('profiles' not in self.config or not isinstance(self.config['profiles'], dict) or any(
                [not isinstance(self.config['profiles'][x], dict) for x in self.config['profiles'].keys()])):
            self.exit1(
                'missing profiles config or profiles is not a list name: ldapgroupDN')
        self.instances = self.config['profiles'].keys()
        self.check_config()

# --------------------------------------------------------------------------- #

    def script_up(self, args):
        self.script_not_supported()

    def script_down(self, args):
        self.script_not_supported()

    def script_ipchange(self, args):
        self.script_not_supported()

    def script_route_up(self, args):
        self.script_not_supported()

    def script_tls_verify(self, args):
        self.script_not_supported()

    def script_auth_user_pass_verify(self, args):
        self.script_not_supported()

    def script_client_connect(self, args):
        self.script_not_supported()

    def script_client_disconnect(self, args):
        self.script_not_supported()

    def script_learn_address(self, args):
        self.script_not_supported()

    def script_not_supported(self):
        self.exit1('script type %s is not supported' % self.script_type)

# --------------------------------------------------------------------------- #

    def run(self):
        script_method_name = 'script_' + self.script_type.replace('-', '_')
        script_method = getattr(self, script_method_name, None)
        if script_method is None:
            self.exit1('script type %s unknown' % self.script_type)
        else:
            script_method(self.script_args)
        # fallback, exit with error
        self.exit1()

# --------------------------------------------------------------------------- #


if __name__ == '__main__':
    script = OpenVPNScript(sys.argv)
    script.run()
