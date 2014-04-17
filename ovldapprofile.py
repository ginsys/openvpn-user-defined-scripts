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

import ovpnscript
import sys
import os
import ldap
import md5
import shelve


# --------------------------------------------------------------------------- #
# OpenVPN User Defined Script base class
# --------------------------------------------------------------------------- #

class ClientConnectScript(ovpnscript.OpenVPNScript):

    def check_config(self):
        ldapconfigkeys = [
                'ldap_host', 'ldap_port',
                'ldap_userDN', 'ldap_userpass',
                'ldap_user_baseDN',
                'ldap_user_searchfilter',
                'ldap_group_baseDN']
        if any([not x in self.config for x in ldapconfigkeys]):
            self.exit1('missing ldap config key, need %s' % ldapconfigkeys)

    def exit_error(self, msg=None):
        self.write_cc(disable=True)

    def check_group_member(self, con, userDN, cn, username):

        group = None
        if username == cn:
            # loop all groups and validate first matching
            sortedgroups = self.config['groups'].keys()
            sortedgroups.sort()
            for g in sortedgroups:
                groupDN = self.config['groups'][g]
                if self.ldap_memberof(con, userDN, groupDN):
                    group = g
                    break
        else:
            if self.ldap_memberof(con, userDN, self.config['groups'][username]):
                group = username
        return group

    def validate_user(self, common_name, username):

        con = self.ldap_bind(userDN=self.config['ldap_userDN'],
                        userpass=self.config['ldap_userpass'])

        # so username equals common name or is a known profile group
        if username != common_name and username not in self.config['groups'].keys():
            self.exit1('unknown profile %s' % username)

        # lookup user with common name
        userDN, _ = self.ldap_search_user(con, uid=common_name)
        if userDN is None:
            self.exit1('ldap user with uid %s from certificate common name was not found' % common_name)

        # check group membership
        groupname = self.check_group_member(con, userDN, common_name, username)
        if groupname is None:
            self.exit1('no matching group membership for %s/%s %s' % (common_name, username, userDN))

        con.unbind()
        return groupname


    def get_ip(self, username, profile, session_id):

        if profile not in self.config['profiles'][self.instance]:
            # no subnet info
            return None, None

        # retrieve our subnet info
        base  = self.config['profiles'][self.instance][profile]['base']
        count = self.config['profiles'][self.instance][profile]['count']
        mask  = self.config['profiles'][self.instance][profile]['mask']


        ip = [ int(i) for i in base.split('.') ]
        if ip[3] + count > 255:
            self.exit1('sorry, no support yet for subnets crossing /24 boundaries')

        # list of ip's we can provide
        iprange = ['%s.%s.%s.%s' % (ip[0], ip[1], ip[2], ip[3] + x) for x in range(count)]

        # open the persistance database
        # we need to keep track of which ip's are in use, amd remember old ip's
        # to reassign the same to the same user, unless we run out of them
        db = shelve.open(self.db_path, writeback=True)
        if not 'ips' in db:
            db['ips'] = {}

        ip = None
        # let's first look for an exact record, assigned or not, but same
        # session
        for i in iprange:
            if i in db['ips'] and db['ips'][i]['session'] == session_id:
                ip = i
                break

        # now loop through ip list and take an unassigned one that
        # previously assigned to this user
        if ip == None:
            for i in iprange:
                if ( i in db['ips'] and not db['ips'][i]['assigned']  and
                        db['ips'][i]['username'] == username and
                        db['ips'][i]['profile'] == profile ):
                    ip = i
                    break

        # is we didn't find one, lets take the first free one
        if ip == None:
            for i in iprange:
                if i not in db['ips']:
                    ip = i
                    break

        # is we didn't find one, lets take the first unassigned one, even from
        # another user (but the same profile, which is actually a redundant
        # check)
        if ip == None:
            for i in iprange:
                if ( i in db['ips'] and not db['ips'][i]['assigned'] and
                                            db['ips'][i]['profile'] == profile ):
                    ip = i
                    break

        # if ip still is None, then we ran out of free ip's here
        if ip == None:
            self.exit1('could not find a free ip for %s/%s' % (username, profile))

        # we found an ip, now persist it to the database
        db['ips'][ip] = {   'assigned':     True,
                            'username':     username,
                            'profile':      profile,
                            'session':      session_id  }
        db.close()
        return ip, mask


    def free_ip(self, ip, session_id):

        # open the persistance database
        db = shelve.open(self.db_path, writeback=True)

        if ip in db['ips']:
            if db['ips'][ip]['assigned']:
                db['ips'][ip]['assigned'] = False
            else:
                self.log('unassign ip %s but alreay unassigned' % ip)

            if session_id != db['ips'][ip]['session']:
                self.log('unassign ip %s but session_id was unexpected' % ip)
            db.close()
        else:
            self.log('ip %s got unassigned, but not found in db' % ip)



    def write_cc(self, ip=None, mask=None, disable=False):

        if disable:
            content = "disable"
        elif ip is not None and mask is not None:
            content = ('ifconfig-push %s %s\npush "route-gateway %s"\n'  % (ip, mask, ip))
        else:
            return
        if self.cc_file is not None:
            with open(self.cc_file, 'w') as f:
                f.write(content)


    def cc(self, action, cc_file=None):

        # file the connect script needs to generate
        self.cc_file = cc_file

        # we use the username from the common name
        # to enforce lnk between certificate and ldap user
        common_name = self.env('common_name')

        # user can give his group/profile name as 'username'
        # in case of member of multiple groups
        # otherwise username should be same as username
        # and first found group it is member of is used
        username =  self.env('username')

        # some env vars we use to identify the client and keep track
        client_ip = self.env('trusted_ip')
        client_port = self.env('trusted_port')

        self.log('%s request from %s/%s  %s:%s' % (action, common_name, username, client_ip, client_port))

        # make some kind of session id, to keep track to who we assign an ip
        # address
        session_string = common_name + username + client_ip + client_port
        m = md5.new()
        m.update(session_string)
        session_id = m.hexdigest()

        if action == 'connect':
            profile = self.validate_user(common_name, username)
            ip, mask = self.get_ip(username, profile, session_id)
            self.write_cc(ip, mask, disable=False)
            self.exit0('assigned ip %s to %s/%s' % (ip, common_name, username))

        elif action == 'disconnect':
            ip = self.env('ifconfig_pool_remote_ip')
            mask = self.env('ifconfig_pool_netmask')
            self.free_ip(ip, session_id)
            self.exit0('disconnected ip %s from %s/%s' % (ip, common_name, username))


    def script_client_connect(self, args):
        self.cc('connect', args[0])

    def script_client_disconnect(self, args):
        self.cc('disconnect')

# --------------------------------------------------------------------------- #

if __name__ == '__main__':
    script = ClientConnectScript(sys.argv)
    script.run()

