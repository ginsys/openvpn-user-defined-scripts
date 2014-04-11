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
import ConfigParser as configparser

# --------------------------------------------------------------------------- #
# configuration defaults
# --------------------------------------------------------------------------- #

DEFAULTS = {    'libdir':       '/var/lib/openvpn',
                'instance':     'server'
                }

# --------------------------------------------------------------------------- #
# utilities
# --------------------------------------------------------------------------- #

def env(var):
    return os.getenv(var, "")

def exit0(msg=''):
    if msg != '':
        sys.stdout.write(msg + '\n')
    sys.exit(0)

def exit1(msg=''):
    if msg != '':
        sys.stderr.write(msg + '\n')
    sys.exit(0)

# --------------------------------------------------------------------------- #
# OpenVPN User Defined Script base class
# --------------------------------------------------------------------------- #

class OpenVPNScript(object):


    def __init__(self, args):

        self.script_type = env('script_type')
        self.args = args

        self.script_path = args[0]
        # config is at same location as script
        self.config_path = self.script_path.replace('.py',
                                            '').replace('.pyc', '') + '.ini'
        # init config object
        self.config = configparser.ConfigParser(DEFAULTS)

        # read config file
        try:
            self.config_path = self.config.read(self.config_path)
        except Exception as e:
            exit1(str(e))

        # use instance name from first arg if available
        if len(args) >= 2:
            self.config('openvpn', 'instance', args[1])

        # remainder args are script specific from openvpn
        self.script_args = args[2:]


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
        exit1('script type %s is not supported' % self.script_type)

# --------------------------------------------------------------------------- #

    def run(self):
        script_method_name = 'script_' + self.script_type.replace('-', '_')
        script_method = getattr(self, script_method_name, None)
        if script_method is None:
            exit1('script type %s unknown' % self.script_type)
        else:
            script_method(self.script_args)
        # fallback, exit with error
        exit1()

# --------------------------------------------------------------------------- #

if __name__ == '__main__':
    script = OpenVPNScript(sys.argv)
    script.run()

