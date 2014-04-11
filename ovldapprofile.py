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
from ovpnscr import OpenVPNScript


# --------------------------------------------------------------------------- #
# OpenVPN User Defined Script base class
# --------------------------------------------------------------------------- #

class ClientConnectScript(OpenVPNScript):

    def script_client_connect(self, args):
        print 'connect'

    def script_client_disconnect(self, args):
        print 'disconnect'

# --------------------------------------------------------------------------- #

if __name__ == '__main__':
    script = ClientConnectScript(sys.argv)
    script.run()

