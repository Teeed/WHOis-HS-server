# -*- coding: utf-8 -*-

# Appplication that monitors users being currently in hackerspace.
# - HS part (is only responsible for getting data from DHCP)
#
# Copyright (C) 2013 Tadeusz Magura-Witkowski
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from Crypto.Cipher import AES
from Crypto import Random
from routeros import *
import web
import json
import datetime
import socket
import time
import ConfigParser
import base64

config = ConfigParser.ConfigParser()
config.read(('config.cfg', 'localconfig.cfg'))

web.config.debug = config.getboolean('application', 'debug')

urls = (
	r'^/r/(\d+)/(.{10})$', 'register_device',
	'/', 'index',
)

app = web.application(urls, globals())

def get_current_dhcp_leases():
	# mikrotik's version
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((config.get('routeros', 'host'), config.getint('routeros', 'port')))
		apiros = ApiRos(s)
		apiros.login(config.get('routeros', 'login'), config.get('routeros', 'password'))

		dhcp_leases = apiros.talk(['/ip/dhcp-server/lease/print'])

		s.close()
	except:
		dhcp_leases = []

	matches = set([])

	for lease in dhcp_leases:
		if lease[0] != '!re':
			continue

		lease_data = lease[1]

		# print lease_data['=mac-address'], lease_data['=active-address']
		matches.add( (lease_data['=mac-address'], lease_data['=address'].lower()) )

	return list(matches)

def encrypt_data_for_whois(data):
	data = json.dumps(data)

	iv = Random.new().read(AES.block_size)
	cipher = AES.new(config.get('whois_master', 'key'), AES.MODE_CFB, iv)

	return iv + cipher.encrypt(data)

def return_data_for_whois(data):
		web.header('Content-Type', 'application/octet-stream')
		web.header('Access-Control-Allow-Origin', '*')
		web.header('Cache-Control', 'no-cache')

		return base64.b64encode(encrypt_data_for_whois(data))
	
class index:
	def GET(self):
		users = get_current_dhcp_leases()

		return return_data_for_whois(users)

class register_device:
	def GET(self, uid, access_key):
		uid = int(uid)

		user_ip = web.ctx.ip
		user_mac = None
		dhcp_leases = get_current_dhcp_leases()

		for lease in dhcp_leases:
			if lease[0] == user_ip:
				user_mac = lease[1]

				break

		if not user_mac:
			raise web.badrequest(u'Wlacz pobieranie adresu przez DHCP')

		data = encrypt_data_for_whois( (int(uid), access_key, user_mac) )

		raise web.seeother('%s/register_device/%s' % (config.get('whois_master', 'url'), base64.urlsafe_b64encode(data)))

if __name__ == '__main__':
	app.run()
