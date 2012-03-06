#!/usr/bin/env python3
# coding: utf-8

# Invalidates one or more files cached by an (AWS) Cloudfront
# distribution.

# Copyright © 2012 euphoria GmbH
# Author: Lukas Martini <lutoma@phoria.eu>

# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.

# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.

# You should have received a copy of the GNU Lesser General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import time
import hashlib
import hmac
import base64
import urllib
import http.client
from xml.dom import minidom

_API_URL = '/2010-11-01/distribution/{0}/invalidation'
_API_SERVER = 'cloudfront.amazonaws.com'

class CloudfrontRemoteError(Exception):
	pass

class Connection:
	getDistribution = lambda self, did: Distribution(self, did)

	def __init__(self, keyid, key, apiServer = _API_SERVER, apiURL = _API_URL):
		self.keyid = keyid
		self.key = key
		self.apiServer = apiServer
		self.apiURL = apiURL

		self.httpConnection = http.client.HTTPSConnection(apiServer)

	def close(self):
		self.httpConnection.close()


class Distribution:
	_XML = """
	<InvalidationBatch>
	    <Path>{2}</Path>
	    <CallerReference>{0}{1}</CallerReference>
	</InvalidationBatch>
	"""
	buildXML = lambda self, files: self._XML.format(self.id, int(time.time()), '</Path><Path>'.join(files))

	def __init__(self, connection, did):
		self.connection = connection
		self.id = did
	
	def calculateKey(self):
		now = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())
		signature = base64.b64encode(hmac.new(self.connection.key.encode('ascii'), now.encode('ascii'), hashlib.sha1).digest())
		return now, signature.decode()

	def invalidate(self, files):
		timeString, signature = self.calculateKey()
		query = self.buildXML(files)

		headers = {
			'Date': timeString,
			'Content-Type': 'text/xml; charset=UTF-8',
			'Authorization': 'AWS {0}:{1}'.format(self.connection.keyid, str(signature)),
			'Content-Length': len(query)
		}

		self.connection.httpConnection.request(
			'POST',
			self.connection.apiURL.format(self.id),
			query,
			headers
		)

		response = self.connection.httpConnection.getresponse()
		data = response.read()

		if not data:
			raise CloudfrontRemoteError

		if response.status != 201:
			print(data)
			xmldoc = minidom.parseString(data)
			code = xmldoc.getElementsByTagName('Code')[0].childNodes[0].data
			description = xmldoc.getElementsByTagName('Message')[0].childNodes[0].data

			raise CloudfrontRemoteError('{0}: {1}'.format(code, description))

# Possibility to run the lib as standalone executable
if __name__ == '__main__':
	if len(sys.argv) < 4:
		print('Usage: {0} [keyid] [key] [distribution id] [file(s)]'.format(sys.argv[0]))
		exit(1)
	
	c = Connection(sys.argv[1], sys.argv[2])
	d = c.getDistribution(sys.argv[3])
	d.invalidate(sys.argv[4:])
	c.close()