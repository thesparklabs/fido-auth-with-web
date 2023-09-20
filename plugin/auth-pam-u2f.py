#!/usr/bin/python3
# Copyright (C) 2023 SparkLabs Pty Ltd
#
# This file is part of OpenVPN U2F Server Support.
#
# OpenVPN U2F Server Support is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# OpenVPN U2F Server Support is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OpenVPN U2F Server Support.  If not, see <http://www.gnu.org/licenses/>.

import sys, os, base64, pickle
import json, zlib, requests, json

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def base64encode(string: str):
	return base64.b64encode(string.encode('utf-8')).decode('utf-8')

def base64decode(string: str):
	return base64.b64decode(string.encode('utf-8')).decode('utf-8')

class OpenVPNU2FAuthPlugin:
	def __init__(self):
		pass

	def save_cookies(self, session, filename):
		with open(filename, 'wb') as file:
			pickle.dump(session.cookies, file)
			
	def load_cookies(self, session, filename):
		with open(filename, 'rb') as file:
			session.cookies.update(pickle.load(file))

	def Run(self):
		username = os.environ.get('username')
		password = os.environ.get('password')

		if username == None:
			print("No username issued")
			exit(1)

		if password == None:
			# Always assume auth
			reply = self.buildU2FAuth(username)
			if reply == None:
				exit(1)
			print(reply)
			exit(2)

		elif password.startswith('CRV1:'):
			# Finish
			passwordSplit = password.split('::')
			ident = passwordSplit[1]
			token = base64.b64decode(passwordSplit[2].encode('utf-8'))
			# Check if our token data is compressed
			if token.startswith(b'\x1f\x8b'):
				# Data is compressed, inflate
				try:
					token = zlib.decompress(token, 47)
				except:
					pass #Try without decompressing					   

			# Assume auth request
			response = json.loads(str(token.decode('utf-8')))
			success = self.finishU2FAuth(username, json.dumps(response))
			if success:
				#Let the user connect
				exit(0)

		exit(1)

	def buildU2FAuth(self, user):
		url = "https://127.0.0.1/api/authenticate/begin"
		headers = {"Content-Type": "application/json"}
		payload = {}
		with requests.Session() as session:
			response = session.post(url, json=payload, headers=headers, verify=False)
			self.save_cookies(session, "/etc/openvpn/cookies.pkl")
		if response.status_code == 200:
			authstr = response.text.strip()
			b64auth = base64encode(authstr)
			b64user = base64encode(user)
			reply = "CRV1:U2F:auth:%s:%s" % (b64user, b64auth)
			return reply
		return None

	def finishU2FAuth(self, user, reply):
		url = "https://127.0.0.1/api/authenticate/complete"
		replyB64 = base64encode(reply)
		payload = {"authdata" : replyB64}
		with requests.Session() as session:
			self.load_cookies(session, "/etc/openvpn/cookies.pkl")
			response = session.post(url, data=payload, verify=False)
		if response.status_code == 200:
			jsonData = response.json()
			if jsonData.get("status") == "OK":
				return True
		return False

if __name__ == "__main__":
	authClient = OpenVPNU2FAuthPlugin()
	authClient.Run()
