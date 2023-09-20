# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#	Redistribution and use in source and binary forms, with or
#	without modification, are permitted provided that the following
#	conditions are met:
#
#	 1. Redistributions of source code must retain the above copyright
#		notice, this list of conditions and the following disclaimer.
#	 2. Redistributions in binary form must reproduce the above
#		copyright notice, this list of conditions and the following
#		disclaimer in the documentation and/or other materials provided
#		with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Example demo server to use a supported web browser to call the WebAuthn APIs
to register and use a credential.
"""
from fido2.webauthn import (
	PublicKeyCredentialRpEntity,
	PublicKeyCredentialUserEntity,
	CollectedClientData,
	UserVerificationRequirement,
	AuthenticationResponse
)
from fido2.server import Fido2Server
from flask import Flask, session, request, redirect, abort, jsonify
import fido2.features
import os, base64, json, hashlib
from fido2.utils import websafe_encode, websafe_decode
from cryptography.hazmat.primitives import constant_time
from cryptography.exceptions import InvalidSignature as _InvalidSignature
from urllib.parse import urlparse

# WARNING: Do not use this server in production environments. This code is only designed to
# act as a proof-of-concept for developers seeking an example of how to integrate a FIDO
# authenticator registered in a web browser using the WebAuthn APIs with Viscosity's
# FIDO/U2F authentication support. This code does not fully error check or validate
# data, does not validate usernames, and does not isolate sessions.

# To share a registration with a web browser the following advanced command will need to be
# added to your Viscosity connection: #viscosity U2FURIScheme none
# https://www.sparklabs.com/support/kb/article/advanced-configuration-commands/

# Set the following to the domain of the server
serverDomain = "myserver.example.com"

class Fido2ServerWithU2FAuth(Fido2Server):
	def webauthn_to_u2f(self, webauthn_data):
		u2f_auth_request = {}

		# Add U2F version field
		u2f_auth_request['version'] = "U2F_V2"

		# Get the Relying Party ID (rpId)
		rp_id = webauthn_data.get('publicKey', {}).get('rpId')
		if rp_id:
			u2f_auth_request['appId'] = rp_id

		# Get the challenge
		challenge = webauthn_data.get('publicKey', {}).get('challenge')
		if challenge:
			u2f_auth_request['challenge'] = base64.urlsafe_b64encode(websafe_decode(challenge)).decode('utf-8')

		# Get the list of allowed credentials
		allow_credentials = webauthn_data.get('publicKey', {}).get('allowCredentials')
		if allow_credentials:
			key_handles = [base64.urlsafe_b64encode(websafe_decode(cred['id'])).decode('utf-8') for cred in allow_credentials]

			if len(key_handles) == 1:
				u2f_auth_request['keyHandle'] = key_handles[0]
			else:
				u2f_auth_request['keyHandles'] = key_handles

		return u2f_auth_request
	
	def u2f_to_webauthn(self, u2f_response):
		webauthn_response = {}
		response = {}
	
		webauthn_response['type'] = 'public-key'
		webauthn_response['authenticatorAttachment'] = 'cross-platform'
	
		# Get the key handle (used to identify the credential)
		key_handle = u2f_response.get('keyHandle')
		if key_handle:
			webauthn_response['id'] = base64.urlsafe_b64encode(websafe_decode(key_handle)).decode('utf-8')
	
		# Get the client data (used for challenge verification, etc.)
		client_data = u2f_response.get('clientData')
		if client_data:
			# Keep the original data for signature validation
			webauthn_response['u2f_clientData'] = client_data
			client_data_dict = json.loads(websafe_decode(client_data))
			if client_data_dict["typ"] == "navigator.id.getAssertion":
				webauthn_client_data = {'type': CollectedClientData.TYPE.GET,
					'challenge' : client_data_dict['challenge'],
					'origin' : client_data_dict['origin']}
			response['clientDataJSON'] = base64.urlsafe_b64encode(json.dumps(webauthn_client_data).encode('utf-8')).decode('utf-8')
	
		# Decode signatureData and split it into authenticatorData and signature
		signature_data = u2f_response.get('signatureData')
		if signature_data:
			raw_signature_data = websafe_decode(signature_data)
			u2f_auth_data = raw_signature_data[:5]	# 1 byte for user presence and 4 bytes for counter
			signature = raw_signature_data[5:]

			# Construct new authenticatorData for WebAuthn
			rp_id_hash = hashlib.sha256(self.rp.id.encode()).digest()
			flags = u2f_auth_data[0:1]	# Assuming flags are the same, usually 0x01 for user present
			counter = u2f_auth_data[1:5]
			authenticator_data = rp_id_hash + flags + counter

			response['authenticatorData'] = base64.urlsafe_b64encode(authenticator_data).decode('utf-8')
			response['signature'] = base64.urlsafe_b64encode(signature).decode('utf-8')
			response['userHandle'] = ''

		webauthn_response['response'] = response
		
		return webauthn_response
	
	def authenticate_begin(self, credentials=None, user_verification=None, challenge=None):
		options, state = super().authenticate_begin(credentials, user_verification, challenge)
		return self.webauthn_to_u2f(options), state
	
	def authenticate_complete_b64(self, state, credentials, base64Response):
		response = json.loads(base64.b64decode(base64Response))
		response = self.u2f_to_webauthn(response)
		self.authenticate_complete(state, credentials, response)
	
	def authenticate_complete(self, state, credentials, *args, **kwargs):
		response = None
		if len(args) == 1 and not kwargs:
			response = args[0]
		elif set(kwargs) == {"response"} and not args:
			response = kwargs["response"]
		if response:
			authentication = AuthenticationResponse.from_dict(response)
			credential_id = authentication.id
			client_data = authentication.response.client_data
			auth_data = authentication.response.authenticator_data
			signature = authentication.response.signature
		else:
			raise ValueError("Missing data.")

		if client_data.type != CollectedClientData.TYPE.GET:
			raise ValueError("Incorrect type in CollectedClientData.")
		if not self.verify_origin(client_data.origin, self.rp.id):
			raise ValueError("Invalid origin in CollectedClientData.")
		if websafe_decode(state["challenge"]) != client_data.challenge:
			raise ValueError("Wrong challenge in response.")
		if not constant_time.bytes_eq(self.rp.id_hash, auth_data.rp_id_hash):
			raise ValueError("Wrong RP ID hash in response.")
		if not auth_data.is_user_present():
			raise ValueError("User Present flag not set.")

		if (
			state["user_verification"] == UserVerificationRequirement.REQUIRED
			and not auth_data.is_user_verified()
		):
			raise ValueError(
				"User verification required, but user verified flag not set."
			)

		# Construct U2F signed data
		clientDataHash = hashlib.sha256(websafe_decode(response.get("u2f_clientData"))).digest()
		signedData = auth_data + clientDataHash

		for cred in credentials:
			if cred.credential_id == credential_id:
				try:
					#cred.public_key.verify(auth_data + client_data.hash, signature)
					cred.public_key.verify(signedData, signature)
				except _InvalidSignature:
					raise ValueError("Invalid signature.")
				return cred
		raise ValueError("Unknown credential ID.")
		
	def verify_origin(self, origin, rp_id):
		# Allow no prefix, a https:// prefix, or an openvpn:// prefix
		allowedSchemes = ["", "https", "openvpn"]
		
		if not rp_id or not origin:
			return False

		url = urlparse(origin)
		if not url.scheme in allowedSchemes:
			return False
		if url.scheme == "" and origin == rp_id:
			return True
		host = url.hostname
		if host == rp_id:
			return True
		return False

fido2.features.webauthn_json_mapping.enabled = True

app = Flask(__name__, static_url_path="")
app.secret_key = os.urandom(32)	 # Used for session.

rp = PublicKeyCredentialRpEntity(name="Demo server", id=serverDomain)
server = Fido2ServerWithU2FAuth(rp)


# Registered credentials are stored globally, in memory only. Single user
# support, state is lost when the server terminates.
credentials = []


@app.route("/")
def index():
	return redirect("/index.html")


@app.route("/api/register/begin", methods=["POST"])
def register_begin():
	options, state = server.register_begin(
		PublicKeyCredentialUserEntity(
			id=b"user_id",
			name="a_user",
			display_name="A. User",
		),
		credentials,
		user_verification="discouraged",
		authenticator_attachment="cross-platform",
	)

	session["state"] = state
	print("\n\n\n\n")
	print(options)
	print("\n\n\n\n")

	return jsonify(dict(options))


@app.route("/api/register/complete", methods=["POST"])
def register_complete():
	response = request.json
	auth_data = server.register_complete(session["state"], response)

	credentials.append(auth_data.credential_data)
	return jsonify({"status": "OK"})


@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
	if not credentials:
		abort(404)

	options, state = server.authenticate_begin(credentials)
	session["state"] = state
	return jsonify(dict(options))


@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
	if not credentials:
		abort(404)

	# Base64 decode response
	response = request.form.get('authdata')

	server.authenticate_complete_b64(
		session.pop("state"),
		credentials,
		response,
	)
	return jsonify({"status": "OK"})


def main():
	print(__doc__)
	app.run(host='0.0.0.0', port=443, ssl_context="adhoc", debug=False)


if __name__ == "__main__":
	main()
