"""Example script showing how to use acme client API."""
import logging
import os,sys
import pkg_resources
import re
import json
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509

import josepy as jose
import OpenSSL

import six

from acme import client
from acme import messages
from acme import crypto_util, challenges
from acme.client import ClientV2, ClientNetwork

import dns.resolver

from dns_write import dns_apply_challenge as dns_apply
from dns_write import dns_remove_challenge as dns_remove

#logging.basicConfig(level=logging.INFO)


DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
BITS = 4096  # minimum for Boulder
REG_DIRECTORY = '/root/wildcard/registrations'




def wildcard_revoke(cert_pem,account):

		#Check if registrar exists
		if account not in os.listdir(REG_DIRECTORY):
			print "This account does not exists, register it first with new_account.py"
			sys.exit(1)

		#Load files from disk
		with open(REG_DIRECTORY + "/" + account + "/private.key", "rb") as key_file:
			privkey = serialization.load_pem_private_key(
				key_file.read(),
				password=None,
				backend=default_backend()
			)
		with open(REG_DIRECTORY + "/" + account + "/reguri.txt", "r") as reguri_file:
			reg_uri = reguri_file.read()

		#Compose registration resource (regr)
		key = jose.JWKRSA(key=privkey)
		regr = messages.RegistrationResource(
			body=messages.Registration(
				key=key.public_key()),
			uri = reg_uri)

		#Init ACME
		net = ClientNetwork(key)
		directory = net.get(DIRECTORY_URL).json()

		acme = client.ClientV2(directory, net)


		#Check if registration is valid
		if acme.query_registration(regr).body.status == u'valid':
			print "Registration valid"
		else:
			print "Registration invalid"
			sys.exit(1)

		#Deserialize key from variable
		cert = jose.ComparableX509(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem))

		#Try to revoke cert, return false on error or revoked-already state
		try:
			revokation = acme.revoke(cert,1)
		except messages.Error,acme_exc:
			if str(acme_exc) == str("urn:ietf:params:acme:error:alreadyRevoked :: Certificate already revoked"):
				return ["Certificate already revoked",False]
			else:
				return [acme_exc, False]


		if revokation == None:
			return["Certificate revoked succesfully", True]
		elif revokation.detail:
			return["Something went seriously wrong",False]


#Debug input
# with open("tmp/fullchain.pem", "r") as cert_pem:
# 	print wildcard_revoke(cert_pem.read(),"h90sys-new")
