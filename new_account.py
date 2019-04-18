"""Example script showing how to use acme client API."""
import logging
import os,sys
import pkg_resources
import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import josepy as jose
import OpenSSL

import six

from acme import client
from acme import messages
from acme import crypto_util, challenges
from acme.client import ClientV2, ClientNetwork

logging.basicConfig(level=logging.DEBUG)
DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
BITS = 4096  # minimum for Boulder
REG_DIRECTORY = 'registrations'




def usage():
	print 'Usage: ' + sys.argv[0] + ' REG '
	print 'example: ' + sys.argv[0] + ' h90'
	sys.exit(1)

def input_san():
	if len(sys.argv) != 2 :
		usage()
	elif sys.argv[1] not in os.listdir(REG_DIRECTORY):
		global REGISTRATOR
		REGISTRATOR = sys.argv[1]
	else:
		print "Registration with this name already exsits"
		sys.exit(1)








def create_registration():
	global privkey, regr
	privkey = rsa.generate_private_key(
		public_exponent=65537,
		key_size=BITS,
		backend=default_backend())
	key = jose.JWKRSA(key=privkey)
	net = ClientNetwork(key)
	directory = net.get(DIRECTORY_URL).json()
	acme = client.ClientV2(directory, net)
	regbody = dict(messages.Registration(contact=('mailto:admin@hosting90.cz',),terms_of_service_agreed=True, key=key.public_key()))
	#NEED TO SAVE REGBODY VARIABLE TO FILE
	regr = acme.new_account(messages.NewRegistration(**regbody))
	#Need to check if succesfull



def save_registration():
	REG_DIR = 'registrations/'+REGISTRATOR
	try:
		os.mkdir(REG_DIR, 0o755)
	except OSError:
		print ("Creation of the directory %s failed" % REGISTRATOR)


	#Serialize key
	privkey_pem = privkey.private_bytes(
	   encoding=serialization.Encoding.PEM,
	   format=serialization.PrivateFormat.TraditionalOpenSSL,
	   encryption_algorithm=serialization.NoEncryption()
	)
	#And write it
	pkey_file = open(REG_DIR+"/private.key","w")
	pkey_file.write(privkey_pem)
	pkey_file.close()
	#Write regr uri
	reg_uri_file = open(REG_DIR+"/reguri.txt","w")
	reg_uri_file.write(regr.uri)
	reg_uri_file.close()

def final_check():
	print ""


def main():
	input_san()
	create_registration()
	save_registration()
	final_check()
	"""It would be nice to now read those files, and compose acme.query_registration(), then check if it succeeded. But later..."""
main()
