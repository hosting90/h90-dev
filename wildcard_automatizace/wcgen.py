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


logging.basicConfig(level=logging.INFO)


DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
BITS = 4096  # minimum for Boulder
REG_DIRECTORY = 'registrations'



def usage():
    print 'Usage: ' + sys.argv[0] + ' CN REG '
    print 'example: ' + sys.argv[0] + ' moje-domena.cz h90'
    sys.exit(1)

def input_san():
    if len(sys.argv) != 3 :
        usage()
    else:
        global DOMAIN, registrar
        DOMAIN = sys.argv[1]
        registrar = sys.argv[2]

	#Check if CN is valid domain
    domain_regex = re.compile("^([a-zA-Z0-9]([\-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?\.)*([a-zA-Z0-9]([\-a-zA-Z0-9]{0,61}[a-zA-Z0-9])+\.)([a-zA-Z0-9]+([\-a-zA-Z0-9]{0,61}[a-zA-Z])+)$")
    if not domain_regex.match(DOMAIN):
        print 'First argument is not valid CN'
        sys.exit(1)

	#Check if registrar exists
	if registrar not in os.listdir(REG_DIRECTORY):
		print "This registrar does not exists, register it first with new_registrator.py"
		sys.exit(1)



def load_files():
	global privkey, reg_uri
	with open(REG_DIRECTORY + "/" + registrar + "/private.key", "rb") as key_file:
	    privkey = serialization.load_pem_private_key(
	        key_file.read(),
	        password=None,
	        backend=default_backend()
	    )
	with open(REG_DIRECTORY + "/" + registrar + "/reguri.txt", "r") as reguri_file:
		reg_uri = reguri_file.read()


def compose_regr():
	global regr, key
	key = jose.JWKRSA(key=privkey)
	regr = messages.RegistrationResource(
		body=messages.Registration(
			key=key.public_key()),
		uri = reg_uri)




def acme_query():

	net = ClientNetwork(key)
	directory = net.get(DIRECTORY_URL).json()
	acme = client.ClientV2(directory, net)

	#Check if registration is valid
	if acme.query_registration(regr).body.status == u'valid':
		print "Registration valid"
	else:
		print "Registration invalid"
		sys.exit(1)


	# csr = OpenSSL.crypto.load_certificate_request(
	# 	OpenSSL.crypto.FILETYPE_ASN1, pkg_resources.resource_string(
	# 		'acme', os.path.join('testdata', 'csr.der')))

	pkey = OpenSSL.crypto.PKey()
	pkey.generate_key(OpenSSL.crypto.TYPE_RSA, BITS)

	req = crypto_util.make_csr(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,pkey),[DOMAIN,'*.'+DOMAIN])


	orderr = acme.new_order(req)
	d = ''
	while d.strip() == '':
		for authr in orderr.authorizations:
			for chalr in authr.body.challenges:
				if type(chalr.chall) == type(challenges.DNS01()):
					print "%s %s" % (chalr.chall.validation_domain_name(DOMAIN),chalr.chall.validation(key))
					#logging.debug(orderr.authorizations[0].body.challenges[0].chall)
					# jedem DNS validaci
		d = sys.stdin.readline()
		for authr in orderr.authorizations:
			for chalr in authr.body.challenges:
				if type(chalr.chall) == type(challenges.DNS01()):
					try:
						acme.answer_challenge(chalr,challenges.DNS01Response())
					except:
						print chalr.chall.encode('token')+" already answered"

	res = acme.poll_and_finalize(orderr)
	print "PRIVKEY:"
	print OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey, cipher=None, passphrase=None)
	print "FULLCHAIN:"
	print(res.fullchain_pem)






def main():
	input_san()
	load_files()
	compose_regr()
	acme_query()

main()
