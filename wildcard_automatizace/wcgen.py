"""Example script showing how to use acme client API."""
import logging
import os,sys
import pkg_resources
import re
import json

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


logging.basicConfig(level=logging.INFO)


DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
BITS = 4096  # minimum for Boulder
REG_DIRECTORY = 'registrations'



def wildcard_request(cn, account):
    #Check if CN is valid domain
    domain_regex = re.compile("^([a-zA-Z0-9]([\-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?\.)*([a-zA-Z0-9]([\-a-zA-Z0-9]{0,61}[a-zA-Z0-9])+\.)([a-zA-Z0-9]+([\-a-zA-Z0-9]{0,61}[a-zA-Z])+)$")
    if not domain_regex.match(cn):
        print 'First argument is not valid CN'
        sys.exit(1)

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


    #Compose regr
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

    #Generate private key for certificate
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(OpenSSL.crypto.TYPE_RSA, BITS)

    #Serialize key for output
    pkey_printable = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey, cipher=None, passphrase=None)

    #Compose request for acme
    req = crypto_util.make_csr(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,pkey),[cn,'*.'+cn])

    #begin order
    orderr = acme.new_order(req)
    d = ''
    validation_data = []
    while d.strip() == '':
    	for authr in orderr.authorizations:
    		for chalr in authr.body.challenges:
    			if type(chalr.chall) == type(challenges.DNS01()):
    				validation_data.append([str(chalr.chall.validation(key)), chalr.chall.validation_domain_name(cn)])
        print validation_data

    	d = sys.stdin.readline()
    	for authr in orderr.authorizations:
    		for chalr in authr.body.challenges:
    			if type(chalr.chall) == type(challenges.DNS01()):
    				try:
    					acme.answer_challenge(chalr,challenges.DNS01Response())
    				except:
    					print chalr.chall.encode('token')+" already answered"

    #After filling DNS and waiting for propagation, finalize order
    res = acme.poll_and_finalize(orderr)

    #logging.info(res)

    cert = x509.load_pem_x509_certificate(str(res.fullchain_pem), default_backend())



    output_data = {
        'wildcard': {
            'cn' : cn,
            'private_key' : str(pkey_printable),
            'certificate' : str(res.fullchain_pem),
            'expiration' : cert.not_valid_after.strftime("%x %X") #Locale-specific time+date representation. Edit to your need
        }
    }


    print json.dumps(output_data)

# DEBUG INPUT FROM TERMINAL
def usage():
    print 'Usage: ' + sys.argv[0] + ' CN REG '
    print 'example: ' + sys.argv[0] + ' moje-domena.cz h90'
    sys.exit(1)

def input_san():
    if len(sys.argv) != 3 :
        usage()
    else:
        cn = sys.argv[1]
        account = sys.argv[2]
        wildcard_request(cn, account)


input_san() #Input from arguments
wildcard_request("divecky.com", "h90") #Function input
