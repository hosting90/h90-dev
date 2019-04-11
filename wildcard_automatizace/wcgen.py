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

logging.basicConfig(level=logging.INFO)


DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
BITS = 4096  # minimum for Boulder
REG_DIRECTORY = 'registrations'








def wildcard_request(cn, account):

    def dns_check_ns1():
        recieved_data_dup = []
        recieved_data = []

        ns1_resolver = dns.resolver.Resolver()
        #ns1_resolver.nameservers = ['130.193.8.82','2a03:b780::1:1']
        ns1_resolver.nameservers = ['173.245.58.51']

        for data in validation_data:
            domainname = data[1]
            challenge = data[0]
            answers = ns1_resolver.query(domainname, 'txt')
            for rdata in answers:
                recieved_data_dup.append([str(rdata).replace('"', ''), domainname])

        #Deduplication of ns records (in case of more cnames)
        for i in recieved_data_dup:
            if i not in recieved_data:
                recieved_data.append(i)

        # print sorted(recieved_data)
        # print sorted(validation_data)
        if sorted(validation_data) == sorted(recieved_data):
            return True
        else:
            return False



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
    from dns_write import dns_apply_challenge as dns_apply
    from dns_write import dns_remove_challenge as dns_remove

    for authr in orderr.authorizations:
    	for chalr in authr.body.challenges:
    		if type(chalr.chall) == type(challenges.DNS01()):
    			validation_data.append([str(chalr.chall.validation(key)), chalr.chall.validation_domain_name(cn)])
    #print validation_data
    #Now, call DNS writing function to apply challenges
    dns_apply(cn, validation_data)
    #Wait, and than check if DNS propagated to some big servers (goog?)

    #Check if DNS has propagated to goog
    sys.stdin.readline()
    limiter = 2
    while not dns_check_ns1():
        if limiter != 0:
            print "DNS records are not correct, trying again in few seconds"
            limiter = limiter - 1
            time.sleep(5)
        else:
            print "DNS are not correct even after several tries. Aborting"
            sys.exit(1)



    for authr in orderr.authorizations:
        for chalr in authr.body.challenges:
            if type(chalr.chall) == type(challenges.DNS01()):
                try:
                    acme.answer_challenge(chalr,challenges.DNS01Response())
                except:
                    print chalr.chall.encode('token')+" already answered (challenge failed, you have to generate new one)"


    #After filling DNS and waiting for propagation, finalize order
    try:
        res = acme.poll_and_finalize(orderr)
    finally:
        dns_remove(cn)
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

#wildcard_request("divecky.com", "h90") #Function input
