"""Example script showing how to use acme client API."""
import logging
import os,sys
import pkg_resources

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
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
DOMAIN = 'jlsystem.cz'  # example.com is ignored by Boulder

# generate_private_key requires cryptography>=0.5
key = jose.JWKRSA(key=rsa.generate_private_key(
	public_exponent=65537,
	key_size=BITS,
	backend=default_backend()))
net = ClientNetwork(key)

directory = net.get(DIRECTORY_URL).json()



acme = client.ClientV2(directory, net)

regbody = dict(messages.Registration(contact=('mailto:admin@hosting90.cz',),terms_of_service_agreed=True, key=key.public_key()))
logging.debug(regbody)
regr = acme.new_account(messages.NewRegistration(**regbody))
#logging.info('Auto-accepting TOS: %s', regr.terms_of_service)
# acme.agree_to_tos(regr)
logging.debug(regr)

csr = OpenSSL.crypto.load_certificate_request(
	OpenSSL.crypto.FILETYPE_ASN1, pkg_resources.resource_string(
		'acme', os.path.join('testdata', 'csr.der')))

pkey = OpenSSL.crypto.PKey()
pkey.generate_key(OpenSSL.crypto.TYPE_RSA, BITS)

req = crypto_util.make_csr(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,pkey),[DOMAIN,'*.'+DOMAIN])

#logging.debug(req)

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
logging.debug(res)
