"""Example script showing how to use acme client API."""
import logging
import os,sys
import pkg_resources

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
DOMAIN = 'divecky.com'  # example.com is ignored by Boulder

# generate_private_key requires cryptography>=0.5
# privkey = rsa.generate_private_key(
# 	public_exponent=65537,
# 	key_size=BITS,
# 	backend=default_backend())



# Load privkey from file
with open("reg_privkey.pem", "rb") as key_file:
    privkey = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )



key = jose.JWKRSA(key=privkey)
net = ClientNetwork(key)

#Serialize private key, so we can print it later
privkey_pem = privkey.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.TraditionalOpenSSL,
   encryption_algorithm=serialization.NoEncryption()
)


print privkey_pem






directory = net.get(DIRECTORY_URL).json()



acme = client.ClientV2(directory, net)


#Registration - we do not want to do that, no need?
# regbody = dict(messages.Registration(contact=('mailto:matej.divecky@hosting90.cz',),terms_of_service_agreed=True, key=key.public_key()))
# logging.debug(regbody)
# regr = acme.new_account(messages.NewRegistration(**regbody))
#logging.info(regr)



regr = messages.RegistrationResource(
	body=messages.Registration(
		#contact=(u'mailto:matej.divecky@hosting90.cz',),
		key=key.public_key()),
	uri='https://acme-staging-v02.api.letsencrypt.org/acme/acct/8851026',)
	#new_authzr_uri=None,
	#terms_of_service='https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf')


print "QUERY:"
print acme.query_registration(regr)

#print acme.query_registration(messages.RegistrationResource"https://acme-staging-v02.api.letsencrypt.org/acme/acct/8850736")


#logging.info('Auto-accepting TOS: %s', regr.terms_of_service)
# acme.agree_to_tos(regr)



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
print "THERE IS YOUR PRIVKEY:"
print OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey, cipher=None, passphrase=None)
print "THERE IS YOUR CERT:"
print(res.fullchain_pem)
print "Reg privkey:"
print privkey_pem
