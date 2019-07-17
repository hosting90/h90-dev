
import os, sys
import re
import datetime
sys.path.append('../')
import base
import mysql.connector
from mydns import sign_and_compile as mydns_sign_and_compile
from fcntl import flock, LOCK_EX

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
from acme import errors
from acme import crypto_util, challenges
from acme.client import ClientV2, ClientNetwork


import dns.resolver

#logging.basicConfig(level=logging.DEBUG)

DNS_MASTER_ZONE_PATH='/var/named/master'
DNS_COMPILED_ZONE_PATH='/var/named/master-compiled'

#DNS_MASTER_ZONE_PATH='master'
#DNS_COMPILED_ZONE_PATH='master-compiled'

######
# For wildcard_request
######
DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
BITS = 4096  # minimum for Boulder
REG_DIRECTORY = 'registrations'



class Wildcard(object):
	def __init__(self):
		import socket
		if socket.gethostname() == 'ns1.hosting90.cz':
			self.active = True
		else:
			self.active = False
		self.interval = 60*60
		self.last_run = None

	def run(self):
		if not self.active:
			return None
		if self.last_run != None and self.last_run > (time.time()-self.interval):
			return None
		self.last_run = time.time()


		mydb = mysql.connector.connect(
			host="galera-db1.hosting90.cz",
			user="root",
			passwd="xyooZfUzthvQE",
			database="hosting"
		)
		mysql_select = mydb.cursor()
		mysql_select.execute("SELECT * FROM certificates WHERE expiration IS NULL OR expiration < date_add(now(), interval 1 month) ")
		myresult = mysql_select.fetchall()
		if not myresult:
			return None

		for record in myresult:
			db_projekt =  record[1]
			db_cn = record[2]
	#		db_expiration = record[3]
	#		db_certificate_pem = record[4]
	#		db_privkey_pem = record[5]

		#  print projekt, cn, expiration, certificate_pem, privkey_pem

			wildcard_output = wildcard_request(db_cn, db_projekt)
			if False in wildcard_output:
				stderr_output = 'Wildcard: ' + wildcard_output[0]+' ' + db_cn + '\n'
				sys.stderr.write(stderr_output)
			else:
				cn = wildcard_output[0]
				privkey_pem = wildcard_output[1]
				certificate_pem = wildcard_output[2]
				expiration = wildcard_output[3]

				#print wildcard_output


				mysql_write = mydb.cursor()
				mysql_write.execute("""
					UPDATE certificates
					SET certificate=%s, private_key=%s, expiration=%s
					WHERE cn=%s
				""", (certificate_pem, privkey_pem, expiration, cn))

				mydb.commit()
				if mysql_write.rowcount == 1:
					#Debug info

					stdout_output = 'Wildcard: ' + cn + ' succesfully requested' + '\n'
					sys.stdout.write(stdout_output)
				#	return ["Successfully written to db", True]
				else:
					sys.stderr.write("Wildcard: Nothing was written to DB")
				#	return ["Error on writing to db", False]


##########################
##		DNS Writing		##
##########################
#Main functions
def dns_apply_challenge(cn, validation_data):
	base_domain = extract_base_domain(cn)
	zonefile = DNS_MASTER_ZONE_PATH + "/" + base_domain
	zonefile_compiled = DNS_COMPILED_ZONE_PATH + "/" + base_domain


	if base_domain not in os.listdir(DNS_MASTER_ZONE_PATH):
		#print zonefile
		return ["Zonefile not found", False]


	#Check if there are any old records. If so, remove them.
	if dns_challenge_in_file(zonefile):
		dns_remove_challenge(cn, False)

	#Write challenges to zonefile
	dns_recs = []
	for data in validation_data:
		dns_recs.append('%s\t60\tIN\tTXT\t"%s"\n' % (data[1].rsplit(".",2)[:-2][0], data[0]))
	zonefile_append = open(zonefile, "a+")
	flock(zonefile_append,LOCK_EX)
	for dns_rec in dns_recs:
		zonefile_append.write(dns_rec)
	zonefile_append.close()
	#Check if we really have chalres in zonefile
	if dns_challenge_in_file(zonefile):
		return dns_compile_zonefile(base_domain, zonefile, zonefile_compiled)
	else:
		return ["Unable to write challenge", False]
def dns_remove_challenge(cn, commit = True):
	base_domain = extract_base_domain(cn)
	zonefile = DNS_MASTER_ZONE_PATH + "/" + base_domain
	zonefile_compiled = DNS_COMPILED_ZONE_PATH + "/" + base_domain

	if base_domain not in os.listdir(DNS_MASTER_ZONE_PATH):
		return ["Zonefile not found", False]

	zonefile_file = open(zonefile, "r+")
	flock(zonefile_file,LOCK_EX)
	with zonefile_file:
		zonefile_read = zonefile_file.readlines()
		zonefile_file.seek(0)
		for line in zonefile_read:
			if "_acme-challenge" not in line:
				zonefile_file.write(line)
		zonefile_file.truncate()
	if dns_challenge_in_file(zonefile):
		print "Something is wrong, cannot remove challenge"
		return False

	#If commit variable is False, do not compile&commit to bind. Just remove records from fileself.
	#Designed for removing residual challenges before trying new
	if not commit:
		return True
	else:
		return dns_compile_zonefile(base_domain, zonefile, zonefile_compiled)

#DNS writing - Subfunctions
def extract_base_domain(cn):
	#Just removing everything except top and second level domains (eg. new.docs.hosting90.cz => hosting90.cz)
	nsfile = cn.split(".")[-2:]
	base_domain = nsfile[0] + "." + nsfile[1]
	return base_domain
def dns_challenge_in_file(zonefile):
	list = []
	for line in open(zonefile, "r"):
		if "_acme-challenge" in line:
			list.append(line)
	if list:
		return True
		#return list
	else:
		return False
def dns_detect_dnssec(zonefile_compiled):
	if 'DNSKEY' in open(zonefile_compiled).read():
		return True
	else:
		return False
def dns_compile_zonefile(base_domain, zonefile, zonefile_compiled):


	if dns_detect_dnssec(zonefile_compiled):
	#If there are DNSSEC records in zonefile, use prepared function
		compile_result = mydns_sign_and_compile(base_domain, zonefile, zonefile_compiled, True)
		#return dnssec_write

	else:
		#If no dnssec is used, just increase serial and compile zone.
		increment_serial = True
		serial_updated = False
		line = None
		srcfh = open(zonefile,'r+')
		flock(srcfh,LOCK_EX)
		while line == None or line != '':
			line = srcfh.readline()
			if increment_serial and not serial_updated:
				mymatch = re.match('^(\s+([0-9]{10})\s*;\s*serial\s*)$',line)
				if mymatch != None:
					old_serial = int(mymatch.group(2))
					today_serial = int(datetime.date.today().strftime('%Y%m%d00'))
					new_serial = max(old_serial,today_serial)+1
					line = line.replace(mymatch.group(2),str(new_serial))
					filepos = srcfh.tell()
					srcfh.seek(filepos-len(line))
					srcfh.write(line)
					serial_updated=True
		srcfh.close()
		#Compile zone
		(out, err, res) = base.shell_exec2('named-compilezone -o '+zonefile_compiled+' '+ base_domain +' '+zonefile)
		compile_result = res == 0

	os.utime(zonefile_compiled, None)


	if compile_result == True:
		base.shell_exec('rndc reload '+base_domain)
		return [True, "ok" ]
	else:
		return [True, "Zone not loaded:\n"+str(out)+"\n\n"+str(err)]

######################
##	ACME WC request	##
######################

def wildcard_request(cn, account):

	def dns_check_ns1():
		recieved_data_dup = []
		recieved_data = []

		ns1_resolver = dns.resolver.Resolver()
		ns1_resolver.nameservers = ['130.193.8.82','2a03:b780::1:1'] #ns1.hosting90.cz
		#ns1_resolver.nameservers = ['173.245.58.51'] #DigitalOcean (pro testovani, svoje DNS mam tam)

		for data in validation_data:
			domainname = data[1]
			#challenge = data[0]
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
		return ['First argument is not valid CN',False]


	#Check if registrar exists
	if account not in os.listdir(REG_DIRECTORY):
		return ["This account does not exists, register it first with new_account.py", False]


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
	if acme.query_registration(regr).body.status != u'valid':
		return ["Registration invalid", False]

	#Generate private key for certificate
	pkey = OpenSSL.crypto.PKey()
	pkey.generate_key(OpenSSL.crypto.TYPE_RSA, BITS)

	#Serialize key for output
	pkey_printable = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)

	#Compose request for acme
	req = crypto_util.make_csr(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,pkey),[cn,'*.'+cn])

	#begin order
	orderr = acme.new_order(req)

	validation_data = []


	for authr in orderr.authorizations:
		for chalr in authr.body.challenges:
			if type(chalr.chall) == type(challenges.DNS01()):
				validation_data.append([str(chalr.chall.validation(key)), chalr.chall.validation_domain_name(cn)])
	#print validation_data
	#Now, call DNS writing function to apply challenges
	dns_apply_res = dns_apply_challenge(cn, validation_data)
	if not dns_apply_res:
		return dns_apply_res


	#Check if DNS is valid on our server
	#print "DEBUG: waiting for manual DNS input. Press a key after."
	#sys.stdin.readline() #DEBUG: wait for manual DNS input
	limiter = 5

	try:
		dns_check_ns1()
	except dns.resolver.NoNameservers:
		return ["DNS record not found on ns1", False]


	while not dns_check_ns1():
		if limiter != 0:
			print "DNS records are not correct, trying again in few seconds"
			limiter = limiter - 1
			time.sleep(5)
		else:
			return ["DNS are not correct even after several tries. Aborting", False]




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
	except errors.ValidationError:
		return ["Validation error", False]
	finally:
		dns_remove_challenge(cn)
	cert = x509.load_pem_x509_certificate(str(res.fullchain_pem), default_backend())


	output_data = [cn, str(pkey_printable), str(res.fullchain_pem), cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")]
	return output_data
