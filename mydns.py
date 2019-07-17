#
# obsluha commandu binda
#

import re, os, json
from fcntl import flock, LOCK_EX, LOCK_NB, LOCK_SH, LOCK_UN
from xml.dom.minidom import parseString
import sys
sys.path.append('../')
import base
import datetime, time, tempfile, ConfigParser

DNS_MASTER_ZONE_PATH='/var/named/master'
DNS_COMPILED_ZONE_PATH='/var/named/master-compiled'
DNSSEC_KEYS_LOCATION='/var/named/keys'
DNSSEC_KSK_LOCATION='/var/named/ksk'
DNSSEC_ZONE_KEY_TTL=90*24*60*60
DNSSEC_ZONE_REHASH=5*24*60*60
DNSSEC_TYPE_KSK=257
DNSSEC_TYPE_ZSK=256
DNSSEC_ALGO='ECDSAP256SHA256'

class DNSSecRoller(object):
	"""docstring for DNSSecRoller"""
	def __init__(self):
		import socket
		if socket.gethostname() == 'ns1.hosting90.cz':
			self.active = True
		else:
			self.active = False
		self.interval = 60*60
		self.last_run = None

	def run(self):
		"""docstring for run"""
		if not self.active:
			return None
		if self.last_run != None and self.last_run > (time.time()-self.interval):
			return None
		self.last_run = time.time()

		for domain in os.listdir(DNSSEC_KEYS_LOCATION):
			if os.path.isdir(os.path.join(DNSSEC_KEYS_LOCATION,domain)):
				config = ConfigParser.ConfigParser(
					{
						'src_file':os.path.join(DNS_MASTER_ZONE_PATH,domain),
						'dst_file':os.path.join(DNS_COMPILED_ZONE_PATH,domain),
						'in_keyroll':'False',
						'keyroll_timestamp':'0',
						'zone_ttl':'3600',
					}
				)
				try:
					config_fp = open(os.path.join(DNSSEC_KEYS_LOCATION,domain,'config.ini'),'r')
					flock(config_fp,LOCK_SH)
					config.readfp(config_fp)
					config_fp.close()
				except:
					continue
				zonefile = config.get(domain,'src_file')
				compiled_file = config.get(domain,'dst_file')
				in_keyroll = config.getboolean(domain,'in_keyroll')
				zone_ttl = config.getint(domain,'zone_ttl')
				try:
					last_signature = config.getint(domain,'last_signature')
				except:
					continue

				keyroll_timestamp = config.getint(domain,'keyroll_timestamp')
				if keyroll_timestamp == 0:
					keyroll_timestamp = last_signature

				if (last_signature < (time.time() - DNSSEC_ZONE_REHASH)) or (in_keyroll and zone_ttl != None and keyroll_timestamp < (time.time() - zone_ttl)):
					compile_result = sign_and_compile(domain,zonefile,compiled_file,increment_serial=True)
					if compile_result == True:
						base.shell_exec('rndc reload '+domain)


def update_master_config(domain_name, remove = False):
	modified = False
	conf_file = '/etc/auto_named.conf'
	pattern = re.compile('^zone\ \"(.*)\"\ \{$')
	custom_zone_config = json.load(open('/etc/bind/custom_zone_params.json'))
	zones = []
	fh = open(conf_file, 'r+')
	flock(fh, LOCK_EX)
	for line in fh:
		mymatch = pattern.match(line)
		if mymatch != None:
			zones.append(mymatch.group(1))
	if remove and domain_name in zones:
		zones.remove(domain_name)
		modified = True
	elif not remove and domain_name not in zones:
		zones.append(domain_name)
		modified = True
	elif domain_name in custom_zone_config:
		# pro jistotu aktualizujeme, kdyby se zmenil custom config
		modified = True
	if modified:
		zones.sort()
		fh.seek(0)
		for domain in zones:
			conf = 'zone "%s" {\n' % (domain)
			conf += '	type master;\n'
			conf += '	file "master-compiled/%s";\n' % (domain,)
			if domain in custom_zone_config:
				conf += custom_zone_config[domain]+'\n'
			conf += '};\n\n'
			fh.write(conf)
		fh.truncate()
	fh.flush()
	fh.close()
	return modified

def load_keys(location):
	key_list = {}
	for filename in os.listdir(location):
		mymatch = re.match('^(K(.*)\.\+([0-9]+)\+([0-9]+))\.key$', filename)
		if mymatch != None:
			pkey_file = os.path.join(location,mymatch.group(1)+'.private')
			if not os.path.exists(pkey_file):
				continue
			key = {
				'domain':mymatch.group(2),
				'algo':int(mymatch.group(3)),
				'keyid':int(mymatch.group(4)),
				'filename':os.path.join(location,filename),
				'private_key':pkey_file,
				'data': None
			}
			for line in open(os.path.join(location,filename)):
				mymatch = re.match('^; ([a-zA-Z]+): ([0-9]{14}).*$', line)
				if mymatch != None:
					key[mymatch.group(1).lower()] = datetime.datetime.strptime(mymatch.group(2),'%Y%m%d%H%M%S')
				mymatch = re.match('^.*(IN DNSKEY ([0-9]+) .*)$', line)
				if mymatch != None:
					key['data'] = mymatch.group(1)
					key['type'] = int(mymatch.group(2))
			key_list[key['keyid']] = key
	return key_list

def check_zone_keys(domain, zone_ttl = 3600,config = None):
	if config == None:
		config = ConfigParser.ConfigParser()
		config.add_section(domain)
	domain_keys_location = os.path.join(DNSSEC_KEYS_LOCATION,domain)
	if not os.path.exists(domain_keys_location):
		os.mkdir(domain_keys_location)
	ks_keys = load_keys(DNSSEC_KSK_LOCATION)
	zone_keys = load_keys(domain_keys_location)
	zone_keys_bytime = {}
	for keyid in zone_keys.keys():
		# for TYPE_KSK check if key in ks_keys, else delete
		if zone_keys[keyid]['type'] == DNSSEC_TYPE_KSK:
			if keyid not in ks_keys:
				os.unlink(zone_keys[keyid]['filename'])
				os.unlink(zone_keys[keyid]['private_key'])
		else:
			zone_keys_bytime[int(zone_keys[keyid]['publish'].strftime('%s'))] = zone_keys[keyid]
	# sort zone keys by publish time
	zone_keys_timestamps = sorted(zone_keys_bytime.keys(),reverse=True)
	if len(zone_keys_timestamps) == 0 or ((datetime.datetime.utcnow() - zone_keys_bytime[zone_keys_timestamps[0]]['publish']) > datetime.timedelta(seconds=DNSSEC_ZONE_KEY_TTL)):
		# generate new key if
		# * no domain key exists
		# * newest domain key is older than DNSSEC_ZONE_KEY_TTL
		myworkdir = os.getcwd()
		os.chdir(domain_keys_location)
		if os.system('dnssec-keygen -a %s -3 -n ZONE %s >/dev/null' % (DNSSEC_ALGO,domain)) != 0:
			raise Exception('Unable to generate key for domain %s' % (domain,))
		if len(zone_keys_timestamps) > 0:
			config.set(domain,'keyroll_timestamp',int(time.time()))
			config.set(domain,'in_keyroll',True)
		os.chdir(myworkdir)
	if len(zone_keys_timestamps) > 1 and ((datetime.datetime.utcnow() - zone_keys_bytime[zone_keys_timestamps[0]]['publish']) > datetime.timedelta(seconds=zone_ttl)):
		# delete old keys if current key is older than zone TTL
		config.set(domain,'in_keyroll',False)
		for key_timestamp in zone_keys_timestamps[1:]:
			os.unlink(zone_keys_bytime[key_timestamp]['filename'])
			os.unlink(zone_keys_bytime[key_timestamp]['private_key'])
	for keyid in ks_keys:
		# check if all KSK are present for domain
		if keyid not in zone_keys:
			# copy ksk here
			keyfile_base = os.path.join(domain_keys_location,'K%s.+%03d+%d' % (domain,ks_keys[keyid]['algo'],keyid))
			os.link(ks_keys[keyid]['private_key'],keyfile_base+'.private')
			fh = open(keyfile_base+'.key','w')
			fh.write(domain+'. '+ks_keys[keyid]['data']+'\n')
			fh.close()
	# reload zone keys and return
	zone_keys = load_keys(domain_keys_location)
	return zone_keys

def sign_and_compile(domain,srcfile,dstfile,increment_serial=False):
	# find domain TTL and possibly update zone serial
	domain_ttl = None
	src_lock_fh = open(srcfile,'r')
	flock(src_lock_fh,LOCK_SH)
	srcfh = open(srcfile,'r+')
	serial_updated = False
	line = None
	while line == None or line != '':
		line = srcfh.readline()
		mymatch = re.match('@\s+([0-9]+)\s+IN\s+SOA\s.*$', line)
		if mymatch != None:
			domain_ttl = int(mymatch.group(1))
			if not increment_serial:
				break
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
	if increment_serial and not serial_updated:
		raise Exception('Unable to find zone serial')

	if domain_ttl == None:
		raise Exception('Unable to get domain TTL')

	config = ConfigParser.ConfigParser()
	config_file = os.path.join(DNSSEC_KEYS_LOCATION,domain,'config.ini')
	try:
		config_fp = open(config_file)
		flock(config_fp,LOCK_SH)
		config.readfp(config_fp)
		config_fp.close()
	except:
		config.add_section(domain)
	config.set(domain,'src_file',srcfile)
	config.set(domain,'dst_file',dstfile)
	config.set(domain,'zone_ttl',domain_ttl)
	domain_keys = check_zone_keys(domain,domain_ttl,config)

	tmpfile = tempfile.NamedTemporaryFile(delete=False)
	tmpfile.write(open(srcfile).read())

	for keyid in domain_keys.keys():
		tmpfile.write('$INCLUDE %s\n' % (domain_keys[keyid]['filename']))
	tmpfile.close()

	# sign zone
	myworkdir = os.getcwd()
	os.chdir(os.path.join(DNSSEC_KEYS_LOCATION,domain))
	(out, err, res) = base.shell_exec2('dnssec-signzone -A -3 $(head -c 1000 /dev/random | sha1sum | cut -b 1-16) -N INCREMENT -o %s -t %s' % (domain,tmpfile.name))
	if res != 0:
		raise Exception('Unable to sign zone %s, Stdout: %s, Stderr: %s', (domain,out,err))
	os.chdir(myworkdir)

	config.set(domain,'last_signature',int(time.time()))

	if os.path.exists(config_file):
		config_fp = open(config_file,'r+')
	else:
		config_fp = open(config_file,'w')

	flock(config_fp,LOCK_EX)
	config_fp.seek(0)
	config_fp.truncate()
	config.write(config_fp)
	config_fp.close()

	if not os.path.exists(dstfile):
		open(dstfile,'w').close()
	dst_lock_fh = open(dstfile,'r')
	flock(dst_lock_fh,LOCK_EX)
	(out, err, res) = base.shell_exec2('named-compilezone -o '+dstfile+' '+domain+' '+tmpfile.name+'.signed')
	os.unlink(tmpfile.name+'.signed')
	os.unlink(tmpfile.name)
	dst_lock_fh.close()
	src_lock_fh.close()

	return res == 0

def syscmd_domain_update_dns(data):
	trigger_file = '/var/lock/rndc-trigger.lock'
	lock_file = '/var/lock/rndc-reconfig.lock'
	dns = parseString(data)

	domain = dns.getElementsByTagName('domain')[0].childNodes[0].data
	dnssec = bool(int(dns.getElementsByTagName('dnssec')[0].childNodes[0].data))
	if re.match(base.EREG_DOMAIN_NAME, domain) == None:
		return [False, "Domena %s neprosla eregem" % domain]
	if os.path.exists(DNS_MASTER_ZONE_PATH):
		zonefile = os.path.join(DNS_MASTER_ZONE_PATH,domain)
		compiled_file = os.path.join(DNS_COMPILED_ZONE_PATH,domain)
		# check original zone serial, increment if needed
		old_serial = 0
		if os.path.exists(zonefile):
			for line in open(zonefile):
				mymatch = re.match('^(\s+([0-9]{10})\s*;\s*serial\s*)$',line)
				if mymatch != None:
					old_serial = int(mymatch.group(2))
					break
		serial_checked = False
		f = open(zonefile, "w+")
		flock(f,LOCK_EX)
		for line in dns.getElementsByTagName('zone')[0].childNodes[0].data.split('\n'):
			if not serial_checked:
				mymatch = re.match('^(\s+([0-9]{10})\s*;\s*serial\s*)$',line)
				if mymatch != None:
					serial_checked = True
					new_serial = int(mymatch.group(2))
					if new_serial <= old_serial:
						line = line.replace(str(new_serial),str(old_serial+1))
			f.write(line+'\n')
		f.close()

		# pokud je zonovy soubor jiz v teto vterine upraven, pockame 1 vterinu, aby bylo zajisteno, ze mtime souboru se zmeni.
		# bind odmita znovu reloadnout zonu, pokud se ji nezmenil mtime v celych cislech
		try:
			st = os.stat(compiled_file)
			if int(st.st_mtime) == int(time.time()):
				time.sleep(1)
		except:
			open(compiled_file,'w').close()
			pass
		lock_fh = ()
		if dnssec:
			compile_result = sign_and_compile(domain,zonefile,compiled_file)
		else:
			if not dnssec and os.path.exists(os.path.join(DNSSEC_KEYS_LOCATION,domain)):
				base.rmrf(os.path.join(DNSSEC_KEYS_LOCATION,domain))
			dst_lock_fh = open(compiled_file,'r')
			flock(dst_lock_fh,LOCK_EX)
			(out, err, res) = base.shell_exec2('named-compilezone -o '+compiled_file+' '+domain+' '+zonefile)
			compile_result = res == 0
			dst_lock_fh.close()

		os.utime(compiled_file, None)
		if compile_result == True:
			if update_master_config(domain):
				base.bind_restart_lock.acquire()
				base.trigger_update(base.bind_restart_data)
				base.bind_restart_lock.release()
			else:
				base.shell_exec('rndc reload '+domain)
			return [True, "ok" ]
		else:
			return [True, "Zone not loaded:\n"+str(out)+"\n\n"+str(err)]

	else:
		return [False, "adresar %s neexistuje" % (DNS_MASTER_ZONE_PATH,)]

def syscmd_bind_delete_domain(domain):
	trigger_file = '/var/lock/rndc-trigger.lock'
	lock_file = '/var/lock/rndc-reconfig.lock'
	if re.match(base.EREG_DOMAIN_NAME, domain):
		if os.path.exists(os.path.join(DNS_MASTER_ZONE_PATH,domain)):
			os.unlink(os.path.join(DNS_MASTER_ZONE_PATH,domain))
		if os.path.exists(os.path.join(DNS_COMPILED_ZONE_PATH,domain)):
			os.unlink(os.path.join(DNS_COMPILED_ZONE_PATH,domain))
		if os.path.exists(os.path.join(DNSSEC_KEYS_LOCATION,domain)):
			base.rmrf(os.path.join(DNSSEC_KEYS_LOCATION,domain))
		if update_master_config(domain,remove=True):
			base.bind_restart_lock.acquire()
			base.trigger_update(base.bind_restart_data)
			base.bind_restart_lock.release()
		return [True, "Zona smazana"]
	else:
		return [False, "Domena %s neprosla eregem" % domain]

def syscmd_check_bind_domain(domain):
	if re.match(base.EREG_DOMAIN_NAME, domain) == None:
		return [False, "Domena %s neprosla eregem" % domain]
	(out, err, status) = base.shell_exec2("/usr/sbin/named-compilezone -o /dev/null %s %s" % (domain, os.path.join(DNS_MASTER_ZONE_PATH,domain)))
	if status <> 0:
		return [True, out+err ]
	else:
		return [True, 'OK' ]

def syscmd_update_reverse(data):
	ip, ip6, hostname = base.xml_cut(data, ['ip', 'ip6', 'hostname'])
	hostname = str(hostname)
	if re.match(base.EREG_IP, ip) == None:
		if ip != '':
			return [False, 'invalid ip']
		else:
			updateip4 = False
	else:
		updateip4 = True
	if re.match(base.EREG_IP6, ip6) == None:
		if ip6 != '':
			return [False, 'invalid ip6']
		else:
			updateip6 = False
	else:
		updateip6 = True
	if re.match(base.EREG_DOMAIN_NAME, hostname) == None:
		if hostname != '':
			return [False, 'invalid domain name']

	if updateip4:
		ipbase = ip.split('.')[0:3]
		ipname = str(ip.split('.')[3])
		ipbase.reverse()
		ipzone = '.'.join(ipbase)+'.in-addr.arpa'

	if updateip6:
		ls = os.listdir('/var/named/reverse')
		zonefiles=[]
		for file in ls:
			mymatch = re.search('^(.*).ip6.arpa', file)
			if mymatch != None:
				zonefiles.append((mymatch.group(1), file))

	if updateip6:
		updateip6 = False
		ip6list = ip6.split(':')
		ip6hex = ''
		for item in ip6list:
			if item == '':
				item = '0'*(8-len(ip6list)+1)*4
			else:
				item = '0'*(4-len(item))+item
			ip6hex+=item
		ip6listhex = list(ip6hex)
		ip6listhex.reverse()
		ip6text = '.'.join(ip6listhex)
		for zonefile in zonefiles:
			if ip6text[-1*len(zonefile[0]):] == zonefile[0]:
				ip6zoneshort = zonefile[0]
				ip6zone = zonefile[1]
				ip6name = ip6text[:-len(zonefile[0])-1]
				updateip6 = True
				break

	ip4updated = False
	if updateip4:
		zonefile = '/etc/bind/reverse/'+ipzone
		ip4fh = open(zonefile, 'r+')
		flock(ip4fh, LOCK_EX)
		lines = ip4fh.readlines()

		for key in range(len(lines)):
			mymatch = re.match('^'+re.escape(ipname)+'(\s+[0-9]+)?\s+IN\s+PTR\s+[a-zA-Z0-9\.\-]+\.$', lines[key].strip('\n'))
			if mymatch != None:
				lines[key] = ipname+mymatch.group(1)+' IN PTR '+hostname+'.\n'
				ip4updated = True
			mymatch = re.match('^(\s+)([0-9]+)(\s+\;\s*serial)$', lines[key])
			if mymatch != None:
				lines[key] = mymatch.group(1)+str(int(mymatch.group(2))+1)+mymatch.group(3)+'\n'
		if ip4updated:
			ip4fh.seek(0)
			lines = ip4fh.writelines(lines)
			ip4fh.truncate()
			ip4fh.close()
			if sign_and_compile(ipzone,zonefile,os.path.join(DNS_COMPILED_ZONE_PATH,ipzone)):
				base.shell_exec('rndc reload '+ipzone)
			else:
				return [False,'Unable to sign zone']
		else:
			ip4fh.close()

	ip6updated = False
	if updateip6 == True:
		zonefile = '/etc/bind/reverse/'+ip6zone
		ip6fh = open(zonefile, 'r+')
		flock(ip6fh, LOCK_EX)
		lines = ip6fh.readlines()
		popkey = None
		for key in range(len(lines)):
			mymatch = re.match('^'+re.escape(ip6name)+'\s+IN\s+PTR\s+[a-zA-Z0-9\.\-]*\.$', lines[key].strip('\n'))
			if mymatch != None:
				if hostname=='':
					popkey = key
				else:
					lines[key] = ip6name+' IN PTR '+hostname+'.\n'
				ip6updated = True
			mymatch = re.match('^(\s+)([0-9]+)(\s+\;\s*serial)$', lines[key])
			if mymatch != None:
				lines[key] = mymatch.group(1)+str(int(mymatch.group(2))+1)+mymatch.group(3)+'\n'
		if popkey != None:
			lines.pop(popkey)
		if ip6updated != True and hostname!='':
			lines.append(ip6name+' IN PTR '+hostname+'.\n')
			ip6updated = True

		if ip6updated:
			ip6fh.seek(0)
			lines = ip6fh.writelines(lines)
			ip6fh.truncate()
			ip6fh.close()
			if sign_and_compile(ip6zoneshort+'.ip6.arpa',zonefile,os.path.join(DNS_COMPILED_ZONE_PATH,ip6zoneshort+'.ip6.arpa')):
				base.shell_exec('rndc reload '+ip6zoneshort+'.ip6.arpa')
			else:
				return [False,'Unable to sign zone']
			base.shell_exec('rndc reload %s.ip6.arpa' % ip6zoneshort)
		else:
			ip6fh.close()

	return [True, 'reverse record updated']



# export funkci
functions = { 'domain_update_dns': syscmd_domain_update_dns,
	'bind_delete_domain': syscmd_bind_delete_domain,
	'check_bind_domain': syscmd_check_bind_domain,
	'update_reverse': syscmd_update_reverse
	}
