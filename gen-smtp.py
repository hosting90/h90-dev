#!/usr/bin/python

import MySQLdb, os, sys

try:
	conn = MySQLdb.connect(host = "galera-hosting-db.hosting90.cz",
		user = "hosting_antispam",
		passwd = "TmnJUrd5bT9WzCSN",
		db = "hosting_smtp")
except MySQLdb.Error, e:
	print 'MySQL Error'
	sys.exit(1)

#try:
#	blacklist = open('antispam/blacklist','w')
#	cursor = conn.cursor()
#	cursor.execute('SELECT from_local_part,from_domain FROM email_blacklist')
#	row = cursor.fetchone()
#	while row:
#		blacklist.write(row[0]+'@'+row[1]+'\n')
#		row = cursor.fetchone()
#	cursor.close()
#	blacklist.close()
#except:
#	print 'Blacklist error'
#	sys.exit(1)

try:
	php_limits = open('smtp/php_limits','w')
	cursor = conn.cursor()
	cursor.execute('SELECT DISTINCT CONCAT(mainftp, ":", hourly_limit) FROM `php_users` ORDER BY mainftp')
	row = cursor.fetchone()
	while row:
		php_limits.write(row[0]+'\n')
		row = cursor.fetchone()
	cursor.close()
	php_limits.close()
except:
	print 'Php limits error'
	sys.exit(1)

try:
	php_limits = open('smtp/php_daily_limits','w')
	cursor = conn.cursor()
	cursor.execute('SELECT DISTINCT CONCAT(mainftp, ":", daily_limit) FROM `php_users` ORDER BY mainftp')
	row = cursor.fetchone()
	while row:
		php_limits.write(row[0]+'\n')
		row = cursor.fetchone()
	cursor.close()
	php_limits.close()
except:
	print 'Php daily limits error'
	sys.exit(1)

try:
	php_alternatives = open('smtp/php_alternatives','w')
	cursor = conn.cursor()
	cursor.execute('SELECT DISTINCT CONCAT(ftp, ":", mainftp) AS item FROM `php_users` WHERE ftp IS NOT NULL AND mainftp IS NOT NULL UNION SELECT DISTINCT CONCAT(jmeno_domeny, ":", mainftp) AS item FROM `php_users` WHERE jmeno_domeny IS NOT NULL AND mainftp IS NOT NULL ORDER BY item')
#	cursor.execute('SELECT DISTINCT CONCAT(ftp, ":", mainftp) FROM `php_users` WHERE ftp IS NOT NULL AND mainftp IS NOT NULL ORDER BY ftp')
	row = cursor.fetchone()
	while row:
		php_alternatives.write(row[0]+'\n')
		row = cursor.fetchone()
	cursor.close()
	php_alternatives.close()
except:
	print 'PHP alternatives error'
	sys.exit(1)

try:
  php_domains = open('smtp/php_domains','w')
  cursor = conn.cursor()
  cursor.execute('SELECT DISTINCT CONCAT(mainftp, ":", jmeno_domeny) FROM `php_users` ORDER BY mainftp')
  row = cursor.fetchone()
  while row:
    php_domains.write(row[0]+'\n')
    row = cursor.fetchone()
  cursor.close()
  php_domains.close()
except:
  print 'Php domains error'
  sys.exit(1)

try:
	smtp_limits = open('smtp/smtp_limits','w')
	cursor = conn.cursor()
	cursor.execute('SELECT CONCAT(jmeno, "@", domena, ":", max_email_daily) FROM `v_smtp` WHERE block_outgoing_mail = 0 ORDER BY domena, jmeno')
	row = cursor.fetchone()
	while row:
		if row[0] != None:
			smtp_limits.write(row[0]+'\n')
		row = cursor.fetchone()
	cursor.close()
	smtp_limits.write('*:0\n')
	smtp_limits.close()
except:
	print 'smtp limits error'
	sys.exit(1)

#try:
#	smtp_password = open('smtp/smtp_password','w')
#	cursor = conn.cursor()
#	cursor.execute('SELECT CONCAT(jmeno, "@", domena, ":", heslo) FROM `v_smtp` WHERE block_outgoing_mail = 0 ORDER BY domena, jmeno')
#	row = cursor.fetchone()
#	while row:
#		if row[0] != None:
#			smtp_password.write(row[0]+'\n')
#		row = cursor.fetchone()
#	cursor.close()
#	smtp_password.close()
#except:
#	print 'smtp password'
#	sys.exit(1)
try:
	smtp_password = open('smtp/smtp_password_sha1','w')
	cursor = conn.cursor()
	cursor.execute('SELECT concat(jmeno, "@", domena, ":",hex(password_ssha)) as mystring FROM `v_smtp` WHERE block_outgoing_mail = 0 AND jmeno IS NOT NULL AND domena IS NOT NULL AND password_ssha is not null ORDER BY domena, jmeno;')
	row = cursor.fetchone()
	while row:
		if row[0] != None:
			smtp_password.write(row[0]+'\n')
		row = cursor.fetchone()
	cursor.close()
	smtp_password.close()
except:
	print 'smtp password sha1'
	sys.exit(1)
try:
	smtp_bd = open('smtp/smtp_blacklist_domain','w')
	cursor = conn.cursor()
	cursor.execute('SELECT `domena` FROM `v_smtp` WHERE `block_outgoing_mail_domain` = 1 GROUP BY `domena`')
	row = cursor.fetchone()
	while row:
		if row[0] != None:
			smtp_bd.write(row[0]+'\n')
		row = cursor.fetchone()
	cursor.close()
	smtp_bd.close()
except:
	print 'smtp blacklist_domain'
	sys.exit(1)
try:
	smtp_top_domains = open('smtp/smtp_top_domains','w')
	cursor = conn.cursor()
	cursor.execute('SELECT CONCAT(jmeno, "@", domena, ":", domena_top) FROM `v_smtp` ORDER BY domena, jmeno')
	row = cursor.fetchone()
	while row:
		if row[0] != None:
			smtp_top_domains.write(row[0]+'\n')
		row = cursor.fetchone()
	cursor.close()
	smtp_top_domains.close()
except:
	print 'smtp top_domains error'
	sys.exit(1)
try:
	smtp_top_domains_limits = open('smtp/smtp_top_domains_limits','w')
	cursor = conn.cursor()
	cursor.execute('SELECT DISTINCT CONCAT(domena_top,":",domain_limit) FROM `v_smtp` ORDER BY domena_top')
	row = cursor.fetchone()
	while row:
		if row[0] != None:
			smtp_top_domains_limits.write(row[0]+'\n')
		row = cursor.fetchone()
	cursor.close()
	smtp_top_domains_limits.close()
except:
	print 'smtp top domains limits error'
	sys.exit(1)


try:
	domain_keys_dir = 'smtp/domain_keys'
	cursor = conn.cursor()
	cursor.execute('SELECT jmeno_domeny, dkim_key FROM `hosting`.`domeny` WHERE `dkim_key` IS NOT NULL')
	dkim_domainlist = []
	while True:
		row = cursor.fetchone()
		if row == None:
			break #This is the end of sql response
		dkim_domain =  row[0]
		dkim_key = row[1]
		if dkim_key:
			dkim_domainlist.append(dkim_domain + '.key')
			#Lets write keys to their files.
			try:
				key_file = open(domain_keys_dir + '/' + dkim_domain + '.key', 'w')
				key_file.write(dkim_key)
			finally:
				key_file.close()
	cursor.close()

	#Now, let's delete old keyfiles, that are no longer in database
	local_key_list = os.listdir(domain_keys_dir)
	files_to_delete = set(local_key_list) - set(dkim_domainlist)
	for file in files_to_delete:
		os.remove(domain_keys_dir + '/' + file)
except:
	print 'DKIM keys error'
	sys.exit(1)


os.chdir('smtp')

#This could also be done while we are creating/removing keyfiles before. But this may be bit faster and efficient. But who knows
os.system('git add domain_keys/*')		#Add new keys to git repo
os.system('git add -u domain_keys/*')	#Remove deleted keys from git repo

#os.execlp('git', 'git', 'commit', 'php_domains', 'php_limits', 'php_daily_limits', 'php_alternatives', 'smtp_limits', 'smtp_password', 'smtp_blacklist_domain','smtp_top_domains','smtp_top_domains_limits', '-m', 'Autocommit')
os.system('git commit php_domains php_limits php_daily_limits php_alternatives smtp_limits smtp_password_sha1 smtp_blacklist_domain smtp_top_domains smtp_top_domains_limits domain_keys -m Autocommit >/dev/null')
