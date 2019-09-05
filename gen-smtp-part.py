#!/usr/bin/python

import MySQLdb, os, sys

try:
	conn = MySQLdb.connect(host = "db-devel.hosting90.cz",
		user = "root",
		passwd = "Nd6E7k1cL6mW",
		db = "hosting")
except MySQLdb.Error, e:
	print 'MySQL Error'
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



# 	try:
# 	smtp_top_domains_limits = open('smtp/smtp_top_domains_limits','w')
# 	cursor = conn.cursor()
# 	cursor.execute('SELECT DISTINCT CONCAT(domena_top,":",domain_limit) FROM `v_smtp` ORDER BY domena_top')
# 	row = cursor.fetchone()
# 	while row:
# 		if row[0] != None:
# 			smtp_top_domains_limits.write(row[0]+'\n')
# 		row = cursor.fetchone()
# 	cursor.close()
# 	smtp_top_domains_limits.close()
# except:
# 	print 'smtp top domains limits error'
# 	sys.exit(1)