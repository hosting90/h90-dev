#!/usr/bin/python

import sys,os
sys.path.append('/root/server/command/plugins')
sys.path.append('/root/server/command')
import mydns

zonefile = os.path.abspath(sys.argv[1])
zonefile_basename = os.path.basename(zonefile)
if zonefile_basename.endswith('.zone'):
	domain = zonefile_basename.replace('.zone','')
else:
	domain = zonefile_basename
sign_result = mydns.sign_and_compile(domain,zonefile,'/var/named/master-compiled/%s' % domain,increment_serial=True)
print '''Domain:\t\t%s
Source file:\t%s
Dest. file:\t%s
Signing result:\t%s''' % (domain,zonefile,'/var/named/master-compiled/%s' % domain,sign_result)
if sign_result:
	os.system('rndc reload '+domain)
