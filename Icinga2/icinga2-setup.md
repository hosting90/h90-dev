Server přidat do VLAN 'H90 VPN'

# Icinga2

yum -y update
yum -y install centos-release-scl
yum -y install epel-release
yum -y install https://packages.icinga.com/epel/icinga-rpm-release-7-latest.noarch.rpm
yum -y install icinga2
yum -y install nagios-plugins-all check_nrpe php php-xmlrpc.x86_64
yum -y install vim-icinga2 
git clone git://git.hosting90.cz/autohosting.git /root/server
yum -y install /root/server/virtual/rfoo-1.3.0-1-el7.x86_64.rpm
systemctl enable icinga2 

_Now we have basic Icinga2 setup installed_

# Icinga2web2 na mariadb
yum -y install mariadb-server mariadb
systemctl enable mariadb
systemctl start mariadb
mysql_secure_installation

yum -y install icinga2-ido-mysql

*POZOR - je potřeba specificky instalovat PHP7*
rh-php72-php-mysqlnd