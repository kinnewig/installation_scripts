#! /bin/bash

# This installation script follows the guide
# https://www.linuxbabe.com/mail-server/build-email-server-from-scratch-debian-postfix-smtp

# The chapter is marked in commends

# =======================================
# Settings
# =======================================

POSTFIXADMIN_VER=3.3.10
PHPV=8.0

# Installation path
pfaroot=/var/www
pfapath=/var/www/postfixadmin

# MariaDB
DB_ADMIN=postfix_admin
DB_NAME=postfix

# domain
username=sebastian
domain=kinnewig.org

# Certificates
ssl_cert="/etc/ssl/certs/ssl-cert-snakeoil.pem"
ssl_key="/etc/ssl/private/ssl-cert-snakeoil.key"
ssl_cert_sed="\/etc\/ssl\/certs\/ssl-cert-snakeoil.pem"
ssl_key_sed="\/etc\/ssl\/private\/ssl-cert-snakeoil.key"

# =======================================
# Preamble
# =======================================

# exit when any command fails
set -e

[[ ${EUID} -ne 0 ]] && {
  printf "Must be run as root. Try 'sudo $0'\n"
  exit 1
}

# check if the password file already exists, if it does not exist create a file
if [ -f "/root/.postfix.cnf" ]; then
  touch /root/.postfix.cnf
fi

# get the password for the databse
DB_PWD=$(grep "database password" /root/.postfix.cnf | sed 's|database password=||');
if [ -z "$DB_PWD" ]; then
  echo "Creating password for the mysql user mail_db"
  DB_PWD=$(echo $RANDOM | md5sum | head -c 32; echo;)
  cat >> /root/.postfix.cnf <<EOF
database password=$DB_PWD
EOF
fi

# get the setup password
echo "Enter the setup password"
SETUP_TEST_PWD=true
while ${NC_TEST_PWD} ; do
  read -s -p "Enter the password: " SETUP_PWD_1
  echo ""
  read -s -p "Retype the password: " SETUP_PWD_2
  echo ""

  if [ ${SETUP_PWD_1} = ${SETUP_PWD_2} ] ; then
    SETUP_TEST_PWD=false
    SETUP_PWD=${SETUP_PWD_1}
  fi
done

# update
apt-get update
apt-get upgrade -yqq



# =======================================
# (Step 1): Postfix 
# =======================================

# === (1.4) Install Postfix SMTP Server on Debian Server ===
echo "Install Postfix"
apt-get install -yqq postfix


# === (1.5, 2.1) Configure firewall === 
echo "Install and configure Firewall (ufw)"
apt-get install -yqq ufw

# allow ssh
ufw allow ssh

# allow http
ufw allow 80

# allow https
ufw allow 443

# allow inbound email
ufw allow 25/tcp

# email
ufw allow 465

uwf allow 587

# allow IMAP
ufw allow 143

# allow IMAPS
ufw allow 993/tcp

# allow POP3
ufw allow 110
ufw allow 995/tcp

ufw enable


# === (1.8) Attachment size ===
echo "Increase attachment size"
# allow attachment of 50MB in size
#postconf -e message_size_limit=52428800

# allow attachment of 100MB in size
postconf -e message_size_limit=104857600


# === (1.9) Setting the Postfix Hostname ===
echo "Set Hostname"
sed -i "s/myhostname = */myhostname =${domain}/" /etc/postfix/main.cf

systemctl restart postfix


# === (1.10) Creating Email Alias ===
echo "Set Alias"
cat >> /etc/aliases <<EOF
root:   ${USERNAME}
EOF



# =======================================
# (Step 2): Installing Dovecot IMAP Server 
# =======================================

# === (2.3) Enable Submission Service in Postfix ===
echo "Configure Submission Service in Postfix"
echo "  configure /etc/postfix/master.cf"
cat >> /etc/postfix/master.cf <<EOF
submission     inet     n    -    y    -    -    smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_tls_wrappermode=no
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
# For Outlook
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
EOF

systemctl restart postfix

# TLS
echo "  configure /etc/postfix/main.cf"
sed -i "s/smtpd_tls_cert_file=\/etc\/ssl\/certs\/ssl-cert-snakeoil.pem/smtpd_tls_cert_file=${ssl_cert_sed}/" /etc/postfix/main.cf
sed -i "s/smtpd_tls_key_file=\/etc\/ssl\/private\/ssl-cert-snakeoil.key/smtpd_tls_key_file=${ssl_key_sed}/" /etc/postfix/main.cf
cat >> /etc/postfix/main.cf << EOF

#Enable TLS Encryption when Postfix receives incoming emails
smtpd_tls_loglevel = 1
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache

#Enable TLS Encryption when Postfix sends outgoing emails
smtp_tls_security_level = may
smtp_tls_loglevel = 1
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache

#Enforce TLSv1.3 or TLSv1.2
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
EOF


# === (2.4) Installing Dovecot IMAP Server ===
echo "Insall Dovecot"
apt-get install -yqq dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd


# === (2.5) Enabling IMAP/POP3 Protocol ===
echo "  configure /etc/dovecot/dovecot.conf"
sed -i "s/# Enable installed protocols/# Enable installed protocols\nprotocols = imap pop3 lmtp/" /etc/dovecot/dovecot.conf


# === (2.6) Configuring Mailbox Location ===
# will be overwritten in (3.12)
#sed -i 's/mail_location = mbox:~\/mail:INBOX=\/var\/mail\/%u/mail_location = maildir:~\/Maildir/' /etc/dovecot/conf.d/10-mail.conf

# add dovecot to the mail group so that Dovecot can read the INBOX
adduser dovecot mail


# === (2.7) Using Dovecot to Deliver Email to Message Store ===
echo "  configure /etc/dovecot/conf.d/10-master.conf"
sed -i 's/  unix_listener lmtp {/  unix_listener \/var\/spool\/postfix\/private\/dovecot-lmtp {\n    mode = 0600\n    user = postfix\n    group = postfix/' /etc/dovecot/conf.d/10-master.conf

# The first line tells Postfix to deliver incoming emails to local message store via the Dovecot LMTP server. 
# The second line disables SMTPUTF8 in Postfix, because Dovecot-LMTP doesn’t support this email extension
echo "configure /etc/postfix/main.cf"
cat >> /etc/postfix/main.cf <<EOF
mailbox_transport = lmtp:unix:private/dovecot-lmtp
smtputf8_enable = no
EOF


# === (2.8) Configuring User Authentication Mechanism ===
echo "  configure /etc/dovecot/conf.d/10-auth.conf"
sed -i 's/#disable_plaintext_auth = yes/disable_plaintext_auth = yes/' /etc/dovecot/conf.d/10-auth.conf
#sed -i 's/#auth_username_format = %Lu/auth_username_format = %n/' /etc/dovecot/conf.d/10-auth.conf # will be overwritten in (3.12)
sed -i 's/auth_mechanisms = plain/auth_mechanisms = plain login/' /etc/dovecot/conf.d/10-auth.conf


# === (2.9) Configuring SSL/TLS Encryption ===
echo "  configure /etc/dovecot/conf.d/10-ssl.conf"
sed -i "s/ssl = yes/ssl = required/" /etc/dovecot/conf.d/10-ssl.conf
sed -i "s/ssl_cert = <\/etc\/dovecot\/private\/dovecot.pem/ssl_cert = <${ssl_cert_sed}/" /etc/dovecot/conf.d/10-ssl.conf
sed -i "s/ssl_key = <\/etc\/dovecot\/private\/dovecot.key/ssl_key = <${ssl_key_sed}/" /etc/dovecot/conf.d/10-ssl.conf
sed -i "s/#ssl_prefer_server_ciphers = no/ssl_prefer_server_ciphers = yes/" /etc/dovecot/conf.d/10-ssl.conf
sed -i "s/#ssl_min_protocol = TLSv1/ssl_min_protocol = TLSv1.2/" /etc/dovecot/conf.d/10-ssl.conf


# === (2.10) Configuring SASL Authentication ===
echo "  configure /etc/dovecot/conf.d/10-master.conf"
sed -i "s/  unix_listener auth-userdb {/  unix_listener \/var\/spool\/postfix\/private\/auth {\n    mode = 0660\n    user = postfix\n    group = postfix/" /etc/dovecot/conf.d/10-master.conf

systemctl restart postfix dovecot



# =======================================
# (Part 3): PostfixAdmin – Create Virtual Mailboxes 
# =======================================
# In this step I changed the order:

# === (3.7) Install Required and Recommended PHP Modules ===
echo "Install PHP"
apt-get install -yqq php${PHPV}-fpm php${PHPV}-imap php${PHPV}-mbstring  \
                     php${PHPV}-curl php${PHPV}-zip php${PHPV}-xml       \
                     php${PHPV}-bz2 php${PHPV}-intl php${PHPV}-gmp

# For PHPV > 8 Json was moved into the core package
if [[ ${PHPV} < 8 ]]; then
    apt-get install -yqq php${PHPV}-json
fi


# === (3.1) Install MariaDB Database Server ===
# We assume MariaDB is already installed and configured
# apt-get install php${PHPV}-mysql

# === (3.4) Create PostfixAdmin Database ===
echo "Create MariaDB Database"
mysql <<EOF
CREATE DATABASE $DB_NAME;
CREATE USER '$DB_ADMIN'@'localhost' IDENTIFIED BY '$DB_PWD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO $DB_ADMIN@localhost;
FLUSH PRIVILEGES;
EOF

# === (3.2) Download PostfixAdmin ===

# Download and extract PostfixAdmin
echo "Install PostfixAdmin"
cd $pfaroot
wget -O postfixadmin.tgz https://github.com/postfixadmin/postfixadmin/archive/postfixadmin-${POSTFIXADMIN_VER}.tar.gz
tar -zxf postfixadmin.tgz
rm postfixadmin.tgz
mv postfixadmin-postfixadmin-${POSTFIXADMIN_VER} postfixadmin
cd $pfapath


# === (3.3) Setting Up Permissions === 
mkdir -p $pfapath/templates_c

apt-get install -yqq acl
setfacl -R -m u:www-data:rwx $pfapath/templates_c

# Permission for Encrypt TLS certificate
setfacl -R -m u:www-data:rx ${ssl_cert} 
setfacl -R -m u:www-data:rx ${ssl_key}


# === (3.5) Configure PostfixAdmin ===
echo "Configure PostfixAdmin"
echo "  create /var/www/postfixadmin/config.local.php"
cat > /var/www/postfixadmin/config.local.php <<EOF
<?php
$CONF['configured'] = true;
$CONF['database_type'] = 'mysql';
$CONF['database_host'] = 'localhost';
$CONF['database_port'] = '3306';
$CONF['database_user'] = '${DB_ADMIN}';
$CONF['database_password'] = '${DB_PWD}';
$CONF['database_name'] = '${DB_NAME}';
$CONF['encrypt'] = 'dovecot:ARGON2I';
$CONF['dovecotpw'] = "/usr/bin/doveadm pw -r 5";
if(@file_exists('/usr/bin/doveadm')) { // @ to silence openbase_dir stuff; see https://github.com/postfixadmin/postfixadmin/issues/171
    $CONF['dovecotpw'] = "/usr/bin/doveadm pw -r 5"; # debian
}
EOF



# === (3.6, 3.8) Create Apache Virtual Host Config File for PostfixAdmin ===
echo "Create Apache Virtual Host Config File for PostfixAdmin"
cat > /etc/apache2/sites-available/postfixadmin.conf <<EOF
<VirtualHost *:80> 
  ServerName postfixadmin.${domain}
  ServerAlias www.postfixadmin.${domain}

  Redirect permanent / https://postfixadmin.${domain}
</VirtualHost>

<IfModule mod_ssl.c>
  <VirtualHost _default_:443>

    ServerName postfixadmin.${domain}
    DocumentRoot ${pfapath}/public

    ErrorLog \${APACHE_LOG_DIR}/postfixadmin_error.log
    CustomLog \${APACHE_LOG_DIR}/postfixadmin_access.log combined

    SSLEngine on
    SSLCertificateFile ${ssl_cert}
    SSLCertificateKeyFile ${ssl_key}

    <FilesMatch \.php$>
      SetHandler "proxy:unix:/run/php/php${PHPV}-fpm.sock|fcgi://localhost"
    </FilesMatch>

    <Directory />
      Options FollowSymLinks
      AllowOverride All
    </Directory>

    <Directory ${pfapath}/>
      Options FollowSymLinks MultiViews
      AllowOverride All
      Order allow,deny
      allow from all
    </Directory>

  </VirtualHost>
</IfModule>
EOF

a2ensite postfixadmin.conf
systemctl reload apache2


# === (3.9) Enable Statistics in Dovecot ===

# PostfixAdmin needs to read Dovecot statistics
cat >> /etc/dovecot/conf.d/10-master.conf <<EOF
service stats {
    unix_listener stats-reader {
    user = www-data
    group = www-data
    mode = 0660
}

unix_listener stats-writer {
    user = www-data
    group = www-data
    mode = 0660
  }
}
EOF

# Then add the web server to the dovecot group.
sudo gpasswd -a www-data dovecot
sudo systemctl restart dovecot

=== (3.10) ===
# get the hash of the setup password
HASH_SETUP_PWD=$(php -r "echo password_hash('${SETUP_PWD}', PASSWORD_DEFAULT);") 

cat >> /var/www/postfixadmin/config.local.php <<EOF
$CONF['setup_password'] = '${HASH_SETUP_PWD}';
EOF

# === (3.11) Configure Postfix to Use MySQL/MariaDB Database

# Install MySQL map support for Postfix
apt-get install -yqq postfix-mysql

cat >> /etc/postfix/main.cf <<EOF
virtual_mailbox_domains = proxy:mysql:/etc/postfix/sql/mysql_virtual_domains_maps.cf
virtual_mailbox_maps =
   proxy:mysql:/etc/postfix/sql/mysql_virtual_mailbox_maps.cf,
   proxy:mysql:/etc/postfix/sql/mysql_virtual_alias_domain_mailbox_maps.cf
virtual_alias_maps =
   proxy:mysql:/etc/postfix/sql/mysql_virtual_alias_maps.cf,
   proxy:mysql:/etc/postfix/sql/mysql_virtual_alias_domain_maps.cf,
   proxy:mysql:/etc/postfix/sql/mysql_virtual_alias_domain_catchall_maps.cf
virtual_transport = lmtp:unix:private/dovecot-lmtp
EOF

# Create the .cf files:
mkdir -p /etc/postfix/sql/

cat > /etc/postfix/sql/mysql_virtual_domains_maps.cf <<EOF
user = ${DB_ADMIN}
password = ${DB_PWD}
hosts = localhost
dbname = ${DB_NAME}
query = SELECT domain FROM domain WHERE domain='%s' AND active = '1'
#query = SELECT domain FROM domain WHERE domain='%s'
#optional query to use when relaying for backup MX
#query = SELECT domain FROM domain WHERE domain='%s' AND backupmx = '0' AND active = '1'
#expansion_limit = 100
EOF

cat > /etc/postfix/sql/mysql_virtual_mailbox_maps.cf <<EOF
user = ${DB_ADMIN}
password = ${DB_PWD}
hosts = localhost
dbname = ${DB_NAME}
query = SELECT maildir FROM mailbox WHERE username='%s' AND active = '1'
#expansion_limit = 100
EOF

cat > /etc/postfix/sql/mysql_virtual_alias_domain_mailbox_maps.cf <<EOF
user = ${DB_ADMIN}
password = ${DB_PWD}
hosts = localhost
dbname = ${DB_NAME}
query = SELECT maildir FROM mailbox,alias_domain WHERE alias_domain.alias_domain = '%d' and mailbox.username = CONCAT('%u', '@', alias_domain.target_domain) AND mailbox.active = 1 AND alias_domain.active='1'
EOF

cat > /etc/postfix/sql/mysql_virtual_alias_maps.cf <<EOF
user = ${DB_ADMIN}
password = ${DB_PWD}
hosts = localhost
dbname = ${DB_NAME}
query = SELECT goto FROM alias WHERE address='%s' AND active = '1'
#expansion_limit = 100
EOF

cat > /etc/postfix/sql/mysql_virtual_alias_domain_maps.cf<<EOF
user = ${DB_ADMIN}
password = ${DB_PWD}
hosts = localhost
dbname = ${DB_NAME}
query = SELECT goto FROM alias,alias_domain WHERE alias_domain.alias_domain = '%d' and alias.address = CONCAT('%u', '@', alias_domain.target_domain) AND alias.active = 1 AND alias_domain.active='1'
EOF

cat >  /etc/postfix/sql/mysql_virtual_alias_domain_catchall_maps.cf <<EOF
# handles catch-all settings of target-domain
user = ${DB_ADMIN}
password = ${DB_PWD}
hosts = localhost
dbname = ${DB_NAME}
query = SELECT goto FROM alias,alias_domain WHERE alias_domain.alias_domain = '%d' and alias.address = CONCAT('@', alias_domain.target_domain) AND alias.active = 1 AND alias_domain.active='1'
EOF

sudo chmod 0640 /etc/postfix/sql/*
sudo setfacl -R -m u:postfix:rx /etc/postfix/sql/


# === (3.12) Configure Dovecot to Use MySQL/MariaDB Database ===
apt-get install -yqq dovecot-mysql

# virtual mailbox 
sed -i 's/mail_location = mbox:~\/mail:INBOX=\/var\/mail\/%u/mail_location = maildir:~\/Maildir\nmail_home = \/var\/vmail\/%d\/%n\//' /etc/dovecot/conf.d/10-mail.conf

# This allows users to login with the full email address
sed -i 's/#auth_username_format = %Lu/auth_username_format = %u/' /etc/dovecot/conf.d/10-auth.conf 

# Dovecot can query user information from MySQL/MariaDB database
sed -i 's/#!include auth-sql.conf.ext/!include auth-sql.conf.ext/' /etc/dovecot/conf.d/10-auth.conf 

# Dovecot won’t query the local /etc/passwd or /etc/shadow file
sed -i 's/!include auth-system.conf.ext/#!include auth-system.conf.ext/' /etc/dovecot/conf.d/10-auth.conf 

# DEBUG
#cat >> /etc/dovecot/conf.d/10-auth.conf <<EOF
#auth_debug = yes
#auth_debug_passwords = yes
#EOF

cat >> /etc/dovecot/dovecot-sql.conf.ext <<EOF
driver = mysql

connect = host=localhost dbname=${DB_NAME} user=${DB_ADMIN} password=${DB_PWD}

default_pass_scheme = ARGON2I

password_query = SELECT username AS user,password FROM mailbox WHERE username = '%u' AND active='1'

user_query = SELECT maildir, 2000 AS uid, 2000 AS gid FROM mailbox WHERE username = '%u' AND active='1'

iterate_query = SELECT username AS user FROM mailbox
EOF

systemctl restart dovecot

echo "======================================================"
echo "DONE!"
