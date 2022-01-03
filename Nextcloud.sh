#! /bin/bash

# =======================================
# Settings
# =======================================

NCVER=23.0.0
PHPV=8.0

# Redis
REDIS_MEM=4gb # recommended 70% of total available memory

# FPM: Use https://spot13.com/pmcalculator/
FPM_MAX_CHILDREN=14
FPM_START_SERVERS=3
FPM_SPARE_SERVERS=3
FPM_MAX_SPARSE_SERVERS=10

MAXFILESIZE=16G
MEMORYLIMIT=4G
MAXTRANSFERTIME=600

# Installation path
ncroot=/var/www
ncpath=/var/www/nextcloud

# MariaDB
DB_ADMIN=ncadmin
DB_NAME=nextcloud

# Nextcloud Admin User
NCADMIN_USER=sebastian_admin

# domain
domain=cloud.kinnewig.org



# =======================================
# Preamble
# =======================================

# exit when any command fails
set -e

[[ ${EUID} -ne 0 ]] && {
  printf "Must be run as root. Try 'sudo $0'\n"
  exit 1
}

# get the password for the Nextcloud admin user
echo "Enter a password for the Nextcloud admin user"
NC_TEST_PWD=true
while ${NC_TEST_PWD} ; do
  read -s -p "Enter the password: " NC_PWD_1
  echo ""
  read -s -p "Retype the password: " NC_PWD_2
  echo ""

  if [ ${NC_PWD_1} = ${NC_PWD_2} ] ; then
    NC_TEST_PWD=false
    NCADMIN_PWD=${NC_PWD_1}
  fi
done

# check if the password file already exists, if it does not exist create a file
if [ -f "/root/.mariadb.cnf" ]; then
  touch /root/.mariadb.cnf
fi
# get the password for MariaDB Root
MARIA_ROOT_PWD=$(grep "redis password" /root/.mariadb.cnf | sed 's|root password=||');
if [ -z "$MARIA_ROOT_PWD" ]; then
  echo "Creating root password for MariaDB"
  MARIA_ROOT_PWD=$(echo $RANDOM | md5sum | head -c 32; echo;)
  cat >> /root/.mariadb.cnf <<EOF
root password=$MARIA_ROOT_PWD
EOF
fi

# check if the password file already exists, if it does not exist create a file
if [ -f "/root/.nextcloud.cnf" ]; then
  touch /root/.nextcloud.cnf
fi

# get the password for the databse
DB_PWD=$(grep "database password" /root/.nextcloud.cnf | sed 's|database password=||');
if [ -z "$DB_PWD" ]; then
  echo "Creating password for the mysql user nc_admin"
  DB_PWD=$(echo $RANDOM | md5sum | head -c 32; echo;)
  cat >> /root/.nextcloud.cnf <<EOF
database password=$DB_PWD
EOF
fi

# get the password for redis
REDIS_PWD=$(grep "redis password" /root/.nextcloud.cnf | sed 's|redis password=||');
if [ -z "$REDIS_PWD" ]; then
  echo "Creating password for redis"
  REDIS_PWD=$(echo $RANDOM | md5sum | head -c 32; echo;)
  cat >> /root/.nextcloud.cnf <<EOF
redis password=$REDIS_PWD
EOF
fi

# update
apt-get update
apt-get upgrade -yqq



# =======================================
# LAMP
# =======================================

echo "Install dependecies"
apt-get install -yqq curl wget
apt-get install -yqq apt-utils cron curl
apt-get install -yqq ssl-cert # self signed snakeoil certs

# === Samba ===
echo "Install Samba"
apt-get install -yqq samba

# === Install PHP ===
echo "Install PHP${PHPV}"

# get latest php
apt-get install -yqq lsb-release ca-certificates apt-transport-https software-properties-common gnupg2
echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/sury-php.list
wget -qO - https://packages.sury.org/php/apt.gpg | sudo apt-key add -

apt-get update
apt-get install -yqq php${PHPV}

# Required PHP-packages for Nextcloud:
apt-get install -yqq php${PHPV}-ctype php${PHPV}-curl php${PHPV}-dom php${PHPV}-gd php${PHPV}-iconv \
                     php${PHPV}-mbstring php${PHPV}-posix  \
                     php${PHPV}-simplexml php${PHPV}-xml php${PHPV}-xmlreader php${PHPV}-xmlwriter php${PHPV}-zip 
                     
# Not used:
# php${PHPV}-zlib php${PHPV}-session php${PHPV}-openssl php${PHPV}-libxml 

# For PHPV > 8 Json was moved into the core package
if [[ ${PHPV} < 8 ]]; then
    apt-get install -yqq php${PHPV}-json
fi

# Recommended packages for Nextcloud:
apt-get install -yqq php${PHPV}-bz2 php${PHPV}-fileinfo php${PHPV}-intl php${PHPV}-gmp php${PHPV}-bcmath

# Required for specific apps:
apt-get install -yqq php${PHPV}-ldap php${PHPV}-smbclient php${PHPV}-ftp php${PHPV}-exif

# For enhanced server performance
apt-get install -yqq php${PHPV}-apcu 
apt-get install -yqq php${PHPV}-cli php${PHPV}-fpm php${PHPV}-opcache 

# Languages
# apt-get install -yqq php${PHPV}-german

# For preview generation
apt-get install -yqq php${PHPV}-imagick ffmpeg


# === Install and configure Apache2 ===
echo "Install apache2"
apt-get install -yqq apache2
systemctl enable apache2
systemctl start apache2

# Configure Apache for HTTP/2
cat > /etc/apache2/conf-available/http2.conf <<EOF
Protocols h2 h2c http/1.1

# HTTP2 configuration
H2Push          on
H2PushPriority  *                       after
H2PushPriority  text/css                before
H2PushPriority  image/jpeg              after   32
H2PushPriority  image/png               after   32
H2PushPriority  application/javascript  interleaved

# SSL/TLS Configuration
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLHonorCipherOrder on
SSLCipherSuite ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS
SSLCompression          off
SSLSessionTickets       on

# OCSP Stapling
SSLUseStapling          on
SSLStaplingResponderTimeout 5
SSLStaplingReturnResponderErrors off
SSLStaplingCache        shmcb:/var/run/ocsp(128000)
EOF

# Configure Apache for opcache
cat > /etc/php/${PHPV}/mods-available/opcache.ini <<EOF
zend_extension=opcache.so
opcache.enable=1
opcache.enable_cli=1
opcache.fast_shutdown=1
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=10000
opcache.memory_consumption=128
opcache.save_comments=1
opcache.revalidate_freq=1
opcache.file_cache=/tmp;
EOF

# enable http2
a2enmod http2
a2enconf http2

# enable php-fpm
systemctl start php${PHPV}-fpm
systemctl enable php${PHPV}-fpm
sudo a2dismod php${PHPV}
a2enconf php${PHPV}-fpm
a2enmod proxy_fcgi setenvif

# configure php-fpm
FPM_CONF=/etc/php/${PHPV}/fpm/pool.d/www.conf
sed -i "s|^pm.max_children =.*|pm.max_children = $FPM_MAX_CHILDREN|" "$FPM_CONF"
sed -i "s|^pm.start_servers =.*|pm.start_servers = $FPM_START_SERVERS|" "$FPM_CONF"
sed -i "s|^pm.min_spare_servers=.*|pm.min_spare_servers = $FPM_SPARE_SERVERS|" "$FPM_CONF"
sed -i "s|^pm.max_spare_servers=.*|pm.max_spare_servers = $FPM_MAX_SPARSE_SERVERS|" "$FPM_CONF"

# increase memorylimit
sed -i 's/memory_limit = 128M/memory_limit = 1024M/g' /etc/php/${PHPV}/fpm/php.ini

# by Nextcloud required:
a2enmod rewrite

# by Nextcloud recomended:
a2enmod headers
a2enmod env
a2enmod dir
a2enmod mime

# enable https
a2enmod ssl

# for notify_push app in NC21
a2enmod proxy proxy_http proxy_wstunnel

systemctl restart apache2
systemctl reload php${PHPV}-fpm


# =======================================
# MariaDB
# =======================================

echo "Install MariaDB"
debconf-set-selections <<< "mariadb-server-5.5 mysql-server/root_password password $MARIA_ROOT_PWD"
debconf-set-selections <<< "mariadb-server-5.5 mysql-server/root_password_again password $MARIA_ROOT_PWD"
apt-get install -yqq mariadb-server php${PHPV}-mysql

mkdir -p /run/mysqld
chown mysql /run/mysqld

# configure MariaDB (UTF8 4 byte support)
cat > /etc/mysql/mariadb.conf.d/90-ncp.cnf <<EOF
[mysqld]
datadir = /var/lib/mysql
EOF

cat > /etc/mysql/mariadb.conf.d/91-ncp.cnf <<EOF
[mysqld]
transaction_isolation = READ-COMMITTED
innodb_large_prefix=true
innodb_file_per_table=1
innodb_file_format=barracuda

[server]
# innodb settings
skip-name-resolve
innodb_buffer_pool_size = 256M
innodb_buffer_pool_instances = 1
innodb_flush_log_at_trx_commit = 2
innodb_log_buffer_size = 32M
innodb_max_dirty_pages_pct = 90
innodb_log_file_size = 32M

# disable query cache
query_cache_type = 0
query_cache_size = 0

# other
tmp_table_size= 64M
max_heap_table_size= 64M
EOF

# === launch mariadb if not already running ===
if ! pgrep -c mysqld &>/dev/null; then
  echo "Starting mariaDB"
  mysqld &
fi

# === Wait for MariaDB ===
while :; do
  [[ -S /run/mysqld/mysqld.sock ]] && break
  sleep 0.5
done


# === Sequre Installation ===
mysql_secure_installation <<EOF

y
$MARIA_ROOT_PWD
$MARIA_ROOT_PWD
y
y
y
y
EOF

# === Create Nextcloud Database ===
mysql <<EOF
CREATE DATABASE $DB_NAME
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_general_ci;
GRANT USAGE ON *.* TO '$DB_ADMIN'@'localhost' IDENTIFIED BY '$DB_PWD';
DROP USER '$DB_ADMIN'@'localhost';
CREATE USER '$DB_ADMIN'@'localhost' IDENTIFIED BY '$DB_PWD';
GRANT ALL PRIVILEGES ON nextcloud.* TO $DB_ADMIN@localhost;
EXIT
EOF



# =======================================
# Install Redis
# =======================================

apt-get install -yqq postfix
apt-get install -yqq redis-server
apt-get install -yqq php${PHPV}-redis

# Configure Redis
REDIS_CONF=/etc/redis/redis.conf
sed -i "s|# unixsocket .*|unixsocket /var/run/redis/redis.sock|" $REDIS_CONF
sed -i "s|# unixsocketperm .*|unixsocketperm 770|"               $REDIS_CONF
sed -i "s|# requirepass .*|requirepass $REDIS_PWD|"              $REDIS_CONF
sed -i 's|# maxmemory-policy .*|maxmemory-policy allkeys-lru|'   $REDIS_CONF
sed -i 's|# rename-command CONFIG ""|rename-command CONFIG ""|'  $REDIS_CONF
sed -i "s|^port.*|port 0|"                                       $REDIS_CONF
echo "maxmemory $REDIS_MEM" >> $REDIS_CONF

# activate session lock
echo "redis.session.locking_enabled=1" >> /etc/php/${PHPV}/fpm/php.ini
echo "redis.session.lock_retries=-1" >> /etc/php/${PHPV}/fpm/php.ini
echo "redis.session.lock_wait_time=10000" >> /etc/php/${PHPV}/fpm/php.ini

echo 'vm.overcommit_memory = 1' >> /etc/sysctl.conf

# add the webserver user to the redis group:
usermod -a -G redis www-data

## SET LIMITS
cat > /etc/php/${PHPV}/fpm/conf.d/90-ncp.ini <<EOF
; disable .user.ini files for performance and workaround NC update bugs
user_ini.filename =

; from Nextcloud .user.ini
upload_max_filesize=$MAXFILESIZE
post_max_size=$MAXFILESIZE
memory_limit=$MEMORYLIMIT
mbstring.func_overload=0
always_populate_raw_post_data=-1
default_charset='UTF-8'
output_buffering=0

; slow transfers will be killed after this time
max_execution_time=$MAXTRANSFERTIME
max_input_time=$MAXTRANSFERTIME
EOF

# restart redis
service redis-server restart
update-rc.d redis-server enable
service php${PHPV}-fpm restart
systemctl restart apache2



# =======================================
# Nextcloud
# =======================================

# Download and extract Nextcloud
cd $ncroot
curl https://download.nextcloud.com/server/releases/nextcloud-$NCVER.tar.bz2 --output nextcloud.tar.bz2
tar -xf nextcloud.tar.bz2
rm nextcloud.tar.bz2
cd nextcloud
#git submodule update --init

# Creating possible missing Directories
mkdir -p $ncpath/data
mkdir -p $ncpath/data/tmp # upload folder
mkdir -p $ncpath/updater

# update permissions
chown -R www-data:www-data $ncpath

# install nextcloud
sudo -u www-data php occ  maintenance:install --database \
  "mysql" --database-name "$DB_NAME"  --database-user "$DB_ADMIN" --database-pass \
  "$DB_PWD" --admin-user "$NCADMIN_USER" --admin-pass "$NCADMIN_PWD"

# background job
sudo -u www-data php occ background:cron

# create and configure opcache dir
OPCACHEDIR=$ncpath/data/.opcache
  sed -i "s|^opcache.file_cache=.*|opcache.file_cache=$OPCACHEDIR|" /etc/php/${PHPV}/mods-available/opcache.ini
  mkdir -p $OPCACHEDIR
  chown -R www-data:www-data $OPCACHEDIR



# =======================================
# Config
# =======================================

# === Redis ===
sed -i '$d' config/config.php
CURRENT_REDIS_PWD=$( grep "^requirepass" /etc/redis/redis.conf  | cut -d' ' -f2 )
cat >> $ncpath/config/config.php <<EOF
  'memcache.locking' => '\OC\Memcache\Redis',
  'memcache.local' => '\OC\Memcache\Redis',
  'memcache.distributed' => '\OC\Memcache\Redis',
  'redis' =>
  array (
    'host' => '/var/run/redis/redis.sock',
    'port' => 0,
    'timeout' => 0.0,
    'password' => '$CURRENT_REDIS_PWD',
  ),
);
EOF

# tmp upload folder
sudo -u www-data php occ config:system:set tempdirectory --value "$ncpath/data/tmp"
sed -i "s|^;\?upload_tmp_dir =.*$|upload_tmp_dir = $ncpath/data/tmp|" /etc/php/${PHPV}/cli/php.ini
sed -i "s|^;\?upload_tmp_dir =.*$|upload_tmp_dir = $ncpath/data/tmp|" /etc/php/${PHPV}/fpm/php.ini
sed -i "s|^;\?sys_temp_dir =.*$|sys_temp_dir = $ncpath/data/tmp|"     /etc/php/${PHPV}/fpm/php.ini

# Set time zone
sudo -u www-data php occ config:system:set logtimezone --value="Europe/Berlin"

# 4 Byte UTF8 support
sudo -u www-data php occ config:system:set mysql.utf8mb4 --type boolean --value="true"

# Set domain
# try to get the current ip
CURRENT_IP=$(ifconfig | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | head -1)
sudo -u www-data php occ config:system:set trusted_domains 1 --value="${domain}"
sudo -u www-data php occ config:system:set trusted_domains 2 --value="${CURRENT_IP}"

# email
sudo -u www-data php occ config:system:set mail_smtpmode     --value="sendmail"
sudo -u www-data php occ config:system:set mail_smtpauthtype --value="LOGIN"
sudo -u www-data php occ config:system:set mail_from_address --value="noreply"
sudo -u www-data php occ config:system:set mail_domain       --value="${domain}"

# https
sudo -u www-data php occ config:system:set overwriteprotocol --value=https
sudo -u www-data php occ config:system:set overwrite.cli.url --value="${domain}"

# bash auto completion
apt-get install -yqq bash-completion
sudo -u www-data php occ _completion -g --shell-type bash -p occ > /usr/share/bash-completion/completions/occ
echo ". /etc/bash_completion" >> /etc/bash.bashrc
echo ". /usr/share/bash-completion/completions/occ" >> /etc/bash.bashrc



# =======================================
# Apps
# =======================================

cd $ncpath

# === Install apps ===
sudo -u www-data php occ app:install calendar

sudo -u www-data php occ app:install contacts

sudo -u www-data php occ app:install news

sudo -u www-data php occ app:install notes

sudo -u www-data php occ app:install polls

sudo -u www-data php occ app:install cookbook

sudo -u www-data php occ app:install bookmarks

# === External sites ===
# Link external sites
sudo -u www-data php occ app:install external

# === Talk ===
sudo -u www-data php occ app:install spreed

# === document server ===
# Collabora Online
sudo -u www-data php occ app:install richdocuments
# Collabora Online - Built-in CODE Server
sudo -u www-data php -d memory_limit=512M occ app:install richdocumentscode

# === keepass ===
sudo -u www-data php occ app:install keeweb

# === Preview generator ===
sudo -u www-data php occ app:install previewgenerator

# only create previwes with certain sizes
sudo -u www-data php occ config:app:set previewgenerator squareSizes --value="32 256"
sudo -u www-data php occ config:app:set previewgenerator widthSizes  --value="256 384"
sudo -u www-data php occ config:app:set previewgenerator heightSizes --value="256"
sudo -u www-data php occ config:system:set preview_max_x --value 2048
sudo -u www-data php occ config:system:set preview_max_y --value 2048
sudo -u www-data php occ config:system:set jpeg_quality --value 60
sudo -u www-data php occ config:app:set preview jpeg_quality --value="60"

# run the preview generator once
sudo -u www-data php occ preview:generate-all

# set cron job (runs the preview generator every night 4:00 o'clock)
echo "0 4 * * * /usr/bin/php -f /var/www/nextcloud/occ preview:pre-generate" > /tmp/crontab_http
crontab -u www-data /tmp/crontab_http
rm /tmp/crontab_http

# === Enable external storage ===
sudo -u www-data php occ app:enable files_external 


# =======================================
# Security
# =======================================

# === Uncomplicated Firewall (ufw) ===
apt-get install -yqq ufw

# allow ssh
ufw allow ssh

# allow http and https
ufw allow 80/tcp
ufw allow 443/tcp

ufw allow samba

ufw allow nfs

systemctl enable ufw
systemctl start ufw


# === Fail2Ban ===
apt-get install -yqq fail2ban
systemctl start fail2ban 
systemctl enable fail2ban

mkdir -p /etc/fail2ban/filter.d
cat >> /etc/fail2ban/filter.d/nextcloud.conf <<EOF
[Definition]
_groupsre = (?:(?:,?\s*"\w+":(?:"[^"]+"|\w+))*)
failregex = ^\{%(_groupsre)s,?\s*"remoteAddr":"<HOST>"%(_groupsre)s,?\s*"message":"Login failed:
            ^\{%(_groupsre)s,?\s*"remoteAddr":"<HOST>"%(_groupsre)s,?\s*"message":"Trusted domain error.
datepattern = ,?\s*"time"\s*:\s*"%%Y-%%m-%%d[T ]%%H:%%M:%%S(%%z)?"
EOF

mkdir -p /etc/fail2ban/jail.d
cat >> /etc/fail2ban/jail.d/nextcloud.local <<EOF
[nextcloud]
backend = auto
enabled = true
port = 80,443
protocol = tcp
filter = nextcloud
maxretry = 3
bantime = 86400
findtime = 43200
logpath = ${ncpath}/data/nextcloud.log
EOF

cat >> /etc/fail2ban/jail.d/ufwban.local <<EOF
[ufwban]
enabled = true
port = ssh, http, https
filter = ufwban
logpath = /var/log/ufw.log
action = ufw
EOF

systemctl restart fail2ban


# === ModSecurity ===

# Installation
# get modsecurity
apt-get install -yqq libapache2-mod-security2

# get the core rule set (crs)
apt-get install -yqq modsecurity-crs

# Configuration
# for the moment we have to disable modsecutity so we can modify it files
a2dismod security2
systemctl restart apache2

# add to apache
cat >> /etc/apache2/apache2.conf <<EOF
<IfModule mod_security2.c>
  SecServerSignature " "
</IfModule>
EOF

# Define Rules:
cat >> /etc/modsecurity/crs/crs-setup.conf <<'EOF'

  # NextCloud: allow PROPFIND for webDAV
  SecAction "id:900200, phase:1, nolog, pass, t:none, setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PROPFIND'"
EOF

cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i "s|SecRuleEngine .*|SecRuleEngine Off|"               /etc/modsecurity/modsecurity.conf
sed -i 's|SecTmpDir .*|SecTmpDir   /var/cache/modsecurity/|' /etc/modsecurity/modsecurity.conf
sed -i 's|SecDataDir .*|SecDataDir /var/cache/modsecurity/|' /etc/modsecurity/modsecurity.conf
sed -i 's|^SecRequestBodyLimit .*|#SecRequestBodyLimit 13107200|' /etc/modsecurity/modsecurity.conf

# turn modsecurity logs off, too spammy
sed -i 's|SecAuditEngine .*|SecAuditEngine Off|' /etc/modsecurity/modsecurity.conf

cat > /etc/modsecurity/modsecurity_crs_99_whitelist.conf <<EOF
<Directory $ncpath>
  # VIDEOS
  SecRuleRemoveById 958291             # Range Header Checks
  SecRuleRemoveById 980120             # Correlated Attack Attempt

  # PDF
  SecRuleRemoveById 920230             # Check URL encodings

  # ADMIN (webdav)
  SecRuleRemoveById 960024             # Repeatative Non-Word Chars (heuristic)
  SecRuleRemoveById 981173             # SQL Injection Character Anomaly Usage
  SecRuleRemoveById 980130             # Correlated Attack Attempt
  SecRuleRemoveById 981243             # PHPIDS - Converted SQLI Filters
  SecRuleRemoveById 981245             # PHPIDS - Converted SQLI Filters
  SecRuleRemoveById 981246             # PHPIDS - Converted SQLI Filters
  SecRuleRemoveById 981318             # String Termination/Statement Ending Injection Testing
  SecRuleRemoveById 973332             # XSS Filters from IE
  SecRuleRemoveById 973338             # XSS Filters - Category 3
  SecRuleRemoveById 981143             # CSRF Protections ( TODO edit LocationMatch filter )

  # COMING BACK FROM OLD SESSION
  SecRuleRemoveById 970903             # Microsoft Office document properties leakage

  # NOTES APP
  SecRuleRemoveById 981401             # Content-Type Response Header is Missing and X-Content-Type-Options is either missing or not set to 'nosniff'
  SecRuleRemoveById 200002             # Failed to parse request body

  # UPLOADS ( https://github.com/nextcloud/nextcloudpi/issues/959#issuecomment-529150562 )
  SecRequestBodyNoFilesLimit 536870912

  # GENERAL
  SecRuleRemoveById 920350             # Host header is a numeric IP address

  # REGISTERED WARNINGS, BUT DID NOT HAVE TO DISABLE THEM
  #SecRuleRemoveById 981220 900046 981407
  #SecRuleRemoveById 981222 981405 981185 949160

</Directory>
EOF

# enable modsecurity
a2enmod security2
systemctl restart apache2



# =======================================
# Activate site
# =======================================

cat > /etc/apache2/sites-available/nextcloud_ssl.conf <<EOF
<IfModule mod_ssl.c>
  <VirtualHost _default_:443>
    ServerName ${domain}
    DocumentRoot ${ncpath}
    CustomLog /var/log/apache2/nc-access.log combined
    ErrorLog  /var/log/apache2/nc-error.log
    SSLEngine on
    SSLCertificateFile	/etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
  </VirtualHost>
  <Directory ${ncpath}>
    Options +FollowSymlinks
    AllowOverride All
    <IfModule mod_dav.c>
      Dav of
    </IfModule>
    LimitRequestBody 0
    SSLRenegBufferSize 10486000
  </Directory>
  <IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=15768000; includeSubDomains"
  </IfModule>
</IfModule>
EOF

a2ensite nextcloud_ssl
systemctl reload apache2

# set cron job
echo "*/5  *  *  *  * php -f /var/www/nextcloud/cron.php" > /tmp/crontab_http
crontab -u www-data /tmp/crontab_http
rm /tmp/crontab_http

echo "======================================================================================"
echo "DONE!"
