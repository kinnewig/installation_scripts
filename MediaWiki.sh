#!/bin/bash

# =======================================
# Settings
# =======================================

PHPV=7.4
WIKI_VER_MAJ=1.37
WIKI_VER_MIN=1

# Name
WIKI_NAME=kinne.WIKI.g

# Installation path
wikiroot=/var/www
wikipath=/var/www/mediawiki

# MariaDB
DB_ADMIN=wikiadmin
DB_NAME=mediawiki

# Domain
domain=wiki.kinnewig.org

# Admin
WIKI_ADMIN=sebastian_admin

# =======================================
# Preamble
# =======================================

# exit when any command fails
set -e

[[ ${EUID} -ne 0 ]] && {
  printf "Must be run as root. Try 'sudo $0'\n"
  exit 1
}

# get the password for the mediawiki admin user
echo "Enter a password for the mediawiki admin user"
WIKI_TEST_PWD=true
while ${WIKI_TEST_PWD} ; do
  read -s -p "Enter the password: " WIKI_PWD_1
  echo ""
  read -s -p "Retype the password: " WIKI_PWD_2
  echo ""

  if [ ${WIKI_PWD_1} = ${WIKI_PWD_2} ] ; then
    WIKI_TEST_PWD=false
    WIKI_ADMIN_PWD=${WIKI_PWD_1}
  fi
done


# check if the password file already exists, if it does not exist create a file
if [ -f "/root/.mediawiki.cnf" ]; then
  touch /root/.mediawiki.cnf
fi

DB_PWD=$(grep "database password" /root/.mediawiki.cnf | sed 's|database password=||');
if [ -z "$DB_PWD" ]; then
  echo "Creating password for the mysql user wikiadmin"
  DB_PWD=$(echo $RANDOM | md5sum | head -c 32; echo;)
  cat >> /root/.mediawiki.cnf <<EOF
database password=$DB_PWD
EOF
fi



# =======================================
# dependecies
# =======================================

# === PHP ===
apt-get install -y php${PHPV} php${PHPV} php${PHPV}-apcu php${PHPV}-intl php${PHPV}-mbstring php${PHPV}-xml php${PHPV}-fileinfo

# For PHPV > 8 Json was moved into the core package
if [[ ${PHPV} < 8 ]]; then
    apt-get install -y php${PHPV}-json
fi

systemctl enable php${PHPV}-fpm
systemctl start php${PHPV}-fpm


# I am assuming, the web server and the database are already installed
# === database ===
#apt-get install -y mariadb-server php${PHPV}-mysql 
# === webserver ===
#apt-get install -y apache2

a2enmod php${PHPV}

# === Optional ===
# LaTeX
apt-get install -y texlive

cd ${wikiroot}
curl https://releases.wikimedia.org/mediawiki/${WIKI_VER_MAJ}/mediawiki-${WIKI_VER_MAJ}.${WIKI_VER_MIN}.tar.gz --output mediawiki.tar.gz
tar -xf mediawiki.tar.gz
rm mediawiki.tar.gz
mv mediawiki-${WIKI_VER_MAJ}.${WIKI_VER_MIN} mediawiki
cd mediawiki



# =======================================
# MariaDB
# =======================================
mysql <<EOF
CREATE DATABASE $DB_NAME
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_general_ci;
CREATE USER '$DB_ADMIN'@'localhost' IDENTIFIED BY '$DB_PWD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_ADMIN'@'localhost' WITH GRANT OPTION;
EOF

# update permissions
chown -R www-data:www-data ${wikipath}

# install 
sudo -u www-data php maintenance/install.php --confpath="${wikipath}" --dbname="${DB_NAME}" --dbtype="mysql" \
       	--dbserver="localhost" --dbuser="${DB_ADMIN}" --dbpass="${DB_PWD}" \
	--server="https://${domain}" --lang=de --pass=${WIKI_ADMIN_PWD} "${WIKI_NAME}" "${WIKI_ADMIN}"

# =======================================
# Activate site
# =======================================

cat > /etc/apache2/sites-available/mediawiki_ssl.conf <<EOF
<IfModule mod_ssl.c>
  <VirtualHost _default_:443>

    Alias /wiki ${wikipath}

    ServerName ${domain}
    DocumentRoot ${wikipath}
    CustomLog /var/log/apache2/wiki-access.log combined
    ErrorLog  /var/log/apache2/wiki-error.log
    SSLEngine on
    SSLCertificateFile	/etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

    <FilesMatch \.php$>
      SetHandler "proxy:unix:/run/php/php${PHPV}-fpm.sock|fcgi://localhost"
    </FilesMatch>

    <Directory "${wikipath}">
      Order allow,deny
      Allow from all
    </Directory>

  </VirtualHost>
</IfModule>
EOF

a2ensite mediawiki_ssl 
systemctl reload apache2

