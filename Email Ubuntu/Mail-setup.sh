#!/usr/bin/env bash

set -Eeuo pipefail
trap 'echo; echo "  [FAIL] stopped at line $LINENO: $BASH_COMMAND" >&2' ERR

HOST=webmail
DOMAIN=underpressure.local
RC_VER=1.6.17
RC_DIR=/opt/roundcube
RC_URL="https://github.com/roundcube/roundcubemail/releases/download/$RC_VER/roundcubemail-$RC_VER-complete.tar.gz"
TEST_USERS=(alice bob)
APT=(apt-get -y -q -o DPkg::Lock::Timeout=300)

if [[ -t 1 ]]; then GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[1;34m'; RST=$'\e[0m'; else GRN=""; YEL=""; BLU=""; RST=""; fi
step() { printf '\n%s== %s ==%s\n' "$BLU" "$1" "$RST"; }
ok()   { printf '  %s[OK]%s %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '  %s[WARN]%s %s\n' "$YEL" "$RST" "$1"; }

[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo $0" >&2; exit 1; }
grep -q 'VERSION_ID="22.04"' /etc/os-release || { echo "This is for Ubuntu 22.04 (the competition version)." >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive

step "0/6 Hostname and base packages"
hostnamectl set-hostname "$HOST"
grep -q "$HOST.$DOMAIN" /etc/hosts || echo "127.0.1.1 $HOST.$DOMAIN $HOST" >> /etc/hosts
ok "hostname $HOST, FQDN $HOST.$DOMAIN"
"${APT[@]}" update >/dev/null
"${APT[@]}" install ssl-cert curl ca-certificates software-properties-common openssl >/dev/null
ok "base packages"

step "1/6 Postfix"
echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
echo "postfix postfix/mailname string $DOMAIN" | debconf-set-selections
"${APT[@]}" install postfix >/dev/null
postconf -e "myhostname = $HOST.$DOMAIN" \
            "mydomain = $DOMAIN" \
            'myorigin = $mydomain' \
            'mydestination = $myhostname, $mydomain, localhost.$mydomain, localhost' \
            "inet_interfaces = all" \
            "mailbox_transport = lmtp:unix:private/dovecot-lmtp" \
            "smtpd_sasl_type = dovecot" \
            "smtpd_sasl_path = private/auth"
postconf -M submission/inet="submission inet n - y - - smtpd"
postconf -P "submission/inet/syslog_name=postfix/submission" \
            "submission/inet/smtpd_tls_security_level=encrypt" \
            "submission/inet/smtpd_sasl_auth_enable=yes" \
            "submission/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject"
ok "Postfix $(postconf -h mail_version): delivers through Dovecot LMTP, 587 enabled"

step "2/6 Dovecot"
"${APT[@]}" install dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd >/dev/null
cat > /etc/dovecot/conf.d/99-lab.conf <<'EOF'
protocols = imap pop3 lmtp
mail_location = maildir:~/Maildir
disable_plaintext_auth = no
auth_mechanisms = plain login
auth_username_format = %Ln

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF
doveconf -n >/dev/null
systemctl restart dovecot postfix
ok "Dovecot $(dovecot --version | cut -d' ' -f1): IMAP, POP3, LMTP; Maildir in each home folder"

step "3/6 Apache and PHP 8.3-FPM"
if ! grep -rqs 'ondrej/php' /etc/apt/sources.list.d/; then
  add-apt-repository -y ppa:ondrej/php >/dev/null
  "${APT[@]}" update >/dev/null
fi
"${APT[@]}" install apache2 php8.3-fpm php8.3-cli php8.3-intl php8.3-mbstring php8.3-xml \
  php8.3-zip php8.3-curl php8.3-gd php8.3-sqlite3 php8.3-ldap >/dev/null
a2enmod -q proxy_fcgi setenvif ssl rewrite >/dev/null
a2enconf -q php8.3-fpm >/dev/null
ok "$(apache2 -v | head -1 | cut -d' ' -f3), $(php-fpm8.3 -v | head -1 | cut -d' ' -f1-2)"

step "4/6 Roundcube $RC_VER"
if [[ ! -d $RC_DIR ]]; then
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/rc.tar.gz" "$RC_URL"
  ok "downloaded, sha256 $(sha256sum "$tmp/rc.tar.gz" | cut -d' ' -f1)"
  echo "      compare with https://github.com/roundcube/roundcubemail/releases/tag/$RC_VER"
  tar xzf "$tmp/rc.tar.gz" -C /opt
  mv "/opt/roundcubemail-$RC_VER" "$RC_DIR"
  rm -rf "$tmp"
else
  ok "$RC_DIR already exists, not downloading again"
fi
chown -R root:root "$RC_DIR"
mkdir -p "$RC_DIR/db"
chown -R www-data:www-data "$RC_DIR/temp" "$RC_DIR/logs" "$RC_DIR/db"

CFG=$RC_DIR/config/config.inc.php
if [[ ! -f $CFG ]]; then
  cat > "$CFG" <<'EOF'
<?php
$config = [];
$config['db_dsnw'] = 'sqlite:////opt/roundcube/db/roundcube.db?mode=0640';
$config['imap_host'] = 'localhost:143';
$config['smtp_host'] = 'localhost:25';
$config['smtp_user'] = '';
$config['smtp_pass'] = '';
$config['product_name'] = 'Webmail';
$config['des_key'] = 'DESKEY_PLACEHOLDER';
$config['plugins'] = ['archive', 'zipdownload'];
$config['enable_installer'] = false;
EOF
  sed -i "s|DESKEY_PLACEHOLDER|$(openssl rand -base64 18)|" "$CFG"
fi
chown root:www-data "$CFG"; chmod 640 "$CFG"

if [[ ! -s $RC_DIR/db/roundcube.db ]]; then
  sudo -u www-data "$RC_DIR/bin/initdb.sh" --dir="$RC_DIR/SQL" >/dev/null
fi
ok "Roundcube in $RC_DIR, SQLite database created, installer/ left in place (competition drill)"

cat > /etc/apache2/sites-available/roundcube.conf <<EOF
<VirtualHost *:80>
  ServerName $HOST.$DOMAIN
  DocumentRoot $RC_DIR/public_html
  <Directory $RC_DIR/public_html>
    Options -Indexes
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>
<VirtualHost *:443>
  ServerName $HOST.$DOMAIN
  DocumentRoot $RC_DIR/public_html
  SSLEngine on
  SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
  SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
  <Directory $RC_DIR/public_html>
    Options -Indexes
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>
EOF
a2dissite -q 000-default >/dev/null 2>&1 || true
a2ensite -q roundcube >/dev/null
apache2ctl configtest 2>/dev/null
systemctl restart php8.3-fpm apache2
ok "Apache site enabled on 80 and 443"

step "5/6 Test users"
for u in "${TEST_USERS[@]}"; do
  if id "$u" >/dev/null 2>&1; then ok "$u already exists"; continue; fi
  useradd -m -s /bin/bash "$u"
  while :; do
    read -r -s -p "  >> Password for $u: " p1 < /dev/tty; echo
    read -r -s -p "  >> Again: " p2 < /dev/tty; echo
    [[ -n $p1 && $p1 == "$p2" ]] && break
    warn "empty or didn't match, try again"
  done
  echo "$u:$p1" | chpasswd
  unset p1 p2
  ok "created $u"
done

step "6/6 Verify"
echo "Subject: lab-mailstack test $(date +%T)" | sendmail "${TEST_USERS[0]}"
delivered=0
for _ in $(seq 1 15); do
  if compgen -G "/home/${TEST_USERS[0]}/Maildir/new/*" >/dev/null; then delivered=1; break; fi
  sleep 1
done
if ((delivered)); then
  ok "mail flow works: Postfix -> LMTP -> Dovecot -> /home/${TEST_USERS[0]}/Maildir/new"
else
  warn "test message not delivered yet. Check: sudo journalctl -u postfix@- -n 20"
fi
code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' http://localhost/ || true)
[[ $code == 200 ]] && ok "webmail page answers on http://localhost/ (200)" || warn "webmail page returned $code"
code=$(curl -sk -o /dev/null -m 10 -w '%{http_code}' https://localhost/ || true)
[[ $code == 200 ]] && ok "webmail page answers on https://localhost/ (200)" || warn "HTTPS page returned $code"

echo
echo "  Versions (competition box in brackets):"
echo "    Postfix   $(postconf -h mail_version)   [3.6.4]"
echo "    Dovecot   $(dovecot --version | cut -d' ' -f1)   [2.3.16]"
echo "    Apache    $(apache2 -v | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')   [2.4.52]"
echo "    PHP-FPM   $(php-fpm8.3 -v | head -1 | cut -d' ' -f2)   [8.3.x]"
echo "    Roundcube $(grep -m1 -oE "RCMAIL_VERSION', '[^']+" $RC_DIR/program/include/iniset.php | cut -d"'" -f3)   [1.6.17]"
echo
echo "  Listening TCP ports (expect 22 25 80 110 143 443 587 993 995):"
echo "    $(ss -Htln | awk '{n=split($4,a,":"); print a[n]}' | sort -nu | tr '\n' ' ')"
echo
ok "Done. Log in at http://$(hostname -I | awk '{print $1}')/ as ${TEST_USERS[0]}, send a message to ${TEST_USERS[1]}."
