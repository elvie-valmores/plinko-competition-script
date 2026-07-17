#!/bin/bash
# ==============================================================================
# HPCC Season 3 (Fall 2025) - STORKFRONT  (172.16.t.20, AlmaLinux OS 9.0)
#
# Scored services:
#   SSH  - jmoney must log in via SSH (PASSWORD auth) and run unprivileged commands
#   HTTP - the WooCommerce site must respond successfully AND return the correct
#          product information. Apache hosts WordPress; WooCommerce pulls its
#          data from the MySQL server on FOREMAN (172.16.t.40).
#
# Read that dependency again, because it decides how you triage:
#   storkfront HTTP  ->  needs foreman MySQL  ->  needs foreman's firewall open
# If the HTTP check goes red, check foreman BEFORE you start pulling Apache apart.
#
# Also note the rules: you may NOT swap Apache for nginx. Scored service software
# is mandated. Harden it in place.
#
# AlmaLinux specifics: dnf, firewalld, SELinux (leave it ENFORCING -- it is doing
# free work for you against webshells), httpd not apache2.
#
# Run as root:  sudo bash storkfront-172.16.t.20.sh
# ==============================================================================
set -uo pipefail
source "$(dirname "$0")/lib/common-linux.sh"

require_root
detect_distro
backup_configs
prompt_new_password

read -rp "Team number (the 't' in 172.16.t.20): " TEAM
SUBNET="172.16.${TEAM}.0/24"
FOREMAN="172.16.${TEAM}.40"

log "===== STORKFRONT: SSH + WooCommerce (AlmaLinux 9) ====="

lock_root_account
purge_ssh_keys
audit_uid_zero
audit_empty_passwords
audit_sudoers
audit_cron
audit_suid
rotate_local_passwords
harden_ssh
install_tools
start_fail2ban

# ---------- SELinux ------------------------------------------------------------
# The instinct to "setenforce 0 to make things work" is exactly wrong here.
# SELinux blocks a huge share of the webshell payloads Red Team will drop.
log "SELinux status"
getenforce | sed 's/^/    /'
if [[ "$(getenforce)" != "Enforcing" ]]; then
  warn "SELinux is not enforcing. Turning it on -- it is real protection for a webserver."
  setenforce 1 2>/dev/null
  sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
  ok "SELinux set to enforcing (persists across reboot)"
else
  ok "SELinux already enforcing -- leave it that way"
fi
# WordPress needs to reach a remote database. Without this boolean, SELinux
# blocks it and you will blame the firewall for an hour.
setsebool -P httpd_can_network_connect_db 1 2>/dev/null && ok "httpd_can_network_connect_db enabled"
setsebool -P httpd_can_network_connect 1 2>/dev/null

# ---------- back up the site FIRST ---------------------------------------------
log "Backing up the web root"
WEBROOT=""
for c in /var/www/html /var/www /usr/share/nginx/html /srv/www; do
  if [[ -f "$c/wp-config.php" ]]; then WEBROOT="$c"; break; fi
done
if [[ -z "$WEBROOT" ]]; then
  WP=$(find / -name wp-config.php -not -path '/proc/*' 2>/dev/null | head -1)
  [[ -n "$WP" ]] && WEBROOT=$(dirname "$WP")
fi

if [[ -n "$WEBROOT" ]]; then
  ok "WordPress found at $WEBROOT"
  tar czf "$BACKUP_DIR/webroot.tar.gz" "$WEBROOT" 2>/dev/null
  ok "site backed up: $BACKUP_DIR/webroot.tar.gz ($(du -h "$BACKUP_DIR/webroot.tar.gz" | cut -f1))"
  echo "    Get it off-box:"
  echo "      scp $BACKUP_DIR/webroot.tar.gz plinktern@172.16.${TEAM}.5:/opt/hpcc-vault/storkfront/"
else
  warn "Could not find wp-config.php. Locate the site before continuing."
fi

# ---------- wp-config.php ------------------------------------------------------
if [[ -n "$WEBROOT" && -f "$WEBROOT/wp-config.php" ]]; then
  log "Securing wp-config.php"
  # This file holds the foreman MySQL password in cleartext. It is the single
  # most valuable file on the box for Red Team.
  chown root:apache "$WEBROOT/wp-config.php"
  chmod 640 "$WEBROOT/wp-config.php"
  ok "wp-config.php is now 640 root:apache"

  echo "    Database target configured in wp-config.php:"
  grep -E "DB_HOST|DB_NAME|DB_USER" "$WEBROOT/wp-config.php" | sed 's/^/      /'
  warn "If you rotate the DB user's password on foreman, you MUST update"
  warn "  DB_PASSWORD in $WEBROOT/wp-config.php or the HTTP check dies."

  # Disable the file editor + plugin installs: both are one-click webshells for
  # anyone who gets an admin session.
  if ! grep -q "DISALLOW_FILE_EDIT" "$WEBROOT/wp-config.php"; then
    sed -i "/That's all, stop editing/i \
define('DISALLOW_FILE_EDIT', true);\n\
define('DISALLOW_FILE_MODS', true);\n\
define('WP_DEBUG', false);\n\
define('WP_DEBUG_DISPLAY', false);" "$WEBROOT/wp-config.php" 2>/dev/null
    ok "file editor and plugin installs disabled in wp-config.php"
  fi
fi

# ---------- file permissions on the web root ----------------------------------
if [[ -n "$WEBROOT" ]]; then
  log "Fixing web root ownership and permissions"
  # Apache should be able to READ the site, not WRITE it. A writable web root
  # is how a webshell lands.
  chown -R root:apache "$WEBROOT"
  find "$WEBROOT" -type d -exec chmod 750 {} \;
  find "$WEBROOT" -type f -exec chmod 640 {} \;
  # WooCommerce needs uploads writable, and only uploads.
  if [[ -d "$WEBROOT/wp-content/uploads" ]]; then
    chown -R apache:apache "$WEBROOT/wp-content/uploads"
    find "$WEBROOT/wp-content/uploads" -type d -exec chmod 750 {} \;
    ok "uploads/ writable by apache, everything else read-only"
  fi
  restorecon -R "$WEBROOT" 2>/dev/null
  ok "permissions + SELinux contexts fixed"

  # ---- webshell hunt ----
  log "Hunting for webshells (recently modified PHP)"
  find "$WEBROOT" -name "*.php" -mtime -2 2>/dev/null | head -30 | sed 's/^/    RECENT: /'
  log "PHP files containing classic webshell functions"
  grep -rlE '(eval\(|base64_decode\(|shell_exec\(|passthru\(|system\(\$|assert\(\$)' \
    "$WEBROOT" --include="*.php" 2>/dev/null | head -20 | sed 's/^/    SUSPECT: /'
  warn "Some hits will be legitimate WordPress core. Compare against a clean"
  warn "WordPress of the same version before deleting anything."

  # Uploads must never execute PHP. This one config kills most webshells dead.
  log "Blocking PHP execution in uploads/"
  cat > "$WEBROOT/wp-content/uploads/.htaccess" <<'EOF'
<FilesMatch "\.(php|phtml|php3|php4|php5|php7|phps)$">
    Require all denied
</FilesMatch>
EOF
  ok "uploads/.htaccess blocks PHP execution"
fi

# ---------- Apache -------------------------------------------------------------
log "Hardening Apache (httpd)"
unlock /etc/httpd/conf/httpd.conf
cp -a /etc/httpd/conf/httpd.conf "$BACKUP_DIR/httpd.conf.pre" 2>/dev/null

cat > /etc/httpd/conf.d/99-hpcc-hardening.conf <<'EOF'
# ===== HPCC hardening =====
# Stop advertising what we are running.
ServerTokens Prod
ServerSignature Off
TraceEnable Off

# No directory listings, no CGI, no symlink following.
<Directory /var/www/html>
    Options -Indexes -ExecCGI -Includes
    AllowOverride FileInfo Options=Indexes,MultiViews Limit
</Directory>

# Timeouts: slowloris is cheap and takes the HTTP check down.
Timeout 30
KeepAliveTimeout 5
LimitRequestBody 10485760

# Block access to the files that leak the most.
<FilesMatch "^(wp-config\.php|\.htaccess|\.htpasswd|readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>
<FilesMatch "\.(bak|old|sql|swp|log|~)$">
    Require all denied
</FilesMatch>

# xmlrpc.php: brute-force amplifier, not needed for the storefront.
<Files "xmlrpc.php">
    Require all denied
</Files>

# Basic security headers.
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
EOF
ok "hardening config written to /etc/httpd/conf.d/99-hpcc-hardening.conf"

if httpd -t 2>&1 | grep -qi "Syntax OK"; then
  systemctl restart httpd
  ok "httpd restarted, config valid"
else
  warn "HTTPD CONFIG INVALID -- not restarting:"
  httpd -t 2>&1 | sed 's/^/    /'
fi
systemctl enable httpd >/dev/null 2>&1

# ---------- WordPress / WooCommerce accounts -----------------------------------
log "WordPress admin account"
cat <<EOF
    The packet publishes the WooCommerce admin login:
        plinktern : IHPLRulez!
    Red Team has that too. Change it in the first five minutes.

    From the web UI:  http://172.16.${TEAM}.20/wp-admin  -> Users -> Profile
    Or with wp-cli (if installed), from $WEBROOT:
        wp user list --allow-root
        wp user update plinktern --user_pass='<new>' --allow-root

    Then check for admin accounts you did not create -- adding a hidden admin is
    Red Team's favourite WordPress persistence:
        wp user list --role=administrator --allow-root

    NOTE: the HTTP check reads PRODUCT INFORMATION from the storefront. Do not
    delete products, do not unpublish the shop page, do not change permalinks.
EOF

# ---------- firewall -----------------------------------------------------------
fw_reset
fw_allow_port 22 tcp any "ssh - SCORED"
fw_allow_port 80 tcp any "http - SCORED"
fw_enable
echo "    Outbound to $FOREMAN:3306 must keep working -- WooCommerce's database."

# ---------- verify -------------------------------------------------------------
log "Simulating the score checks"
CODE=$(curl -s -o /tmp/hpcc-http.out -w '%{http_code}' --max-time 10 http://127.0.0.1/ 2>/dev/null)
if [[ "$CODE" == "200" ]]; then
  ok "HTTP SCORE CHECK: got 200 at root"
  if grep -qi "shop\|product\|woocommerce" /tmp/hpcc-http.out 2>/dev/null; then
    ok "storefront content looks present"
  else
    warn "200 returned but no storefront content found -- the content check may still fail"
  fi
else
  warn "HTTP SCORE CHECK FAILED -- got '$CODE'"
fi
md5sum /tmp/hpcc-http.out > /root/homepage.md5 2>/dev/null
ok "homepage hash recorded at /root/homepage.md5 (diff against it later)"

log "Testing the database dependency on foreman"
if timeout 5 bash -c "echo > /dev/tcp/${FOREMAN}/3306" 2>/dev/null; then
  ok "foreman:3306 reachable -- WooCommerce can reach its database"
else
  warn "CANNOT REACH ${FOREMAN}:3306 -- the HTTP check will fail no matter what"
  warn "you do to Apache. Go fix foreman's firewall / MySQL bind address."
fi

systemctl is-active sshd >/dev/null && ok "sshd running" || warn "SSHD NOT RUNNING"
if id "$SCORING_USER" >/dev/null 2>&1; then
  su - "$SCORING_USER" -c "id" >/dev/null 2>&1 \
    && ok "$SCORING_USER can run commands" \
    || warn "$SCORING_USER cannot run commands -- check its shell"
fi

# ---------- permissions + lock -------------------------------------------------
log "Fixing system permissions"
chmod 644 /etc/passwd /etc/group
chmod 640 /etc/shadow
chmod 440 /etc/sudoers
chmod 700 /root
ok "permissions set"

log "Making configs immutable (chattr -i to edit later)"
lock /etc/httpd/conf.d/99-hpcc-hardening.conf
lock /etc/ssh/sshd_config.d/99-hpcc.conf
lock /etc/passwd
lock /etc/shadow
[[ -n "$WEBROOT" ]] && lock "$WEBROOT/wp-config.php"

baseline_report

log "===== STORKFRONT DONE ====="
echo "    Triage order if HTTP goes red:"
echo "      1. Can this box reach ${FOREMAN}:3306?   <- usually the real cause"
echo "      2. Is httpd running?  systemctl status httpd"
echo "      3. Has the homepage changed?  curl -s http://127.0.0.1/ | md5sum"
echo "         compare against /root/homepage.md5"
echo "      4. Restore the site:  tar xzf $BACKUP_DIR/webroot.tar.gz -C /"
