#!/bin/bash
# ==============================================================================
# HPCC Season 2 (Fall 2024) - MAST  (172.16.t.30, Linux)
#
# Scored services:
#   SSH   - hkeating must log in via SSH (PASSWORD auth)
#   MySQL - hkeating must log in to MySQL and read the `user` table in `my_wiki`
#
# Extra wrinkle: sails' MediaWiki reads this database over the network. If you
# firewall MySQL to localhost, you break BOTH the MySQL check AND the HTTP check
# on sails. Bind to the interface, restrict by source IP instead.
#
# Run as root:  sudo bash mast-172.16.t.30.sh
# ==============================================================================
set -uo pipefail
source "$(dirname "$0")/lib/common-linux.sh"

require_root
backup_configs
prompt_new_password

read -rp "Team number (the 't' in 172.16.t.30): " TEAM
SAILS_IP="172.16.${TEAM}.20"
SUBNET="172.16.${TEAM}.0/24"

log "===== MAST: SSH + MySQL ====="

lock_root_account
purge_ssh_keys
audit_uid_zero
audit_empty_passwords
audit_sudoers
audit_cron
rotate_local_passwords
harden_ssh
install_tools
start_fail2ban

# ---------- backup the database FIRST ------------------------------------------
# Do this before touching anything. If a check breaks, you restore in 30 seconds
# instead of eating a 20-minute revert penalty.
log "Dumping all databases before we change anything"
mkdir -p /root/db-backups
if mysqldump -u root --all-databases > /root/db-backups/all-databases.sql 2>/dev/null; then
  ok "dump: /root/db-backups/all-databases.sql ($(du -h /root/db-backups/all-databases.sql | cut -f1))"
else
  warn "root dump failed -- root may already need a password. Try:"
  warn "  mysqldump -u root -p --all-databases > /root/db-backups/all-databases.sql"
fi
# Copy it to sonar (out of Red Team scope) as soon as you can:
echo "    Next:  scp /root/db-backups/all-databases.sql plinktern@172.16.${TEAM}.5:/opt/hpcc-vault/mast/"

# ---------- firewall -----------------------------------------------------------
log "Configuring UFW"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'ssh - SCORED'
# MySQL: scoring engine + sails need in. Everything else does not.
# Widen to the whole subnet because the scoring engine's source IP is not
# published in the packet -- narrow this if you identify it during the round.
ufw allow from "$SUBNET" to any port 3306 proto tcp comment 'mysql - SCORED'
ufw --force enable
ufw status verbose | sed 's/^/    /'

# ---------- MySQL --------------------------------------------------------------
log "Hardening MySQL"

# Set a root password we control, without the interactive mysql_secure_installation.
read -rsp "New MySQL root password: " MYSQL_ROOT; echo
MYSQL_CONF="/root/.my.cnf"

# Try passwordless root first (competition default), fall back to prompting.
if mysql -u root -e "SELECT 1" >/dev/null 2>&1; then
  MYSQL_AUTH="-u root"
else
  read -rsp "Current MySQL root password: " CUR; echo
  MYSQL_AUTH="-u root -p${CUR}"
fi

mysql $MYSQL_AUTH <<SQL
-- Take control of root
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT}';

-- Remove the usual junk: anonymous users, test db, remote root
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
SQL
ok "root password set, anonymous/test removed"

# Stash credentials so later commands do not need -p on the command line
cat > "$MYSQL_CONF" <<EOF
[client]
user=root
password=${MYSQL_ROOT}
EOF
chmod 600 "$MYSQL_CONF"

# ---- the scoring account ----
# hkeating must be able to log in AND read my_wiki.user. Grant exactly that --
# no more. Grant from the subnet, not '%', so Red Team can't reuse the creds
# from their own infrastructure.
read -rsp "Password for MySQL user '${SCORING_USER}' (file a PCR with this!): " HK_PASS; echo
mysql <<SQL
CREATE USER IF NOT EXISTS '${SCORING_USER}'@'localhost'         IDENTIFIED BY '${HK_PASS}';
CREATE USER IF NOT EXISTS '${SCORING_USER}'@'172.16.${TEAM}.%'  IDENTIFIED BY '${HK_PASS}';
ALTER USER '${SCORING_USER}'@'localhost'        IDENTIFIED BY '${HK_PASS}';
ALTER USER '${SCORING_USER}'@'172.16.${TEAM}.%' IDENTIFIED BY '${HK_PASS}';
GRANT SELECT ON my_wiki.* TO '${SCORING_USER}'@'localhost';
GRANT SELECT ON my_wiki.* TO '${SCORING_USER}'@'172.16.${TEAM}.%';
FLUSH PRIVILEGES;
SQL
ok "${SCORING_USER} can SELECT on my_wiki"

echo
echo "    !!! SUBMIT A PCR NOW on scoreboard.plinko.horse !!!"
echo "    Cred list: mast.credlist   Value: ${SCORING_USER},<the password you just typed>"
echo "    Until you do, the MySQL check will fail."
echo
read -rp "    Press enter once the PCR is submitted... " _

# ---- audit every other account ----
log "Remaining MySQL accounts (review by eye - delete anything you don't recognise)"
mysql -e "SELECT user, host, plugin FROM mysql.user;" | sed 's/^/    /'
log "Accounts with dangerous global grants"
mysql -e "SELECT user, host FROM mysql.user WHERE Super_priv='Y' OR Grant_priv='Y' OR File_priv='Y';" | sed 's/^/    /'

# ---- verify the check will actually pass ----
log "Simulating the score check"
if mysql -u "$SCORING_USER" -p"$HK_PASS" -h 127.0.0.1 -e "SELECT user_name FROM my_wiki.user LIMIT 5;" 2>/dev/null; then
  ok "SCORE CHECK SIMULATION PASSED"
else
  warn "SCORE CHECK SIMULATION FAILED - fix this before moving on"
fi

# ---------- mysqld config ------------------------------------------------------
# bind-address 0.0.0.0 is deliberate: sails and the scoring engine are remote.
# UFW is doing the network restriction, not mysqld.
log "Writing mysqld config"
CNF="/etc/mysql/mysql.conf.d/mysqld.cnf"
[[ -f "$CNF" ]] || CNF="/etc/mysql/my.cnf"
unlock "$CNF"
cat > /etc/mysql/conf.d/99-hpcc.cnf <<'EOF'
[mysqld]
# Remote access is REQUIRED (sails MediaWiki + scoring engine). Firewall handles
# the restriction. Do not add skip-networking here.
bind-address    = 0.0.0.0
local-infile    = 0
skip-symbolic-links
secure-file-priv = /var/lib/mysql-files
EOF
systemctl restart mysql 2>/dev/null || service mysql restart
sleep 3
if mysql -e "SELECT 1" >/dev/null 2>&1; then ok "mysql back up"; else warn "MYSQL DID NOT RESTART"; fi

# ---------- file permissions ---------------------------------------------------
log "Fixing permissions"
chmod 644 /etc/passwd /etc/group
chmod 640 /etc/shadow
chmod 440 /etc/sudoers
chmod 700 /root
chmod 600 /root/.my.cnf
ok "permissions set"

# ---------- lock configs -------------------------------------------------------
# Last step. Remember: to edit these later, chattr -i first.
log "Making configs immutable (chattr -i to edit later)"
lock /etc/ssh/sshd_config.d/99-hpcc.conf
lock /etc/mysql/conf.d/99-hpcc.cnf
lock /etc/passwd
lock /etc/shadow

baseline_report

log "===== MAST DONE ====="
echo "    Verify on the scoreboard:  mast-ssh and mast-sql should be green."
echo "    Also check sails' HTTP check -- it depends on this database."
