#!/bin/bash
# ==============================================================================
# HPCC Season 3 (Fall 2025) - GENERATOR  (172.16.t.5, Linux Mint 22 "Wilma")
#
# Role in the packet:  OUT OF SCOPE for Red Team. No scored services.
# What that means:     this is your safe harbour. Red Team may not touch it, so
#                      anything you put here survives the whole round.
#
# Use it as:
#   - the backup vault for every other box's configs and databases
#   - the tmux/monitoring station
#   - the place you keep your notes and inject drafts
#
# Run as root:  sudo bash generator-172.16.t.5.sh
# ==============================================================================
set -uo pipefail
source "$(dirname "$0")/lib/common-linux.sh"

require_root
detect_distro
backup_configs
prompt_new_password

read -rp "Team number (the 't' in 172.16.t.5): " TEAM
SUBNET="172.16.${TEAM}.0/24"

log "===== GENERATOR: safe-box setup (Linux Mint 22) ====="

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

# ---------- firewall -----------------------------------------------------------
# Generator serves nothing scored. SSH from our own subnet is all it needs.
fw_reset
fw_allow_port 22 tcp "$SUBNET" "ssh from team subnet"
fw_enable

# ---------- backup vault -------------------------------------------------------
log "Creating the backup vault at /opt/hpcc-vault"
mkdir -p /opt/hpcc-vault/{antenna,storkfront,depot,foreman,injects}
chmod 700 /opt/hpcc-vault
cat > /opt/hpcc-vault/README.txt <<EOF
GENERATOR IS OUT OF RED TEAM SCOPE. Anything stored here is safe.

Pull backups here early and often:

  # DNS zone from antenna
  scp plinktern@172.16.${TEAM}.10:/etc/bind/db.team${TEAM}.plinko.horse \\
      /opt/hpcc-vault/antenna/

  # WordPress files + config from storkfront
  ssh plinktern@172.16.${TEAM}.20 'sudo tar czf - /var/www' \\
      > /opt/hpcc-vault/storkfront/www.tar.gz

  # horsepress database from foreman (run from a box that can reach it)
  mysqldump -h 172.16.${TEAM}.40 -u jmoney -p horsepress \\
      > /opt/hpcc-vault/foreman/horsepress.sql

  # FTP /memos contents from depot
  wget -r ftp://anonymous:x@172.16.${TEAM}.30/memos/ -P /opt/hpcc-vault/depot/

RULES REMINDER: copying data OUT of the competition environment to your personal
device or an external website is an exfiltration violation. Generator is inside
the environment, so staging backups here is fine.
EOF
ok "vault ready at /opt/hpcc-vault"

# ---------- monitoring station -------------------------------------------------
log "Installing the service watcher"
cat > /usr/local/bin/hpcc-watch <<'EOF'
#!/bin/bash
# Poll every scored service from generator. Red Team cannot see or stop this box.
T="${1:?usage: hpcc-watch <team-number>}"
chk() { timeout 3 bash -c "echo > /dev/tcp/$1/$2" 2>/dev/null && echo "UP  " || echo "DOWN"; }
while :; do
  clear
  echo "=== HPCC service watch - team $T - $(date +%H:%M:%S) ==="
  echo
  printf "antenna    ssh   %s\n" "$(chk 172.16.$T.10 22)"
  printf "antenna    dns   %s\n" "$(timeout 3 nslookup storkfront.team$T.plinko.horse 172.16.$T.10 >/dev/null 2>&1 && echo 'UP  ' || echo 'DOWN')"
  printf "storkfront ssh   %s\n" "$(chk 172.16.$T.20 22)"
  printf "storkfront http  %s\n" "$(timeout 5 curl -s -o /dev/null -w '%{http_code}' http://172.16.$T.20/ || echo 'DOWN')"
  printf "depot      rdp   %s\n" "$(chk 172.16.$T.30 3389)"
  printf "depot      ftp   %s\n" "$(chk 172.16.$T.30 21)"
  printf "foreman    rdp   %s\n" "$(chk 172.16.$T.40 3389)"
  printf "foreman    mysql %s\n" "$(chk 172.16.$T.40 3306)"
  echo
  echo "(ctrl-c to quit)"
  sleep 20
done
EOF
chmod +x /usr/local/bin/hpcc-watch
ok "run it:  tmux new -s watch \"hpcc-watch $TEAM\""

# ---------- deeper FTP/content watcher ----------------------------------------
log "Installing a content-integrity watcher"
cat > /usr/local/bin/hpcc-integrity <<'EOF'
#!/bin/bash
# The FTP and HTTP checks verify CONTENT, not just reachability. A service can
# be "up" and still failing. This catches that.
T="${1:?usage: hpcc-integrity <team-number>}"
BASE=/opt/hpcc-vault/integrity
mkdir -p $BASE
while :; do
  # storkfront shop page hash
  curl -s --max-time 5 "http://172.16.$T.20/" | md5sum | cut -d' ' -f1 > $BASE/http.now
  if [[ -f $BASE/http.baseline ]]; then
    diff -q $BASE/http.baseline $BASE/http.now >/dev/null \
      || echo "[$(date +%T)] !! STORKFRONT HOMEPAGE CHANGED"
  else
    cp $BASE/http.now $BASE/http.baseline
    echo "[$(date +%T)] baseline recorded for storkfront homepage"
  fi
  # depot /memos listing
  timeout 5 curl -s "ftp://anonymous:x@172.16.$T.30/memos/" > $BASE/ftp.now 2>/dev/null
  if [[ -s $BASE/ftp.now ]]; then
    if [[ -f $BASE/ftp.baseline ]]; then
      diff -q $BASE/ftp.baseline $BASE/ftp.now >/dev/null \
        || echo "[$(date +%T)] !! DEPOT /memos LISTING CHANGED"
    else
      cp $BASE/ftp.now $BASE/ftp.baseline
      echo "[$(date +%T)] baseline recorded for depot /memos"
    fi
  else
    echo "[$(date +%T)] !! DEPOT anonymous FTP not responding"
  fi
  sleep 60
done
EOF
chmod +x /usr/local/bin/hpcc-integrity
ok "run it:  tmux new -s integrity \"hpcc-integrity $TEAM\""

# ---------- permissions --------------------------------------------------------
log "Fixing permissions"
chmod 644 /etc/passwd /etc/group
chmod 640 /etc/shadow
chmod 440 /etc/sudoers
chmod 700 /root
ok "permissions set"

baseline_report

log "===== GENERATOR DONE ====="
echo "    Generator is out of Red Team scope -- use it as your vault + monitor."
echo "    Start both watchers now:"
echo "      tmux new -d -s watch     \"hpcc-watch $TEAM\""
echo "      tmux new -d -s integrity \"hpcc-integrity $TEAM\""
