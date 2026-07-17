#!/bin/bash
# ==============================================================================
# HPCC Season 2 (Fall 2024) - SONAR  (172.16.t.5, Linux)
#
# Role in the packet:  out of scope for Red Team. No scored services.
# What that means:     this is your safe box. Treat it as the team's jump host,
#                      note-taking box, and backup vault. Red Team cannot touch
#                      it, so anything you stash here survives.
#
# Because nothing on sonar is scored, we can lock it down HARD -- key-only SSH,
# no scoring exceptions. This is the one box where "PasswordAuthentication no"
# is safe, and even then we leave it on so your teammates can get in fast.
#
# Run as root:  sudo bash sonar-172.16.t.5.sh
# ==============================================================================
set -uo pipefail
source "$(dirname "$0")/lib/common-linux.sh"

require_root
backup_configs
prompt_new_password

log "===== SONAR: safe-box setup ====="

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

# ---------- firewall -----------------------------------------------------------
# Sonar serves nothing. Only SSH in, from our own subnet.
log "Configuring UFW (SSH only, from the team subnet)"
SUBNET=$(ip -4 -o addr show scope global | awk '{print $4}' | head -1 | cut -d/ -f1 | cut -d. -f1-3)
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow from "${SUBNET}.0/24" to any port 22 proto tcp comment 'ssh from team subnet'
ufw --force enable
ufw status verbose | sed 's/^/    /'

# ---------- backup vault -------------------------------------------------------
# Pull config backups off the scored boxes and park them here. If Red Team
# nukes /etc on mast at 5pm, you want a copy somewhere they can't reach.
log "Creating backup vault at /opt/hpcc-vault"
mkdir -p /opt/hpcc-vault/{helm,sails,mast,cargo}
chmod 700 /opt/hpcc-vault
cat > /opt/hpcc-vault/README.txt <<'EOF'
Sonar is out of scope for Red Team. Copy anything valuable here:

  # from your laptop, for each Linux box:
  scp -r plinktern@172.16.<t>.30:/root/hpcc-backup-* plinktern@172.16.<t>.5:/opt/hpcc-vault/mast/

  # database dumps:
  ssh plinktern@172.16.<t>.30 'mysqldump -u root --all-databases' > /opt/hpcc-vault/mast/db.sql

Do NOT copy anything off the competition network to your personal device --
that is an exfiltration rule violation. Sonar is inside the environment, so
it is fine.
EOF
ok "vault ready"

# ---------- watch scripts ------------------------------------------------------
log "Installing a service-check loop you can run in tmux"
cat > /usr/local/bin/hpcc-watch <<'EOF'
#!/bin/bash
# Poll every scored service from sonar. Run in tmux; catches outages before
# the scoreboard does.
T="${1:?usage: hpcc-watch <team-number>}"
while :; do
  clear; date
  echo "--- helm  172.16.$T.10 ---"
  timeout 3 nc -z 172.16.$T.10 22  && echo "  ssh  UP" || echo "  ssh  DOWN"
  timeout 3 nslookup sails.plinko.horse 172.16.$T.10 >/dev/null 2>&1 \
      && echo "  dns  UP" || echo "  dns  DOWN"
  echo "--- sails 172.16.$T.20 ---"
  timeout 3 nc -z 172.16.$T.20 3389 && echo "  rdp  UP" || echo "  rdp  DOWN"
  code=$(timeout 3 curl -s -o /dev/null -w '%{http_code}' http://172.16.$T.20/)
  echo "  http $code"
  echo "--- mast  172.16.$T.30 ---"
  timeout 3 nc -z 172.16.$T.30 22   && echo "  ssh   UP" || echo "  ssh   DOWN"
  timeout 3 nc -z 172.16.$T.30 3306 && echo "  mysql UP" || echo "  mysql DOWN"
  echo "--- cargo 172.16.$T.40 ---"
  timeout 3 nc -z 172.16.$T.40 22 && echo "  ssh UP" || echo "  ssh DOWN"
  timeout 3 nc -z 172.16.$T.40 21 && echo "  ftp UP" || echo "  ftp DOWN"
  sleep 20
done
EOF
chmod +x /usr/local/bin/hpcc-watch
ok "run:  tmux new -s watch 'hpcc-watch <your-team-number>'"

baseline_report

log "===== SONAR DONE ====="
echo "    Sonar is out of Red Team scope. Use it as your vault and monitor."
