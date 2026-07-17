#!/bin/bash
# ==============================================================================
# Horse Plinko Cyber Challenge - Season 2 (Fall 2024)
# Common Linux hardening library. Source this from the per-box scripts.
#   Usage:  source ./00-common-linux.sh
# ==============================================================================

SCORING_USER="hkeating"      # the account the scoring engine logs in as
LOCAL_USER="plinktern"       # your team's interactive account
BACKUP_DIR="/root/hpcc-backup-$(date +%s)"

# ---------- guards -------------------------------------------------------------
require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "[!] Run this as root (sudo -i)." >&2
    exit 1
  fi
}

log()  { echo -e "\n[*] $*"; }
warn() { echo -e "[!] $*" >&2; }
ok()   { echo "    ok: $*"; }

# ---------- backups ------------------------------------------------------------
# Take a copy of everything BEFORE we touch it. If a score check breaks, you can
# diff against these instead of guessing.
backup_configs() {
  log "Backing up configs to $BACKUP_DIR"
  mkdir -p "$BACKUP_DIR"
  for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config \
           /etc/crontab /etc/hosts /etc/resolv.conf; do
    [[ -e "$f" ]] && cp -a "$f" "$BACKUP_DIR/" 2>/dev/null
  done
  for d in /etc/sudoers.d /etc/cron.d /etc/ssh/sshd_config.d; do
    [[ -d "$d" ]] && cp -a "$d" "$BACKUP_DIR/" 2>/dev/null
  done
  crontab -l > "$BACKUP_DIR/root.crontab" 2>/dev/null
  ok "backups in $BACKUP_DIR"
}

# ---------- immutability helpers ----------------------------------------------
# chattr +i is great against Red Team, and equally great at blocking YOU.
# Always unlock before editing.
unlock() { chattr -i "$1" 2>/dev/null; }
lock()   { chattr +i "$1" 2>/dev/null && ok "locked $1"; }

# ---------- password rotation --------------------------------------------------
# Red Team starts with the packet's default creds. Rotating every human account
# in the first two minutes is the single highest-value action you can take.
#
# NOTE: do NOT rotate the scoring user here without filing a PCR on the
# scoreboard first, or the check will start failing.
prompt_new_password() {
  local p1 p2
  while :; do
    read -rsp "New password for local accounts: " p1; echo
    read -rsp "Confirm: " p2; echo
    [[ "$p1" == "$p2" && -n "$p1" ]] && { NEW_PASS="$p1"; return 0; }
    warn "Mismatch or empty, try again."
  done
}

rotate_local_passwords() {
  # Rotates every non-system account except the scoring user and 'nobody'.
  log "Rotating local account passwords"
  local user uid
  while IFS=: read -r user _ uid _; do
    if [[ $uid -ge 1000 && "$user" != "nobody" && "$user" != "$SCORING_USER" ]]; then
      echo "$user:$NEW_PASS" | chpasswd && ok "rotated $user"
    fi
  done < /etc/passwd
  echo
  echo "    Reminder: to rotate $SCORING_USER, submit a PCR on the scoreboard"
  echo "    FIRST, then run:  echo '$SCORING_USER:<newpass>' | chpasswd"
}

# ---------- account hygiene ----------------------------------------------------
lock_root_account() {
  log "Locking root's password (console/sudo still work)"
  passwd -l root >/dev/null && ok "root password locked"
}

purge_ssh_keys() {
  # Red Team's most common persistence: an authorized_keys entry planted before
  # you ever logged in. Wipe them all; you are using passwords for scoring anyway.
  log "Removing all authorized_keys files"
  rm -f /root/.ssh/authorized_keys
  rm -f /home/*/.ssh/authorized_keys
  find / -name authorized_keys -not -path '/proc/*' 2>/dev/null | while read -r k; do
    warn "stray key file: $k"
    rm -f "$k"
  done
  ok "keys purged"
}

audit_uid_zero() {
  # Any account other than root with uid 0 is a backdoor.
  log "Auditing for UID 0 accounts"
  awk -F: '$3==0 && $1!="root" {print "    BACKDOOR ACCOUNT: " $1}' /etc/passwd
  ok "uid 0 audit done"
}

audit_empty_passwords() {
  log "Auditing for empty password hashes"
  awk -F: '($2=="" || $2=="!" ) {print "    NO PASSWORD: " $1}' /etc/shadow
  # Kill Ubuntu's passwordless-login group if present
  sed -i -e '/nopasswdlogin/d' /etc/group
  ok "empty password audit done"
}

audit_sudoers() {
  log "Auditing sudo access (review this output by eye)"
  grep -vE '^\s*#|^\s*$' /etc/sudoers 2>/dev/null | sed 's/^/    /'
  [[ -d /etc/sudoers.d ]] && grep -rvE '^\s*#|^\s*$' /etc/sudoers.d 2>/dev/null | sed 's/^/    /'
  echo "    --- members of sudo/wheel ---"
  getent group sudo wheel 2>/dev/null | sed 's/^/    /'
}

audit_cron() {
  log "Auditing cron (a classic Red Team persistence spot)"
  for f in /etc/crontab /etc/cron.d/*; do
    [[ -e "$f" ]] && { echo "    --- $f ---"; grep -vE '^\s*#|^\s*$' "$f" | sed 's/^/    /'; }
  done
  echo "    --- per-user crontabs ---"
  for u in $(cut -d: -f1 /etc/passwd); do
    local c; c=$(crontab -u "$u" -l 2>/dev/null)
    [[ -n "$c" ]] && echo "    [$u] $c"
  done
}

# ---------- ssh ----------------------------------------------------------------
# IMPORTANT: PasswordAuthentication stays YES. The scoring engine authenticates
# to SSH with a password. Turning it off is an instant zero on the SSH check.
harden_ssh() {
  log "Hardening SSH (password auth intentionally left ON for scoring)"
  unlock /etc/ssh/sshd_config
  cp -a /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.pre" 2>/dev/null

  # Drop-in beats appending: it survives re-runs without duplicating keys.
  mkdir -p /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/99-hpcc.conf <<EOF
# HPCC hardening drop-in
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication yes
PubkeyAuthentication no
AuthorizedKeysFile /dev/null
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
AllowAgentForwarding no
PermitUserEnvironment no
AllowUsers $SCORING_USER $LOCAL_USER
EOF

  # Older sshd builds ignore the drop-in dir unless it is included.
  grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config \
    || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config

  if sshd -t; then
    systemctl restart sshd 2>/dev/null || systemctl restart ssh
    ok "sshd restarted, config valid"
  else
    warn "sshd config INVALID - not restarting. Fix before continuing."
  fi
}

# ---------- tooling ------------------------------------------------------------
install_tools() {
  log "Installing monitoring tools"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y -qq
  apt-get install -y -qq ufw fail2ban tmux curl net-tools lsof auditd 2>/dev/null
  ok "tools installed"
}

start_fail2ban() {
  log "Enabling fail2ban on SSH"
  cat > /etc/fail2ban/jail.d/hpcc.conf <<'EOF'
[sshd]
enabled  = true
maxretry = 5
findtime = 300
bantime  = 600
EOF
  systemctl enable --now fail2ban 2>/dev/null && ok "fail2ban running"
}

# ---------- reporting ----------------------------------------------------------
baseline_report() {
  log "Baseline snapshot (save this; compare against it later)"
  echo "    --- listening ports ---"
  ss -tulpn 2>/dev/null | sed 's/^/    /'
  echo "    --- logged in now ---"
  who | sed 's/^/    /'
  ss -tulpn > "$BACKUP_DIR/ports.baseline" 2>/dev/null
  ps auxf   > "$BACKUP_DIR/ps.baseline"    2>/dev/null
  ok "baseline saved to $BACKUP_DIR"
}
