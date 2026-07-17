#!/bin/bash
# ==============================================================================
# Horse Plinko Cyber Challenge - Season 3 (Fall 2025)
# Common Linux hardening library. Source this from the per-box scripts.
#   Usage:  source ./00-common-linux.sh
#
# Season 3 runs a mix of distros (Linux Mint 22, Debian 12, AlmaLinux 9), so
# this library detects apt vs dnf and ufw vs firewalld rather than assuming.
# ==============================================================================

SCORING_USER="jmoney"        # the account the scoring engine logs in as
LOCAL_USER="plinktern"       # your team's interactive account
BACKUP_DIR="/root/hpcc-backup-$(date +%s)"

# ---------- distro detection ---------------------------------------------------
detect_distro() {
  if command -v apt-get >/dev/null 2>&1; then
    PKG="apt"; FW="ufw"
  elif command -v dnf >/dev/null 2>&1; then
    PKG="dnf"; FW="firewalld"
  else
    echo "[!] Unknown package manager." >&2; exit 1
  fi
  DISTRO=$(grep -oP '^PRETTY_NAME="\K[^"]+' /etc/os-release 2>/dev/null)
  echo "[*] Detected: ${DISTRO:-unknown}  (pkg=$PKG, fw=$FW)"
}

pkg_install() {
  if [[ "$PKG" == "apt" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" 2>/dev/null
  else
    dnf install -y -q "$@" 2>/dev/null
  fi
}

pkg_update() {
  if [[ "$PKG" == "apt" ]]; then apt-get update -y -qq; else dnf check-update -q || true; fi
}

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

unlock() { chattr -i "$1" 2>/dev/null; }
lock()   { chattr +i "$1" 2>/dev/null && ok "locked $1"; }

# ---------- password rotation --------------------------------------------------
# Every team gets plinktern:IHPLRulez! out of the packet. So does Red Team.
# Rotate in the first two minutes or you are simply giving away shells.
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
  log "Removing all authorized_keys files"
  rm -f /root/.ssh/authorized_keys
  rm -f /home/*/.ssh/authorized_keys
  find / -name authorized_keys -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | while read -r k; do
    warn "stray key file: $k"
    rm -f "$k"
  done
  ok "keys purged"
}

audit_uid_zero() {
  log "Auditing for UID 0 accounts"
  awk -F: '$3==0 && $1!="root" {print "    BACKDOOR ACCOUNT: " $1}' /etc/passwd
  ok "uid 0 audit done"
}

audit_empty_passwords() {
  log "Auditing for empty password hashes"
  awk -F: '($2=="" ) {print "    NO PASSWORD: " $1}' /etc/shadow
  sed -i -e '/nopasswdlogin/d' /etc/group
  ok "empty password audit done"
}

audit_sudoers() {
  log "Auditing sudo access (review by eye)"
  grep -vE '^\s*#|^\s*$' /etc/sudoers 2>/dev/null | sed 's/^/    /'
  [[ -d /etc/sudoers.d ]] && grep -rvE '^\s*#|^\s*$' /etc/sudoers.d 2>/dev/null | sed 's/^/    /'
  echo "    --- members of sudo/wheel ---"
  getent group sudo wheel 2>/dev/null | sed 's/^/    /'
  echo "    Look for NOPASSWD entries you did not add."
}

audit_cron() {
  log "Auditing cron"
  for f in /etc/crontab /etc/cron.d/*; do
    [[ -e "$f" ]] && { echo "    --- $f ---"; grep -vE '^\s*#|^\s*$' "$f" | sed 's/^/    /'; }
  done
  echo "    --- per-user crontabs ---"
  for u in $(cut -d: -f1 /etc/passwd); do
    local c; c=$(crontab -u "$u" -l 2>/dev/null)
    [[ -n "$c" ]] && echo "    [$u] $c"
  done
  echo "    --- systemd timers ---"
  systemctl list-timers --all --no-pager 2>/dev/null | head -20 | sed 's/^/    /'
}

audit_suid() {
  log "Unusual SUID binaries (compare against a clean box before deleting anything)"
  find / -perm -4000 -type f 2>/dev/null | grep -vE '^/(usr/bin|usr/sbin|bin|sbin)/' | sed 's/^/    SUSPECT: /'
  ok "suid audit done"
}

# ---------- ssh ----------------------------------------------------------------
# The scoring engine SSHes in as jmoney WITH A PASSWORD and runs unprivileged
# commands. PasswordAuthentication must stay yes, and jmoney must have a real
# shell -- do not give it /sbin/nologin.
harden_ssh() {
  log "Hardening SSH (password auth intentionally left ON for scoring)"
  unlock /etc/ssh/sshd_config
  cp -a /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.pre" 2>/dev/null

  mkdir -p /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/99-hpcc.conf <<EOF
# HPCC hardening drop-in
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication yes
PubkeyAuthentication no
AuthorizedKeysFile /dev/null
MaxAuthTries 3
MaxSessions 5
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

  grep -q 'sshd_config.d/\*.conf' /etc/ssh/sshd_config \
    || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config

  # The score check needs a working shell for jmoney.
  if id "$SCORING_USER" >/dev/null 2>&1; then
    local sh; sh=$(getent passwd "$SCORING_USER" | cut -d: -f7)
    if [[ "$sh" == *nologin* || "$sh" == *false* ]]; then
      warn "$SCORING_USER has shell $sh -- the SSH check needs a real shell. Fixing."
      usermod -s /bin/bash "$SCORING_USER"
    fi
    # Also make sure the account is not locked.
    passwd -u "$SCORING_USER" >/dev/null 2>&1
    ok "$SCORING_USER shell/lock state verified"
  else
    warn "$SCORING_USER does not exist on this box -- if SSH is scored here, create it."
  fi

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
  pkg_update
  pkg_install fail2ban tmux curl lsof net-tools
  [[ "$PKG" == "apt" ]] && pkg_install ufw auditd
  [[ "$PKG" == "dnf" ]] && pkg_install firewalld audit
  ok "tools installed"
}

start_fail2ban() {
  log "Enabling fail2ban on SSH"
  mkdir -p /etc/fail2ban/jail.d
  cat > /etc/fail2ban/jail.d/hpcc.conf <<'EOF'
[sshd]
enabled  = true
maxretry = 5
findtime = 300
bantime  = 600
EOF
  systemctl enable --now fail2ban 2>/dev/null && ok "fail2ban running" || warn "fail2ban failed to start"
}

# ---------- firewall wrappers --------------------------------------------------
fw_reset() {
  log "Resetting firewall (deny inbound, allow outbound)"
  if [[ "$FW" == "ufw" ]]; then
    ufw --force reset >/dev/null
    ufw default deny incoming
    ufw default allow outgoing
  else
    systemctl enable --now firewalld
    firewall-cmd --permanent --set-default-zone=drop >/dev/null
    # Wipe whatever the image shipped with
    for s in $(firewall-cmd --zone=public --list-services 2>/dev/null); do
      firewall-cmd --permanent --zone=public --remove-service="$s" >/dev/null 2>&1
    done
  fi
  ok "firewall reset"
}

fw_allow_port() {
  local port="$1" proto="${2:-tcp}" src="${3:-any}" note="${4:-}"
  if [[ "$FW" == "ufw" ]]; then
    if [[ "$src" == "any" ]]; then
      ufw allow "${port}/${proto}" comment "$note"
    else
      ufw allow from "$src" to any port "$port" proto "$proto" comment "$note"
    fi
  else
    if [[ "$src" == "any" ]]; then
      firewall-cmd --permanent --zone=public --add-port="${port}/${proto}" >/dev/null
    else
      firewall-cmd --permanent --zone=public \
        --add-rich-rule="rule family=ipv4 source address=${src} port port=${port} protocol=${proto} accept" >/dev/null
    fi
  fi
  ok "allow ${proto}/${port} from ${src}  ${note:+# $note}"
}

fw_enable() {
  if [[ "$FW" == "ufw" ]]; then
    ufw --force enable
    ufw status verbose | sed 's/^/    /'
  else
    # Bind the NIC into the zone we configured, then reload.
    local iface; iface=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
    firewall-cmd --permanent --zone=public --change-interface="$iface" >/dev/null 2>&1
    firewall-cmd --permanent --set-default-zone=public >/dev/null
    firewall-cmd --reload
    firewall-cmd --list-all | sed 's/^/    /'
  fi
}

# ---------- reporting ----------------------------------------------------------
baseline_report() {
  log "Baseline snapshot (save this; compare later)"
  echo "    --- listening ports ---"
  ss -tulpn 2>/dev/null | sed 's/^/    /'
  echo "    --- logged in now ---"
  who | sed 's/^/    /'
  ss -tulpn > "$BACKUP_DIR/ports.baseline" 2>/dev/null
  ps auxf   > "$BACKUP_DIR/ps.baseline"    2>/dev/null
  ok "baseline saved to $BACKUP_DIR"
}
