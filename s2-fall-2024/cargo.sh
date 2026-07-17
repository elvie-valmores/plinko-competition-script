#!/bin/bash
# ==============================================================================
# HPCC Season 2 (Fall 2024) - CARGO  (172.16.t.40, Linux)
#
# Scored services:
#   SSH - hkeating must log in via SSH (PASSWORD auth)
#   FTP - the ANONYMOUS user must log in and read /var/ftp/ImaHorse.jpg,
#         verified by file hash. vsftpd is the required server.
#
# !!! The single biggest trap on this box !!!
#   anonymous_enable=NO kills the FTP check outright. The check IS an anonymous
#   login. You cannot "harden" that away -- you harden around it: read-only,
#   no upload, chrooted, jailed to /var/ftp, and the scored file made immutable.
#
# Run as root:  sudo bash cargo-172.16.t.40.sh
# ==============================================================================
set -uo pipefail
source "$(dirname "$0")/lib/common-linux.sh"

require_root
backup_configs
prompt_new_password

read -rp "Team number (the 't' in 172.16.t.40): " TEAM
SUBNET="172.16.${TEAM}.0/24"

log "===== CARGO: SSH + anonymous FTP ====="

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

# ---------- protect the scored file --------------------------------------------
# The check hashes ImaHorse.jpg. If Red Team overwrites or deletes it, you fail
# even though FTP is technically "up". Hash it, back it up off-box, freeze it.
log "Protecting the scored file /var/ftp/ImaHorse.jpg"
if [[ -f /var/ftp/ImaHorse.jpg ]]; then
  unlock /var/ftp/ImaHorse.jpg
  sha256sum /var/ftp/ImaHorse.jpg | tee /root/imahorse.sha256 | sed 's/^/    /'
  mkdir -p /root/ftp-backup
  cp -a /var/ftp/ImaHorse.jpg /root/ftp-backup/
  chown root:root /var/ftp/ImaHorse.jpg
  chmod 444 /var/ftp/ImaHorse.jpg
  chattr +i /var/ftp/ImaHorse.jpg
  ok "hash recorded, copy in /root/ftp-backup, file immutable"
  echo "    Copy it to sonar too:"
  echo "      scp /root/ftp-backup/ImaHorse.jpg plinktern@172.16.${TEAM}.5:/opt/hpcc-vault/cargo/"
else
  warn "/var/ftp/ImaHorse.jpg IS MISSING. The FTP check cannot pass. Restore it now."
fi

# Lock the directory itself so nothing new can be dropped alongside it.
chown root:root /var/ftp
chmod 555 /var/ftp
ok "/var/ftp is root-owned and non-writable"

# ---------- vsftpd -------------------------------------------------------------
# Written as a whole file rather than appended. vsftpd takes the LAST occurrence
# of a directive, so appending to a config that already sets anonymous_enable
# produces confusing, hard-to-debug results.
log "Writing a clean vsftpd.conf"
unlock /etc/vsftpd.conf
cp -a /etc/vsftpd.conf "$BACKUP_DIR/vsftpd.conf.pre" 2>/dev/null

cat > /etc/vsftpd.conf <<'EOF'
# ===== HPCC hardened vsftpd =====
listen=YES
listen_ipv6=NO

# --- SCORED: anonymous read access is the check. It stays ON. ---
anonymous_enable=YES
anon_root=/var/ftp
no_anon_password=YES
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_other_write_enable=NO
anon_world_readable_only=YES

# --- local users: off. Nobody needs FTP shell accounts here. ---
local_enable=NO
write_enable=NO

# --- jail everything ---
chroot_local_user=YES
allow_writeable_chroot=NO
hide_ids=YES

# --- logging: you want to see Red Team poking at this ---
xferlog_enable=YES
xferlog_std_format=YES
xferlog_file=/var/log/vsftpd.log
log_ftp_protocol=YES
dual_log_enable=YES

# --- limits ---
max_clients=20
max_per_ip=5
idle_session_timeout=120
data_connection_timeout=60
connect_from_port_20=YES

# --- passive mode: pin the range so the firewall can be tight ---
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100

# --- misc hardening ---
ascii_upload_enable=NO
ascii_download_enable=NO
ftpd_banner=Authorized use only.
seccomp_sandbox=NO
EOF

# Drop any userlist left over from the base image
rm -f /etc/vsftpd.userlist

if vsftpd /etc/vsftpd.conf -olisten=NO 2>&1 | grep -qi 'bad\|error'; then
  warn "vsftpd config may be invalid - check manually"
fi
systemctl restart vsftpd 2>/dev/null || service vsftpd restart
sleep 2
systemctl is-active vsftpd >/dev/null && ok "vsftpd running" || warn "VSFTPD NOT RUNNING"

# ---------- firewall -----------------------------------------------------------
log "Configuring UFW"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    comment 'ssh - SCORED'
ufw allow 21/tcp    comment 'ftp control - SCORED'
ufw allow 20/tcp    comment 'ftp active data'
ufw allow 40000:40100/tcp comment 'ftp passive data'
ufw --force enable
ufw status verbose | sed 's/^/    /'

# ---------- verify the check will pass -----------------------------------------
log "Simulating the FTP score check"
if command -v curl >/dev/null; then
  if curl -s --max-time 10 "ftp://anonymous:x@127.0.0.1/ImaHorse.jpg" -o /tmp/scoretest.jpg 2>/dev/null; then
    if sha256sum -c /root/imahorse.sha256 --status 2>/dev/null <<< "$(cat /root/imahorse.sha256 | cut -d' ' -f1)  /tmp/scoretest.jpg"; then
      ok "SCORE CHECK SIMULATION PASSED - anonymous download, hash matches"
    else
      ok "anonymous download worked (verify hash manually)"
    fi
    rm -f /tmp/scoretest.jpg
  else
    warn "SCORE CHECK SIMULATION FAILED - anonymous FTP download did not work"
  fi
fi

# ---------- file permissions ---------------------------------------------------
log "Fixing permissions"
chmod 644 /etc/passwd /etc/group
chmod 640 /etc/shadow
chmod 440 /etc/sudoers
chmod 700 /root
ok "permissions set"

# ---------- lock configs -------------------------------------------------------
log "Making configs immutable (chattr -i to edit later)"
lock /etc/vsftpd.conf
lock /etc/ssh/sshd_config.d/99-hpcc.conf
lock /etc/passwd
lock /etc/shadow

baseline_report

log "===== CARGO DONE ====="
echo "    Watch /var/log/vsftpd.log during the round: tail -f /var/log/vsftpd.log"
echo "    If ImaHorse.jpg vanishes:  chattr -i /var/ftp 2>/dev/null;"
echo "                               cp -a /root/ftp-backup/ImaHorse.jpg /var/ftp/;"
echo "                               chattr +i /var/ftp/ImaHorse.jpg"
