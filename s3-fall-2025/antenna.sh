#!/bin/bash
# ==============================================================================
# HPCC Season 3 (Fall 2025) - ANTENNA  (172.16.t.10, Debian 12 "Bookworm")
#
# Scored services:
#   SSH - jmoney must log in via SSH (PASSWORD auth) and run unprivileged commands
#   DNS - BIND must resolve name lookups for your scored servers, e.g.
#         storkfront.teamt.plinko.horse -> 172.16.t.20
#
# The DNS check is a content check, not a liveness check. named can be running
# perfectly while the check is red because a record points somewhere wrong.
# Red Team knows this. So: back up the zone, re-assert it, hash it, self-heal it.
#
# Zone file:  /etc/bind/db.teamt.plinko.horse
# Zone conf:  /etc/bind/named.conf.default-zones
#
# Run as root:  sudo bash antenna-172.16.t.10.sh
# ==============================================================================
set -uo pipefail
source "$(dirname "$0")/lib/common-linux.sh"

require_root
detect_distro
backup_configs
prompt_new_password

read -rp "Team number (the 't' in 172.16.t.10): " TEAM
SUBNET="172.16.${TEAM}.0/24"
ZONE="team${TEAM}.plinko.horse"
ZONEFILE="/etc/bind/db.${ZONE}"

log "===== ANTENNA: SSH + BIND DNS (Debian 12) ====="

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

# ---------- back up the zone FIRST ---------------------------------------------
log "Backing up BIND configuration"
mkdir -p "$BACKUP_DIR/bind"
cp -a /etc/bind/* "$BACKUP_DIR/bind/" 2>/dev/null
ok "all of /etc/bind copied to $BACKUP_DIR/bind"
echo "    Get it off-box now:"
echo "      scp -r $BACKUP_DIR/bind plinktern@172.16.${TEAM}.5:/opt/hpcc-vault/antenna/"

# ---------- rewrite the zone file ----------------------------------------------
# Written whole rather than patched. The packet gives us the exact record set,
# so we can restore it to a known-good state instead of trusting what is there.
log "Writing a known-good zone file: $ZONEFILE"
unlock "$ZONEFILE"
SERIAL=$(date +%Y%m%d%H)

cat > "$ZONEFILE" <<EOF
\$TTL    300
@   IN  SOA ns.${ZONE}. admin.${ZONE}. (
        ${SERIAL} ; Serial
        3600      ; Refresh
        1800      ; Retry
        604800    ; Expire
        300 )     ; Minimum TTL

; Name servers
        IN  NS      ns.${ZONE}.

; A record for the Name Server
ns.${ZONE}.             IN  A   172.16.${TEAM}.10

; A Records  -- storkfront is the one the packet names explicitly as scored,
; but the check says "your scored servers", so keep them all correct.
generator.${ZONE}.      IN  A   172.16.${TEAM}.5
antenna.${ZONE}.        IN  A   172.16.${TEAM}.10
storkfront.${ZONE}.     IN  A   172.16.${TEAM}.20
depot.${ZONE}.          IN  A   172.16.${TEAM}.30
foreman.${ZONE}.        IN  A   172.16.${TEAM}.40
EOF

named-checkzone "$ZONE" "$ZONEFILE" | sed 's/^/    /'
if named-checkzone "$ZONE" "$ZONEFILE" >/dev/null 2>&1; then
  ok "zone file is valid"
  sha256sum "$ZONEFILE" > /root/zone.sha256
  cp -a "$ZONEFILE" /root/zone.known-good
  ok "known-good copy at /root/zone.known-good"
else
  warn "ZONE FILE INVALID -- restoring from backup and stopping"
  cp -a "$BACKUP_DIR/bind/db.${ZONE}" "$ZONEFILE" 2>/dev/null
fi

# ---------- harden named.conf.options ------------------------------------------
log "Hardening BIND options"
unlock /etc/bind/named.conf.options
cp -a /etc/bind/named.conf.options "$BACKUP_DIR/named.conf.options.pre" 2>/dev/null

cat > /etc/bind/named.conf.options <<EOF
acl "trusted" {
    ${SUBNET};
    localhost;
    localnets;
};

options {
    directory "/var/cache/bind";

    // Answer authoritative queries from anyone (the score check may come from
    // scoring infrastructure outside our subnet -- do not gamble on that).
    allow-query { any; };

    // But only OUR network gets recursion. An open resolver is free
    // amplification for anyone who finds it.
    recursion yes;
    allow-recursion { trusted; };
    allow-query-cache { trusted; };

    // No AXFR. Zone transfer is free recon for Red Team.
    allow-transfer { none; };

    // No dynamic updates. This is how a zone gets rewritten remotely.
    allow-update { none; };

    // Do not advertise the version to scanners.
    version "not available";
    hostname none;
    server-id none;

    // Rate limit so we are not a useful reflector.
    rate-limit {
        responses-per-second 20;
        window 5;
    };

    dnssec-validation auto;
    listen-on-v6 { none; };
};
EOF

# ---------- verify zone declaration --------------------------------------------
log "Checking that $ZONE is declared as a master zone"
if ! grep -q "zone \"${ZONE}\"" /etc/bind/named.conf.default-zones 2>/dev/null; then
  warn "$ZONE not declared -- adding it"
  cat >> /etc/bind/named.conf.default-zones <<EOF

zone "${ZONE}" {
    type master;
    file "/etc/bind/db.${ZONE}";
    allow-transfer { none; };
    allow-update { none; };
};
EOF
else
  ok "$ZONE already declared"
fi

named-checkconf && ok "named.conf is valid" || warn "NAMED.CONF INVALID -- fix before restarting"

# ---------- restart ------------------------------------------------------------
log "Restarting BIND"
systemctl restart named 2>/dev/null || systemctl restart bind9
sleep 2
if systemctl is-active named >/dev/null 2>&1 || systemctl is-active bind9 >/dev/null 2>&1; then
  ok "BIND running"
else
  warn "BIND IS NOT RUNNING -- the DNS check will fail. Check: journalctl -u named -n 50"
fi

# ---------- self-heal ----------------------------------------------------------
# If the zone file is modified, restore the known-good copy and reload.
log "Installing a zone self-heal timer"
cat > /usr/local/bin/hpcc-dns-heal <<EOF
#!/bin/bash
# Restores the zone file if it drifts from the known-good copy.
if ! sha256sum -c /root/zone.sha256 --status 2>/dev/null; then
    echo "[\$(date)] ZONE FILE CHANGED - restoring known-good" >> /var/log/hpcc-dns-heal.log
    chattr -i ${ZONEFILE} 2>/dev/null
    cp -a /root/zone.known-good ${ZONEFILE}
    chattr +i ${ZONEFILE} 2>/dev/null
    systemctl reload named 2>/dev/null || systemctl reload bind9
fi
# Also verify the record actually resolves.
if ! nslookup storkfront.${ZONE} 127.0.0.1 2>/dev/null | grep -q "172.16.${TEAM}.20"; then
    echo "[\$(date)] SCORED RECORD NOT RESOLVING - restarting named" >> /var/log/hpcc-dns-heal.log
    systemctl restart named 2>/dev/null || systemctl restart bind9
fi
EOF
chmod +x /usr/local/bin/hpcc-dns-heal

cat > /etc/systemd/system/hpcc-dns-heal.service <<'EOF'
[Unit]
Description=HPCC DNS zone self-heal
[Service]
Type=oneshot
ExecStart=/usr/local/bin/hpcc-dns-heal
EOF
cat > /etc/systemd/system/hpcc-dns-heal.timer <<'EOF'
[Unit]
Description=Run HPCC DNS self-heal every minute
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now hpcc-dns-heal.timer
ok "self-heal timer running (log: /var/log/hpcc-dns-heal.log)"

# ---------- firewall -----------------------------------------------------------
fw_reset
fw_allow_port 22 tcp any "ssh - SCORED"
fw_allow_port 53 tcp any "dns tcp - SCORED"
fw_allow_port 53 udp any "dns udp - SCORED"
fw_enable

# ---------- verify -------------------------------------------------------------
log "Simulating the score checks"
RESULT=$(nslookup "storkfront.${ZONE}" 127.0.0.1 2>/dev/null | grep -A1 "Name:" | grep Address | awk '{print $2}')
if [[ "$RESULT" == "172.16.${TEAM}.20" ]]; then
  ok "DNS SCORE CHECK SIMULATION PASSED (storkfront.${ZONE} -> $RESULT)"
else
  warn "DNS SCORE CHECK SIMULATION FAILED -- got '$RESULT', expected 172.16.${TEAM}.20"
fi

if systemctl is-active ssh >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1; then
  ok "sshd running"
else
  warn "SSHD NOT RUNNING -- the SSH check will fail"
fi

# Confirm jmoney can actually run a command (the check does this)
if id "$SCORING_USER" >/dev/null 2>&1; then
  su - "$SCORING_USER" -c "id" >/dev/null 2>&1 \
    && ok "$SCORING_USER can run commands" \
    || warn "$SCORING_USER cannot run commands -- check shell and home directory"
fi

# ---------- permissions + lock -------------------------------------------------
log "Fixing permissions"
chmod 644 /etc/passwd /etc/group
chmod 640 /etc/shadow
chmod 440 /etc/sudoers
chmod 700 /root
chown -R root:bind /etc/bind
chmod 640 "$ZONEFILE"
ok "permissions set"

log "Making configs immutable (chattr -i to edit later)"
lock "$ZONEFILE"
lock /etc/bind/named.conf.options
lock /etc/ssh/sshd_config.d/99-hpcc.conf
lock /etc/passwd
lock /etc/shadow

baseline_report

log "===== ANTENNA DONE ====="
echo "    Zone file is immutable. To edit:  chattr -i $ZONEFILE"
echo "    ...and remember to update /root/zone.sha256 afterwards, or the"
echo "    self-heal timer will revert your change within a minute."
echo "    Watch it:  tail -f /var/log/hpcc-dns-heal.log"
