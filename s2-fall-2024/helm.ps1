<#
================================================================================
 HPCC Season 2 (Fall 2024) - HELM  (172.16.t.10, Windows Server)

 Scored services:
   SSH - the hkeating user must log in over SSH (unusual on Windows, but scored)
   DNS - an A record  sails.plinko.horse -> 172.16.t.20  must resolve

 The DNS check is the one people lose. It is not enough for the DNS service to
 be running -- the specific A record must resolve to the specific IP. Red Team's
 favourite move here is editing the record to point somewhere else, which leaves
 the service "up" and the check red. This script records the correct zone,
 re-asserts it, and installs a self-healing task.

 Run in an ELEVATED PowerShell:
   powershell -ExecutionPolicy Bypass -File .\helm-172.16.t.10.ps1
================================================================================
#>

. "$PSScriptRoot\lib\common-windows.ps1"

Require-Admin
Backup-State

$Team    = Read-Host "Team number (the 't' in 172.16.t.10)"
$Subnet  = "172.16.$Team.0/24"
$SailsIP = "172.16.$Team.20"

Log "===== HELM: DNS + SSH ====="

# ---------- accounts ----------------------------------------------------------
Audit-Administrators
Disable-GuestAndDefault
$pw = Get-NewPassword
Rotate-LocalPasswords -Password $pw
Set-PasswordPolicy

# ---------- baseline ----------------------------------------------------------
Disable-SMBv1
Enable-Defender
Enable-AuditLogging
Harden-RDP-Common
Audit-Persistence

# Keep nothing extra. DNS Server + sshd are the only services that matter here.
Disable-UnneededServices

# ---------- DNS ---------------------------------------------------------------
Log "Securing the DNS server role"

Import-Module DnsServer -ErrorAction SilentlyContinue

# --- Back up the zone before touching it ---
$zone = "plinko.horse"
try {
    Export-DnsServerZone -Name $zone -FileName "hpcc-zone-backup.dns" -ErrorAction Stop
    Ok "zone exported to C:\Windows\System32\dns\hpcc-zone-backup.dns"
} catch { Warn "zone export failed: $_" }

Get-DnsServerResourceRecord -ZoneName $zone -ErrorAction SilentlyContinue |
    Export-Csv "$BackupDir\dns-records.csv" -NoTypeInformation

Log "Current records in $zone"
Get-DnsServerResourceRecord -ZoneName $zone -ErrorAction SilentlyContinue |
    Select-Object HostName, RecordType,
        @{n='Data';e={$_.RecordData.IPv4Address.IPAddressToString}} |
    Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }

# --- Re-assert the SCORED record ---
# sails.plinko.horse -> 172.16.t.20 is the literal score check.
Log "Asserting the scored A record: sails.$zone -> $SailsIP"
try {
    $existing = Get-DnsServerResourceRecord -ZoneName $zone -Name "sails" -RRType A -ErrorAction SilentlyContinue
    if ($existing) {
        Remove-DnsServerResourceRecord -ZoneName $zone -Name "sails" -RRType A -Force -ErrorAction SilentlyContinue
    }
    Add-DnsServerResourceRecordA -ZoneName $zone -Name "sails" -IPv4Address $SailsIP -TimeToLive 00:05:00
    Ok "sails.$zone -> $SailsIP"
} catch { Warn "could not set the scored record: $_" }

# --- Helpful (unscored) records for your own sanity ---
$others = @{ "helm" = "172.16.$Team.10"; "mast" = "172.16.$Team.30";
             "cargo" = "172.16.$Team.40"; "sonar" = "172.16.$Team.5" }
foreach ($h in $others.Keys) {
    try {
        Remove-DnsServerResourceRecord -ZoneName $zone -Name $h -RRType A -Force -ErrorAction SilentlyContinue
        Add-DnsServerResourceRecordA -ZoneName $zone -Name $h -IPv4Address $others[$h] -TimeToLive 00:05:00
        Ok "$h.$zone -> $($others[$h])  (not scored, but useful)"
    } catch {}
}

# --- Lock the zone down ---
Log "Restricting DNS behaviour"
try {
    # Dynamic updates are how an attacker rewrites your record without touching the box.
    Set-DnsServerPrimaryZone -Name $zone -DynamicUpdate "None" -ErrorAction Stop
    Ok "dynamic updates DISABLED on $zone"
} catch { Warn "could not disable dynamic updates: $_" }

try {
    # Do not be an open resolver for the rest of the network.
    Set-DnsServerRecursion -Enable $false -ErrorAction Stop
    Ok "recursion disabled"
} catch { Warn "could not disable recursion: $_" }

try {
    Set-DnsServerZoneTransferPolicy -ZoneName $zone -ErrorAction SilentlyContinue
    Set-DnsServerPrimaryZone -Name $zone -SecureSecondaries "NoTransfer" -ErrorAction Stop
    Ok "zone transfers disabled (no AXFR for Red Team recon)"
} catch { Warn "could not disable zone transfer: $_" }

# --- Self-healing task ---
# If the scored record gets changed, this puts it back within a minute.
Log "Installing a DNS self-heal scheduled task"
$healScript = "C:\HPCC-Backup\dns-heal.ps1"
@"
# Re-asserts the scored A record if it drifts.
`$want = '$SailsIP'
try {
    `$r = Get-DnsServerResourceRecord -ZoneName '$zone' -Name 'sails' -RRType A -ErrorAction Stop
    `$have = `$r.RecordData.IPv4Address.IPAddressToString
    if (`$have -ne `$want) {
        Remove-DnsServerResourceRecord -ZoneName '$zone' -Name 'sails' -RRType A -Force
        Add-DnsServerResourceRecordA -ZoneName '$zone' -Name 'sails' -IPv4Address `$want -TimeToLive 00:05:00
        "[`$(Get-Date)] HEALED sails: was `$have, now `$want" | Out-File C:\HPCC-Backup\dns-heal.log -Append
    }
} catch {
    Add-DnsServerResourceRecordA -ZoneName '$zone' -Name 'sails' -IPv4Address `$want -TimeToLive 00:05:00 -ErrorAction SilentlyContinue
    "[`$(Get-Date)] RECREATED sails record" | Out-File C:\HPCC-Backup\dns-heal.log -Append
}
"@ | Set-Content $healScript

$act  = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File $healScript"
$trg  = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "HPCC-DNS-Heal" -Action $act -Trigger $trg `
    -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Ok "HPCC-DNS-Heal runs every minute (log: C:\HPCC-Backup\dns-heal.log)"

Restart-Service DNS -Force -ErrorAction SilentlyContinue
Ok "DNS service restarted"

# ---------- SSH ---------------------------------------------------------------
# OpenSSH on Windows. The scoring engine logs in as hkeating WITH A PASSWORD,
# so password auth stays enabled here too.
Log "Hardening OpenSSH Server"

$sshd = Get-Service sshd -ErrorAction SilentlyContinue
if (-not $sshd) {
    Warn "sshd service not found. The SSH check cannot pass. Installing OpenSSH..."
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue
}

$sshConf = "C:\ProgramData\ssh\sshd_config"
if (Test-Path $sshConf) {
    Copy-Item $sshConf "$BackupDir\sshd_config.pre" -Force
    @"
# HPCC hardened sshd_config
Port 22
PermitRootLogin no
PermitEmptyPasswords no
# SCORED: the engine authenticates with a password. Leave this yes.
PasswordAuthentication yes
PubkeyAuthentication no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
# Only these two accounts may SSH in.
AllowUsers $ScoringUser $LocalUser
Subsystem sftp sftp-server.exe
"@ | Set-Content $sshConf -Encoding ASCII
    Ok "sshd_config rewritten"
}

# Windows OpenSSH ignores AuthorizedKeysFile for admins by default and uses this
# file instead -- a well-known persistence spot. Clear it.
$adminKeys = "C:\ProgramData\ssh\administrators_authorized_keys"
if (Test-Path $adminKeys) {
    Copy-Item $adminKeys "$BackupDir\admin_keys.found" -Force
    Warn "Found administrators_authorized_keys -- backed up and REMOVED (possible Red Team persistence)"
    Remove-Item $adminKeys -Force
}
Get-ChildItem "C:\Users\*\.ssh\authorized_keys" -ErrorAction SilentlyContinue | ForEach-Object {
    Warn "Removing $($_.FullName)"
    Remove-Item $_.FullName -Force
}

Set-Service sshd -StartupType Automatic
Restart-Service sshd -Force -ErrorAction SilentlyContinue
Ok "sshd restarted"

# ---------- firewall ----------------------------------------------------------
Reset-Firewall
Allow-In -Name "SSH-SCORED" -Port 22
Allow-In -Name "DNS-TCP-SCORED" -Port 53 -Protocol TCP
Allow-In -Name "DNS-UDP-SCORED" -Port 53 -Protocol UDP
# RDP is not scored on helm, but you need it to administer the box. Team subnet only.
Allow-In -Name "RDP-admin" -Port 3389 -RemoteIP $Subnet
Allow-In -Name "ICMP-ping" -Port 0 -Protocol ICMPv4 -RemoteIP $Subnet 2>$null
New-NetFirewallRule -DisplayName "HPCC-ICMP" -Direction Inbound -Protocol ICMPv4 `
    -Action Allow -RemoteAddress $Subnet -ErrorAction SilentlyContinue | Out-Null

# ---------- verify ------------------------------------------------------------
Log "Simulating the score checks"
$r = Resolve-DnsName -Name "sails.plinko.horse" -Server "127.0.0.1" -Type A -ErrorAction SilentlyContinue
if ($r -and $r.IPAddress -contains $SailsIP) {
    Ok "DNS SCORE CHECK SIMULATION PASSED (sails.plinko.horse -> $SailsIP)"
} else {
    Warn "DNS SCORE CHECK SIMULATION FAILED -- got: $($r.IPAddress)"
}
if ((Get-Service sshd -ErrorAction SilentlyContinue).Status -eq "Running") {
    Ok "sshd is running"
} else {
    Warn "SSHD IS NOT RUNNING -- the SSH check will fail"
}

Baseline-Report

Log "===== HELM DONE ====="
Write-Host "    If you change hkeating's password, submit a PCR FIRST (helm.credlist)."
Write-Host "    Watch the heal log:  Get-Content C:\HPCC-Backup\dns-heal.log -Wait"
