<#
================================================================================
 HPCC Season 2 (Fall 2024) - SAILS  (172.16.t.20, Windows Server)

 Scored services:
   RDP  - hkeating must be able to log in over RDP
   HTTP - MediaWiki must return 200 OK at the site root, AND specific strings
          must still be present on Dr. Ravy's page. Apache is the required
          web server.

 Two things make this box tricky:

 1. The HTTP check reads PAGE CONTENT, not just the status code. Red Team can
    leave Apache happily serving 200s while defacing Dr. Ravy's article, and
    you fail. Deleting the page = fail. So: back up the wiki, watch the page.

 2. MediaWiki here reads its database from MAST over the network. If mast's
    MySQL goes down or gets firewalled to localhost, sails' HTTP check dies
    too, and you will waste twenty minutes debugging the wrong box.

 Wiki accounts from the packet: PlinkoMaster:plinkosauce, Dr.Ravy:plinkularity
 Both are public knowledge = both are Red Team's first login attempt.

 Run in an ELEVATED PowerShell:
   powershell -ExecutionPolicy Bypass -File .\sails-172.16.t.20.ps1
================================================================================
#>

. "$PSScriptRoot\lib\common-windows.ps1"

Require-Admin
Backup-State

$Team   = Read-Host "Team number (the 't' in 172.16.t.20)"
$Subnet = "172.16.$Team.0/24"
$MastIP = "172.16.$Team.30"

Log "===== SAILS: RDP + HTTP (MediaWiki on Apache) ====="

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
Audit-Persistence
Disable-UnneededServices

# ---------- RDP (SCORED) ------------------------------------------------------
Log "Configuring RDP -- this is a SCORED service, it must stay reachable"

Harden-RDP-Common

# Explicitly ensure RDP is ON. Never set fDenyTSConnections=1 here.
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
    fDenyTSConnections -Value 0 -Force
Set-Service TermService -StartupType Automatic
Start-Service TermService -ErrorAction SilentlyContinue
Ok "RDP enabled with NLA"

# hkeating must be able to RDP in. Make sure it is in Remote Desktop Users.
Log "Ensuring $ScoringUser can RDP in"
try {
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $ScoringUser -ErrorAction SilentlyContinue
    Ok "$ScoringUser is in Remote Desktop Users"
} catch { Warn "could not add $ScoringUser to Remote Desktop Users: $_" }

Log "Remote Desktop Users membership -- remove anything unexpected"
Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host "    $($_.Name)" }

# Kill any RDP session that is not yours -- Red Team may already be logged in.
Log "Current sessions (log off anything you do not recognise with: logoff <ID>)"
query user 2>$null

# ---------- Apache / MediaWiki (SCORED) ---------------------------------------
Log "Backing up the wiki BEFORE hardening"

# Find the Apache install -- path varies by image.
$apachePaths = @("C:\Apache24","C:\xampp\apache","C:\Program Files\Apache Group\Apache2",
                 "C:\Program Files\Apache24")
$apacheRoot = $apachePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($apacheRoot) { Ok "Apache found at $apacheRoot" }
else { Warn "Apache not found in the usual places -- locate it manually: Get-CimInstance Win32_Service | ? Name -like '*apache*'" }

# Find MediaWiki (LocalSettings.php is the giveaway)
$lsFile = Get-ChildItem -Path C:\ -Filter "LocalSettings.php" -Recurse -ErrorAction SilentlyContinue |
          Select-Object -First 1
if ($lsFile) {
    $wikiRoot = $lsFile.DirectoryName
    Ok "MediaWiki found at $wikiRoot"

    # Full file backup of the wiki -- fast insurance against defacement.
    $wikiBak = "$BackupDir\wiki-files"
    New-Item -ItemType Directory -Force -Path $wikiBak | Out-Null
    Copy-Item -Path $wikiRoot -Destination $wikiBak -Recurse -Force -ErrorAction SilentlyContinue
    Ok "wiki files copied to $wikiBak"

    # LocalSettings.php holds the DB password in cleartext. Read-protect it.
    icacls "$($lsFile.FullName)" /inheritance:r /grant:r "Administrators:F" "SYSTEM:F" | Out-Null
    Ok "LocalSettings.php locked down to Administrators/SYSTEM"

    Warn "LocalSettings.php contains the mast MySQL password in cleartext."
    Warn "If you rotate that DB user's password on mast, you MUST update"
    Warn "  `$wgDBpassword in $($lsFile.FullName) or the HTTP check dies."

    # Snapshot the scored page so you can spot a defacement instantly.
    Log "Recording a hash of Dr. Ravy's page (the scored content)"
    try {
        $ravy = Invoke-WebRequest -Uri "http://localhost/index.php/Dr._Ravy_Gordon" `
                -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        $ravy.Content | Out-File "$BackupDir\ravy-page.baseline.html" -Encoding UTF8
        Ok "baseline saved: $BackupDir\ravy-page.baseline.html"
    } catch { Warn "could not fetch Dr. Ravy's page: $_" }
} else {
    Warn "LocalSettings.php not found -- find the wiki root before continuing."
}

# ---------- MediaWiki account hardening ---------------------------------------
Log "MediaWiki accounts"
Write-Host @"
    The packet publishes these wiki logins, so Red Team has them too:
        PlinkoMaster : plinkosauce
        Dr.Ravy      : plinkularity

    Change both from the wiki UI (Special:ChangePassword) or from the wiki root:
        php maintenance/changePassword.php --user=PlinkoMaster --password=<new>
        php maintenance/changePassword.php --user=Dr.Ravy      --password=<new>

    Then list every account and delete/lock anything you did not create:
        php maintenance/listusers.php

    NOTE: the HTTP check reads Dr. Ravy's PAGE, not the account. Changing the
    password is safe. DELETING the user or the page is not.
"@ -ForegroundColor White

if ($wikiRoot) {
    Log "Hardening MediaWiki config (appending to LocalSettings.php)"
    $ls = "$wikiRoot\LocalSettings.php"
    $harden = @"

# ===== HPCC hardening =====
# Anonymous editing is how a wiki gets defaced in ten seconds.
`$wgGroupPermissions['*']['edit']            = false;
`$wgGroupPermissions['*']['createaccount']   = false;
`$wgGroupPermissions['*']['createpage']      = false;
`$wgGroupPermissions['*']['createtalk']      = false;
`$wgGroupPermissions['*']['upload']          = false;
`$wgGroupPermissions['user']['createaccount']= false;
# Anonymous READ stays on -- the score check is an unauthenticated GET.
`$wgGroupPermissions['*']['read']            = true;
# Turn off file upload entirely; it is a webshell vector and is not scored.
`$wgEnableUploads = false;
# Do not leak version info to Red Team's scanners.
`$wgShowExceptionDetails = false;
`$wgShowDBErrorBacktrace = false;
"@
    Add-Content -Path $ls -Value $harden
    Ok "MediaWiki permissions tightened (anonymous read preserved)"
}

# ---------- Apache hardening --------------------------------------------------
if ($apacheRoot) {
    Log "Apache hardening notes"
    Write-Host @"
    Add to $apacheRoot\conf\httpd.conf (then restart the Apache service):

        ServerTokens Prod          # stop advertising version numbers
        ServerSignature Off
        TraceEnable Off
        Timeout 30
        <Directory />
            Options -Indexes -ExecCGI -FollowSymLinks
            AllowOverride None
        </Directory>

    Then hunt for webshells -- .php files that do not belong to MediaWiki:
        Get-ChildItem $wikiRoot -Recurse -Include *.php |
            Where-Object { `$_.LastWriteTime -gt (Get-Date).AddDays(-2) } |
            Select-Object FullName, LastWriteTime

    The rule sheet forbids swapping Apache for another web server, so keep it.
"@ -ForegroundColor White

    $apacheSvc = Get-Service | Where-Object { $_.Name -like "*apache*" } | Select-Object -First 1
    if ($apacheSvc) {
        Set-Service $apacheSvc.Name -StartupType Automatic
        Ok "$($apacheSvc.Name) set to automatic start"
    }
}

# ---------- firewall ----------------------------------------------------------
Reset-Firewall
Allow-In -Name "RDP-SCORED"  -Port 3389
Allow-In -Name "HTTP-SCORED" -Port 80
New-NetFirewallRule -DisplayName "HPCC-ICMP" -Direction Inbound -Protocol ICMPv4 `
    -Action Allow -RemoteAddress $Subnet -ErrorAction SilentlyContinue | Out-Null
# Outbound to mast's MySQL must keep working -- default policy allows outbound,
# so nothing to add, but do not "harden" outbound to deny-all on this box.
Ok "note: outbound to $MastIP:3306 must stay open (MediaWiki's database)"

# ---------- verify ------------------------------------------------------------
Log "Simulating the score checks"
try {
    $r = Invoke-WebRequest -Uri "http://localhost/" -UseBasicParsing -TimeoutSec 10
    if ($r.StatusCode -eq 200) { Ok "HTTP SCORE CHECK: got 200 OK at root" }
    else { Warn "HTTP root returned $($r.StatusCode)" }
} catch { Warn "HTTP SCORE CHECK FAILED at root: $_" }

try {
    $r2 = Invoke-WebRequest -Uri "http://localhost/index.php/Dr._Ravy_Gordon" -UseBasicParsing -TimeoutSec 10
    if ($r2.StatusCode -eq 200) { Ok "Dr. Ravy's page returns 200 (content strings must also match)" }
} catch { Warn "Dr. Ravy's page failed: $_" }

Log "Testing database reachability on mast"
if (Test-NetConnection -ComputerName $MastIP -Port 3306 -InformationLevel Quiet) {
    Ok "mast:3306 reachable -- MediaWiki can reach its database"
} else {
    Warn "CANNOT REACH $MastIP:3306 -- the HTTP check will fail. Fix mast's firewall/mysqld."
}

if ((Get-Service TermService).Status -eq "Running") { Ok "RDP service running" }
else { Warn "TermService not running -- the RDP check will fail" }

Baseline-Report

Log "===== SAILS DONE ====="
Write-Host "    Watch for defacement:"
Write-Host "      Compare against C:\HPCC-Backup\ravy-page.baseline.html"
Write-Host "    If you rotate hkeating's password, submit a PCR FIRST (sails.credlist)."
