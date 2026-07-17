<#
================================================================================
 HPCC Season 3 (Fall 2025) - FOREMAN  (172.16.t.40, Windows Server 2022)

 Scored services:
   RDP   - jmoney must be able to log in over RDP
   MySQL - jmoney must log in to MySQL and read data from the "horsepress"
           database

 THE BIG ONE: storkfront's WooCommerce site reads its data FROM THIS BOX. So
 foreman's MySQL backs TWO score checks:
     foreman-sql   (direct)
     storkfront-web (indirect -- no database, no storefront)
 Which means: binding MySQL to 127.0.0.1, or firewalling 3306 shut, takes down
 two services at once. Do not do it. Restrict by SOURCE ADDRESS instead.

 Packet inconsistency worth knowing: the "Interacting With Your Services" MySQL
 walkthrough says to log into DEPOT to reach MySQL, but the Scored Services page
 puts MySQL on FOREMAN (172.16.t.40). Foreman is authoritative -- the scored
 services list is what the engine checks. Verify on day one and ask White Team
 if it looks different in your environment.

 Run in an ELEVATED PowerShell:
   powershell -ExecutionPolicy Bypass -File .\foreman-172.16.t.40.ps1
================================================================================
#>

. "$PSScriptRoot\lib\common-windows.ps1"

Require-Admin
Show-Platform
Backup-State

$Team       = Read-Host "Team number (the 't' in 172.16.t.40)"
$Subnet     = "172.16.$Team.0/24"
$Storkfront = "172.16.$Team.20"

Log "===== FOREMAN: RDP + MySQL (Server 2022) ====="

# ---------- accounts ----------------------------------------------------------
Audit-Administrators
Disable-GuestAndDefault
$pw = Get-NewPasswordPlain
Rotate-LocalPasswords -PlainPassword $pw
Set-PasswordPolicy

# ---------- baseline ----------------------------------------------------------
Disable-SMBv1
Enable-Defender
Enable-AuditLogging
Audit-Persistence
Disable-UnneededServices

# Server 2022 extras worth having.
Log "Enabling Defender attack surface reduction rules"
try {
    # Block credential stealing from LSASS -- stops the mimikatz-shaped attacks.
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 `
        -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
    # Block process creations from PSExec/WMI commands.
    Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c `
        -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
    Ok "ASR rules enabled"
} catch { Warn "could not set ASR rules: $_" }

# ---------- RDP (SCORED) ------------------------------------------------------
Harden-RDP

# ---------- MySQL: find it -----------------------------------------------------
Log "Locating the MySQL installation"
$mysqlSvc = Get-Service | Where-Object { $_.Name -match "mysql" } | Select-Object -First 1
if ($mysqlSvc) { Ok "MySQL service: $($mysqlSvc.Name) [$($mysqlSvc.Status)]" }
else { Warn "No MySQL service found. The MySQL check cannot pass." }

$mysqlExe = Get-ChildItem "C:\Program Files\MySQL","C:\Program Files (x86)\MySQL","C:\xampp\mysql" `
            -Filter "mysql.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($mysqlExe) {
    $MYSQL = $mysqlExe.FullName
    $MYSQLDUMP = Join-Path $mysqlExe.DirectoryName "mysqldump.exe"
    Ok "mysql.exe at $MYSQL"
} else {
    Warn "mysql.exe not found. Enter its full path."
    $MYSQL = Read-Host "Path to mysql.exe"
    $MYSQLDUMP = $MYSQL -replace "mysql.exe","mysqldump.exe"
}

# ---------- back up the database FIRST -----------------------------------------
# Before anything else. A dump is a 30-second restore instead of a 20-minute
# revert penalty.
Log "Dumping the horsepress database before we touch anything"
New-Item -ItemType Directory -Force -Path "$BackupDir\db" | Out-Null
$rootPw = Read-Host "Current MySQL root password (blank if none)"

$dumpArgs = if ($rootPw) { "-u root -p$rootPw --all-databases" } else { "-u root --all-databases" }
try {
    $out = "$BackupDir\db\all-databases.sql"
    Start-Process -FilePath $MYSQLDUMP -ArgumentList $dumpArgs -NoNewWindow -Wait `
        -RedirectStandardOutput $out -RedirectStandardError "$BackupDir\db\dump.err"
    if ((Get-Item $out -ErrorAction SilentlyContinue).Length -gt 1000) {
        Ok "dump saved: $out ($([math]::Round((Get-Item $out).Length/1MB,2)) MB)"
        Write-Host "    Get it off-box NOW:"
        Write-Host "      scp $out plinktern@172.16.$Team.5:/opt/hpcc-vault/foreman/"
    } else {
        Warn "Dump looks empty. Check $BackupDir\db\dump.err"
    }
} catch { Warn "mysqldump failed: $_" }

# ---------- MySQL hardening ----------------------------------------------------
function Invoke-MySQL {
    param([string]$Sql, [string]$User = "root", [string]$Pass = $rootPw)
    $a = if ($Pass) { @("-u",$User,"-p$Pass","-e",$Sql) } else { @("-u",$User,"-e",$Sql) }
    & $MYSQL @a 2>&1
}

Log "Auditing MySQL accounts -- delete anything you do not recognise"
Invoke-MySQL "SELECT user, host, plugin FROM mysql.user;" | ForEach-Object { Write-Host "    $_" }

Log "Accounts with dangerous global privileges"
Invoke-MySQL "SELECT user, host FROM mysql.user WHERE Super_priv='Y' OR Grant_priv='Y' OR File_priv='Y';" |
    ForEach-Object { Write-Host "    $_" }

Log "Cleaning up MySQL"
Invoke-MySQL "DELETE FROM mysql.user WHERE User='';" | Out-Null
Invoke-MySQL "DROP DATABASE IF EXISTS test;" | Out-Null
Invoke-MySQL "DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';" | Out-Null
Invoke-MySQL "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');" | Out-Null
Invoke-MySQL "FLUSH PRIVILEGES;" | Out-Null
Ok "anonymous users, test db, and remote root removed"

# ---- set a root password we control ----
$newRoot = Read-Host "New MySQL root password"
Invoke-MySQL "ALTER USER 'root'@'localhost' IDENTIFIED BY '$newRoot';" | Out-Null
Ok "root password rotated"
$rootPw = $newRoot

# ---- the scoring account ----
# jmoney must reach horsepress. Grant SELECT only, and only from our subnet --
# not from '%', which would let Red Team use the creds from their own box.
Log "Configuring the $ScoringUser MySQL account"
$jmoneyPw = Read-Host "Password for MySQL user '$ScoringUser' (you will PCR this)"
$sql = @"
CREATE USER IF NOT EXISTS '$ScoringUser'@'localhost'        IDENTIFIED BY '$jmoneyPw';
CREATE USER IF NOT EXISTS '$ScoringUser'@'172.16.$Team.%'   IDENTIFIED BY '$jmoneyPw';
ALTER USER '$ScoringUser'@'localhost'      IDENTIFIED BY '$jmoneyPw';
ALTER USER '$ScoringUser'@'172.16.$Team.%' IDENTIFIED BY '$jmoneyPw';
GRANT SELECT ON horsepress.* TO '$ScoringUser'@'localhost';
GRANT SELECT ON horsepress.* TO '$ScoringUser'@'172.16.$Team.%';
FLUSH PRIVILEGES;
"@
Invoke-MySQL $sql | Out-Null
Ok "$ScoringUser can SELECT on horsepress from the team subnet"

Write-Host ""
Write-Host "    !!! SUBMIT A PCR NOW on scoreboard.plinko.horse !!!" -ForegroundColor Yellow
Write-Host "    Cred list: foreman.credlist   Value: $ScoringUser,<the password you just typed>" -ForegroundColor Yellow
Write-Host "    Until you do, the MySQL check will fail." -ForegroundColor Yellow
Read-Host "    Press enter once the PCR is submitted"

# ---- the WordPress database account ----
Log "The WordPress/WooCommerce database account"
Write-Host @"
    storkfront's wp-config.php authenticates to THIS server. Find that account:
        SELECT user, host FROM mysql.user;
    It is usually something like wordpress@172.16.$Team.20 or wp@%.

    If you rotate its password here, you MUST update DB_PASSWORD in
    /var/www/html/wp-config.php on storkfront in the same breath, or you take
    down the storkfront-web check.

    Safer play under time pressure: leave that account's password alone, but
    tighten its host from '%' to '$Storkfront' so only storkfront can use it:
        RENAME USER 'wpuser'@'%' TO 'wpuser'@'$Storkfront';
        FLUSH PRIVILEGES;
"@ -ForegroundColor White

# ---------- mysqld config ------------------------------------------------------
Log "Writing mysqld hardening config"
$iniPaths = @("C:\ProgramData\MySQL\MySQL Server 8.0\my.ini",
              "C:\ProgramData\MySQL\MySQL Server 9.4\my.ini",
              "C:\Program Files\MySQL\MySQL Server 8.0\my.ini",
              "C:\xampp\mysql\bin\my.ini")
$myini = $iniPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $myini) {
    $found = Get-ChildItem C:\ -Filter "my.ini" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $myini = $found.FullName }
}

if ($myini) {
    Ok "config at $myini"
    Copy-Item $myini "$BackupDir\my.ini.pre" -Force
    Add-Content $myini @"

# ===== HPCC hardening =====
# bind-address 0.0.0.0 is DELIBERATE. storkfront's WooCommerce and the scoring
# engine both connect over the network. The Windows Firewall does the
# restriction, not mysqld. Do NOT set this to 127.0.0.1.
bind-address = 0.0.0.0
# Kill LOAD DATA LOCAL INFILE -- a file-read primitive for anyone with a session.
local-infile = 0
# Do not let SELECT ... INTO OUTFILE write anywhere it likes.
secure-file-priv = "C:/ProgramData/MySQL/uploads"
# Skip the name-resolution step: faster, and avoids DNS-based auth bypass games.
skip-name-resolve = 0
"@
    New-Item -ItemType Directory -Force -Path "C:\ProgramData\MySQL\uploads" | Out-Null
    Ok "hardening appended to my.ini"

    if ($mysqlSvc) {
        Restart-Service $mysqlSvc.Name -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        if ((Get-Service $mysqlSvc.Name).Status -eq "Running") { Ok "MySQL restarted" }
        else { Warn "MYSQL DID NOT COME BACK UP -- restore $BackupDir\my.ini.pre and restart" }
    }
} else {
    Warn "my.ini not found. Apply the settings above by hand."
}

# ---------- firewall ----------------------------------------------------------
Reset-Firewall
Allow-In -Name "RDP-SCORED" -Port 3389
# MySQL: the scoring engine AND storkfront need in. Their source addresses are
# not published, so allow the team subnet. Narrow this if you identify the
# scoring engine's IP during the round.
Allow-In -Name "MySQL-SCORED" -Port 3306 -RemoteIP $Subnet
New-NetFirewallRule -DisplayName "HPCC-ICMP" -Direction Inbound -Protocol ICMPv4 `
    -Action Allow -RemoteAddress $Subnet -ErrorAction SilentlyContinue | Out-Null
Warn "If the MySQL check fails but storkfront works, the scoring engine is"
Warn "probably OUTSIDE $Subnet. Widen the rule to Any and re-test."

# ---------- verify ------------------------------------------------------------
Log "Simulating the score checks"

if ((Get-Service TermService).Status -eq "Running") { Ok "TermService running" }
else { Warn "TermService NOT RUNNING -- the RDP check will fail" }

Log "Testing $ScoringUser -> horsepress over TCP"
$test = & $MYSQL "-u" $ScoringUser "-p$jmoneyPw" "-h" "127.0.0.1" "-e" "SHOW TABLES FROM horsepress;" 2>&1
if ($LASTEXITCODE -eq 0) {
    Ok "MYSQL SCORE CHECK SIMULATION PASSED"
    $test | Select-Object -First 10 | ForEach-Object { Write-Host "      $_" }
} else {
    Warn "MYSQL SCORE CHECK SIMULATION FAILED:"
    $test | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
}

Log "Checking that storkfront can still reach us"
if (Test-NetConnection -ComputerName $Storkfront -Port 80 -InformationLevel Quiet) {
    try {
        $r = Invoke-WebRequest "http://$Storkfront/" -UseBasicParsing -TimeoutSec 10
        if ($r.StatusCode -eq 200) { Ok "storkfront returns 200 -- the database link is healthy" }
    } catch {
        Warn "storkfront is NOT serving properly. If you just changed a MySQL"
        Warn "password, update wp-config.php on storkfront right now."
    }
} else { Warn "cannot reach storkfront on port 80" }

Baseline-Report

Log "===== FOREMAN DONE ====="
Write-Host @"
    Remember: this box backs TWO checks. If storkfront-web goes red, check here
    before you touch Apache.

    Restore the database if it gets wrecked:
      & "$MYSQLDUMP" ... (or)
      cmd /c "`"$MYSQL`" -u root -p<pw> < $BackupDir\db\all-databases.sql"
"@ -ForegroundColor White
