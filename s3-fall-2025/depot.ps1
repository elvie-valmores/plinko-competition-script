<#
================================================================================
 HPCC Season 3 (Fall 2025) - DEPOT  (172.16.t.30, Windows Server 2012 R2)

 Scored services:
   RDP - jmoney must be able to log in over RDP
   FTP - the ANONYMOUS user must log in and read the files in /memos, with the
         files INTACT (verified by name correlated to hash). IIS FTP is the
         mandated server.

 Two traps on this box:

 1. "Harden FTP by disabling anonymous access" fails the check instantly. The
    check IS an anonymous login. You harden AROUND it: read-only, no upload,
    no write, scoped to /memos, logging on, and the files themselves frozen.

 2. This is Server 2012 R2. PowerShell 4.0. No Get-LocalUser, no
    New-NetFirewallRule in some builds, Defender may not exist. The shared
    module handles the fallbacks -- do not strip them out.

 Note the packet ships depot with "passwords (DO NOT SHARE).txt" sitting in the
 anonymous FTP share. That is a joke file, but check whether it is one of the
 hashed scored files before you delete it. If it is scored, LEAVE IT.

 Run in an ELEVATED PowerShell:
   powershell -ExecutionPolicy Bypass -File .\depot-172.16.t.30.ps1
================================================================================
#>

. "$PSScriptRoot\lib\common-windows.ps1"

Require-Admin
Show-Platform
Backup-State

$Team   = Read-Host "Team number (the 't' in 172.16.t.30)"
$Subnet = "172.16.$Team.0/24"

Log "===== DEPOT: RDP + anonymous IIS FTP (Server 2012 R2) ====="

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
# Keep nothing extra; IIS FTP (FTPSVC) and TermService are all that matter.
Disable-UnneededServices

# ---------- RDP (SCORED) ------------------------------------------------------
Harden-RDP

# ---------- FTP: find the share ------------------------------------------------
Log "Locating the FTP site and the /memos directory"
Import-Module WebAdministration -ErrorAction SilentlyContinue

$ftpSite = Get-Website -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -like "*depot*" -or $_.Name -like "*ftp*" } |
           Select-Object -First 1
if ($ftpSite) {
    $ftpRoot = $ftpSite.PhysicalPath -replace '%SystemDrive%','C:'
    Ok "FTP site '$($ftpSite.Name)' rooted at $ftpRoot"
} else {
    Warn "Could not auto-detect the FTP site. Open IIS Manager and check Sites."
    $ftpRoot = Read-Host "Enter the FTP physical root path (e.g. C:\inetpub\ftproot)"
}

$memos = Join-Path $ftpRoot "memos"
if (-not (Test-Path $memos)) {
    # It may be the root itself rather than a subfolder.
    Warn "$memos does not exist. Checking the FTP root directly."
    $memos = $ftpRoot
}
Ok "Scored content directory: $memos"

# ---------- back up + hash the scored files -----------------------------------
# The check correlates file name to file hash. If Red Team edits a memo, the
# service is "up" and the check is red. Hash everything now.
Log "Hashing and backing up the scored files"
$ftpBak = "$BackupDir\ftp-memos"
New-Item -ItemType Directory -Force -Path $ftpBak | Out-Null
Copy-Item -Path "$memos\*" -Destination $ftpBak -Recurse -Force -ErrorAction SilentlyContinue
Ok "files copied to $ftpBak"

$hashes = @()
Get-ChildItem $memos -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $h = Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
    if ($h) {
        $hashes += [pscustomobject]@{ Name = $_.Name; Path = $_.FullName; Hash = $h.Hash }
        Write-Host "    $($_.Name)  $($h.Hash.Substring(0,16))..."
    }
}
$hashes | Export-Csv "$BackupDir\memos-hashes.csv" -NoTypeInformation
Ok "$($hashes.Count) file hashes recorded in $BackupDir\memos-hashes.csv"

if ($hashes.Count -eq 0) {
    Warn "NO FILES FOUND in the scored directory. The FTP check cannot pass."
    Warn "Find the real path in IIS Manager -> Sites -> depot.team$Team.plinko.horse -> Explore"
}

Write-Host "    Get the backup off-box:"
Write-Host "      scp -r $ftpBak plinktern@172.16.$Team.5:/opt/hpcc-vault/depot/"

# ---------- lock the files down ------------------------------------------------
Log "Making the scored files read-only"
# Anonymous IIS FTP runs as IUSR. It needs READ. It must never get WRITE.
icacls $memos /inheritance:r | Out-Null
icacls $memos /grant:r "Administrators:(OI)(CI)F" | Out-Null
icacls $memos /grant:r "SYSTEM:(OI)(CI)F"         | Out-Null
icacls $memos /grant:r "IUSR:(OI)(CI)RX"          | Out-Null
icacls $memos /grant:r "IIS_IUSRS:(OI)(CI)RX"     | Out-Null
Ok "ACLs: Administrators/SYSTEM full, IUSR read+execute only"

Get-ChildItem $memos -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    Set-ItemProperty $_.FullName -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue
}
Ok "files marked read-only"

# ---------- IIS FTP configuration ----------------------------------------------
Log "Configuring IIS FTP"

if ($ftpSite) {
    $site = $ftpSite.Name

    # --- SCORED: anonymous authentication stays ON ---
    Set-ItemProperty "IIS:\Sites\$site" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true -ErrorAction SilentlyContinue
    Ok "anonymous authentication ENABLED (this is the score check -- do not turn it off)"

    # --- basic auth off: nothing needs it, and it is a brute-force target ---
    Set-ItemProperty "IIS:\Sites\$site" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $false -ErrorAction SilentlyContinue
    Ok "basic authentication disabled"

    # --- authorization: anonymous gets READ only, never Write ---
    Clear-WebConfiguration -Filter "/system.ftpServer/security/authorization" -PSPath "IIS:\Sites\$site" -ErrorAction SilentlyContinue
    Add-WebConfiguration -Filter "/system.ftpServer/security/authorization" -PSPath "IIS:\Sites\$site" `
        -Value @{accessType="Allow"; users="*"; permissions="Read"} -ErrorAction SilentlyContinue
    Ok "authorization rule: everyone = Read only (no Write)"

    # --- SSL: do NOT require it. The check is a plain anonymous FTP login. ---
    Set-ItemProperty "IIS:\Sites\$site" -Name ftpServer.security.ssl.controlChannelPolicy -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty "IIS:\Sites\$site" -Name ftpServer.security.ssl.dataChannelPolicy    -Value 0 -ErrorAction SilentlyContinue
    Ok "SSL not required (requiring it would break the plaintext score check)"

    # --- logging on: you want to see Red Team poking ---
    Set-ItemProperty "IIS:\Sites\$site" -Name ftpServer.logFile.enabled -Value $true -ErrorAction SilentlyContinue
    Ok "FTP logging enabled"

    # --- pin the passive port range so the firewall can be tight ---
    Set-WebConfigurationProperty -Filter "/system.ftpServer/firewallSupport" `
        -Name lowDataChannelPort  -Value 40000 -PSPath "IIS:\" -ErrorAction SilentlyContinue
    Set-WebConfigurationProperty -Filter "/system.ftpServer/firewallSupport" `
        -Name highDataChannelPort -Value 40100 -PSPath "IIS:\" -ErrorAction SilentlyContinue
    Ok "passive data channel pinned to 40000-40100"

    Restart-Service FTPSVC -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Ok "FTPSVC restarted"
} else {
    Warn "Skipping IIS FTP config -- site not detected. Configure by hand in IIS Manager:"
    Write-Host @"
      IIS Manager -> Sites -> depot.team$Team.plinko.horse
        FTP Authentication   : Anonymous = ENABLED, Basic = Disabled
        FTP Authorization    : Allow  All users  Permissions = Read  (NOT Write)
        FTP SSL Settings     : Allow SSL (do NOT Require)
        FTP Logging          : Enabled
"@ -ForegroundColor White
}

# ---------- self-heal ----------------------------------------------------------
Log "Installing an FTP file self-heal task"
$healScript = "C:\HPCC-Backup\ftp-heal.ps1"
@"
# Restores the scored FTP files if their hashes drift.
`$csv = Import-Csv "$BackupDir\memos-hashes.csv"
foreach (`$row in `$csv) {
    `$restore = `$false
    if (-not (Test-Path `$row.Path)) {
        "[`$(Get-Date)] MISSING: `$(`$row.Name)" | Out-File C:\HPCC-Backup\ftp-heal.log -Append
        `$restore = `$true
    } else {
        `$h = (Get-FileHash `$row.Path -Algorithm SHA256).Hash
        if (`$h -ne `$row.Hash) {
            "[`$(Get-Date)] MODIFIED: `$(`$row.Name)" | Out-File C:\HPCC-Backup\ftp-heal.log -Append
            `$restore = `$true
        }
    }
    if (`$restore) {
        `$src = Join-Path "$ftpBak" `$row.Name
        if (Test-Path `$src) {
            Copy-Item `$src `$row.Path -Force
            Set-ItemProperty `$row.Path -Name IsReadOnly -Value `$true -ErrorAction SilentlyContinue
            "[`$(Get-Date)] RESTORED: `$(`$row.Name)" | Out-File C:\HPCC-Backup\ftp-heal.log -Append
        }
    }
}
"@ | Set-Content $healScript

schtasks /create /tn "HPCC-FTP-Heal" /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $healScript" `
    /sc minute /mo 1 /ru SYSTEM /rl HIGHEST /f | Out-Null
Ok "HPCC-FTP-Heal runs every minute (log: C:\HPCC-Backup\ftp-heal.log)"

# ---------- firewall ----------------------------------------------------------
Reset-Firewall
Allow-In -Name "RDP-SCORED"      -Port 3389
Allow-In -Name "FTP-CTRL-SCORED" -Port 21
Allow-In -Name "FTP-DATA"        -Port 20
Allow-In -Name "FTP-PASV"        -Port "40000-40100"
netsh advfirewall firewall add rule name="HPCC-ICMP" protocol=icmpv4:8,any dir=in action=allow remoteip=$Subnet | Out-Null

# IIS FTP needs the stateful FTP helper for the control channel to negotiate data.
netsh advfirewall set global StatefulFTP enable | Out-Null
Ok "stateful FTP inspection enabled"

# ---------- verify ------------------------------------------------------------
Log "Simulating the score checks"
if ((Get-Service FTPSVC -ErrorAction SilentlyContinue).Status -eq "Running") { Ok "FTPSVC running" }
else { Warn "FTPSVC NOT RUNNING -- the FTP check will fail" }

if ((Get-Service TermService).Status -eq "Running") { Ok "TermService running" }
else { Warn "TermService NOT RUNNING -- the RDP check will fail" }

Log "Testing anonymous FTP login from this box"
try {
    $req = [System.Net.FtpWebRequest]::Create("ftp://127.0.0.1/")
    $req.Method      = [System.Net.WebRequestMethods+Ftp]::ListDirectory
    $req.Credentials = New-Object System.Net.NetworkCredential("anonymous","x@x.com")
    $req.Timeout     = 10000
    $resp = $req.GetResponse()
    $sr   = New-Object IO.StreamReader $resp.GetResponseStream()
    $list = $sr.ReadToEnd()
    $sr.Close(); $resp.Close()
    Ok "FTP SCORE CHECK SIMULATION PASSED -- anonymous login worked"
    Write-Host "    Directory listing:"
    $list -split "`n" | ForEach-Object { if ($_.Trim()) { Write-Host "      $_" } }
} catch {
    Warn "FTP SCORE CHECK SIMULATION FAILED: $_"
    Warn "Check: anonymous auth enabled? authorization rule present? FTPSVC running?"
}

Baseline-Report

Log "===== DEPOT DONE ====="
Write-Host @"
    If the FTP check goes red:
      1. Is FTPSVC running?        Get-Service FTPSVC
      2. Anonymous auth still on?  IIS Manager -> FTP Authentication
      3. Files still intact?       Get-Content C:\HPCC-Backup\ftp-heal.log
      4. Manual restore:           Copy-Item $ftpBak\* $memos -Force

    If you rotate jmoney's password, submit a PCR on the scoreboard FIRST
    (cred list: depot.credlist).
"@ -ForegroundColor White
