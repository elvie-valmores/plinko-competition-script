<#
================================================================================
 Horse Plinko Cyber Challenge - Season 3 (Fall 2025)
 Common Windows hardening library. Dot-source from the per-box scripts:
     . .\00-common-windows.ps1

 IMPORTANT COMPATIBILITY NOTE:
   depot is Windows Server 2012 R2 -> PowerShell 4.0, NO Microsoft.PowerShell
   .LocalAccounts module. Get-LocalUser / Set-LocalUser / New-NetFirewallRule
   behave differently or do not exist at all.
   foreman is Windows Server 2022 -> everything modern works.

   So every function here probes for the modern cmdlet and falls back to
   net.exe / netsh. Do not "simplify" this by ripping out the fallbacks unless
   you only ever run it on 2022.
================================================================================
#>

$Global:ScoringUser = "jmoney"      # account the scoring engine authenticates as
$Global:LocalUser   = "plinktern"   # your team's interactive account
$Global:BackupDir   = "C:\HPCC-Backup"

$Global:HasLocalAccounts = $null -ne (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)
$Global:HasNetFirewall   = $null -ne (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)

function Require-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[!] Run this in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Red
        exit 1
    }
}

function Log  { param($m) Write-Host "`n[*] $m" -ForegroundColor Cyan }
function Ok   { param($m) Write-Host "    ok: $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }

function Show-Platform {
    $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
    if (-not $os) { $os = (Get-WmiObject Win32_OperatingSystem).Caption }
    Write-Host "[*] $os  |  PowerShell $($PSVersionTable.PSVersion)  |  LocalAccounts module: $HasLocalAccounts"
}

# ---------- backups -----------------------------------------------------------
function Backup-State {
    Log "Snapshotting current state to $BackupDir"
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    if ($HasLocalAccounts) {
        Get-LocalUser  | Export-Csv "$BackupDir\users.csv"  -NoTypeInformation -ErrorAction SilentlyContinue
        Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
            Export-Csv "$BackupDir\admins.csv" -NoTypeInformation
    } else {
        net user            | Out-File "$BackupDir\users.txt"
        net localgroup administrators | Out-File "$BackupDir\admins.txt"
    }
    Get-Service | Export-Csv "$BackupDir\services.csv" -NoTypeInformation
    schtasks /query /fo CSV /v | Out-File "$BackupDir\tasks.csv"
    netstat -anob | Out-File "$BackupDir\listening.txt"
    netsh advfirewall export "$BackupDir\firewall.wfw" | Out-Null
    Ok "state saved"
}

# ---------- users: compatibility layer ----------------------------------------
function Get-Users {
    if ($HasLocalAccounts) {
        return (Get-LocalUser | Select-Object @{n='Name';e={$_.Name}}, @{n='Enabled';e={$_.Enabled}})
    }
    # 2012 R2 fallback via WMI
    return (Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" |
            Select-Object Name, @{n='Enabled';e={ -not $_.Disabled }})
}

function Set-UserPassword {
    param([string]$Name, [string]$PlainPassword)
    if ($HasLocalAccounts) {
        $sec = ConvertTo-SecureString $PlainPassword -AsPlainText -Force
        Set-LocalUser -Name $Name -Password $sec -ErrorAction Stop
    } else {
        $r = net user $Name $PlainPassword 2>&1
        if ($LASTEXITCODE -ne 0) { throw "net user failed: $r" }
    }
}

function Disable-User {
    param([string]$Name)
    if ($HasLocalAccounts) { Disable-LocalUser -Name $Name -ErrorAction Stop }
    else { net user $Name /active:no | Out-Null }
}

function Get-NewPasswordPlain {
    param([string]$Prompt = "New password for local accounts")
    while ($true) {
        $a = Read-Host -AsSecureString $Prompt
        $b = Read-Host -AsSecureString "Confirm"
        $pa = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
              [Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
        $pb = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
              [Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
        if ($pa -eq $pb -and $pa.Length -ge 12) { return $pa }
        Warn "Mismatch, empty, or shorter than 12 characters. Try again."
    }
}

# Every team starts with plinktern:IHPLRulez! straight out of the packet.
# So does Red Team. This is the highest-value two minutes of the round.
function Rotate-LocalPasswords {
    param([string]$PlainPassword)
    Log "Rotating local account passwords"
    $skip = @($Global:ScoringUser, "DefaultAccount", "WDAGUtilityAccount", "Guest", "krbtgt")
    Get-Users | Where-Object { $_.Enabled -and $skip -notcontains $_.Name } | ForEach-Object {
        try { Set-UserPassword -Name $_.Name -PlainPassword $PlainPassword; Ok "rotated $($_.Name)" }
        catch { Warn "could not rotate $($_.Name): $_" }
    }
    Write-Host "    Reminder: rotate $($Global:ScoringUser) only AFTER submitting a PCR."
}

function Disable-GuestAndDefault {
    Log "Disabling Guest / DefaultAccount"
    foreach ($n in @("Guest","DefaultAccount")) {
        try { Disable-User -Name $n; Ok "disabled $n" } catch {}
    }
}

function Audit-Administrators {
    Log "Local Administrators -- REMOVE ANYTHING YOU DO NOT RECOGNISE"
    net localgroup administrators | ForEach-Object { Write-Host "    $_" }
    Log "All local users"
    Get-Users | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
    Warn "Red Team's #1 Windows persistence is a new local admin. Check this list twice."
}

function Audit-Persistence {
    Log "Run keys"
    foreach ($k in @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                     "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                     "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")) {
        if (Test-Path $k) {
            Write-Host "    --- $k ---"
            Get-ItemProperty $k | Out-String | ForEach-Object { Write-Host $_ }
        }
    }
    Log "Non-Microsoft scheduled tasks"
    schtasks /query /fo TABLE 2>$null | Select-String -NotMatch "Microsoft" |
        Select-Object -First 30 | ForEach-Object { Write-Host "    $_" }
    Log "Auto-start services running from outside C:\Windows"
    Get-WmiObject Win32_Service |
        Where-Object { $_.PathName -notmatch 'C:\\Windows' -and $_.StartMode -eq 'Auto' } |
        Select-Object Name, PathName |
        Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
    Log "Sticky-keys style binary hijacks (should all be the real Microsoft binaries)"
    foreach ($b in @("sethc.exe","utilman.exe","osk.exe","magnify.exe")) {
        $p = "C:\Windows\System32\$b"
        if (Test-Path $p) {
            $sig = (Get-AuthenticodeSignature $p -ErrorAction SilentlyContinue).Status
            $col = if ($sig -eq "Valid") { "Green" } else { "Red" }
            Write-Host "    $b : $sig" -ForegroundColor $col
        }
    }
    Log "Image File Execution Options debuggers (a debugger= value here is a backdoor)"
    Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $d = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
            if ($d) { Write-Host "    BACKDOOR: $($_.PSChildName) -> $d" -ForegroundColor Red }
        }
}

function Set-PasswordPolicy {
    Log "Setting local password / lockout policy"
    net accounts /minpwlen:12 /maxpwage:unlimited /uniquepw:5 | Out-Null
    net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 | Out-Null
    Ok "policy applied"
    Warn "Lockout applies to $($Global:ScoringUser) too. If Red Team brute-forces that"
    Warn "account they can lock out the SCORE CHECK. Watch Event ID 4740."
}

function Disable-SMBv1 {
    Log "Disabling SMBv1"
    try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop; Ok "SMBv1 off" }
    catch {
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
            SMB1 -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue
        Ok "SMBv1 disabled via registry (2012 R2 path; reboot for full effect)"
    }
}

function Enable-Defender {
    Log "Enabling Defender real-time protection"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
        Ok "Defender on"
    } catch { Warn "Defender unavailable here (normal on Server 2012 R2)" }
}

function Enable-AuditLogging {
    Log "Turning on useful audit categories"
    auditpol /set /category:"Logon/Logoff"       /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Account Logon"      /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Policy Change"      /success:enable /failure:enable | Out-Null
    wevtutil sl Security /ms:104857600 2>$null
    Ok "auditing on, Security log grown to 100MB"
    Write-Host "    Useful during the round:"
    Write-Host "      Get-EventLog Security -InstanceId 4625 -Newest 20   # failed logons"
    Write-Host "      Get-EventLog Security -InstanceId 4720 -Newest 20   # user created"
    Write-Host "      Get-EventLog Security -InstanceId 4732 -Newest 20   # added to group"
}

# RDP is SCORED on both Season 3 Windows boxes. Never set fDenyTSConnections=1.
function Harden-RDP {
    Log "Hardening RDP -- SCORED, must stay reachable"
    $ts = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
    Set-ItemProperty $ts fDenyTSConnections -Value 0 -Force
    Set-ItemProperty "$ts\WinStations\RDP-Tcp" UserAuthentication -Value 1 -Force  # NLA on
    Set-ItemProperty "$ts\WinStations\RDP-Tcp" MinEncryptionLevel -Value 3 -Force
    Set-ItemProperty "$ts\WinStations\RDP-Tcp" SecurityLayer -Value 2 -Force
    Set-Service TermService -StartupType Automatic
    Start-Service TermService -ErrorAction SilentlyContinue
    Ok "RDP enabled, NLA on, high encryption"

    # The scoring engine logs in as jmoney over RDP -- it must be permitted.
    try {
        net localgroup "Remote Desktop Users" $Global:ScoringUser /add 2>&1 | Out-Null
        Ok "$($Global:ScoringUser) is in Remote Desktop Users"
    } catch { Warn "could not add $($Global:ScoringUser) to Remote Desktop Users" }

    Log "Remote Desktop Users membership -- remove anything unexpected"
    net localgroup "Remote Desktop Users" | ForEach-Object { Write-Host "    $_" }
}

function Disable-UnneededServices {
    param([string[]]$Keep = @())
    Log "Disabling commonly-abused services"
    $candidates = @("RemoteRegistry","TlntSvr","SNMP","Spooler","SSDPSRV","upnphost","WinRM","Browser")
    foreach ($s in $candidates) {
        if ($Keep -contains $s) { Write-Host "    keeping $s (needed on this box)"; continue }
        if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
            try {
                Stop-Service $s -Force -ErrorAction SilentlyContinue
                Set-Service  $s -StartupType Disabled -ErrorAction Stop
                Ok "disabled $s"
            } catch { Warn "could not disable ${s}" }
        }
    }
}

# ---------- firewall ----------------------------------------------------------
function Reset-Firewall {
    Log "Resetting firewall: block inbound, allow outbound"
    netsh advfirewall reset | Out-Null
    netsh advfirewall set allprofiles state on | Out-Null
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
    Ok "firewall reset and enabled"
}

function Allow-In {
    param([string]$Name, [string]$Port, [string]$Protocol = "TCP", [string]$RemoteIP = "Any")
    if ($HasNetFirewall) {
        New-NetFirewallRule -DisplayName "HPCC-$Name" -Direction Inbound -Action Allow `
            -Protocol $Protocol -LocalPort $Port -RemoteAddress $RemoteIP `
            -ErrorAction SilentlyContinue | Out-Null
    } else {
        # 2012 R2 fallback
        netsh advfirewall firewall add rule name="HPCC-$Name" dir=in action=allow `
            protocol=$Protocol localport=$Port remoteip=$RemoteIP | Out-Null
    }
    Ok "allow in: $Name ($Protocol/$Port from $RemoteIP)"
}

function Baseline-Report {
    Log "Listening ports"
    netstat -ano | Select-String "LISTENING" | Select-Object -First 25 |
        ForEach-Object { Write-Host "    $_" }
    Log "Active sessions -- log off anything you do not recognise: logoff <ID>"
    query user 2>$null
}
