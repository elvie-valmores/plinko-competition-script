<#
================================================================================
 Horse Plinko Cyber Challenge - Season 2 (Fall 2024)
 Common Windows hardening library. Dot-source from the per-box scripts:
     . .\00-common-windows.ps1
================================================================================
#>

$Global:ScoringUser = "hkeating"    # account the scoring engine authenticates as
$Global:LocalUser   = "plinktern"   # your team's interactive account
$Global:BackupDir   = "C:\HPCC-Backup"

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

# ---------- backups -----------------------------------------------------------
function Backup-State {
    Log "Snapshotting current state to $BackupDir"
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    Get-LocalUser  | Export-Csv "$BackupDir\users.csv"  -NoTypeInformation -ErrorAction SilentlyContinue
    Get-LocalGroup | Export-Csv "$BackupDir\groups.csv" -NoTypeInformation -ErrorAction SilentlyContinue
    Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Export-Csv "$BackupDir\admins.csv" -NoTypeInformation
    Get-Service    | Export-Csv "$BackupDir\services.csv" -NoTypeInformation
    Get-ScheduledTask | Select-Object TaskName,TaskPath,State |
        Export-Csv "$BackupDir\tasks.csv" -NoTypeInformation
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Export-Csv "$BackupDir\listening.csv" -NoTypeInformation
    netsh advfirewall export "$BackupDir\firewall.wfw" | Out-Null
    Ok "state saved"
}

# ---------- passwords ---------------------------------------------------------
function Get-NewPassword {
    param([string]$Prompt = "New password for local accounts")
    while ($true) {
        $a = Read-Host -AsSecureString $Prompt
        $b = Read-Host -AsSecureString "Confirm"
        $pa = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
              [Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
        $pb = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
              [Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
        if ($pa -eq $pb -and $pa.Length -gt 0) { return $a }
        Warn "Mismatch or empty, try again."
    }
}

# Rotates every enabled local account except the scoring user and built-ins we
# handle separately. The scoring user needs a PCR first -- handled per-box.
function Rotate-LocalPasswords {
    param([Security.SecureString]$Password)
    Log "Rotating local account passwords"
    $skip = @($Global:ScoringUser, "DefaultAccount", "WDAGUtilityAccount", "Guest")
    Get-LocalUser | Where-Object { $_.Enabled -and $skip -notcontains $_.Name } | ForEach-Object {
        try {
            Set-LocalUser -Name $_.Name -Password $Password -ErrorAction Stop
            Ok "rotated $($_.Name)"
        } catch { Warn "could not rotate $($_.Name): $_" }
    }
    Write-Host "    Reminder: rotate $($Global:ScoringUser) only AFTER submitting a PCR."
}

# ---------- account hygiene ---------------------------------------------------
function Disable-GuestAndDefault {
    Log "Disabling Guest / DefaultAccount"
    foreach ($n in @("Guest","DefaultAccount")) {
        try { Disable-LocalUser -Name $n -ErrorAction Stop; Ok "disabled $n" } catch {}
    }
}

function Audit-Administrators {
    Log "Local Administrators group -- REMOVE ANYTHING YOU DO NOT RECOGNISE"
    Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host "    $($_.Name)  [$($_.ObjectClass)]" -ForegroundColor White }
    Log "All local users"
    Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordLastSet -AutoSize |
        Out-String | ForEach-Object { Write-Host $_ }
}

function Audit-Persistence {
    Log "Run keys (classic persistence)"
    $keys = @(
      "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
      "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
      "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($k in $keys) {
        if (Test-Path $k) {
            Write-Host "    --- $k ---"
            Get-ItemProperty $k | Out-String | ForEach-Object { Write-Host $_ }
        }
    }
    Log "Non-Microsoft scheduled tasks"
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
        Select-Object TaskName, TaskPath, State |
        Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
    Log "Auto-start services with non-standard paths"
    Get-CimInstance Win32_Service |
        Where-Object { $_.PathName -notmatch 'C:\\Windows' -and $_.StartMode -eq 'Auto' } |
        Select-Object Name, PathName |
        Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
}

# ---------- password policy ---------------------------------------------------
function Set-PasswordPolicy {
    Log "Setting local password / lockout policy"
    net accounts /minpwlen:12 /maxpwage:unlimited /uniquepw:5 | Out-Null
    net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 | Out-Null
    Ok "policy applied (lockout 10 tries / 15 min)"
    Warn "Lockout applies to $($Global:ScoringUser) too. If Red Team brute-forces"
    Warn "that account they can lock the score check out. Watch for it."
}

# ---------- baseline OS hardening ---------------------------------------------
function Disable-SMBv1 {
    Log "Disabling SMBv1"
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
        Ok "SMBv1 off"
    } catch {
        # Server 2012 R2 fallback
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
            SMB1 -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue
        Ok "SMBv1 disabled via registry (reboot to take full effect)"
    }
}

function Enable-Defender {
    Log "Enabling Defender real-time protection"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
        Ok "Defender on"
    } catch { Warn "Defender not available on this box (normal on 2012 R2)" }
}

function Enable-AuditLogging {
    Log "Turning on useful audit categories"
    auditpol /set /category:"Logon/Logoff"    /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Account Logon"   /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Policy Change"   /success:enable /failure:enable | Out-Null
    wevtutil sl Security /ms:104857600 2>$null
    Ok "auditing enabled, Security log grown to 100MB"
}

function Harden-RDP-Common {
    Log "Hardening RDP (Network Level Authentication on, encryption high)"
    $ts = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
    Set-ItemProperty "$ts\WinStations\RDP-Tcp" UserAuthentication -Value 1 -Force
    Set-ItemProperty "$ts\WinStations\RDP-Tcp" MinEncryptionLevel -Value 3 -Force
    Set-ItemProperty "$ts\WinStations\RDP-Tcp" SecurityLayer -Value 2 -Force
    # Do NOT set fDenyTSConnections=1 anywhere RDP is scored.
    Ok "NLA on, TLS security layer, high encryption"
}

function Disable-UnneededServices {
    param([string[]]$Keep = @())
    Log "Disabling commonly-abused services not needed here"
    $candidates = @("RemoteRegistry","Telnet","TlntSvr","SNMP","Spooler","SSDPSRV","upnphost","WinRM")
    foreach ($s in $candidates) {
        if ($Keep -contains $s) { Write-Host "    keeping $s (needed here)"; continue }
        $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
        if ($svc) {
            try {
                Stop-Service $s -Force -ErrorAction SilentlyContinue
                Set-Service  $s -StartupType Disabled -ErrorAction Stop
                Ok "disabled $s"
            } catch { Warn "could not disable ${s}: $_" }
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
    param([string]$Name, [int]$Port, [string]$Protocol = "TCP", [string]$RemoteIP = "Any")
    New-NetFirewallRule -DisplayName "HPCC-$Name" -Direction Inbound -Action Allow `
        -Protocol $Protocol -LocalPort $Port -RemoteAddress $RemoteIP `
        -ErrorAction SilentlyContinue | Out-Null
    Ok "allow in: $Name ($Protocol/$Port from $RemoteIP)"
}

function Baseline-Report {
    Log "Listening ports right now"
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort,
            @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
        Sort-Object LocalPort | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
    Log "Active sessions"
    query user 2>$null
}
