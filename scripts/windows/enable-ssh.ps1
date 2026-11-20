<#
.SYNOPSIS
  Turn on the OpenSSH server of Windows so kxn can scan this machine.

.DESCRIPTION
  Windows Server 2019 and later, and Windows 10 1809 and later, ship OpenSSH
  as an optional feature. This script installs it when it is missing, starts
  sshd now and at every boot, and opens TCP port 22 in Windows Firewall.

  kxn only reads: the OS build, installed updates and installed software. A
  standard (non-administrator) local or domain account is enough to log in.

  Run it once, in an elevated PowerShell:

    Set-ExecutionPolicy -Scope Process Bypass
    .\enable-ssh.ps1                                  # password logins
    .\enable-ssh.ps1 -PublicKey 'ssh-ed25519 AAAA… kxn' -User kxn

  Then, from the kxn machine:

    kxn ssh://kxn@<windows-host>

.PARAMETER PublicKey
  An SSH public key to authorize for -User (default: the current user).

.PARAMETER User
  The account that logs in with -PublicKey.

.PARAMETER Port
  The TCP port sshd listens on (default 22).
#>
#Requires -RunAsAdministrator
param(
    [string]$PublicKey,
    [string]$User = $env:USERNAME,
    [int]$Port = 22
)
$ErrorActionPreference = 'Stop'

# 1. The OpenSSH server feature.
$cap = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | Select-Object -First 1
if (-not $cap) {
    throw 'OpenSSH Server is not available on this Windows version (Windows Server 2019 / Windows 10 1809 or later needed).'
}
if ($cap.State -ne 'Installed') {
    Write-Host "Installing $($cap.Name)..."
    Add-WindowsCapability -Online -Name $cap.Name | Out-Null
}

# 2. The port, before the first start (sshd writes its config on first start).
$config = Join-Path $env:ProgramData 'ssh\sshd_config'
if ($Port -ne 22) {
    if (-not (Test-Path $config)) { Start-Service sshd; Stop-Service sshd }
    (Get-Content $config) -replace '^#?Port\s+\d+', "Port $Port" | Set-Content $config -Encoding ascii
}

# 3. Start now and at boot.
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd

# 4. Windows Firewall.
$rule = Get-NetFirewallRule -Name 'kxn-OpenSSH-In-TCP' -ErrorAction SilentlyContinue
if (-not $rule) {
    New-NetFirewallRule -Name 'kxn-OpenSSH-In-TCP' -DisplayName 'OpenSSH Server (kxn)' `
        -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort $Port | Out-Null
}

# 5. Optional key login. Administrators read their keys from one shared file.
if ($PublicKey) {
    $isAdmin = (Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "\\$([regex]::Escape($User))$" })
    if ($isAdmin) {
        $keys = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
        Add-Content -Path $keys -Value $PublicKey -Encoding ascii
        icacls $keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
    } else {
        $profile = (Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -match "\\$([regex]::Escape($User))$" }).LocalPath
        if (-not $profile) { throw "No profile for $User yet: log in once as $User, then run this again." }
        $dir = Join-Path $profile '.ssh'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Add-Content -Path (Join-Path $dir 'authorized_keys') -Value $PublicKey -Encoding ascii
    }
}

$svc = Get-Service sshd
Write-Host "sshd is $($svc.Status), listening on port $Port. Scan with: kxn ssh://$User@$env:COMPUTERNAME"
