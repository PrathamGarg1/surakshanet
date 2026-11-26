#Requires -RunAsAdministrator
<#
.SYNOPSIS
  SurakshaNet Parent-Locked Tamper-Evident Vault Installer (Windows).

.DESCRIPTION
  Run once from the Parent's Administrator account:
    1. Builds/installs surakshanet-vault.exe under C:\Program Files\SurakshaNet\
    2. Initializes the admin-only vault under C:\ProgramData\SurakshaNet\vault
       with strict NTFS ACLs (SYSTEM & Administrators ONLY; Standard Users denied)
    3. Forces SurakshaNet installation in Chrome via HKLM Enterprise Policies,
       disables DevTools & Incognito, and injects Parent Public Key into managed storage
    4. Registers the Native Messaging Host in HKLM
    5. Registers a SYSTEM-level startup task to run the privileged Vault Daemon
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ExtensionId,

    [string]$UpdateUrl = "https://clients2.google.com/service/update2/crx",
    [string]$ParentKeyOut = "$env:USERPROFILE\Desktop\surakshanet-parent.key.json",
    [string]$ParentLabel = "SurakshaNet Parent Guardian",
    [string]$Passphrase = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VaultRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$InstallDir = "C:\Program Files\SurakshaNet"
$VaultBase = "C:\ProgramData\SurakshaNet"
$VaultDir = Join-Path $VaultBase "vault"
$ExePath = Join-Path $InstallDir "surakshanet-vault.exe"
$BridgeCmd = Join-Path $InstallDir "surakshanet-vault-bridge.cmd"

if ([string]::IsNullOrWhiteSpace($Passphrase)) {
    $sec = Read-Host -Prompt "Enter passphrase (>=8 chars) to encrypt Parent Private Key" -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    $Passphrase = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

Write-Host "[1/5] Building surakshanet-vault.exe..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Push-Location $VaultRoot
try {
    go build -o $ExePath ./cmd/surakshanet-vault
} finally {
    Pop-Location
}

Set-Content -Path $BridgeCmd -Encoding ASCII -Value "@echo off`r`n`"$ExePath`" bridge --network tcp --addr 127.0.0.1:48921 %*"

Write-Host "[2/5] Initializing admin-only vault & locking NTFS ACLs..."
New-Item -ItemType Directory -Force -Path $VaultDir | Out-Null

# Strip inherited permissions; grant Full Control ONLY to SYSTEM and Administrators.
icacls $VaultBase /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

$PubJson = Join-Path $VaultBase "parent.pub.json"
$CertPem = Join-Path $VaultBase "parent.crt.pem"

if (-not (Test-Path (Join-Path $VaultDir "vault.config.json"))) {
    & $ExePath init `
        --vault-dir $VaultDir `
        --parent-key-out $ParentKeyOut `
        --parent-pub-out $PubJson `
        --parent-cert-out $CertPem `
        --label $ParentLabel `
        --passphrase $Passphrase
}

$PubData = Get-Content $PubJson -Raw | ConvertFrom-Json
$ParentPubKey = $PubData.parent_public_key

Write-Host "[3/5] Applying HKLM Chrome Enterprise Managed Policies..."
$ChromePolicy = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$ForceList = Join-Path $ChromePolicy "ExtensionInstallForcelist"
$ExtPolicy = Join-Path $ChromePolicy "3rdparty\extensions\$ExtensionId\policy"

New-Item -Path $ForceList -Force | Out-Null
New-Item -Path $ExtPolicy -Force | Out-Null

Set-ItemProperty -Path $ForceList -Name "1000" -Value "$ExtensionId;$UpdateUrl" -Type String
Set-ItemProperty -Path $ChromePolicy -Name "DeveloperToolsAvailability" -Value 2 -Type DWord
Set-ItemProperty -Path $ChromePolicy -Name "IncognitoModeAvailability" -Value 1 -Type DWord

Set-ItemProperty -Path $ExtPolicy -Name "lockMode" -Value 1 -Type DWord
Set-ItemProperty -Path $ExtPolicy -Name "parentPublicKey" -Value $ParentPubKey -Type String
Set-ItemProperty -Path $ExtPolicy -Name "nativeHostName" -Value "com.surakshanet.vault" -Type String
Set-ItemProperty -Path $ExtPolicy -Name "heartbeatSec" -Value 60 -Type DWord

Write-Host "[4/5] Registering HKLM Native Messaging Host..."
$NmManifestPath = Join-Path $InstallDir "com.surakshanet.vault.json"
$NmManifest = @{
    name = "com.surakshanet.vault"
    description = "SurakshaNet Tamper-Evident Evidence Vault Native Bridge"
    path = $BridgeCmd
    type = "stdio"
    allowed_origins = @("chrome-extension://$ExtensionId/")
} | ConvertTo-Json -Depth 4
Set-Content -Path $NmManifestPath -Encoding UTF8 -Value $NmManifest

$NmRegKey = "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.surakshanet.vault"
New-Item -Path $NmRegKey -Force | Out-Null
Set-ItemProperty -Path $NmRegKey -Name "(Default)" -Value $NmManifestPath -Type String

Write-Host "[5/5] Registering SYSTEM-level Vault Daemon scheduled service..."
$Action = New-ScheduledTaskAction -Execute $ExePath -Argument "daemon --vault-dir `"$VaultDir`" --network tcp --addr 127.0.0.1:48921 --heartbeat-timeout 5m"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "SurakshaNetVaultDaemon" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName "SurakshaNetVaultDaemon"

Write-Host ""
Write-Host "========================================================================"
Write-Host "SurakshaNet Parent-Locked Vault installed successfully!"
Write-Host "  Locked Vault Dir:    $VaultDir (SYSTEM + Administrators ONLY)"
Write-Host "  Parent Private Key:  $ParentKeyOut"
Write-Host "  IMPORTANT: Move $ParentKeyOut to a USB drive/parent device and ensure"
Write-Host "             the child uses a Standard (non-Administrator) Windows account."
Write-Host "========================================================================"
