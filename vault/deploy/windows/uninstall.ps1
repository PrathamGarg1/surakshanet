#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory = $true)]
    [string]$ExtensionId
)

$ErrorActionPreference = "Continue"

Stop-ScheduledTask -TaskName "SurakshaNetVaultDaemon" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "SurakshaNetVaultDaemon" -Confirm:$false -ErrorAction SilentlyContinue

Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist" -Name "1000" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$ExtensionId" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.surakshanet.vault" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Removed SurakshaNet policies and daemon task."
Write-Host "Preserved evidence vault at C:\ProgramData\SurakshaNet\vault so records are not lost."
