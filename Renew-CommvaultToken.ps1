<#
    Keeps the Commvault Cloud tokens in SecretStore alive between monthly reports.
    --------------------------------------------------------------
    Commvault Cloud access tokens expire after 30 minutes. Even with "Renewal until: Forever",
    the token chain is deleted if it is not renewed within 14 days of expiring, so this script
    renews every stored Commvault Cloud token pair and is meant to run weekly.

    One-time setup, run interactively as the account that runs Report.ps1:
      .\Renew-CommvaultToken.ps1 -Register
        - saves the SecretStore password to a file that only this Windows user on this machine can decrypt (DPAPI)
        - registers a weekly scheduled task running this script as that user
        - renews the tokens once to confirm it works

    Each run appends to Renew-CommvaultToken.log next to this script.
#>

[CmdletBinding()]
param(
    # Renew only this secret; by default every Commvault Cloud token in the vault.
    [string]$SecretName,

    [string]$VaultName = 'SecretStore1',

    [string]$VaultPasswordFile = (  'SecretStore1.password.xml'),

    [string]$LogFile = (  'Renew-CommvaultToken.log'),

    [string]$TaskName = 'MOSE Commvault token renewal',

    [switch]$Register
)


if ("" -eq $PSScriptRoot) {
    $PSScriptRoot = "C:\scripts"
    cd  $PSScriptRoot
}
 [string]$VaultPasswordFile = (Join-Path $PSScriptRoot $VaultPasswordFile)
 [string]$LogFile = (Join-Path $PSScriptRoot $LogFile)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'helper.ps1')
$commvaultScript = Join-Path $PSScriptRoot 'CommvaultCloud report.ps1'
Import-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore

if ($Register) {
    $vaultPassword = Read-Host -Prompt "Password for SecretStore vault '$VaultName'" -AsSecureString
    # Unlocking first rejects a mistyped password before it is saved.
    Unlock-SecretVaultIfNeeded -VaultName $VaultName -Password $vaultPassword
    $vaultPassword | Export-Clixml -LiteralPath $VaultPasswordFile

    $windowsCredential = Get-Credential -UserName "$env:USERDOMAIN\$env:USERNAME" -Message 'Windows password for the scheduled task, so it also runs when you are logged off'
    if ($null -eq $windowsCredential) {
        throw 'Credential prompt was cancelled; no scheduled task was registered.'
    }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At '07:00'
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
        -User $windowsCredential.UserName -Password $windowsCredential.GetNetworkCredential().Password -Force | Out-Null
    Write-Host "Saved the vault password to '$VaultPasswordFile' and registered scheduled task '$TaskName' (every Monday 07:00)." -ForegroundColor Green
}

Start-Transcript -LiteralPath $LogFile -Append | Out-Null
try {
    if (-not (Test-Path -LiteralPath $VaultPasswordFile -PathType Leaf)) {
        throw "Vault password file '$VaultPasswordFile' was not found. Run this script once with -Register."
    }
    Unlock-SecretVaultIfNeeded -VaultName $VaultName -Password (Import-Clixml -LiteralPath $VaultPasswordFile)

    $secretNames = @($SecretName | Where-Object { $_ })
    if ($secretNames.Count -eq 0) {
        $secretNames = @(Get-CommvaultSecretNames -Mode Cloud -Vault $VaultName)
    }
    if ($secretNames.Count -eq 0) {
        throw "No Commvault Cloud token is saved in vault '$VaultName', so there is nothing to renew."
    }

    # One expired chain must not stop the others from being renewed.
    $failed = @()
    foreach ($name in $secretNames) {
        try {
            & $commvaultScript -ClientName $name -Mode Cloud -SecretSuffix '' -SecretVaultName $VaultName -RenewTokenOnly
        }
        catch {
            $failed += $name
            Write-Warning "Renewing '$name' failed: $($_.Exception.Message)"
        }
    }
    if ($failed.Count -gt 0) {
        throw "Could not renew: $($failed -join ', ')"
    }
}
finally {
    Stop-Transcript | Out-Null
}
