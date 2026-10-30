
function Ensure-Module {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Version]$MinimumVersion = '1.0.0'
    )
    if (-not (Get-Module -ListAvailable -Name $Name | Where-Object { $_.Version -ge $MinimumVersion })) {
        Write-Host "Installing module '$Name' (min $MinimumVersion) for CurrentUser..." -ForegroundColor Cyan
        Install-Module -Name $Name -MinimumVersion $MinimumVersion -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    Import-Module $Name -ErrorAction Stop
}



function Ensure-SecretVault {
    param(
        [string]$VaultName = 'MySecretStore2',
        [string]$ModuleName = 'Microsoft.PowerShell.SecretStore'
    )

    # Ensure modules
    Ensure-Module -Name Microsoft.PowerShell.SecretManagement -MinimumVersion '1.1.0'
    Ensure-Module -Name $ModuleName -MinimumVersion '1.0.6'

    # Register vault if missing
    $existing = Get-SecretVault | Where-Object { $_.Name -eq $VaultName }
    if (-not $existing) {
        Write-Host "Registering secret vault '$VaultName'..." -ForegroundColor Cyan
        Register-SecretVault -Name $VaultName -ModuleName $ModuleName -DefaultVault
    }

    Write-Host "Vault '$VaultName' is registered." -ForegroundColor Green
}

function Unlock-SecretVaultIfNeeded {
    param(
        [string]$VaultName = 'MySecretStore2',
        [Security.SecureString]$Password
    )
    if (-not $Password) {
        $Password = Read-Host -Prompt "Password for SecretStore vault '$VaultName'" -AsSecureString
    }

    try {
        Unlock-SecretStore -Password $Password -ErrorAction Stop | Out-Null
    }
    catch {
        throw "Could not unlock SecretStore vault '$VaultName': $($_.Exception.Message)"
    }
}

function Set-AppSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [Security.SecureString]$Secret,
        [string]$Vault = 'MySecretStore2'
    )
    Set-Secret -Name $Name -Secret $Secret -Vault $Vault
}

function Get-AppSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Name,
        [string]$Vault = 'MySecretStore2',
        [switch]$AsPlainText
    )
    if ($AsPlainText) {
        return Get-Secret -Name $Name -Vault $Vault -AsPlainText
    } else {
        # Returns as the stored type; for secrets we recommend storing SecureString
        return Get-Secret -Name $Name -Vault $Vault
    }
}

function Get-AppCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$UserName,
        [Parameter(Mandatory)] [string]$PasswordSecretName,
        [string]$Vault = 'MySecretStore2'
    )
    $secure = Get-AppSecret -Name $PasswordSecretName -Vault $Vault
    if (-not $secure -or -not ($secure -is [Security.SecureString])) {
        throw "Secret '$PasswordSecretName' was not found or is not a SecureString."
    }
    return [pscredential]::new($UserName, $secure)
}
