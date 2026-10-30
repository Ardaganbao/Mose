
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

# Everything about the client stays in this vault, never in the scripts: the client name and
# servers (secret MOSE:Config, as JSON) and one credential or token secret per server.
$MoseVaultName = 'SecretStore1'
$MoseConfigSecretName = 'MOSE:Config'

# Modules a client configuration can use, in report order.
$MoseModules = [ordered]@{
    iLO             = @{ Label = 'HPE iLO'; Script = 'iloreport.ps1' }
    iDRAC           = @{ Label = 'Dell iDRAC'; Script = 'IDRAC.ps1' }
    BMC             = @{ Label = 'Lenovo BMC'; Script = 'BMCreport.ps1' }
    NAS             = @{ Label = 'Synology NAS'; Script = 'nas2.ps1' }
    StorMagic       = @{ Label = 'StorMagic SvSAN'; Script = 'stormagicHealth.ps1' }
    VMware          = @{ Label = 'VMware vCenter'; Script = 'vmwarereport.ps1' }
    Veeam           = @{ Label = 'Veeam Backup & Replication'; Script = 'VeeamReport.ps1' }
    CommvaultCloud  = @{ Label = 'Commvault Cloud'; Script = 'CommvaultCloud report.ps1' }
    CommvaultOnPrem = @{ Label = 'Commvault on-premises'; Script = 'CommvaultCloud report.ps1' }
}

function Open-MoseVault {
    Ensure-Module -Name 'Microsoft.PowerShell.SecretManagement' -MinimumVersion '1.1.0'
    Ensure-Module -Name 'Microsoft.PowerShell.SecretStore' -MinimumVersion '1.0.6'
    Ensure-SecretVault -VaultName $MoseVaultName
    Unlock-SecretVaultIfNeeded -VaultName $MoseVaultName
}

# Returns $null when this computer has no client configuration yet.
function Get-MoseConfig {
    param(
        [string]$Vault = $MoseVaultName
    )

    if (-not (Get-SecretInfo -Vault $Vault -Name $MoseConfigSecretName -ErrorAction SilentlyContinue)) {
        return $null
    }
    return Get-Secret -Vault $Vault -Name $MoseConfigSecretName -AsPlainText | ConvertFrom-Json
}

function Save-MoseConfig {
    param(
        [Parameter(Mandatory)] [string]$Client,
        [object[]]$Targets = @()
    )

    $json = [pscustomobject]@{ Client = $Client; Targets = @($Targets) } | ConvertTo-Json -Depth 5
    Set-Secret -Vault $MoseVaultName -Name $MoseConfigSecretName -Secret $json
    Save-MoseModuleList -Targets $Targets
}

# Start.ps1 only downloads and updates the module scripts listed here, those of the client
# configured on this computer. File names only, no client data (kept out of the repository, see .gitignore).
$MoseModuleListPath = Join-Path $PSScriptRoot 'modules.local.json'

function Save-MoseModuleList {
    param(
        [object[]]$Targets = @()
    )

    $previous = @()
    if (Test-Path -LiteralPath $MoseModuleListPath) {
        # Inner parentheses: Windows PowerShell returns a JSON array as one object.
        $previous = @((Get-Content -LiteralPath $MoseModuleListPath -Raw | ConvertFrom-Json))
    }
    $scripts = @($Targets | Where-Object { $MoseModules.Contains($_.Module) } |
        ForEach-Object { $MoseModules[$_.Module].Script } | Sort-Object -Unique)
    ConvertTo-Json -InputObject $scripts | Set-Content -LiteralPath $MoseModuleListPath -Encoding utf8

    # A module added since the last update is downloaded (or brought up to date) right away.
    $added = @($scripts | Where-Object { $previous -notcontains $_ })
    if ($added.Count -gt 0) {
        Write-Host "Downloading the modules: $($added -join ', ')" -ForegroundColor DarkGray
        & (Join-Path $PSScriptRoot 'Start.ps1') -UpdateOnly -Quiet | Out-Null
    }
}

# Commvault keeps its tokens in the secret itself, so a target is named after that secret.
function Get-MoseTargetName {
    param(
        [Parameter(Mandatory)] [object]$Target
    )

    if ($Target.Server) {
        return $Target.Server
    }
    return $Target.Secret
}

# Vault secrets holding Commvault tokens in the format 'CommvaultCloud report.ps1' reads.
function Get-CommvaultSecretNames {
    param(
        [Parameter(Mandatory)] [ValidateSet('Cloud', 'OnPrem')] [string]$Mode,
        [string]$Vault = $MoseVaultName
    )

    foreach ($info in @(Get-SecretInfo -Vault $Vault | Where-Object { "$($_.Type)" -eq 'Hashtable' })) {
        $secret = Get-Secret -Vault $Vault -Name $info.Name -AsPlainText
        if ($secret -is [System.Collections.IDictionary] -and $secret['Type'] -eq $Mode) {
            $info.Name
        }
    }
}
