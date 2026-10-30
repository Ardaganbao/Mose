[CmdletBinding()]
param (
    

    [Parameter(HelpMessage = 'Secret name for the EURID Commvault Cloud API token.')]
    [string]$CommvaultCloudClientName = 'EURID:CommvaultCloud',

    [Parameter(HelpMessage = 'Secret name for the EURID Commvault on-premises API token.')]
    [string]$CommvaultOnPremClientName = 'EURID:Commvaultprem',

    [Parameter(HelpMessage = 'Secret suffix used for both Commvault API token secrets.')]
    [string]$CommvaultSecretSuffix = '',

    [Parameter(HelpMessage = 'Secret vault containing both Commvault API tokens.')]
    [string]$CommvaultSecretVaultName = 'SecretStore1',

    [Parameter(HelpMessage = 'Optional Commvault Command Center URL override. Defaults to the URL saved in the on-prem secret.')]
    [string]$CommvaultOnPremServer,

    [Parameter(HelpMessage = 'Number of days of Commvault backup and restore job history to include.')]
    [ValidateRange(1, 365)]
    [int]$CommvaultJobLookbackDays = 30,
    
 
    [Parameter(HelpMessage = 'Accept any certificate for the EURID NAS only. Insecure; use only on a trusted network when necessary.')]
    [switch]$AcceptAnyNasCertificate,


    [switch]$NoOpen
)
if ("" -eq $PSScriptRoot) {
    $PSScriptRoot = "C:\script"
    cd  $PSScriptRoot
}
$ErrorActionPreference = 'Stop'
$scriptDirectory = $PSScriptRoot
$originalLocation = Get-Location

[string]$OutputPath = (Join-Path $PSScriptRoot "EURID_Report_$(Get-Date -Format 'yyyy-MM-dd').md")


# SecretStore returns every string value of a hashtable secret as a SecureString.
function ConvertTo-PlainSecretValue {
    param($Value)

    if ($Value -is [System.Security.SecureString]) {
        return [System.Net.NetworkCredential]::new('', $Value).Password
    }
    return [string]$Value
}

function Get-EURIDCredential {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SecretName,

        [string]$UserName,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('Credential', 'CommvaultCloud', 'CommvaultPrem')]
        [string]$SecretType = 'Credential'
    )

    $secretInfo = Get-SecretInfo -Vault $vaultName -Name $SecretName -ErrorAction SilentlyContinue

    if ($SecretType -eq 'Credential') {
        if (-not $secretInfo) {
            $credential = Get-Credential -Message $Message -UserName $UserName
            if ($null -eq $credential) {
                throw "Credential prompt was cancelled: $Message"
            }

            Set-AppSecret -Vault $vaultName -Name $SecretName -Secret $credential.Password -ErrorAction Stop
        }

        return Get-AppCredential -Vault $vaultName -UserName $UserName -PasswordSecretName $SecretName
    }

    $existingSecret = if ($secretInfo) {
        Get-Secret -Vault $vaultName -Name $SecretName -ErrorAction Stop
    }
    else {
        $null
    }
    if ($SecretType -eq 'CommvaultCloud' -and $existingSecret) {
        $hasRequiredFields = (ConvertTo-PlainSecretValue $existingSecret.Type) -eq 'Cloud' -and
            $existingSecret.AccessToken -is [System.Security.SecureString] -and
            $existingSecret.RefreshToken -is [System.Security.SecureString] -and
            -not [string]::IsNullOrWhiteSpace((ConvertTo-PlainSecretValue $existingSecret.Ring))
        if ($hasRequiredFields) {
            return $existingSecret
        }
    }
    elseif ($SecretType -eq 'CommvaultPrem' -and $existingSecret) {
        $hasRequiredFields = (ConvertTo-PlainSecretValue $existingSecret.Type) -eq 'OnPrem' -and
            $existingSecret.AccessToken -is [System.Security.SecureString] -and
            -not [string]::IsNullOrWhiteSpace((ConvertTo-PlainSecretValue $existingSecret.Server))
        if ($hasRequiredFields) {
            return $existingSecret
        }
    }

    if ($SecretType -eq 'CommvaultCloud') {
        $accessToken = Read-Host -Prompt 'Enter the Commvault Cloud ACCESS token' -AsSecureString
        $refreshToken = Read-Host -Prompt 'Enter the Commvault Cloud REFRESH token' -AsSecureString
        $ring = Read-Host -Prompt 'Enter the Commvault Cloud ring ID'
        if ($accessToken.Length -eq 0 -or $refreshToken.Length -eq 0 -or
            [string]::IsNullOrWhiteSpace($ring)) {
            throw "Commvault Cloud secret prompt was incomplete for '$SecretName'; no secret was saved."
        }

        $newSecret = @{
            Type = 'Cloud'
            AccessToken = $accessToken
            RefreshToken = $refreshToken
            Ring = $ring
        }
    }
    else {
        $accessToken = Read-Host -Prompt 'Enter the Commvault on-prem ACCESS token' -AsSecureString
        $server = Read-Host -Prompt 'Enter the Commvault on-prem server URL'
        if ($accessToken.Length -eq 0 -or [string]::IsNullOrWhiteSpace($server)) {
            throw "Commvault on-prem secret prompt was incomplete for '$SecretName'; no secret was saved."
        }

        $newSecret = @{
            Type = 'OnPrem'
            AccessToken = $accessToken
            Server = $server
        }
    }

    Set-Secret -Name $SecretName -Vault $vaultName -Secret $newSecret -ErrorAction Stop
    return $newSecret
}

$report = [System.Collections.Generic.List[string]]::new()

function Add-ReportSection {
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$Report,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Collector
    )

    $Report.Add("## $Title")
    try {
        $section = @(& $Collector | Where-Object { $_ -is [string] })
        $content = ($section -join [Environment]::NewLine).Trim()
        if ([string]::IsNullOrWhiteSpace($content)) {
            $Report.Add('_No report data was returned._')
        }
        else {
            $Report.Add($content)
        }
    }
    catch {
        $Report.Add("Collection failed: $($_.Exception.Message)")
        Write-Warning "$Title collection failed: $($_.Exception.Message)"
    }
}

function Add-CommvaultReportSection {
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$Report,

        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [string]$ClientName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Cloud', 'OnPrem')]
        [string]$Mode,

        [string]$Server,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$SecretSuffix,

        [Parameter(Mandatory = $true)]
        [string]$SecretVaultName,

        [Parameter(Mandatory = $true)]
        [int]$JobLookbackDays
    )

    $commvaultTempFolder = Join-Path ([System.IO.Path]::GetTempPath()) ("CommvaultReport_{0}" -f [guid]::NewGuid().ToString('N'))
    try {
        New-Item -Path $commvaultTempFolder -ItemType Directory -ErrorAction Stop | Out-Null
        Add-ReportSection -Report $Report -Title "Commvault $Mode ($ClientName)" -Collector {
            & $ScriptPath `
                -ClientName $ClientName `
                -Mode $Mode `
                -CommvaultServer $Server `
                -SecretSuffix $SecretSuffix `
                -SecretVaultName $SecretVaultName `
                -JobLookbackDays $JobLookbackDays `
                -OutputFolder $commvaultTempFolder | Out-Null

            $commvaultReports = @(Get-ChildItem -LiteralPath $commvaultTempFolder -Filter 'CommvaultReport_*.md' -File -ErrorAction Stop)
            if ($commvaultReports.Count -ne 1) {
                throw "Expected one Commvault Markdown report in '$commvaultTempFolder', found $($commvaultReports.Count)."
            }
            Get-Content -LiteralPath $commvaultReports[0].FullName -Raw -ErrorAction Stop
        }.GetNewClosure()
    }
    finally {
        if (Test-Path -LiteralPath $commvaultTempFolder -PathType Container) {
            foreach ($tempFile in Get-ChildItem -LiteralPath $commvaultTempFolder -File -Force -ErrorAction Stop) {
                Remove-Item -LiteralPath $tempFile.FullName -Force -ErrorAction Stop
            }
            Remove-Item -LiteralPath $commvaultTempFolder -Force -ErrorAction Stop
        }
    }
}

try {
    if (-not (Test-Path -LiteralPath $scriptDirectory -PathType Container)) {
        throw "Script directory was not found: $scriptDirectory"
    }
    Set-Location -LiteralPath $scriptDirectory

    $idracScript = Join-Path $scriptDirectory 'IDRAC.ps1' 
    $commvaultScript = Join-Path $scriptDirectory 'CommvaultCloud report.ps1'

    foreach ($path in @($idracScript, $commvaultScript)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required report script was not found: $path"
        }
    }

    $helperPath = Join-Path $scriptDirectory 'helper.ps1'
    if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
        throw "Secret vault helper script was not found: $helperPath"
    }
    . $helperPath

    $vaultName = 'SecretStore1'
    Ensure-Module -Name 'Microsoft.PowerShell.SecretManagement' -MinimumVersion '1.1.0'
    Ensure-Module -Name 'Microsoft.PowerShell.SecretStore' -MinimumVersion '1.0.6'
    Ensure-SecretVault -VaultName $vaultName
    Unlock-SecretVaultIfNeeded -VaultName $vaultName

    $idracCredential = Get-EURIDCredential -SecretName 'EURID:idrac' -UserName 'SPIE' -Message 'Please, provide the EURID idrac credential'
    $commvaultCloudCredential = Get-EURIDCredential -SecretName $CommvaultCloudClientName -Message 'Configure the EURID Commvault Cloud API token' -SecretType CommvaultCloud
    $commvaultOnPremCredential = Get-EURIDCredential -SecretName $CommvaultOnPremClientName -Message 'Configure the EURID Commvault on-prem API token' -SecretType CommvaultPrem
  

    $report.Add("## Hardware")
    $ServersIlo = @('10.32.175.109', '10.33.175.109', '172.20.99.223')
    foreach ($server in $ServersIlo) {
        Add-ReportSection -Report $report -Title "### Check Status Hardware (IDRAC:  $($server))" -Collector {
            & $idracScript -server $server -credential $idracCredential 
        }.GetNewClosure()
    }

     
    
    
    

    Add-CommvaultReportSection `
        -Report $report `
        -ScriptPath $commvaultScript `
        -ClientName $CommvaultCloudClientName `
        -Mode Cloud `
        -SecretSuffix $CommvaultSecretSuffix `
        -SecretVaultName $CommvaultSecretVaultName `
        -JobLookbackDays $CommvaultJobLookbackDays

    Add-CommvaultReportSection `
        -Report $report `
        -ScriptPath $commvaultScript `
        -ClientName $CommvaultOnPremClientName `
        -Mode OnPrem `
        -Server $CommvaultOnPremServer `
        -SecretSuffix $CommvaultSecretSuffix `
        -SecretVaultName $CommvaultSecretVaultName `
        -JobLookbackDays $CommvaultJobLookbackDays

    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $reportText = $report -join ([Environment]::NewLine + [Environment]::NewLine)
    Set-Content -LiteralPath $OutputPath -Value $reportText -Encoding UTF8 -ErrorAction Stop
    Write-Host "EURID report written to $OutputPath" -ForegroundColor Green

    if (-not $NoOpen) {
        Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$OutputPath`"" -ErrorAction Stop
    }

    $reportText
}
finally {
    Set-Location -LiteralPath $originalLocation
}
