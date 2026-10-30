[CmdletBinding()]
param (
    [Parameter(HelpMessage = 'Veeam Backup & Replication server. Set this to the Veeam server when running away from it.')]
    [string]$VeeamServer = 'localhost',

    [Parameter(HelpMessage = 'Commvault deployment to report on.')]
    [ValidateSet('Cloud', 'OnPrem')]
    [string]$CommvaultMode = 'Cloud',

    [Parameter(HelpMessage = 'Commvault client name used to retrieve the stored API token and label the report section.')]
    [string]$CommvaultClientName = 'Clait',

    [Parameter(HelpMessage = 'Secret suffix used for the Commvault API token secret.')]
    [string]$CommvaultSecretSuffix = '_Token',

    [Parameter(HelpMessage = 'Secret vault containing the Commvault API token.')]
    [string]$CommvaultSecretVaultName = 'SecretStore1',

    [Parameter(HelpMessage = 'Optional Commvault Command Center URL override for OnPrem mode. Defaults to the URL saved in SecretStore.')]
    [string]$CommvaultServer,

    [Parameter(HelpMessage = 'Number of days of Commvault backup and restore job history to include.')]
    [ValidateRange(1, 365)]
    [int]$CommvaultJobLookbackDays = 30,
    
    [Parameter(HelpMessage = 'Optional verified SHA-1 thumbprint pin for the Clait Synology NAS certificate.')]
    [string]$NasCertificateThumbprint,
        [Parameter(HelpMessage = 'Accept any certificate for the Clait NAS only. Insecure; use only on a trusted network when necessary.')]
    [switch]$AcceptAnyNasCertificate,


    [switch]$NoOpen
)
if("" -eq $PSScriptRoot)
{
$PSScriptRoot ="C:\scripts"
cd  $PSScriptRoot
}
$ErrorActionPreference = 'Stop'
$scriptDirectory = $PSScriptRoot
$originalLocation = Get-Location

[string]$OutputPath = (Join-Path $PSScriptRoot "Clait_Report_$(Get-Date -Format 'yyyy-MM-dd').md")


function Get-ClaitCredential {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SecretName,

        [Parameter(Mandatory = $true)]
        [string]$UserName,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not (Get-SecretInfo -Vault $vaultName -Name $SecretName -ErrorAction SilentlyContinue)) {
        $credential = Get-Credential -Message $Message -UserName $UserName
        if ($null -eq $credential) {
            throw "Credential prompt was cancelled: $Message"
        }

        Set-AppSecret -Vault $vaultName -Name $SecretName -Secret $credential.Password -ErrorAction Stop
    }

    return Get-AppCredential -Vault $vaultName -UserName $UserName -PasswordSecretName $SecretName
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

try {
    if (-not (Test-Path -LiteralPath $scriptDirectory -PathType Container)) {
        throw "Script directory was not found: $scriptDirectory"
    }
    Set-Location -LiteralPath $scriptDirectory

    $iloScript = Join-Path $scriptDirectory 'iloreport.ps1'
    $nasScript = Join-Path $scriptDirectory 'nas2.ps1'
    $stormagicScript = Join-Path $scriptDirectory 'stormagicHealth.ps1'
    $vmwareScript = Join-Path $scriptDirectory 'vmwarereport.ps1'
    $veeamScript = Join-Path $scriptDirectory 'VeeamReport.ps1'
    $commvaultScript = Join-Path $scriptDirectory 'CommvaultCloud report.ps1'

    foreach ($path in @($iloScript, $nasScript, $stormagicScript, $vmwareScript, $veeamScript, $commvaultScript)) {
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

    $iloCredential = Get-ClaitCredential -SecretName 'Clait:iLO' -UserName 'systemat' -Message 'Please, provide the Clait iLO credential'
    $nasCredential = Get-ClaitCredential -SecretName 'Clait:NAS:89.0.1.208' -UserName 'Admincdl' -Message 'Please, provide the Clait NAS Sony credential'
    $vcenterCredential = Get-ClaitCredential -SecretName 'Clait:vCenter:srv-vcenter-2024.cdl.local' -UserName 'administrator@vsphere.local' -Message 'Please, provide the Clait vCenter credential'
    $stormagicCredential = Get-ClaitCredential -SecretName 'Clait:StorMagic:89.0.2.9' -UserName 'admin' -Message 'Please, provide the Clait StorMagic credential'

    $report.Add("## Hardware")
    $ServersIlo = @('89.0.2.165', '89.0.2.166')
    foreach ($server in $ServersIlo) {
        Add-ReportSection -Report $report -Title "### Check Status Hardware (iLo:  $($server))" -Collector {
            & $iloScript -server $server -credential $iloCredential 
        }.GetNewClosure()
    }

     $server = '89.0.1.208'
    Add-ReportSection -Report $report -Title "NAS $server" -Collector {
        $nasParameters = @{
            server = $server
            user = $nasCredential.UserName
            pass = $nasCredential.Password
            CertificateThumbprint = "D3F381EEFFF3CCFEC4E8654D93188C2ED64A8C4E"
        }
         
            $nasParameters.AcceptAnyCertificate = $true
         
        & $nasScript @nasParameters
    }.GetNewClosure()

    $server = '89.0.2.9'
    Add-ReportSection -Report $report -Title "StorMagic $server" -Collector {
        & $stormagicScript -Server $server -Credential $stormagicCredential.GetNetworkCredential()
    }.GetNewClosure()

    $server = 'srv-vcenter-2024.cdl.local'
    Add-ReportSection -Report $report -Title "VMware vCenter $server" -Collector {
        & $vmwareScript -server $server -user $vcenterCredential.UserName -pass $vcenterCredential.Password -Client 'Clait' -Site 'main'
    }.GetNewClosure()

    $veeamTempPath = [System.IO.Path]::GetTempFileName()
    try {
        Add-ReportSection -Report $report -Title "Veeam ($VeeamServer)" -Collector {
            & $veeamScript -Server $VeeamServer -OutputPath $veeamTempPath -NoOpen
        }.GetNewClosure()
    }
    finally {
        if (Test-Path -LiteralPath $veeamTempPath) {
            Remove-Item -LiteralPath $veeamTempPath -Force -ErrorAction Stop
        }
    }

    $commvaultTempFolder = Join-Path ([System.IO.Path]::GetTempPath()) ("CommvaultReport_{0}" -f [guid]::NewGuid().ToString('N'))
    try {
        New-Item -Path $commvaultTempFolder -ItemType Directory -ErrorAction Stop | Out-Null
        Add-ReportSection -Report $report -Title "Commvault $CommvaultMode ($CommvaultClientName)" -Collector {
            & $commvaultScript `
                -ClientName $CommvaultClientName `
                -Mode $CommvaultMode `
                -CommvaultServer $CommvaultServer `
                -SecretSuffix $CommvaultSecretSuffix `
                -SecretVaultName $CommvaultSecretVaultName `
                -JobLookbackDays $CommvaultJobLookbackDays `
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

    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $reportText = $report -join ([Environment]::NewLine + [Environment]::NewLine)
    Set-Content -LiteralPath $OutputPath -Value $reportText -Encoding UTF8 -ErrorAction Stop
    Write-Host "Clait report written to $OutputPath" -ForegroundColor Green

    if (-not $NoOpen) {
        Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$OutputPath`"" -ErrorAction Stop
    }

    $reportText
}
finally {
    Set-Location -LiteralPath $originalLocation
}
