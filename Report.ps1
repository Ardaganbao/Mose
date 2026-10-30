[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'Number of days of Commvault backup and restore job history to include.')]
    [ValidateRange(1, 365)]
    [int]$CommvaultJobLookbackDays = 30,

    [switch]$NoOpen
)

# Builds the report of the client configured on this computer (see Configure.ps1):
# runs every module on its servers and writes <Client>_Report_<yyyy-MM-dd>.md.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'helper.ps1')

Open-MoseVault
$config = Get-MoseConfig
if (-not $config) {
    Write-Host "This computer has no client configuration yet." -ForegroundColor Yellow
    & (Join-Path $PSScriptRoot 'Configure.ps1') -VaultUnlocked
    $config = Get-MoseConfig
    if (-not $config) {
        throw "No client configuration was saved, so there is nothing to report. Run .\Start.ps1 -Configure."
    }
}
# Also lists the modules of a configuration saved before Start.ps1 downloaded only those.
Save-MoseModuleList -Targets @($config.Targets)

function Get-TargetCredential {
    param(
        [object]$Target
    )

    $credential = Get-Secret -Vault $MoseVaultName -Name $Target.Secret
    if ($credential -isnot [pscredential]) {
        throw "Secret '$($Target.Secret)' is not a saved login. Run .\Start.ps1 -Configure and add this server again."
    }
    return $credential
}

# Runs the module of one server and returns its Markdown.
function Invoke-Target {
    param(
        [object]$Target
    )

    # The module scripts were written without strict mode, which Start.ps1 turns on for the scripts it runs.
    Set-StrictMode -Off

    $scriptPath = Join-Path $PSScriptRoot $MoseModules[$Target.Module].Script
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "Module script was not found: $scriptPath. Run .\Start.ps1 -UpdateOnly to download it."
    }

    switch ($Target.Module) {
        { $_ -in 'iLO', 'iDRAC', 'BMC' } {
            & $scriptPath -server $Target.Server -credential (Get-TargetCredential $Target)
        }
        'NAS' {
            $credential = Get-TargetCredential $Target
            $nasParameters = @{ server = $Target.Server; user = $credential.UserName; pass = $credential.Password }
            if ($Target.CertificateThumbprint) {
                $nasParameters.CertificateThumbprint = $Target.CertificateThumbprint
            }
            if ($Target.AcceptAnyCertificate) {
                $nasParameters.AcceptAnyCertificate = $true
            }
            & $scriptPath @nasParameters
        }
        'StorMagic' {
            & $scriptPath -Server $Target.Server -Credential (Get-TargetCredential $Target).GetNetworkCredential()
        }
        'VMware' {
            $credential = Get-TargetCredential $Target
            # The section title already names vCenter, so its own heading is dropped.
            $section = @(& $scriptPath -server $Target.Server -user $credential.UserName -pass $credential.Password -Client $config.Client -Site $Target.Site |
                Where-Object { $_ -is [string] })
            ($section -join [Environment]::NewLine).Trim() -replace '^### VMware\s*', ''
        }
        'Veeam' {
            $veeamParameters = @{ Server = $Target.Server; OutputPath = [System.IO.Path]::GetTempFileName(); NoOpen = $true }
            if ($Target.Secret) {
                $veeamParameters.RemotingCredential = Get-TargetCredential $Target
            }
            try {
                & $scriptPath @veeamParameters
            }
            finally {
                Remove-Item -LiteralPath $veeamParameters.OutputPath -Force -ErrorAction SilentlyContinue
            }
        }
        { $_ -in 'CommvaultCloud', 'CommvaultOnPrem' } {
            # The Commvault script writes its report to a file, read back here.
            $folder = Join-Path ([System.IO.Path]::GetTempPath()) ("CommvaultReport_{0}" -f [guid]::NewGuid().ToString('N'))
            New-Item -Path $folder -ItemType Directory | Out-Null
            try {
                & $scriptPath -ClientName $Target.Secret -Mode ($Target.Module -replace '^Commvault', '') -SecretSuffix '' `
                    -SecretVaultName $MoseVaultName -JobLookbackDays $CommvaultJobLookbackDays -OutputFolder $folder | Out-Null

                $files = @(Get-ChildItem -LiteralPath $folder -Filter 'CommvaultReport_*.md' -File)
                if ($files.Count -ne 1) {
                    throw "Expected one Commvault Markdown report in '$folder', found $($files.Count)."
                }
                Get-Content -LiteralPath $files[0].FullName -Raw
            }
            finally {
                Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        default {
            throw "Unknown module '$($Target.Module)'."
        }
    }
}

$originalLocation = Get-Location
try {
    # The module scripts expect to run from their own folder.
    Set-Location -LiteralPath $PSScriptRoot

    $report = New-Object System.Collections.Generic.List[string]
    $report.Add("# $($config.Client) report $(Get-Date -Format 'yyyy-MM-dd')")

    foreach ($module in $MoseModules.Keys) {
        foreach ($target in @($config.Targets | Where-Object { $_.Module -eq $module })) {
            $title = "$($MoseModules[$module].Label) $(Get-MoseTargetName $target)"
            if ($module -eq 'VMware') {
                $title += " ($($target.Site))"
            }

            Write-Host "Collecting $title..." -ForegroundColor DarkGray
            $report.Add("## $title")
            try {
                $section = @(Invoke-Target $target | Where-Object { $_ -is [string] })
                $content = ($section -join [Environment]::NewLine).Trim()
                if ($content) {
                    $report.Add($content)
                }
                else {
                    $report.Add('_No report data was returned._')
                }
            }
            catch {
                $report.Add("Collection failed: $($_.Exception.Message)")
                Write-Warning "$title collection failed: $($_.Exception.Message)"
            }
        }
    }

    $fileName = "$($config.Client -replace '[\\/:*?"<>|\s]', '_')_Report_$(Get-Date -Format 'yyyy-MM-dd').md"
    $outputPath = Join-Path $PSScriptRoot $fileName
    $reportText = $report -join ([Environment]::NewLine + [Environment]::NewLine)
    Set-Content -LiteralPath $outputPath -Value $reportText -Encoding UTF8
    Write-Host "$($config.Client) report written to $outputPath" -ForegroundColor Green

    if (-not $NoOpen) {
        Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$outputPath`""
    }

    $reportText
}
finally {
    Set-Location -LiteralPath $originalLocation
}
