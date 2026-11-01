[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'Number of days of Commvault backup and restore job history to include.')]
    [ValidateRange(1, 365)]
    [int]$CommvaultJobLookbackDays = 30,

    [switch]$NoOpen
)

# Builds the report of the client configured on this computer (see Configure.ps1):
# runs every module on its servers and writes <Client>_Report_<yyyy-MM-dd>.md,
# with the section order, titles and groups of the client's report layout.

$ErrorActionPreference = 'Stop'
# Start.ps1 hides progress bars to download faster; the modules show theirs.
$ProgressPreference = 'Continue'
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
            & $scriptPath -server $Target.Server -user $credential.UserName -pass $credential.Password -Client $config.Client -Site $Target.Site
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

# Moves the headings of a module under its section: the heading levels the module uses, in order,
# become $TopLevel, $TopLevel + 1... whatever level each module starts at. With -DropTitle, a first
# line that is a heading only repeats the section title and is removed.
function Set-MarkdownHeadingLevel {
    param(
        [string]$Markdown,
        [int]$TopLevel,
        [switch]$DropTitle
    )

    $lines = [System.Collections.Generic.List[string]]($Markdown.Trim() -split '\r?\n')
    if ($DropTitle -and $lines[0] -match '^#{1,6}\s') {
        $lines.RemoveAt(0)
    }

    $headings = @()
    $fence = $null
    for ($i = 0; $i -lt $lines.Count; $i++) {
        # A # line inside a code block is not a heading.
        if ($lines[$i] -match '^\s{0,3}(`{3,}|~{3,})') {
            if (-not $fence) {
                $fence = $matches[1][0]
            }
            elseif ($matches[1][0] -eq $fence) {
                $fence = $null
            }
            continue
        }
        if (-not $fence -and $lines[$i] -match '^(#{1,6})\s+(.*?)\s*$') {
            $headings += [pscustomobject]@{ Index = $i; Level = $matches[1].Length; Text = $matches[2] }
        }
    }

    $levels = @($headings | ForEach-Object Level | Sort-Object -Unique)
    foreach ($heading in $headings) {
        $level = [Math]::Min(6, $TopLevel + [array]::IndexOf($levels, $heading.Level))
        $lines[$heading.Index] = "$('#' * $level) $($heading.Text)"
    }
    return ($lines -join [Environment]::NewLine).Trim()
}

# A group is shown when one of its sections is.
function Test-ReportSectionShown {
    param(
        [object]$Section
    )

    if ($Section.Hide) {
        return $false
    }
    if ($Section.Target) {
        return $true
    }
    return @($Section.Children | Where-Object { Test-ReportSectionShown $_ }).Count -gt 0
}

function Add-ReportSection {
    param(
        [object]$Section,
        [int]$Level
    )

    if (-not (Test-ReportSectionShown $Section)) {
        return
    }
    $title = Get-MoseSectionTitle -Section $Section -Client $config.Client -Date $reportDate
    $report.Add("$('#' * [Math]::Min(6, $Level)) $title")
    foreach ($child in $Section.Children) {
        Add-ReportSection -Section $child -Level ($Level + 1)
    }
    if (-not $Section.Target) {
        return
    }

    Write-Host "Collecting $title..." -ForegroundColor DarkGray
    try {
        $output = @(Invoke-Target $Section.Target | Where-Object { $_ -is [string] })
        $content = Set-MarkdownHeadingLevel -Markdown ($output -join [Environment]::NewLine) -TopLevel ($Level + 1) `
            -DropTitle:([bool]$MoseModules[$Section.Target.Module]['DropTitle'])
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
    finally {
        # Some modules allow only TLS 1.2, which would stop the next ones from using TLS 1.3.
        [Net.ServicePointManager]::SecurityProtocol = $securityProtocol
    }
}

$originalLocation = Get-Location
try {
    # The module scripts expect to run from their own folder.
    Set-Location -LiteralPath $PSScriptRoot

    $reportDate = Get-Date -Format 'yyyy-MM-dd'
    $layout = Get-MoseProperty $config 'Layout'
    $sections = Get-MoseReportSections -Layout $layout -Targets @($config.Targets)

    $title = Get-MoseProperty $layout 'Title'
    if (-not $title) {
        $title = $MoseDefaultReportTitle
    }
    $report = New-Object System.Collections.Generic.List[string]
    $report.Add("# $(Format-MoseTitle $title @{ Client = $config.Client; Date = $reportDate })")
    $securityProtocol = [Net.ServicePointManager]::SecurityProtocol

    foreach ($section in $sections) {
        Add-ReportSection -Section $section -Level 2
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
