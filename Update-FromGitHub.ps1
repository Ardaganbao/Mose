[CmdletBinding()]
param(
    [Parameter()]
    [string]$Owner,

    [Parameter()]
    [string]$Repository,

    [Parameter()]
    [string]$Branch,

    [Parameter()]
    [string]$TargetFolder = $PSScriptRoot,

    [Parameter()]
    [string[]]$Files = @(),

    [Parameter()]
    [string]$ConfigPath = (Join-Path $PSScriptRoot "updater.config.json"),

    [Parameter()]
    [switch]$UpdateProject,

    [Parameter()]
    [switch]$UseRelease,

    [Parameter()]
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-StrictMode -Version Latest

# GitHub requires TLS 1.2; Windows PowerShell 5.1 may not enable it by default.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Get-ConfigValue {
    param(
        [object]$Config,
        [string]$Name,
        [object]$Default
    )

    if ($Config -and $Config.PSObject.Properties[$Name] -and $Config.$Name) {
        return $Config.$Name
    }

    return $Default
}

function Get-FileList {
    param(
        [string]$Folder,
        [string[]]$Names
    )

    if ($Names.Count -gt 0) {
        return $Names
    }

    $items = Get-ChildItem -Path $Folder -File |
        Where-Object { $_.Name -notmatch 'Update-FromGitHub\.ps1' } |
        Select-Object -ExpandProperty Name

    return $items
}

function New-TempFolder {
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("gh-update-" + [Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    return $path
}

function Save-RemoteFile {
    param(
        [string]$Uri,
        [string]$Destination,
        [hashtable]$Headers
    )

    Write-Host "Downloading: $Uri"
    Invoke-WebRequest -Uri $Uri -OutFile $Destination -Headers $Headers -UseBasicParsing
}

function Copy-ExtractedFiles {
    param(
        [string]$ExtractFolder,
        [string]$Target
    )

    # GitHub archives wrap everything in one top-level folder; release zips may not.
    $source = $ExtractFolder
    $entries = @(Get-ChildItem -Path $ExtractFolder)
    if ($entries.Count -eq 1 -and $entries[0].PSIsContainer) {
        $source = $entries[0].FullName
    }

    Get-ChildItem -Path $source -Recurse -File | ForEach-Object {
        $relativePath = $_.FullName.Substring($source.Length + 1)
        $destination = Join-Path $Target $relativePath

        $destinationFolder = Split-Path -Parent $destination
        if (-not (Test-Path $destinationFolder)) {
            New-Item -ItemType Directory -Path $destinationFolder -Force | Out-Null
        }

        Copy-Item -Path $_.FullName -Destination $destination -Force
        Write-Host "Updated: $relativePath"
    }
}

function Update-SingleFiles {
    param(
        [string]$OwnerName,
        [string]$RepoName,
        [string]$Target,
        [string[]]$Names,
        [string]$BranchName,
        [hashtable]$Headers
    )

    foreach ($fileName in $Names) {
        $destination = Join-Path $Target $fileName
        $rawUrl = "https://raw.githubusercontent.com/$OwnerName/$RepoName/$BranchName/$($fileName -replace '\\', '/')"
        $tempFile = [System.IO.Path]::GetTempFileName()

        try {
            Save-RemoteFile -Uri $rawUrl -Destination $tempFile -Headers $Headers

            if (-not $Force -and (Test-Path $destination) -and
                (Get-FileHash $tempFile).Hash -eq (Get-FileHash $destination).Hash) {
                Write-Host "Already up to date: $fileName"
                continue
            }

            $destinationFolder = Split-Path -Parent $destination
            if (-not (Test-Path $destinationFolder)) {
                New-Item -ItemType Directory -Path $destinationFolder -Force | Out-Null
            }

            Copy-Item -Path $tempFile -Destination $destination -Force
            Write-Host "Updated: $fileName"
        }
        catch {
            Write-Warning "Could not update ${fileName}: $($_.Exception.Message)"
        }
        finally {
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Update-EntireProject {
    param(
        [string]$OwnerName,
        [string]$RepoName,
        [string]$BranchName,
        [string]$Target,
        [hashtable]$Headers
    )

    # The API zipball endpoint works for both public and private (token) repositories.
    $archiveUrl = "https://api.github.com/repos/$OwnerName/$RepoName/zipball/$BranchName"
    $tempDir = New-TempFolder

    try {
        $zipPath = Join-Path $tempDir "repo.zip"
        $extractFolder = Join-Path $tempDir "extract"

        Save-RemoteFile -Uri $archiveUrl -Destination $zipPath -Headers $Headers
        Expand-Archive -Path $zipPath -DestinationPath $extractFolder -Force
        Copy-ExtractedFiles -ExtractFolder $extractFolder -Target $Target
    }
    finally {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "Project synced from GitHub into $Target"
}

function Update-FromRelease {
    param(
        [string]$OwnerName,
        [string]$RepoName,
        [string]$Target,
        [hashtable]$Headers
    )

    $apiUrl = "https://api.github.com/repos/$OwnerName/$RepoName/releases/latest"
    $release = Invoke-RestMethod -Uri $apiUrl -Headers ($Headers + @{ Accept = "application/vnd.github+json" })
    $asset = $release.assets | Where-Object { $_.name -match '\.(zip|ps1)$' } | Select-Object -First 1

    if (-not $asset) {
        throw "Latest release '$($release.tag_name)' has no .zip or .ps1 asset."
    }

    # Private repos need the API asset URL with the token; public repos can use the browser URL.
    $downloadUrl = $asset.browser_download_url
    $downloadHeaders = $Headers
    if ($Headers.ContainsKey("Authorization")) {
        $downloadUrl = $asset.url
        $downloadHeaders = $Headers + @{ Accept = "application/octet-stream" }
    }

    $tempDir = New-TempFolder

    try {
        $downloadPath = Join-Path $tempDir $asset.name
        Save-RemoteFile -Uri $downloadUrl -Destination $downloadPath -Headers $downloadHeaders

        if ($asset.name -like '*.zip') {
            $extractFolder = Join-Path $tempDir "extract"
            Expand-Archive -Path $downloadPath -DestinationPath $extractFolder -Force
            Copy-ExtractedFiles -ExtractFolder $extractFolder -Target $Target
        }
        else {
            Copy-Item -Path $downloadPath -Destination (Join-Path $Target $asset.name) -Force
            Write-Host "Updated: $($asset.name)"
        }
    }
    finally {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "Updated files from release $($release.tag_name)."
}

# Command-line parameters override values from updater.config.json.
$config = $null
if (Test-Path $ConfigPath) {
    $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
}

if (-not $Owner) { $Owner = Get-ConfigValue -Config $config -Name "Owner" -Default $null }
if (-not $Repository) { $Repository = Get-ConfigValue -Config $config -Name "Repository" -Default $null }
if (-not $Branch) { $Branch = Get-ConfigValue -Config $config -Name "Branch" -Default "main" }
if ($Files.Count -eq 0) { $Files = @(Get-ConfigValue -Config $config -Name "Files" -Default @()) }

if (-not $Owner -or -not $Repository -or $Owner -eq "your-github-user" -or $Repository -eq "your-repository") {
    throw "GitHub repository is not configured. Set Owner and Repository in $ConfigPath or pass -Owner and -Repository."
}

# For a private repository, set GITHUB_TOKEN, save a token with .\Start.ps1 -SaveToken,
# or set TokenSecretName in the config to read the token from the SecretManagement vault.
$headers = @{ "User-Agent" = "PowerShell-Updater" }
$token = $env:GITHUB_TOKEN
$tokenPath = Join-Path $PSScriptRoot "github-token.xml"
if (-not $token -and (Test-Path $tokenPath)) {
    $token = [System.Net.NetworkCredential]::new("", (Import-Clixml -Path $tokenPath)).Password
}
$tokenSecretName = Get-ConfigValue -Config $config -Name "TokenSecretName" -Default $null
if (-not $token -and $tokenSecretName) {
    $token = Get-Secret -Name $tokenSecretName -AsPlainText
}
if ($token) {
    $headers["Authorization"] = "Bearer $token"
}

if (-not (Test-Path $TargetFolder)) {
    New-Item -ItemType Directory -Path $TargetFolder -Force | Out-Null
}

if ($UpdateProject) {
    Update-EntireProject -OwnerName $Owner -RepoName $Repository -BranchName $Branch -Target $TargetFolder -Headers $headers
    return
}

if ($UseRelease) {
    try {
        Update-FromRelease -OwnerName $Owner -RepoName $Repository -Target $TargetFolder -Headers $headers
        return
    }
    catch {
        Write-Warning "GitHub release update failed, falling back to branch '$Branch': $($_.Exception.Message)"
    }
}

$resolvedFiles = Get-FileList -Folder $TargetFolder -Names $Files
Update-SingleFiles -OwnerName $Owner -RepoName $Repository -Target $TargetFolder -Names $resolvedFiles -BranchName $Branch -Headers $headers
