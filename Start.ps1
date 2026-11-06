[CmdletBinding()]
param(
    [Parameter()]
    [string]$Owner = "Ardaganbao",

    [Parameter()]
    [string]$Repository = "Mose",

    # Branch, tag or commit to update to, e.g. -Version v1.0.0-rc.1. The next run without it goes back to main.
    [Parameter()]
    [Alias("Version")]
    [string]$Branch = "main",

    # Where the one-liner installs the scripts.
    [Parameter()]
    [string]$InstallPath = (Join-Path $HOME "Mose"),

    [Parameter()]
    [switch]$SkipUpdate,

    # Ask for a new GitHub token (e.g. when the old one expired) and save it for later runs.
    [Parameter()]
    [switch]$SaveToken,

    # Save this GitHub token for later runs instead of asking for it (e.g. when installing many computers).
    [Parameter()]
    [string]$GitHubToken,

    # Only update the files; don't run any script.
    [Parameter()]
    [switch]$UpdateOnly,

    # Open Manager.ps1 after updating instead of running the scripts.
    [Parameter()]
    [switch]$Gui,

    # Enter or change the client of this computer (servers and credentials) after updating.
    [Parameter()]
    [switch]$Configure,

    # Preview the report with sample data after updating: no server is contacted.
    [Parameter()]
    [switch]$DryRun,

    # Run the report and also write a debug log: where each failed server stopped, with the call stack.
    [Parameter()]
    [switch]$DebugLog,

    # A partial report: only the servers whose module or name contains one of these words, e.g. -Only veeam,sql.
    # The modules: iLO, iDRAC, BMC, NAS, StorMagic, VMware, HyperV, Veeam (both Veeam modules), VeeamApi,
    # Commvault (Cloud and on-premises), CommvaultCloud, CommvaultOnPrem, SQL; or a server name or IP address.
    # Tab completes them (the list is the same in Report.ps1).
    [Parameter()]
    [ArgumentCompleter({
            param($commandName, $parameterName, $wordToComplete)
            'iLO', 'iDRAC', 'BMC', 'NAS', 'StorMagic', 'VMware', 'HyperV', 'Veeam', 'VeeamApi', 'Commvault', 'CommvaultCloud', 'CommvaultOnPrem', 'SQL' |
                Where-Object { $_ -like "$wordToComplete*" }
        })]
    [string[]]$Only,

    # A partial report: pick its servers from the list of configured servers.
    [Parameter()]
    [switch]$Choose,

    # Import or export Keeper entries over its API (Keeper.ps1) after updating, instead of the report.
    # The Keeper scripts are downloaded the first time.
    [Parameter()]
    [switch]$Keeper,

    # Set internally when the script restarts after all updates were downloaded.
    [Parameter(DontShow)]
    [switch]$UpdatesApplied,

    # Set by older versions, which restart before downloading the other files.
    [Parameter(DontShow)]
    [switch]$SelfUpdated,

    # Set by Configure.ps1 to download the modules just added, without the welcome text.
    [Parameter(DontShow)]
    [switch]$Quiet
)

# GitHub requires TLS 1.2; Windows PowerShell 5.1 may not enable it by default. SystemDefault (0, the
# versions Windows allows, TLS 1.3 included) is kept: adding TLS 1.2 to it would turn the others off,
# also for the reports run in this process.
if ([int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

# The scripts downloaded from GitHub are run, so GitHub always gets the normal certificate check. A
# module run earlier in this PowerShell window may have left its own in place: one accepting any
# certificate (iDRAC, BMC), or one written in PowerShell ({ $true }), which .NET cannot run on its
# own threads, so that every HTTPS call fails with "There is no Runspace available".
[Net.ServicePointManager]::ServerCertificateValidationCallback = $null
$defaultCertPolicy = [Net.ServicePointManager].Assembly.GetType('System.Net.DefaultCertPolicy')
if ($defaultCertPolicy -and [Net.ServicePointManager]::CertificatePolicy -isnot $defaultCertPolicy) {
    [Net.ServicePointManager]::CertificatePolicy = [Activator]::CreateInstance($defaultCertPolicy, $true)
}

# Started from the one-liner (irm ... | iex): there is no file yet, so save Start.ps1
# into $InstallPath and run it from there in a new process, which keeps this session
# clean and works whatever the execution policy is. It then opens the Script Manager.
if (-not $PSCommandPath) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    $startPath = Join-Path $InstallPath "Start.ps1"
    $bootstrapHeaders = @{ "User-Agent" = "PowerShell-Updater" }

    # The repository is private: the one-liner sets GITHUB_TOKEN, which is saved
    # (encrypted for this Windows user on this computer) so later runs can update.
    if ($env:GITHUB_TOKEN) {
        $bootstrapHeaders["Authorization"] = "Bearer $env:GITHUB_TOKEN"
        ConvertTo-SecureString -String $env:GITHUB_TOKEN -AsPlainText -Force |
            Export-Clixml -Path (Join-Path $InstallPath "github-token.xml")
    }

    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/$Owner/$Repository/$Branch/Start.ps1" -OutFile $startPath -UseBasicParsing -Headers $bootstrapHeaders
    Write-Host "Installed to $InstallPath"
    & (Get-Process -Id $PID).Path -NoProfile -ExecutionPolicy Bypass -File $startPath -Owner $Owner -Repository $Repository -Branch $Branch -Gui
    return
}

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-StrictMode -Version Latest

# The version is the git commit this folder was last updated to (kept out of the repository, see .gitignore).
$VersionPath = Join-Path $PSScriptRoot "installed-version.txt"
$InstalledCommit = ""
if (Test-Path $VersionPath) {
    $InstalledCommit = (Get-Content -Path $VersionPath -Raw).Trim()
}

$versionLabel = "unknown"
if ($InstalledCommit) {
    $versionLabel = $InstalledCommit.Substring(0, 7)
}

# A folder without the config has never been installed (e.g. Start.ps1 copied there by hand),
# so everything is downloaded first, even with -SkipUpdate.
$ConfigPath = Join-Path $PSScriptRoot "updater.config.json"
$FirstRun = -not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)
$ModuleListPath = Join-Path $PSScriptRoot "modules.local.json"

# onIT logo as pixels: T = teal, W = white, N = navy, . = background.
# Each console line shows two pixel rows using half-block characters.
$LogoPixels = @(
    '.......TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT.......',
    '.....TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTWWWWTTTT.....',
    '...TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTWWWWWWWWTTTT...',
    '..TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTWWWWWWWWWWWWTTT..',
    '..TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTWWWWWWWWWWWWWWTT..',
    '.TTTTTTTTTTTTWWWWWTTTTTWWWTWWWWWTTTTTTTTTTWWWWWWWWWWWWWWTTT.',
    '.TTTTTTTTTTWWWWWWWWWTTTWWWWWWWWWWTTTTTTTTWWNNNWNNNNNNNNNWTT.',
    'TTTTTTTTTTWWWWTTTWWWWTTWWWWWTTWWWWTTTTTTTWWNNNWNNNNNNNNNWTTT',
    'TTTTTTTTTTWWWTTTTTWWWTTWWWTTTTTWWWTTTTTTWWWNNNWWWWNNNWWWWWTT',
    'TTTTTTTTTTWWWTTTTTWWWTTWWWTTTTTWWWTTTTTTWWWNNNWWWWNNNWWWWWTT',
    'TTTTTTTTTTWWWTTTTTWWWTTWWWTTTTTWWWTTTTTTWWWNNNWWWWNNNWWWWWTT',
    'TTTTTTTTTTWWWTTTTTWWWTTWWWTTTTTWWWTTTTTTWWWNNNWWWWNNNWWWWWTT',
    'TTTTTTTTTTWWWWTTTWWWWTTWWWTTTTTWWWTTTTTTTWWNNNWWWWNNNWWWWTTT',
    '.TTTTTTTTTTWWWWWWWWWTTTWWWTTTTTWWWTTTTTTTWWNNNWWWWNNNWWWWTT.',
    '.TTTTTTTTTTTTWWWWWTTTTTWWWTTTTTWWWTTTTTTTTWWWWWWWWWWWWWWTTT.',
    '..TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTWWWWWWWWWWWWWWTT..',
    '..TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTWWWWWWWWWWWWTTT..',
    '...TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTWWWWWWWWTTTT...',
    '.....TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTWWWWTTTT.....',
    '.......TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT.......'
)

# Brand colours as "R;G;B" for 24-bit console colour codes.
$LogoColors = @{ T = "108;192;194"; W = "255;255;255"; N = "26;43;73" }

# The nearest of the 16 console colours, for consoles without 24-bit colour (e.g. PowerShell ISE).
$LogoConsoleColors = @{ T = "DarkCyan"; W = "White"; N = "DarkBlue" }

# Plain-text logo for output written to a file or a pipe.
$AsciiLogo = @(
    '    __________________________________________ ',
    '   /                         _____________    \',
    '  |      ___  _ __          /  ___ _____  \    |',
    '  |     / _ \| ''_ \        |  |_ _|_   _|  |   |',
    '  |    | (_) | | | |       |   | |  | |    |   |',
    '  |     \___/|_| |_|       |  |___| |_|    |   |',
    '   \                        \_____________/   / ',
    '    \________________________________________/  '
)

function Write-Logo {
    $console = -not [Console]::IsOutputRedirected

    if ($console -and $Host.UI.PSObject.Properties["SupportsVirtualTerminal"] -and $Host.UI.SupportsVirtualTerminal) {
        Write-PixelLogo
    }
    elseif ($console -or $Host.Name -eq "Windows PowerShell ISE Host") {
        # PowerShell ISE has no console, so it looks redirected.
        Write-PixelLogo -ConsoleColors
    }
    else {
        Write-AsciiLogo
    }
}

function Write-PixelLogo {
    param([switch]$ConsoleColors)

    # Characters are built at run time so this file stays plain ASCII for Windows PowerShell 5.1.
    $esc = [char]27
    $upperHalf = [string][char]0x2580
    $lowerHalf = [string][char]0x2584

    for ($y = 0; $y -lt $LogoPixels.Count; $y += 2) {
        $top = $LogoPixels[$y]
        $bottom = $LogoPixels[$y + 1]

        # Characters next to each other with the same colours are written together;
        # no colour leaves the console's own background.
        $segments = New-Object System.Collections.ArrayList
        for ($x = 0; $x -lt $top.Length; $x++) {
            $upper = [string]$top[$x]
            $lower = [string]$bottom[$x]

            if ($upper -eq "." -and $lower -eq ".") {
                $char = " "; $foreground = $null; $background = $null
            }
            elseif ($lower -eq ".") {
                $char = $upperHalf; $foreground = $upper; $background = $null
            }
            elseif ($upper -eq ".") {
                $char = $lowerHalf; $foreground = $lower; $background = $null
            }
            else {
                $char = $upperHalf; $foreground = $upper; $background = $lower
            }

            $last = $null
            if ($segments.Count -gt 0) {
                $last = $segments[$segments.Count - 1]
            }
            if ($last -and $last.Foreground -eq $foreground -and $last.Background -eq $background) {
                $last.Text += $char
            }
            else {
                [void]$segments.Add(@{ Text = $char; Foreground = $foreground; Background = $background })
            }
        }

        if ($ConsoleColors) {
            Write-Host "  " -NoNewline
            foreach ($segment in $segments) {
                $colors = @{}
                if ($segment.Foreground) { $colors["ForegroundColor"] = $LogoConsoleColors[$segment.Foreground] }
                if ($segment.Background) { $colors["BackgroundColor"] = $LogoConsoleColors[$segment.Background] }
                Write-Host $segment.Text -NoNewline @colors
            }
            Write-Host ""
        }
        else {
            $line = New-Object System.Text.StringBuilder
            [void]$line.Append("  ")
            foreach ($segment in $segments) {
                $code = "0"
                if ($segment.Foreground) { $code += ";38;2;$($LogoColors[$segment.Foreground])" }
                if ($segment.Background) { $code += ";48;2;$($LogoColors[$segment.Background])" }
                [void]$line.Append("$esc[$($code)m$($segment.Text)")
            }
            [void]$line.Append("$esc[0m")
            Write-Host $line.ToString()
        }
    }
}

function Write-AsciiLogo {
    for ($row = 0; $row -lt $AsciiLogo.Count; $row++) {
        $line = $AsciiLogo[$row].PadRight(48)

        if ($row -eq 0 -or $row -eq $AsciiLogo.Count - 1) {
            Write-Host $line -ForegroundColor DarkCyan
            continue
        }

        # Columns: pill | "on" | pill | circle | "IT" (circle edge on its first and last row) | circle | pill
        $itColor = "Blue"
        if ($row -eq 1 -or $row -eq $AsciiLogo.Count - 2) {
            $itColor = "White"
        }

        $parts = @(
            @(0, 7, "DarkCyan"), @(7, 13, "White"), @(20, 7, "DarkCyan"),
            @(27, 3, "White"), @(30, 11, $itColor), @(41, 3, "White"), @(44, 4, "DarkCyan")
        )
        foreach ($part in $parts) {
            Write-Host $line.Substring($part[0], $part[1]) -ForegroundColor $part[2] -NoNewline
        }
        Write-Host ""
    }
}

# Shown once per run; the restart after a self-update confirms it instead.
if ($UpdatesApplied -or $SelfUpdated) {
    Write-Host "Restarted with the new Start.ps1." -ForegroundColor Green
    Write-Host ""
}
elseif (-not $Quiet) {
    Write-Host ""
    # Skipped for -UpdateOnly, whose output the Script Manager shows as plain text.
    if (-not $UpdateOnly) {
        Write-Logo
        Write-Host ""
    }
    Write-Host "Welcome to MOSE (version $versionLabel), $env:USERNAME!" -ForegroundColor Cyan
    Write-Host "This keeps the MOSE report scripts up to date from GitHub and runs the report of the client configured on this computer."
    Write-Host ""
    Write-Host "  .\Start.ps1 -Configure   Enter or change the client, its servers and credentials" -ForegroundColor DarkGray
    Write-Host "  .\Start.ps1 -DryRun      Preview the report with sample data, without contacting any server" -ForegroundColor DarkGray
    Write-Host "  .\Start.ps1 -DebugLog    Run the report and log where each failed server stopped" -ForegroundColor DarkGray
    Write-Host "  .\Start.ps1 -Only veeam,sql  Run only the servers whose module or name contains these words:" -ForegroundColor DarkGray
    Write-Host "                           iLO, iDRAC, BMC, NAS, StorMagic, VMware, HyperV, Veeam, VeeamApi," -ForegroundColor DarkGray
    Write-Host "                           Commvault, CommvaultCloud, CommvaultOnPrem, SQL, or a server name (Tab completes)" -ForegroundColor DarkGray
    Write-Host "  .\Start.ps1 -Choose      Pick the servers of the report from a list" -ForegroundColor DarkGray
    Write-Host "  .\Start.ps1 -Keeper      Import or export Keeper entries over its API" -ForegroundColor DarkGray
    Write-Host "  .\Start.ps1 -Gui         Open the Script Manager to turn reports on/off and run them" -ForegroundColor DarkGray
    Write-Host "  .\Start.ps1 -UpdateOnly  Update without running anything" -ForegroundColor DarkGray
    Write-Host "  .\Start.ps1 -SkipUpdate  Run without checking GitHub" -ForegroundColor DarkGray
    Write-Host "  .\Start.ps1 -Version v1.0.0-rc.1  Update to a tag (or a branch or commit) instead of the latest" -ForegroundColor DarkGray
    Write-Host "  .\Start.ps1 -SaveToken   Replace the saved GitHub token" -ForegroundColor DarkGray
    Write-Host ""
    if ($FirstRun) {
        Write-Host "First run in this folder: downloading every script from GitHub..." -ForegroundColor DarkGray
    }
    elseif ($SkipUpdate) {
        Write-Host "Update check skipped." -ForegroundColor DarkGray
    }
    else {
        Write-Host "Checking GitHub for updates..." -ForegroundColor DarkGray
    }
    Write-Host ""
}

$ApiBase = "https://api.github.com/repos/$Owner/$Repository"
$Headers = @{ "User-Agent" = "PowerShell-Updater" }

# A private repository needs a GitHub token with read access to it: GITHUB_TOKEN, or the one
# saved by the one-liner, -GitHubToken or -SaveToken (kept out of the repository, see .gitignore).
# A public one needs none, so a first run only asks for it when GitHub refuses the files without it.
$TokenPath = Join-Path $PSScriptRoot "github-token.xml"
if ($GitHubToken) {
    ConvertTo-SecureString -String $GitHubToken -AsPlainText -Force |
        Export-Clixml -Path $TokenPath
    Write-Host "Saved the GitHub token to $TokenPath" -ForegroundColor Green
    # Not passed again when the script restarts after updating itself.
    [void]$PSBoundParameters.Remove("GitHubToken")
}
elseif (-not $SaveToken -and $FirstRun -and -not $env:GITHUB_TOKEN -and -not (Test-Path $TokenPath)) {
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/$Owner/$Repository/$Branch/updater.config.json" -Method Head -UseBasicParsing -Headers $Headers | Out-Null
    }
    catch {
        Write-Host "GitHub doesn't give the files without a token, so $Owner/$Repository is private. The token needs read access to it (see README.md)." -ForegroundColor Yellow
        $SaveToken = $true
    }
}
if ($SaveToken) {
    Read-Host -Prompt "GitHub token with read access to $Owner/$Repository" -AsSecureString |
        Export-Clixml -Path $TokenPath
    Write-Host "Saved the GitHub token to $TokenPath" -ForegroundColor Green
    # Not asked again when the script restarts after updating itself.
    [void]$PSBoundParameters.Remove("SaveToken")
}

$token = $env:GITHUB_TOKEN
if (-not $token -and (Test-Path $TokenPath)) {
    $token = [System.Net.NetworkCredential]::new("", (Import-Clixml -Path $TokenPath)).Password
}
if ($token) {
    $Headers["Authorization"] = "Bearer $token"
}

# A download error with its cause, e.g. "The underlying connection was closed: ... (An existing
# connection was forcibly closed by the remote host)", which tells a blocked network from a TLS problem.
function Get-WebErrorText {
    param(
        [System.Exception]$Exception
    )

    # Without its final period, which the messages around it add.
    $text = $Exception.Message.Trim().TrimEnd('.')
    $inner = $Exception
    while ($inner.InnerException) {
        $inner = $inner.InnerException
    }
    if ($inner -ne $Exception -and -not $text.Contains($inner.Message.Trim().TrimEnd('.'))) {
        $text += " ($($inner.Message.Trim().TrimEnd('.')))"
    }
    return $text
}

# The HTTP status GitHub answered with, or $null when it did not answer at all.
function Get-WebStatusCode {
    param(
        [System.Exception]$Exception
    )

    if ($Exception -is [System.Net.WebException] -and $Exception.Response) {
        return [int]$Exception.Response.StatusCode
    }
    return $null
}

# Git's hash of a local file, the same value GitHub lists for each file in the repository.
function Get-GitBlobHash {
    param(
        [string]$Path
    )

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $header = [System.Text.Encoding]::ASCII.GetBytes("blob $($bytes.Length)`0")
    $sha1 = [System.Security.Cryptography.SHA1]::Create()

    try {
        $sha1.TransformBlock($header, 0, $header.Length, $null, 0) | Out-Null
        $sha1.TransformFinalBlock($bytes, 0, $bytes.Length) | Out-Null
        return -join ($sha1.Hash | ForEach-Object { $_.ToString("x2") })
    }
    finally {
        $sha1.Dispose()
    }
}

# Downloads one file only when it is missing or differs from the repository;
# returns $true when the local copy changed.
function Update-RepoFile {
    param(
        [string]$Name
    )

    $repoPath = $Name -replace '\\', '/'
    $destination = Join-Path $PSScriptRoot $Name

    # With the API's file hashes, skip unchanged files without downloading them.
    if ($RemoteHashes) {
        if (-not $RemoteHashes.ContainsKey($repoPath)) {
            Write-Warning "$Name is not in the repository."
            return $false
        }

        if ((Test-Path $destination) -and (Get-GitBlobHash $destination) -eq $RemoteHashes[$repoPath]) {
            return $false
        }
    }

    $tempFile = [System.IO.Path]::GetTempFileName()

    try {
        # Download from the exact commit when known, so a just-pushed change is never served stale.
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/$Owner/$Repository/$DownloadRef/$repoPath" -OutFile $tempFile -UseBasicParsing -Headers $Headers

        # Without the API's hashes, compare the download with the local file instead.
        if (-not $RemoteHashes -and (Test-Path $destination) -and
            (Get-FileHash $tempFile).Hash -eq (Get-FileHash $destination).Hash) {
            return $false
        }

        $destinationFolder = Split-Path -Parent $destination
        if (-not (Test-Path $destinationFolder)) {
            New-Item -ItemType Directory -Path $destinationFolder -Force | Out-Null
        }

        Copy-Item -Path $tempFile -Destination $destination -Force
        Write-Host "Updated: $Name"
        return $true
    }
    finally {
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
    }
}

if (-not $UpdatesApplied -and ($FirstRun -or -not $SkipUpdate)) {
    $restart = $false

    try {
        # Ask GitHub for the latest commit and the hash of every file in it,
        # so only the files that changed are downloaded.
        try {
            $commit = Invoke-RestMethod -Uri "$ApiBase/commits/$Branch" -Headers $Headers
            $tree = Invoke-RestMethod -Uri "$ApiBase/git/trees/$($commit.sha)?recursive=1" -Headers $Headers
            $RemoteHashes = @{}
            $tree.tree | Where-Object { $_.type -eq "blob" } | ForEach-Object { $RemoteHashes[$_.path] = $_.sha }
            $DownloadRef = $commit.sha
        }
        catch {
            # The API allows 60 requests an hour per network without a token; plain file
            # downloads have no such limit, so compare the files directly instead.
            Write-Host "GitHub API unavailable ($(Get-WebErrorText $_.Exception)), comparing files directly." -ForegroundColor DarkGray
            $commit = $null
            $RemoteHashes = $null
            $DownloadRef = $Branch
        }

        # 1. Download every update first: this script, the config, then every file it lists.
        #    Named as in the repository, whose paths are case-sensitive (the file may be saved as start.ps1).
        $restart = -not $SelfUpdated -and (Update-RepoFile -Name "Start.ps1")
        $configChanged = Update-RepoFile -Name "updater.config.json"
        $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

        # Module scripts only for the client configured on this computer (listed by Configure.ps1
        # and Report.ps1), so a computer only has the modules it uses.
        $usedModules = @()
        if (Test-Path $ModuleListPath) {
            # Inner parentheses: Windows PowerShell returns a JSON array as one object.
            $usedModules = @((Get-Content -Path $ModuleListPath -Raw | ConvertFrom-Json))
        }
        $files = @($config.Files) + @($config.Modules | Where-Object { $usedModules -contains $_ })
        # The Keeper scripts only where Keeper is used: with -Keeper, and once they are here.
        if ($config.PSObject.Properties['Keeper']) {
            $files += @($config.Keeper | Where-Object { $Keeper -or (Test-Path -LiteralPath (Join-Path $PSScriptRoot $_) -PathType Leaf) })
        }
        $changed = @($files | Where-Object { Update-RepoFile -Name $_ })

        if (-not $restart -and -not $configChanged -and $changed.Count -eq 0) {
            Write-Host "Everything is up to date."
        }

        # The version comes from the API, so it is only known when the API answered.
        if ($commit) {
            $date = ([datetime]$commit.commit.committer.date).ToLocalTime().ToString("yyyy-MM-dd HH:mm")
            $message = ($commit.commit.message -split "`n")[0]
            $versionText = "version $($commit.sha.Substring(0, 7)) ($date): $message"

            if ($commit.sha -ne $InstalledCommit) {
                Set-Content -Path $VersionPath -Value $commit.sha -Encoding ascii
                Write-Host "Updated to $versionText" -ForegroundColor Green
            }
            else {
                Write-Host "Running $versionText" -ForegroundColor DarkGray
            }
        }
        Write-Host ""
    }
    catch {
        # Without the config there is no local version to fall back on.
        if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
            throw "Could not download the scripts from GitHub: $(Get-WebErrorText $_.Exception). Check that this computer can reach GitHub and the GitHub token (replace it with: .\Start.ps1 -SaveToken), then run Start.ps1 again."
        }
        $statusCode = Get-WebStatusCode $_.Exception
        if ($null -eq $statusCode -and $_.Exception -is [System.Net.WebException]) {
            # No answer at all: a network without GitHub access (firewall, proxy), or TLS refused.
            Write-Warning "GitHub can't be reached from this computer, so the local version ($versionLabel) runs: $(Get-WebErrorText $_.Exception). TLS protocols: $([Net.ServicePointManager]::SecurityProtocol). To skip this check: .\Start.ps1 -SkipUpdate"
        }
        else {
            Write-Warning "Update check failed, running the local version: $(Get-WebErrorText $_.Exception)."
            # GitHub answers 404 for a private repository asked without a token.
            if (-not $token -and $statusCode -in 401, 403, 404) {
                Write-Warning "No GitHub token is saved on this computer. Save one with: .\Start.ps1 -SaveToken"
            }
        }
    }

    # 2. If this script changed, restart so the new version runs the scripts.
    #    The other scripts are read from disk when they run, so they need no restart.
    if ($restart) {
        Write-Host "Start.ps1 was updated, restarting with the new version..." -ForegroundColor Green
        & $PSCommandPath @PSBoundParameters -UpdatesApplied
        return
    }
}

if ($UpdateOnly) {
    return
}

if ($Configure) {
    & (Join-Path $PSScriptRoot "Configure.ps1")
    return
}

if ($Keeper) {
    & (Join-Path $PSScriptRoot "Keeper.ps1")
    return
}

# A partial report: only some servers (-Only, -Choose).
$reportParameters = @{}
if ($Only) {
    $reportParameters.Only = $Only
}
if ($Choose) {
    $reportParameters.Choose = $true
}

if ($DryRun) {
    & (Join-Path $PSScriptRoot "Report.ps1") -DryRun @reportParameters | Out-Null
    return
}

if ($DebugLog) {
    & (Join-Path $PSScriptRoot "Report.ps1") -DebugLog @reportParameters | Out-Null
    return
}

if ($Gui) {
    & (Join-Path $PSScriptRoot "Manager.ps1")
    return
}

if ($reportParameters.Count -gt 0) {
    & (Join-Path $PSScriptRoot "Report.ps1") @reportParameters
    return
}

# 3. Run every script in the config unless it was turned off on this computer in Manager.ps1.
Write-Host "Running scripts..." -ForegroundColor DarkGray
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Required file not found: '$ConfigPath'. Run .\Start.ps1 again to download it."
}
$config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
$statePath = Join-Path $PSScriptRoot "scripts.local.json"
$turnedOff = @()
if (Test-Path $statePath) {
    $turnedOff = @((Get-Content -Path $statePath -Raw | ConvertFrom-Json).PSObject.Properties |
        Where-Object { -not $_.Value } |
        ForEach-Object { $_.Name })
}

foreach ($name in $config.Scripts) {
    if ($turnedOff -contains $name) {
        Write-Host "Skipped (turned off): $name"
        continue
    }

    try {
        & (Join-Path $PSScriptRoot $name)
    }
    catch {
        Write-Warning "$name failed: $($_.Exception.Message)"
    }
}
