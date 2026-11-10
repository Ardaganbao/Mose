<#
.SYNOPSIS
  Aggressively switch a Windows client to ONLINE updates (Microsoft/Windows Update),
  reset WU components, force scan, download, install, and log results.

.PARAMETER IncludeMicrosoftUpdate
  Also register the Microsoft Update service (for Office/other MS products). Default: $true.

.PARAMETER ResetProxy
  Resets WinHTTP proxy to direct. Useful when a stale proxy breaks updates.

.PARAMETER DeepReset
  Stops services and resets SoftwareDistribution and catroot2 (safe but disruptive). Default: $true.

.PARAMETER ForceReboot
  If updates require a reboot, forcibly restarts the machine with a short countdown.

.NOTES
  - Run as Administrator.
  - Tested on Windows 10/11 and Server 2016+.
  - This intentionally disables WSUS client settings on the local machine (registry policy).
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [bool]$IncludeMicrosoftUpdate = $true,
    [bool]$ResetProxy = $false,
    [bool]$DeepReset = $true,
    [bool]$ForceReboot = $false
)

# ----------------- Helpers -----------------
function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "Run this script from an elevated PowerShell session (Run as Administrator)." }
}
function Write-Stage($msg){ Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Gray }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Ok($msg)   { Write-Host "[✓] $msg" -ForegroundColor Green }
function Write-Err($msg)  { Write-Host "[✗] $msg" -ForegroundColor Red }

$ErrorActionPreference = 'Stop'
Assert-Admin

# Log folder + transcript
$logRoot = Join-Path $env:ProgramData "WU-Force-Online"
if (-not (Test-Path $logRoot)) { New-Item -ItemType Directory -Path $logRoot | Out-Null }
$logFile = Join-Path $logRoot ("WU-Force-Online_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $logFile | Out-Null

try {
    # ----------------- Stop services (if deep reset) -----------------
    if ($DeepReset) {
        Write-Stage "Stopping update-related services"
        $services = @('wuauserv','bits','cryptsvc','trustedinstaller')
        foreach ($svc in $services) {
            try {
                $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
                if ($s -and $s.Status -ne 'Stopped') {
                    Write-Info "Stopping service: $svc"
                    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                    $s.WaitForStatus('Stopped','00:00:25')
                }
            } catch { Write-Warn "Could not stop $($svc): $($_.Exception.Message)" }
        }
    }

    # ----------------- Optional proxy reset -----------------
    if ($ResetProxy) {
        Write-Stage "Resetting WinHTTP proxy to direct"
        & netsh winhttp reset proxy | Out-Null
    }

    # ----------------- Remove/disable WSUS policy -----------------
    Write-Stage "Removing WSUS policy (switching to ONLINE updates)"
    $polRoot = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $auKey   = Join-Path $polRoot "AU"

    # Set UseWUServer=0 and remove WSUS server URLs if present
    if (Test-Path $auKey) {
        New-ItemProperty -Path $auKey -Name UseWUServer -PropertyType DWord -Value 0 -Force | Out-Null
    } else {
        New-Item -Path $auKey -Force | Out-Null
        New-ItemProperty -Path $auKey -Name UseWUServer -PropertyType DWord -Value 0 -Force | Out-Null
    }

    foreach ($name in @('WUServer','WUStatusServer','TargetGroup','TargetGroupEnabled')) {
        if (Get-ItemProperty -Path $polRoot -Name $name -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $polRoot -Name $name -ErrorAction SilentlyContinue
        }
    }

    # ----------------- Deep component reset (optional) -----------------
    if ($DeepReset) {
        Write-Stage "Resetting SoftwareDistribution and catroot2"
        $sd = Join-Path $env:windir "SoftwareDistribution"
        $cr = Join-Path $env:windir "System32\catroot2"

        foreach ($path in @($sd,$cr)) {
            if (Test-Path $path) {
                $bak = "$path.bak_{0:yyyyMMdd_HHmmss}" -f (Get-Date)
                Write-Info "Resetting $path -> $bak"
                try   { Rename-Item -Path $path -NewName $bak -ErrorAction SilentlyContinue }
                catch {
                    Write-Warn "Rename failed, attempting delete of contents"
                    Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    # ----------------- Start services -----------------
    Write-Stage "Starting services"
    foreach ($svc in @('cryptsvc','bits','wuauserv','trustedinstaller')) {
        try {
            Write-Info "Starting service: $svc"
            Start-Service -Name $svc -ErrorAction SilentlyContinue
            (Get-Service $svc).WaitForStatus('Running','00:00:25')
        } catch { Write-Warn "Could not start $($svc): $($_.Exception.Message)" }
    }

    # ----------------- Register Microsoft Update (optional) -----------------
    if ($IncludeMicrosoftUpdate) {
        Write-Stage "Ensuring Microsoft Update service is registered"
        try {
            $svcManager = New-Object -ComObject Microsoft.Update.ServiceManager
            # 7 = AlwaysRegisterService, registers "Microsoft Update" if missing
            $null = $svcManager.AddService2('7971f918-a847-4430-9279-4a52d1efe18d', 7, '')
            Write-Ok "Microsoft Update service registered (Office/other MS products included)."
        } catch {
            Write-Warn "Failed to register Microsoft Update service: $($_.Exception.Message)"
        }
    } else {
        Write-Info "Using Windows Update only (no Microsoft Update catalog)."
    }

    # ----------------- Trigger scans via tasks/clients -----------------
    Write-Stage "Triggering detection via scheduled tasks / clients"
    $tasks = @(
        "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
        "\Microsoft\Windows\WindowsUpdate\Scheduled Start",
        "\Microsoft\Windows\WindowsUpdate\Automatic App Update"
    )
    foreach ($t in $tasks) {
        try { schtasks /Run /TN $t | Out-Null; Write-Info "Scheduled task queued: $t" }
        catch { Write-Warn "Scheduled task $t not found or failed." }
    }

    $uso = Join-Path $env:SystemRoot "System32\UsoClient.exe"
    if (Test-Path $uso) {
        foreach ($arg in @('StartScan','StartDownload','StartInstall')) {
            try {
                Write-Info "UsoClient $arg"
                Start-Process -FilePath $uso -ArgumentList $arg -WindowStyle Hidden -ErrorAction SilentlyContinue
            } catch { Write-Warn "UsoClient $arg failed: $($_.Exception.Message)" }
        }
    }

    # ----------------- COM-based search, download, install -----------------
    Write-Stage "Searching, downloading, and installing updates (ONLINE)"
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    # By default, with WSUS disabled, this targets Windows/Microsoft Update online
    $criteria = "IsInstalled=0 and IsHidden=0"
    Write-Info "Searching for updates: $criteria"
    $searchRes = $searcher.Search($criteria)

    if ($searchRes.Updates.Count -eq 0) {
        Write-Ok "No updates found."
    } else {
        Write-Info ("Found {0} update(s)." -f $searchRes.Updates.Count)

        # Download
        $toDownload = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $searchRes.Updates) { if (-not $u.IsDownloaded) { [void]$toDownload.Add($u) } }

        if ($toDownload.Count -gt 0) {
            Write-Info ("Downloading {0} update(s)..." -f $toDownload.Count)
            $downloader = $session.CreateUpdateDownloader()
            $downloader.Updates = $toDownload
            $dlResult = $downloader.Download()
            Write-Info ("Download Result: {0}" -f $dlResult.ResultCode)
        } else {
            Write-Info "All updates already downloaded."
        }

        # Install
        $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $searchRes.Updates) { if (-not $u.IsInstalled) { [void]$toInstall.Add($u) } }
        if ($toInstall.Count -gt 0) {
            Write-Info ("Installing {0} update(s)..." -f $toInstall.Count)
            $installer = $session.CreateUpdateInstaller()
            $installer.ForceQuiet = $true
            $installer.Updates = $toInstall
            $instResult = $installer.Install()
            Write-Info ("Install Result: {0}" -f $instResult.ResultCode)
            if ($instResult.RebootRequired) { Write-Warn "Reboot is required." } else { Write-Ok "No reboot required." }
        } else {
            Write-Ok "Nothing to install."
        }
    }

    # ----------------- Finalization & optional reboot -----------------
    Write-Stage "Final status"
    try {
        $wuLog = Join-Path $logRoot ("WindowsUpdate_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
        Get-WindowsUpdateLog -LogPath $wuLog -ErrorAction SilentlyContinue | Out-Null
        Write-Info "WindowsUpdate.log generated: $wuLog"
    } catch { Write-Warn "Could not generate WindowsUpdate.log (Get-WindowsUpdateLog not available/failed)." }

    $rebootRequired = $false
    $pending1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    $pending2 = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    if (Test-Path $pending1) { $rebootRequired = $true }
    try {
        $pfr = (Get-ItemProperty -Path $pending2 -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
        if ($pfr) { $rebootRequired = $true }
    } catch {}

    if ($rebootRequired -and $ForceReboot) {
        Write-Warn "Rebooting in 60 seconds to complete update installation..."
        shutdown.exe /r /t 60 /c "Updates installed—system will reboot to complete installation." /f
    } elseif ($rebootRequired) {
        Write-Warn "A reboot is required to complete installation. Reboot when ready."
    } else {
        Write-Ok "No reboot pending."
    }

    Write-Ok "Completed. Log: $logFile"
}
catch {
    Write-Err "Failed: $($_.Exception.Message)"
    throw
}
finally {
    Stop-Transcript | Out-Null
}