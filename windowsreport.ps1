[CmdletBinding()]
param(
    # Windows computer to report on: IP address or host name. 'localhost' / '.' reads this computer.
    [Parameter(Mandatory)]
    [string]$Server,

    # Account for PowerShell remoting (WinRM); the current Windows user when not given.
    [pscredential]$Credential,

    [string]$Site = 'main'
)

# Windows system report, read from inside Windows over PowerShell remoting (WinRM 5985), like the
# Hyper-V module: operating system and build, update status (last installed KB and the updates still
# pending), disks, antivirus and firewall, last logons and local administrators, and a short list of
# installed software. Only reads; the login needs no special rights beyond what these queries use.
# A server that cannot be reached does not stop the report - the engine prints "Collection failed".

$ErrorActionPreference = 'Stop'

# Runs on the target (locally or over remoting) and returns plain values only, so they come back
# over the session. Self-contained: it must not use anything from this script's scope.
$collect = {
    param([int]$SoftwareLimit, [int]$RecentUpdateDays)

    function ConvertTo-PlainDate {
        param($Value)
        if (-not $Value) { return $null }
        try { return ([datetime]$Value).ToString('o') } catch { return $null }
    }

    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue

    # Windows 11 Pro 24H2 (26100.4349): the release (DisplayVersion / ReleaseId) and the build with
    # its patch level (UBR), read from the registry like the Hyper-V module does.
    $currentVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $release = "$($currentVersion.DisplayVersion)"
    if (-not $release) { $release = "$($currentVersion.ReleaseId)" }
    $build = "$($os.BuildNumber)"
    if ($currentVersion.UBR) { $build += ".$($currentVersion.UBR)" }

    # Updates: the last installed hotfix and how many went in over the recent window. Get-HotFix only
    # lists servicing-stack / cumulative style updates, but its newest row is the usual "patched up to"
    # date; InstalledOn is sometimes empty on old builds, so those rows are ignored for the date.
    $hotfixes = @()
    try { $hotfixes = @(Get-HotFix -ErrorAction Stop) } catch { $hotfixes = @() }
    $dated = @($hotfixes | Where-Object { $_.InstalledOn } | Sort-Object -Property InstalledOn)
    $lastHotfix = if ($dated.Count) { $dated[-1] } else { $null }
    $recentCutoff = (Get-Date).AddDays(-$RecentUpdateDays)
    $recentCount = @($dated | Where-Object { $_.InstalledOn -ge $recentCutoff }).Count

    # Updates still pending, from the Windows Update agent (needs the box to reach WSUS / Microsoft
    # Update). Best-effort: offline or locked-down servers just report "could not be read".
    $pendingUpdates = @()
    $pendingError = $null
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result = $searcher.Search('IsInstalled=0 and IsHidden=0')
        foreach ($u in $result.Updates) {
            $kb = @($u.KBArticleIDs | ForEach-Object { "KB$_" }) -join ', '
            $pendingUpdates += [pscustomobject]@{
                Title = "$($u.Title)"
                KB = $kb
                Severity = "$($u.MsrcSeverity)"
            }
        }
    }
    catch { $pendingError = "$($_.Exception.Message)" }

    # Pending reboot: the usual three signals.
    $pendingReboot = $false
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pendingReboot = $true }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pendingReboot = $true }
    try {
        $pfr = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations
        if ($pfr) { $pendingReboot = $true }
    }
    catch {}

    # Disks: fixed logical volumes (DriveType 3).
    $disks = foreach ($d in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | Sort-Object -Property DeviceID)) {
        [pscustomobject]@{
            Drive = "$($d.DeviceID)"
            Label = "$($d.VolumeName)"
            SizeBytes = [long]$d.Size
            FreeBytes = [long]$d.FreeSpace
        }
    }

    # Antivirus: Microsoft Defender through its own cmdlet, plus any product registered in the
    # Security Center (desktop Windows only; Server has no SecurityCenter2 namespace).
    $defender = $null
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $defender = [pscustomobject]@{
            AmEnabled = [bool]$mp.AMServiceEnabled
            RealTime = [bool]$mp.RealTimeProtectionEnabled
            SignatureAge = [int]$mp.AntivirusSignatureAge
            SignatureUpdated = ConvertTo-PlainDate $mp.AntivirusSignatureLastUpdated
            LastQuickScan = ConvertTo-PlainDate $mp.QuickScanEndTime
            LastFullScan = ConvertTo-PlainDate $mp.FullScanEndTime
        }
    }
    catch { $defender = $null }

    $avProducts = @()
    try {
        foreach ($p in @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)) {
            # productState is a bitmask: bit 0x1000 of the high byte = enabled, 0x10 of the low byte = up to date.
            $state = [int]$p.productState
            $enabled = (($state -band 0x1000) -ne 0)
            $upToDate = (($state -band 0x10) -eq 0)
            $avProducts += [pscustomobject]@{ Name = "$($p.displayName)"; Enabled = $enabled; UpToDate = $upToDate }
        }
    }
    catch { $avProducts = @() }

    # Firewall: the three profiles, from the NetSecurity module when present, else netsh.
    $firewall = @()
    try {
        foreach ($fp in @(Get-NetFirewallProfile -ErrorAction Stop)) {
            $firewall += [pscustomobject]@{ Profile = "$($fp.Name)"; Enabled = [bool]$fp.Enabled }
        }
    }
    catch {
        try {
            foreach ($line in @(netsh advfirewall show allprofiles state)) {
                if ($line -match '^(\w+) Profile Settings') { $prof = $Matches[1] }
                elseif ($line -match '^State\s+(ON|OFF)') { $firewall += [pscustomobject]@{ Profile = $prof; Enabled = ($Matches[1] -eq 'ON') } }
            }
        }
        catch { $firewall = @() }
    }

    # Last logons: the most recent per local account (Win32_NetworkLoginProfile).
    $logons = @()
    try {
        foreach ($lp in @(Get-CimInstance -ClassName Win32_NetworkLoginProfile -ErrorAction Stop | Where-Object { $_.LastLogon })) {
            $logons += [pscustomobject]@{ Name = "$($lp.Name)"; LastLogon = ConvertTo-PlainDate $lp.LastLogon }
        }
    }
    catch { $logons = @() }

    # Local administrators.
    $admins = @()
    try {
        $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { "$($_.Name)" })
    }
    catch {
        try {
            $raw = @(net localgroup administrators)
            $start = [array]::IndexOf($raw, ($raw | Where-Object { $_ -match '^-{3,}' } | Select-Object -First 1))
            if ($start -ge 0) {
                $admins = @($raw[($start + 1)..($raw.Count - 1)] | Where-Object { $_ -and $_ -notmatch 'command completed' })
            }
        }
        catch { $admins = @() }
    }

    # Installed software from the uninstall registry keys (not Win32_Product, which is slow and can
    # trigger a repair). Deduplicated by name, newest few first by install date when known.
    $software = @()
    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $seen = @{}
    foreach ($entry in @(Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue)) {
        $name = "$($entry.DisplayName)"
        if (-not $name -or $entry.SystemComponent -eq 1 -or $seen.ContainsKey($name)) { continue }
        $seen[$name] = $true
        $software += [pscustomobject]@{
            Name = $name
            Version = "$($entry.DisplayVersion)"
            Publisher = "$($entry.Publisher)"
            InstallDate = "$($entry.InstallDate)"
        }
    }
    $software = @($software | Sort-Object -Property @{ Expression = 'InstallDate'; Descending = $true }, Name)
    $softwareTotal = $software.Count
    if ($SoftwareLimit -gt 0 -and $software.Count -gt $SoftwareLimit) { $software = @($software[0..($SoftwareLimit - 1)]) }

    [pscustomobject]@{
        Hostname = "$($computer.Name)"
        Domain = "$($computer.Domain)"
        Manufacturer = "$($computer.Manufacturer)"
        Model = "$($computer.Model)"
        Serial = "$($bios.SerialNumber)"
        MemoryBytes = [long]$computer.TotalPhysicalMemory
        OsCaption = "$($os.Caption)"
        OsVersion = "$($os.Version)"
        Release = $release
        Build = $build
        InstallDate = ConvertTo-PlainDate $os.InstallDate
        LastBoot = ConvertTo-PlainDate $os.LastBootUpTime
        LastHotfixId = if ($lastHotfix) { "$($lastHotfix.HotFixID)" } else { '' }
        LastHotfixDate = if ($lastHotfix) { ConvertTo-PlainDate $lastHotfix.InstalledOn } else { $null }
        RecentUpdateCount = $recentCount
        RecentUpdateDays = $RecentUpdateDays
        HotfixTotal = $hotfixes.Count
        PendingUpdates = @($pendingUpdates)
        PendingUpdateError = $pendingError
        PendingReboot = $pendingReboot
        Disks = @($disks)
        Defender = $defender
        AvProducts = @($avProducts)
        Firewall = @($firewall)
        Logons = @($logons)
        Admins = @($admins)
        Software = @($software)
        SoftwareTotal = $softwareTotal
    }
}

# --- The script: connect (locally or over remoting), then build the Markdown from the data. ---

$softwareLimit = 15
$recentUpdateDays = 30
$isLocal = $Server -in @('localhost', '.', '127.0.0.1', $env:COMPUTERNAME)

Write-Progress -Activity "Windows system: $Server" -Status 'Reading the system' -PercentComplete 20
try {
    if ($isLocal) {
        $data = & $collect $softwareLimit $recentUpdateDays
    }
    else {
        $invokeParameters = @{ ComputerName = $Server; ScriptBlock = $collect; ArgumentList = @($softwareLimit, $recentUpdateDays); ErrorAction = 'Stop' }
        if ($Credential) { $invokeParameters.Credential = $Credential }
        $data = Invoke-Command @invokeParameters
    }
}
catch {
    throw "The Windows computer $Server could not be read over PowerShell remoting (WinRM): $($_.Exception.Message). The host must have remoting enabled (Enable-PSRemoting), and an IP or a non-domain host must be in this computer's TrustedHosts with a login given."
}
Write-Progress -Activity "Windows system: $Server" -Completed

# --- Markdown helpers ---

function Format-Gb {
    param([long]$Bytes)
    if ($Bytes -le 0) { return '0' }
    return ('{0:n0}' -f ($Bytes / 1GB))
}

function Get-DiskPill {
    param([int]$UsedPercent)
    if ($UsedPercent -ge 90) { return ':red_circle:' }
    if ($UsedPercent -ge 75) { return ':yellow_circle:' }
    return ':green_circle:'
}

function Format-LocalDate {
    param($Iso, [string]$Format = 'yyyy-MM-dd')
    if (-not $Iso) { return '-' }
    try { return ([datetime]$Iso).ToString($Format) } catch { return '-' }
}

$lines = New-Object System.Collections.Generic.List[string]

# System
$lines.Add("## System")
$lines.Add("")
$lines.Add("| Field | Value |")
$lines.Add("|---|---|")
$lines.Add("| Host name | $($data.Hostname) |")
if ($data.Domain) { $lines.Add("| Domain / workgroup | $($data.Domain) |") }
$osLine = $data.OsCaption
if ($data.Release) { $osLine += " ($($data.Release))" }
$lines.Add("| Operating system | $osLine |")
$lines.Add("| Build | $($data.Build) |")
$lines.Add("| Installed on | $(Format-LocalDate $data.InstallDate) |")
$uptime = '-'
if ($data.LastBoot) {
    try { $uptime = '{0:n0} day(s), since {1}' -f ((Get-Date) - [datetime]$data.LastBoot).TotalDays, (Format-LocalDate $data.LastBoot 'yyyy-MM-dd HH:mm') } catch {}
}
$lines.Add("| Uptime | $uptime |")
if ($data.Manufacturer -or $data.Model) { $lines.Add("| Machine | $($data.Manufacturer) $($data.Model) |") }
if ($data.Serial) { $lines.Add("| Serial number | $($data.Serial) |") }
if ($data.MemoryBytes -gt 0) { $lines.Add("| Memory | $(Format-Gb $data.MemoryBytes) GB |") }
$lines.Add("")

# Updates
$lines.Add("## Updates")
$lines.Add("")
$lastKb = if ($data.LastHotfixId) { "$($data.LastHotfixId) ($(Format-LocalDate $data.LastHotfixDate))" } else { 'none recorded' }
$lines.Add("- **Last update installed:** $lastKb")
$lines.Add("- **Installed in the last $($data.RecentUpdateDays) days:** $($data.RecentUpdateCount)")
$rebootPill = if ($data.PendingReboot) { ':yellow_circle: yes' } else { ':green_circle: no' }
$lines.Add("- **Reboot pending:** $rebootPill")
if ($null -ne $data.PendingUpdateError) {
    $lines.Add("- **Pending updates:** could not be read ($($data.PendingUpdateError))")
}
elseif (@($data.PendingUpdates).Count -eq 0) {
    $lines.Add("- **Pending updates:** :green_circle: none")
}
else {
    $lines.Add("- **Pending updates:** :yellow_circle: $(@($data.PendingUpdates).Count)")
    $lines.Add("")
    $lines.Add("| Update | KB | Severity |")
    $lines.Add("|---|---|---|")
    foreach ($u in @($data.PendingUpdates)) {
        $sev = if ($u.Severity) { $u.Severity } else { '-' }
        $kb = if ($u.KB) { $u.KB } else { '-' }
        $lines.Add("| $($u.Title) | $kb | $sev |")
    }
}
$lines.Add("")

# Disks
$lines.Add("## Disks")
$lines.Add("")
if (@($data.Disks).Count -eq 0) {
    $lines.Add("No fixed disk reported.")
}
else {
    $lines.Add("| Drive | Label | Size (GB) | Free (GB) | Used % |  |")
    $lines.Add("|---|---|---:|---:|---:|---|")
    foreach ($d in @($data.Disks)) {
        $usedPct = if ($d.SizeBytes -gt 0) { [int][math]::Round((($d.SizeBytes - $d.FreeBytes) / $d.SizeBytes) * 100) } else { 0 }
        $lines.Add("| $($d.Drive) | $($d.Label) | $(Format-Gb $d.SizeBytes) | $(Format-Gb $d.FreeBytes) | $usedPct | $(Get-DiskPill $usedPct) |")
    }
}
$lines.Add("")

# Security: antivirus and firewall
$lines.Add("## Security")
$lines.Add("")
if ($data.Defender) {
    $def = $data.Defender
    if (-not $def.AmEnabled) { $avPill = ':red_circle: disabled' }
    elseif (-not $def.RealTime -or $def.SignatureAge -gt 7) { $avPill = ':yellow_circle:' }
    else { $avPill = ':green_circle:' }
    $rt = if ($def.RealTime) { 'on' } else { 'off' }
    $lines.Add("- **Antivirus (Microsoft Defender):** $avPill real-time $rt, signatures $($def.SignatureAge) day(s) old (updated $(Format-LocalDate $def.SignatureUpdated)), last quick scan $(Format-LocalDate $def.LastQuickScan)")
}
foreach ($p in @($data.AvProducts)) {
    if ($data.Defender -and $p.Name -match 'Defender') { continue }
    $pill = if (-not $p.Enabled) { ':red_circle: disabled' } elseif (-not $p.UpToDate) { ':yellow_circle: out of date' } else { ':green_circle: enabled, up to date' }
    $lines.Add("- **Antivirus ($($p.Name)):** $pill")
}
if (-not $data.Defender -and @($data.AvProducts).Count -eq 0) {
    $lines.Add("- **Antivirus:** :yellow_circle: none detected")
}
if (@($data.Firewall).Count -gt 0) {
    $on = @($data.Firewall | Where-Object { $_.Enabled })
    $fwPill = if ($on.Count -eq @($data.Firewall).Count) { ':green_circle:' } elseif ($on.Count -eq 0) { ':red_circle:' } else { ':yellow_circle:' }
    $profiles = @($data.Firewall | ForEach-Object { "$($_.Profile) $(if ($_.Enabled) { 'on' } else { 'off' })" }) -join ', '
    $lines.Add("- **Firewall:** $fwPill $profiles")
}
else {
    $lines.Add("- **Firewall:** could not be read")
}
$lines.Add("")

# Access: last logons and local administrators
$lines.Add("## Access")
$lines.Add("")
$admins = @($data.Admins)
$lines.Add("- **Local administrators:** $(if ($admins.Count) { $admins -join ', ' } else { 'could not be read' })")
$recentLogons = @($data.Logons | Sort-Object -Property @{ Expression = { try { [datetime]$_.LastLogon } catch { [datetime]::MinValue } }; Descending = $true } | Select-Object -First 5)
if ($recentLogons.Count) {
    $lines.Add("")
    $lines.Add("| Account | Last logon |")
    $lines.Add("|---|---|")
    foreach ($l in $recentLogons) { $lines.Add("| $($l.Name) | $(Format-LocalDate $l.LastLogon 'yyyy-MM-dd HH:mm') |") }
}
$lines.Add("")

# Installed software
$lines.Add("## Installed software")
$lines.Add("")
$software = @($data.Software)
if ($software.Count -eq 0) {
    $lines.Add("No installed software reported.")
}
else {
    $shownNote = if ($data.SoftwareTotal -gt $software.Count) { " (most recent $($software.Count) of $($data.SoftwareTotal))" } else { " ($($data.SoftwareTotal))" }
    $lines.Add("Installed programs$($shownNote):")
    $lines.Add("")
    $lines.Add("| Name | Version | Publisher |")
    $lines.Add("|---|---|---|")
    foreach ($s in $software) { $lines.Add("| $($s.Name) | $(if ($s.Version) { $s.Version } else { '-' }) | $(if ($s.Publisher) { $s.Publisher } else { '-' }) |") }
}
$lines.Add("")

# Emit the real status emoji (🟢🟠🔴) rather than the :green_circle: shortcodes, which this client's
# WordPress does not render. Built from code points so the source file stays plain ASCII.
$pillGreen = [char]::ConvertFromUtf32(0x1F7E2)
$pillYellow = [char]::ConvertFromUtf32(0x1F7E0)
$pillRed = [char]::ConvertFromUtf32(0x1F534)
($lines -join "`n") -replace ':green_circle:', $pillGreen -replace ':yellow_circle:', $pillYellow -replace ':red_circle:', $pillRed
