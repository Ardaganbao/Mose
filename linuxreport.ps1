[CmdletBinding()]
param(
    # Linux host to report on: IP address or host name, reached over SSH (TCP 22).
    [Parameter(Mandatory)]
    [string]$Server,

    # SSH login. The user name is always used; the password is used for password authentication.
    [Parameter(Mandatory)]
    [pscredential]$Credential,

    # Optional path to an SSH private key file, for key authentication instead of (or beside) the password.
    [string]$KeyFile,

    # TCP port of the SSH service.
    [int]$Port = 22,

    [string]$Site = 'main'
)

# Linux system report, read from inside the host over SSH with the Posh-SSH module: distribution and
# kernel, update status (pending updates, last update, reboot required), disks, firewall and other
# security services, last logins and sudoers, and a short list of installed packages. Read-only
# commands only. Some details need root or passwordless sudo; without it they show "permission
# denied / n/a" instead of stopping the report.

$ErrorActionPreference = 'Stop'

# How many packages to list, and over how many days "recent" updates are counted.
$softwareLimit = 15

# Make sure Posh-SSH is available, installing it for the current user like PowerCLI is installed.
$helper = Join-Path $PSScriptRoot 'helper.ps1'
if (Test-Path -LiteralPath $helper -PathType Leaf) {
    try { . $helper } catch { Write-Verbose "helper.ps1 could not be dot-sourced: $($_.Exception.Message)" }
}
if (Get-Command -Name Ensure-Module -ErrorAction SilentlyContinue) {
    Ensure-Module -Name 'Posh-SSH' -MinimumVersion '3.0.0'
}
elseif (-not (Get-Module -ListAvailable -Name 'Posh-SSH')) {
    Install-Module -Name 'Posh-SSH' -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
}
Import-Module Posh-SSH -ErrorAction Stop

# The remote script: one round-trip. Each topic is printed under a @@MARKER line, parsed back here.
# POSIX sh; every tool is probed with 'command -v' so a missing one degrades to "n/a" not an error.
$remoteScript = @'
echo "@@HOSTNAME"; hostname 2>/dev/null
echo "@@OS"; cat /etc/os-release 2>/dev/null
echo "@@KERNEL"; uname -r 2>/dev/null
echo "@@UPTIME"; cat /proc/uptime 2>/dev/null
echo "@@BOOT"; (who -b 2>/dev/null | sed 's/.*boot *//') || true
echo "@@DF"; df -PT 2>/dev/null
echo "@@UPDATES"
if command -v apt-get >/dev/null 2>&1; then
  echo "pm=apt"
  echo "count=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')"
  if [ -f /var/lib/apt/periodic/update-success-stamp ]; then echo "last=$(date -r /var/lib/apt/periodic/update-success-stamp '+%Y-%m-%d %H:%M' 2>/dev/null)"; fi
  if [ -f /var/run/reboot-required ]; then echo "reboot=yes"; else echo "reboot=no"; fi
elif command -v dnf >/dev/null 2>&1; then
  echo "pm=dnf"
  echo "count=$(dnf -q check-update 2>/dev/null | grep -vE '^$|^Last metadata|^Obsoleting|^Security:' | grep -cE '^[A-Za-z0-9]')"
  echo "last=$(rpm -qa --last 2>/dev/null | head -1 | sed 's/^[^ ]*  *//')"
  if command -v needs-restarting >/dev/null 2>&1; then needs-restarting -r >/dev/null 2>&1 && echo "reboot=no" || echo "reboot=yes"; fi
elif command -v yum >/dev/null 2>&1; then
  echo "pm=yum"
  echo "count=$(yum -q check-update 2>/dev/null | grep -vE '^$|^Last metadata|^Obsoleting' | grep -cE '^[A-Za-z0-9]')"
  echo "last=$(rpm -qa --last 2>/dev/null | head -1 | sed 's/^[^ ]*  *//')"
else
  echo "pm=unknown"
fi
echo "@@FIREWALL"
if command -v ufw >/dev/null 2>&1; then echo "ufw=$(ufw status 2>/dev/null | head -1 | awk '{print $2}')"; fi
echo "firewalld=$(systemctl is-active firewalld 2>/dev/null || echo n/a)"
if command -v nft >/dev/null 2>&1; then if nft list ruleset 2>/dev/null | grep -q .; then echo "nftables=rules present"; else echo "nftables=empty"; fi; fi
echo "@@SECURITY"
echo "fail2ban=$(systemctl is-active fail2ban 2>/dev/null || echo n/a)"
echo "clamav=$(systemctl is-active clamav-freshclam 2>/dev/null || systemctl is-active clamav-daemon 2>/dev/null || echo n/a)"
echo "selinux=$(getenforce 2>/dev/null || echo n/a)"
echo "@@LOGONS"; (last -a -n 6 2>/dev/null | grep -vE '^$|^wtmp|^reboot') || true
echo "@@SUDO"; (getent group sudo 2>/dev/null | cut -d: -f4; getent group wheel 2>/dev/null | cut -d: -f4) | tr ',' '\n' | grep -v '^$' | sort -u
echo "@@SOFTWARE"
if command -v dpkg-query >/dev/null 2>&1; then
  echo "total=$(dpkg-query -f '.\n' -W 2>/dev/null | wc -l)"
  dpkg-query -W -f '${Package} ${Version}\n' 2>/dev/null | sort
elif command -v rpm >/dev/null 2>&1; then
  echo "total=$(rpm -qa 2>/dev/null | wc -l)"
  rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | sort
else
  echo "total=0"
fi
echo "@@END"
'@

# --- Connect over SSH, run the script, close the session. ---

Write-Progress -Activity "Linux system: $Server" -Status 'Connecting over SSH' -PercentComplete 20
$session = $null
try {
    $sessionParameters = @{ ComputerName = $Server; Credential = $Credential; Port = $Port; AcceptKey = $true; ConnectionTimeout = 30; ErrorAction = 'Stop' }
    if ($KeyFile) {
        if (-not (Test-Path -LiteralPath $KeyFile -PathType Leaf)) {
            throw "The SSH key file was not found: $KeyFile."
        }
        $sessionParameters.KeyFile = $KeyFile
    }
    $session = New-SSHSession @sessionParameters
}
catch {
    throw "The Linux host $Server could not be reached over SSH on port ${Port}: $($_.Exception.Message)."
}

try {
    Write-Progress -Activity "Linux system: $Server" -Status 'Reading the system' -PercentComplete 50
    $result = Invoke-SSHCommand -SSHSession $session -Command $remoteScript -TimeOut 120
    $output = @($result.Output)
}
finally {
    if ($session) { Remove-SSHSession -SSHSession $session | Out-Null }
    Write-Progress -Activity "Linux system: $Server" -Completed
}

# --- Split the output into its @@MARKER sections. ---

$sections = @{}
$current = $null
foreach ($line in $output) {
    if ($line -match '^@@(\w+)$') {
        $current = $Matches[1]
        if (-not $sections.ContainsKey($current)) { $sections[$current] = New-Object System.Collections.Generic.List[string] }
        continue
    }
    if ($current) { $sections[$current].Add($line) }
}
function Get-Section { param([string]$Name) if ($sections.ContainsKey($Name)) { return @($sections[$Name]) } return @() }
function Get-KeyValue {
    param([string[]]$Lines, [string]$Key)
    foreach ($l in $Lines) { if ($l -match "^$([regex]::Escape($Key))=(.*)$") { return $Matches[1].Trim() } }
    return $null
}

# os-release: PRETTY_NAME.
$osLines = Get-Section 'OS'
$pretty = Get-KeyValue $osLines 'PRETTY_NAME'
if ($pretty) { $pretty = $pretty.Trim('"') } else { $pretty = (Get-Section 'OS' | Select-Object -First 1) }
$kernel = (Get-Section 'KERNEL' | Select-Object -First 1)
$hostname = (Get-Section 'HOSTNAME' | Select-Object -First 1)

# Uptime from /proc/uptime (first number = seconds).
$uptime = '-'
$uptimeRaw = (Get-Section 'UPTIME' | Select-Object -First 1)
if ($uptimeRaw -and ($uptimeRaw -split '\s+')[0] -as [double]) {
    $days = [double](($uptimeRaw -split '\s+')[0]) / 86400
    $uptime = '{0:n0} day(s)' -f $days
}

# --- Markdown helpers ---
function Get-DiskPill { param([int]$UsedPercent) if ($UsedPercent -ge 90) { ':red_circle:' } elseif ($UsedPercent -ge 75) { ':yellow_circle:' } else { ':green_circle:' } }

$lines = New-Object System.Collections.Generic.List[string]

# System
$lines.Add("## System")
$lines.Add("")
$lines.Add("| Field | Value |")
$lines.Add("|---|---|")
$lines.Add("| Host name | $hostname |")
$lines.Add("| Distribution | $pretty |")
$lines.Add("| Kernel | $kernel |")
$lines.Add("| Uptime | $uptime |")
$lines.Add("")

# Updates
$updateLines = Get-Section 'UPDATES'
$pm = Get-KeyValue $updateLines 'pm'
$count = Get-KeyValue $updateLines 'count'
$last = Get-KeyValue $updateLines 'last'
$reboot = Get-KeyValue $updateLines 'reboot'
$lines.Add("## Updates")
$lines.Add("")
$pmLabel = switch ($pm) { 'apt' { 'APT (Debian/Ubuntu)' } 'dnf' { 'DNF (RHEL/Fedora)' } 'yum' { 'YUM' } default { 'unknown package manager' } }
$lines.Add("- **Package manager:** $pmLabel")
if ($null -ne $count) {
    $n = 0; [void][int]::TryParse($count, [ref]$n)
    $pill = if ($n -eq 0) { ':green_circle: up to date' } else { ":yellow_circle: $n update(s) available" }
    $lines.Add("- **Pending updates:** $pill")
}
if ($last) { $lines.Add("- **Last update:** $last") }
if ($reboot) {
    $rPill = if ($reboot -eq 'yes') { ':yellow_circle: yes' } elseif ($reboot -eq 'no') { ':green_circle: no' } else { $reboot }
    $lines.Add("- **Reboot required:** $rPill")
}
$lines.Add("")

# Disks: df -PT, real filesystems only.
$lines.Add("## Disks")
$lines.Add("")
$skipTypes = @('tmpfs', 'devtmpfs', 'overlay', 'squashfs', 'proc', 'sysfs', 'cgroup', 'cgroup2', 'efivarfs', 'ramfs', 'autofs', 'fuse.gvfsd-fuse', 'fuse.portal', 'mqueue', 'hugetlbfs', 'debugfs', 'tracefs', 'pstore', 'bpf', 'configfs', 'securityfs', 'none')
$dfRows = @()
foreach ($l in (Get-Section 'DF')) {
    $cols = @($l -split '\s+' | Where-Object { $_ })
    if ($cols.Count -lt 7 -or $cols[0] -eq 'Filesystem') { continue }
    $fsType = $cols[1]
    if ($skipTypes -contains $fsType) { continue }
    $sizeKb = [double]($cols[2] -as [double]); $availKb = [double]($cols[4] -as [double])
    $usedPct = 0; [void][int]::TryParse(($cols[5] -replace '%', ''), [ref]$usedPct)
    $dfRows += [pscustomobject]@{ Mount = $cols[6]; Type = $fsType; SizeGb = [math]::Round($sizeKb / 1MB, 0); FreeGb = [math]::Round($availKb / 1MB, 0); Used = $usedPct }
}
if ($dfRows.Count -eq 0) {
    $lines.Add("No disk reported.")
}
else {
    $lines.Add("| Mount | Type | Size (GB) | Free (GB) | Used % |  |")
    $lines.Add("|---|---|---:|---:|---:|---|")
    foreach ($d in $dfRows) { $lines.Add("| $($d.Mount) | $($d.Type) | $($d.SizeGb) | $($d.FreeGb) | $($d.Used) | $(Get-DiskPill $d.Used) |") }
}
$lines.Add("")

# Security
$fwLines = Get-Section 'FIREWALL'
$secLines = Get-Section 'SECURITY'
$lines.Add("## Security")
$lines.Add("")
$ufw = Get-KeyValue $fwLines 'ufw'
$firewalld = Get-KeyValue $fwLines 'firewalld'
$nftables = Get-KeyValue $fwLines 'nftables'
$fwParts = @()
if ($ufw) { $fwParts += "ufw $ufw" }
if ($firewalld -and $firewalld -ne 'n/a') { $fwParts += "firewalld $firewalld" }
if ($nftables) { $fwParts += "nftables: $nftables" }
$fwActive = ($ufw -eq 'active') -or ($firewalld -eq 'active') -or ($nftables -eq 'rules present')
$fwPill = if ($fwParts.Count -eq 0) { ':yellow_circle: none detected' } elseif ($fwActive) { ':green_circle:' } else { ':yellow_circle:' }
$lines.Add("- **Firewall:** $fwPill $(($fwParts -join ', '))")
$fail2ban = Get-KeyValue $secLines 'fail2ban'
if ($fail2ban -and $fail2ban -ne 'n/a') { $lines.Add("- **fail2ban:** $fail2ban") }
$clamav = Get-KeyValue $secLines 'clamav'
if ($clamav -and $clamav -ne 'n/a') { $lines.Add("- **ClamAV:** $clamav") }
$selinux = Get-KeyValue $secLines 'selinux'
if ($selinux -and $selinux -ne 'n/a') { $lines.Add("- **SELinux:** $selinux") }
$lines.Add("")

# Access: last logins and sudoers
$lines.Add("## Access")
$lines.Add("")
$sudoers = @(Get-Section 'SUDO' | Where-Object { $_ })
$lines.Add("- **Sudo / wheel members:** $(if ($sudoers.Count) { $sudoers -join ', ' } else { 'none or not readable' })")
$logonRows = @(Get-Section 'LOGONS' | Where-Object { $_ -and $_ -notmatch 'still logged in|begins' } | Select-Object -First 5)
if ($logonRows.Count) {
    $lines.Add("")
    $lines.Add("Recent logins (` last `):")
    $lines.Add("")
    $lines.Add('```')
    foreach ($l in $logonRows) { $lines.Add($l) }
    $lines.Add('```')
}
$lines.Add("")

# Installed software
$lines.Add("## Installed packages")
$lines.Add("")
$swLines = @(Get-Section 'SOFTWARE')
$total = Get-KeyValue $swLines 'total'
$pkgRows = @($swLines | Where-Object { $_ -and $_ -notmatch '^total=' })
if ($pkgRows.Count -eq 0) {
    $lines.Add("No package list available.")
}
else {
    $shown = @($pkgRows | Select-Object -First $softwareLimit)
    $totalNum = if ($total) { $total } else { "$($pkgRows.Count)" }
    $note = if ([int]($totalNum) -gt $shown.Count) { " (first $($shown.Count) of $totalNum)" } else { " ($totalNum)" }
    $lines.Add("Installed packages$($note):")
    $lines.Add("")
    $lines.Add("| Package | Version |")
    $lines.Add("|---|---|")
    foreach ($p in $shown) {
        $parts = @($p -split '\s+', 2)
        $lines.Add("| $($parts[0]) | $(if ($parts.Count -gt 1) { $parts[1] } else { '-' }) |")
    }
}
$lines.Add("")

# Emit the real status emoji (🟢🟠🔴) rather than the :green_circle: shortcodes, which this client's
# WordPress does not render. Built from code points so the source file stays plain ASCII.
$pillGreen = [char]::ConvertFromUtf32(0x1F7E2)
$pillYellow = [char]::ConvertFromUtf32(0x1F7E0)
$pillRed = [char]::ConvertFromUtf32(0x1F534)
($lines -join "`n") -replace ':green_circle:', $pillGreen -replace ':yellow_circle:', $pillYellow -replace ':red_circle:', $pillRed
