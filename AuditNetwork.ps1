[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'Networks to scan instead of those of this computer: 192.0.2.0/24, a range 192.0.2.10-50, or one address. Default: the networks of this computer that have a gateway.')]
    [string[]]$Subnet,

    [Parameter(HelpMessage = 'Networks to scan as well, e.g. a server or camera VLAN behind the firewall: 10.0.20.0/24, 10.0.30.10-50.')]
    [string[]]$AddSubnet,

    [Parameter(HelpMessage = 'After the scan, list the other networks seen from here and ask which ones to scan too.')]
    [switch]$AskSubnet,

    [Parameter(HelpMessage = 'After the scan, scan the other networks seen from here too, those of at most 1024 addresses, without asking.')]
    [switch]$ScanOtherNetworks,

    [Parameter(HelpMessage = 'SNMP communities of the client''s devices, tried after "public". They are never written to the audit.')]
    [string[]]$SnmpCommunity,

    [Parameter(HelpMessage = 'File to write the network diagram to, for draw.io (.drawio). Default: no diagram.')]
    [string]$DiagramPath,

    [Parameter(HelpMessage = 'No speed test of the Internet line.')]
    [switch]$SkipSpeedTest,

    [Parameter(HelpMessage = 'Most addresses scanned per network of this computer: a larger one is reduced to its /24 and that of its gateway.')]
    [ValidateRange(1, 65536)]
    [int]$MaxHosts = 1024,

    [Parameter(HelpMessage = 'Devices examined at once.')]
    [ValidateRange(1, 128)]
    [int]$ThrottleLimit = 32
)

# Audit of the network this computer is on, with no login anywhere: its own network settings, its
# Wi-Fi, the Internet line (public address and provider, the routers on the way to the Internet, a
# speed test), then the devices of its networks and of the other networks given. A device is found
# when it answers a ping, ARP (on this computer's own networks) or a common TCP port; it is then named
# from its DNS and NetBIOS names, its MAC vendor, UPnP and WS-Discovery, SNMP ("public", then the
# communities given), and the title and certificate of its web pages, which also tell its type
# (firewall, switch, NAS, printer, UPS...). SNMP also gives models and serial numbers, a UPS's
# battery, a printer's page count, a switch's VLANs and neighbours (LLDP, CDP), and a router's own
# networks, offered for scanning with the other networks seen. With -DiagramPath, a first network
# diagram for draw.io.

$ErrorActionPreference = 'Stop'
# Start.ps1 runs in strict mode, where a property or regex group that is missing is an error; this
# script expects $null for it. Off for this script only.
Set-StrictMode -Off
. (Join-Path $PSScriptRoot 'AuditCommon.ps1')
$area = 'Network'

# The ports tried on every device found, with the name shown. Not [ordered]: its [135] would be the
# 136th entry, not port 135.
$portNames = @{
    21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 25 = 'SMTP'; 53 = 'DNS'; 80 = 'HTTP'; 88 = 'Kerberos'; 135 = 'RPC'
    139 = 'NetBIOS'; 389 = 'LDAP'; 443 = 'HTTPS'; 444 = 'HTTPS 444'; 445 = 'SMB'; 515 = 'LPD'; 554 = 'RTSP'; 631 = 'IPP'
    636 = 'LDAPS'; 902 = 'VMware'; 1433 = 'SQL Server'; 1723 = 'PPTP'; 2049 = 'NFS'; 3260 = 'iSCSI'; 3306 = 'MySQL'
    3389 = 'RDP'; 4433 = 'HTTPS 4433'; 5000 = 'HTTP 5000'; 5001 = 'HTTPS 5001'; 5060 = 'SIP'; 5480 = 'HTTPS 5480'
    5900 = 'VNC'; 5938 = 'TeamViewer'; 5985 = 'WinRM'; 5986 = 'WinRM HTTPS'; 7070 = 'AnyDesk'; 8000 = 'HTTP 8000'
    8006 = 'Proxmox'; 8080 = 'HTTP 8080'; 8443 = 'HTTPS 8443'; 9100 = 'Printing'; 9419 = 'Veeam API'; 9443 = 'HTTPS 9443'
    10443 = 'HTTPS 10443'
}
# Web pages are read on these ports, HTTPS first unless the port is a plain HTTP one.
$webPorts = @(80, 443, 444, 4433, 5000, 5001, 5480, 8000, 8006, 8080, 8443, 9443, 10443)
$plainHttpPorts = @(80, 5000, 8000, 8080)
# Asked of addresses that answered neither a ping nor ARP, e.g. on a network behind a router.
$quickPorts = @(22, 80, 443, 445, 3389)
# The maker of a device from the enterprise number in its SNMP object ID (1.3.6.1.4.1.<number>...), for
# the devices of other networks, whose MAC address this computer doesn't see.
$snmpVendors = @{
    9 = 'Cisco'; 11 = 'HP'; 171 = 'D-Link'; 232 = 'HPE'; 253 = 'Xerox'; 311 = 'Microsoft'; 318 = 'APC'; 367 = 'Ricoh'
    534 = 'Eaton'; 641 = 'Lexmark'; 674 = 'Dell'; 890 = 'Zyxel'; 1248 = 'Epson'; 1347 = 'Kyocera'; 1602 = 'Canon'
    2011 = 'Huawei'; 2435 = 'Brother'; 2604 = 'Sophos'; 2620 = 'Check Point'; 2636 = 'Juniper'; 4526 = 'Netgear'
    6574 = 'Synology'; 6876 = 'VMware'; 8072 = 'Net-SNMP'; 8741 = 'SonicWall'; 11863 = 'TP-Link'; 12356 = 'Fortinet'
    14823 = 'Aruba'; 14988 = 'MikroTik'; 18334 = 'Konica Minolta'; 24681 = 'QNAP'; 25461 = 'Palo Alto Networks'
    30065 = 'Arista'; 41112 = 'Ubiquiti'
}
# librespeed-cli, the open-source speed test of LibreSpeed (LGPL), for Windows x64: the zip of its
# GitHub release and the program in it. Change the version and both SHA-256 together (the zip's is in
# the release's checksums.txt).
$speedTest = @{
    Name          = 'librespeed-cli-1.0.14'
    Uri           = 'https://github.com/librespeed/speedtest-cli/releases/download/v1.0.14/librespeed-cli_1.0.14_windows_amd64.zip'
    ZipSha256     = '324F9BC16F3B9BB6BFA6AF89BAD1E3E5183AE8C91464B3CB3FC2DB8DF1D6B503'
    Program       = 'librespeed-cli.exe'
    ProgramSha256 = '5E01DF3986486419FEE84238204C3030FBBBE2E3145D4A2F5EF5EBCBAD7598D4'
}

function ConvertTo-IPNumber {
    param(
        [string]$Address
    )

    $bytes = ([System.Net.IPAddress]::Parse($Address)).GetAddressBytes()
    [array]::Reverse($bytes)
    return [long][BitConverter]::ToUInt32($bytes, 0)
}

function ConvertTo-IPText {
    param(
        [long]$Number
    )

    $bytes = [BitConverter]::GetBytes([uint32]$Number)
    [array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

# From First to Last: Windows PowerShell's First..Last only counts within 32-bit signed numbers,
# which addresses from 128.0.0.0 are not.
function Get-NumberRange {
    param(
        [long]$First,
        [long]$Last
    )

    for ($number = $First; $number -le $Last; $number++) {
        $number
    }
}

# The host addresses of a network (without its network and broadcast addresses), of a range of the last
# byte (192.0.2.10-50) or of addresses (192.0.2.10-192.0.2.20), or one address. At most a /16.
function Get-AddressRange {
    param(
        [string]$Text
    )

    $Text = $Text.Trim()
    if ($Text -match '^(?<ip>\d{1,3}(\.\d{1,3}){3})/(?<bits>\d{1,2})$') {
        $bits = [int]$Matches.bits
        if ($bits -lt 16 -or $bits -gt 32) {
            throw "$Text is too large: scan at most a /16 at a time."
        }
        $size = [long][math]::Pow(2, 32 - $bits)
        $number = ConvertTo-IPNumber $Matches.ip
        $network = $number - ($number % $size)
        if ($size -le 2) {
            return @(Get-NumberRange $network ($network + $size - 1))
        }
        return @(Get-NumberRange ($network + 1) ($network + $size - 2))
    }
    if ($Text -match '^(?<ip>(?<prefix>\d{1,3}\.\d{1,3}\.\d{1,3}\.)(?<first>\d{1,3}))-(?<last>\d{1,3})$') {
        return @(Get-NumberRange (ConvertTo-IPNumber $Matches.ip) (ConvertTo-IPNumber "$($Matches.prefix)$($Matches.last)"))
    }
    if ($Text -match '^(?<first>\d{1,3}(\.\d{1,3}){3})-(?<last>\d{1,3}(\.\d{1,3}){3})$') {
        $first = ConvertTo-IPNumber $Matches.first
        $last = ConvertTo-IPNumber $Matches.last
        if ($last - $first -ge 65536) {
            throw "$Text is too large: scan at most 65536 addresses at a time."
        }
        return @(Get-NumberRange $first $last)
    }
    if ($Text -match '^\d{1,3}(\.\d{1,3}){3}$') {
        return @(ConvertTo-IPNumber $Text)
    }
    throw "'$Text' is not a network (192.0.2.0/24), a range (192.0.2.10-50) or an address."
}

# A network to scan: its name in the audit and its addresses, also as a set to find which one an
# address is in.
function New-ScanRange {
    param(
        [string]$Text,
        [string]$Name = $Text,
        [long[]]$Numbers
    )

    if (-not $Numbers) {
        $Numbers = @(Get-AddressRange $Text)
    }
    $set = New-Object 'System.Collections.Generic.HashSet[long]'
    foreach ($number in $Numbers) {
        [void]$set.Add($number)
    }
    return [pscustomobject]@{ Name = $Name; Numbers = $Numbers; Set = $set }
}

# The network of an address, as 192.0.2.0/24.
function Get-NetworkName {
    param(
        [string]$Address,
        [int]$PrefixLength
    )

    $size = [long][math]::Pow(2, 32 - $PrefixLength)
    $number = ConvertTo-IPNumber $Address
    return "$(ConvertTo-IPText ($number - ($number % $size)))/$PrefixLength"
}

# 255.255.255.0 -> 24.
function ConvertTo-PrefixLength {
    param(
        [string]$Mask
    )

    $number = ConvertTo-IPNumber $Mask
    $bits = 0
    while ($bits -lt 32 -and ($number -band [long]2147483648)) {
        $bits++
        $number = ($number * 2) % [long]4294967296
    }
    return $bits
}

# Private (10/8, 172.16/12, 192.168/16), Shared (100.64/10, the addresses a provider shares behind its
# CGNAT), Other (loopback, link-local, multicast) or Public.
function Get-AddressKind {
    param(
        [string]$Address
    )

    $bytes = ([System.Net.IPAddress]::Parse($Address)).GetAddressBytes()
    if ($bytes[0] -eq 10 -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or ($bytes[0] -eq 192 -and $bytes[1] -eq 168)) {
        return 'Private'
    }
    if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) {
        return 'Shared'
    }
    if ($bytes[0] -in 0, 127 -or $bytes[0] -ge 224 -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254)) {
        return 'Other'
    }
    return 'Public'
}

# The IPv4 settings of each connected interface of this computer (not its link-local addresses).
function Get-LocalNetwork {
    $adapters = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.NetAdapter -and "$($_.NetAdapter.Status)" -eq 'Up' })
    $settings = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' -ErrorAction SilentlyContinue)
    foreach ($adapter in $adapters) {
        $setting = $settings | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex } | Select-Object -First 1
        foreach ($address in @($adapter.IPv4Address | Where-Object { $_.IPAddress -notlike '169.254.*' })) {
            [pscustomobject]@{
                Interface    = $adapter.InterfaceAlias
                Adapter      = $adapter.NetAdapter.InterfaceDescription
                Mac          = "$($adapter.NetAdapter.MacAddress)" -replace '-', ':'
                LinkSpeed    = $adapter.NetAdapter.LinkSpeed
                Address      = $address.IPAddress
                PrefixLength = [int]$address.PrefixLength
                Gateway      = @($adapter.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) | Select-Object -First 1
                DnsServers   = @($adapter.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses })
                Dhcp         = [bool]($setting -and $setting.DHCPEnabled)
                DhcpServer   = $(if ($setting -and $setting.DHCPEnabled) { $setting.DHCPServer })
                DnsSuffix    = $(if ($setting) { $setting.DNSDomain })
                NetworkName  = $(if ($adapter.NetProfile) { $adapter.NetProfile.Name })
            }
        }
    }
}

# Reads "label : value" lines of netsh, whose labels are in the language of Windows: English, French
# and Dutch are known.
$wifiLabels = [ordered]@{
    Ssid           = '^SSID$'
    Bssid          = '^(AP )?BSSID$'
    State          = '^(State|.tat|Status)$'
    Authentication = '^(Authentication|Authentification|Verificatie)$'
    Encryption     = '^(Cipher|Encryption|Chiffrement|Codering|Versleuteling)$'
    Radio          = '^(Radio type|Type de radio|Radiotype)$'
    Band           = '^(Band|Bande)$'
    Channel        = '^(Channel|Canal|Kanaal)$'
    Signal         = '^(Signal|Signaal)$'
}

# The Wi-Fi this computer is connected to. Windows 11 hides the network names from netsh unless
# location services are allowed for desktop apps.
function Get-WifiConnection {
    $lines = @(netsh wlan show interfaces 2>$null)
    if ($LASTEXITCODE -ne 0) {
        return
    }
    $current = $null
    foreach ($line in $lines) {
        if ($line -notmatch '^\s*(?<label>[^:]+?)\s*:\s(?<value>.*)$') {
            continue
        }
        $label = $Matches.label.Trim()
        $value = $Matches.value.Trim()
        if ($label -match '^(Name|Nom|Naam)$') {
            if ($current -and $current.Contains('Ssid')) {
                [pscustomobject]$current
            }
            $current = [ordered]@{ Interface = $value }
            continue
        }
        if ($null -eq $current) {
            continue
        }
        foreach ($key in $wifiLabels.Keys) {
            if (-not $current.Contains($key) -and $label -match $wifiLabels[$key]) {
                $current[$key] = $value
            }
        }
    }
    if ($current -and $current.Contains('Ssid')) {
        [pscustomobject]$current
    }
}

# The Wi-Fi networks in range: their security, strongest signal, channels and number of access points.
function Get-WifiNetworks {
    $lines = @(netsh wlan show networks mode=bssid 2>$null)
    if ($LASTEXITCODE -ne 0) {
        return
    }
    $network = $null
    foreach ($line in $lines) {
        if ($line -match '^SSID \d+\s*:\s?(?<name>.*)$') {
            if ($network) {
                [pscustomobject]$network
            }
            $network = [ordered]@{ Ssid = $(if ($Matches.name.Trim()) { $Matches.name.Trim() } else { '(hidden)' }); Authentication = $null; Encryption = $null; Signal = 0; Channels = @(); AccessPoints = 0 }
            continue
        }
        if ($null -eq $network -or $line -notmatch '^\s*(?<label>[^:]+?)\s*:\s(?<value>.*)$') {
            continue
        }
        $label = $Matches.label.Trim()
        $value = $Matches.value.Trim()
        if ($label -match '^BSSID \d+$') {
            $network.AccessPoints++
        }
        elseif ($label -match $wifiLabels.Authentication -and -not $network.Authentication) {
            $network.Authentication = $value
        }
        elseif ($label -match $wifiLabels.Encryption -and -not $network.Encryption) {
            $network.Encryption = $value
        }
        elseif ($label -match $wifiLabels.Signal -and $value -match '(\d+)') {
            $network.Signal = [math]::Max($network.Signal, [int]$Matches[1])
        }
        elseif ($label -match $wifiLabels.Channel -and $value -notin $network.Channels) {
            $network.Channels += $value
        }
    }
    if ($network) {
        [pscustomobject]$network
    }
}

function Get-PublicAddress {
    try {
        $info = Invoke-RestMethod -Uri 'https://ipinfo.io/json' -UseBasicParsing -TimeoutSec 10
        return [pscustomobject]@{ Address = $info.ip; Name = $info.hostname; Provider = $info.org; Location = (@($info.city, $info.country) | Where-Object { $_ }) -join ', ' }
    }
    catch {
        try {
            $address = Invoke-RestMethod -Uri 'https://api.ipify.org' -UseBasicParsing -TimeoutSec 10
            return [pscustomobject]@{ Address = "$address"; Name = $null; Provider = $null; Location = $null }
        }
        catch {
            Write-Warning "The public address could not be read: $($_.Exception.Message)"
        }
    }
}

# Whether the provider's name of the public address says it is fixed or dynamic, when it says so.
function Get-PublicAddressType {
    param(
        [string]$Name
    )

    if ($Name -match '(?i)static|fixed|\bfixe\b') {
        return 'fixed'
    }
    if ($Name -match '(?i)dyn|dhcp|pool|dial') {
        return 'dynamic'
    }
    return $null
}

# The routers between this computer and the Internet: pings to 1.1.1.1 with a time to live of 1, 2, 3...
# answered by the router where each one ends, until 1.1.1.1 answers. A router that doesn't answer is
# a hop without address.
function Get-InternetPath {
    param(
        [string]$Target = '1.1.1.1',
        [int]$MaxHops = 10,
        [int]$TimeoutMs = 2000
    )

    $buffer = New-Object byte[] 32
    $probes = @(foreach ($ttl in 1..$MaxHops) {
            $ping = New-Object System.Net.NetworkInformation.Ping
            [pscustomobject]@{ Hop = $ttl; Ping = $ping; Task = $ping.SendPingAsync($Target, $TimeoutMs, $buffer, (New-Object System.Net.NetworkInformation.PingOptions($ttl, $true))) }
        })
    try {
        [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($probes.Task), $TimeoutMs + 3000)
    }
    catch {
        # A ping that could not be sent: no answer for that hop.
    }
    $hops = New-Object System.Collections.Generic.List[object]
    $reached = $false
    foreach ($probe in $probes) {
        $reply = if ($probe.Task.Status -eq 'RanToCompletion') { $probe.Task.Result }
        $probe.Ping.Dispose()
        if ($reached) {
            continue
        }
        $status = "$($reply.Status)"
        $address = if ($status -in 'Success', 'TtlExpired', 'TimeExceeded' -and $reply.Address) { $reply.Address.ToString() }
        $hops.Add([pscustomobject]@{ Hop = $probe.Hop; Address = $address; Name = $null; Kind = $(if ($address) { Get-AddressKind $address }) })
        $reached = $status -eq 'Success'
    }
    if (-not $reached) {
        # Nothing past the last router that answered.
        while ($hops.Count -gt 0 -and -not $hops[$hops.Count - 1].Address) {
            $hops.RemoveAt($hops.Count - 1)
        }
    }
    $lookups = @($hops | Where-Object { $_.Address } | ForEach-Object { [pscustomobject]@{ Hop = $_; Task = [System.Net.Dns]::GetHostEntryAsync($_.Address) } })
    try {
        [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($lookups.Task), 3000)
    }
    catch {
        # A router without a name in DNS.
    }
    foreach ($lookup in $lookups) {
        if ($lookup.Task.Status -eq 'RanToCompletion' -and $lookup.Task.Result.HostName -ne $lookup.Hop.Address) {
            $lookup.Hop.Name = $lookup.Task.Result.HostName
        }
    }
    return $hops.ToArray()
}

# The speed of the Internet line from this computer, measured by librespeed-cli against the nearest
# LibreSpeed server; it sends no result anywhere (no --share). Over Wi-Fi or a slow network port, it is
# the speed of that link.
function Measure-InternetSpeed {
    $program = Get-AuditTool @speedTest
    if (-not $program) {
        return $null
    }
    $info = New-Object System.Diagnostics.ProcessStartInfo($program, '--json --duration 10')
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.CreateNoWindow = $true
    try {
        $process = [System.Diagnostics.Process]::Start($info)
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(180000)) {
            $process.Kill()
            throw 'no result after 3 minutes'
        }
        # A JSON list, which Windows PowerShell gives as one object: ForEach-Object takes its items out.
        $result = $output.Result | ConvertFrom-Json | ForEach-Object { $_ } | Select-Object -First 1
        if (-not $result -or -not $result.download) {
            throw "no result: $(("$($errors.Result)" -split '\r?\n' | Where-Object { $_.Trim() } | Select-Object -Last 1))"
        }
        return [pscustomobject]@{
            Download = [math]::Round([double]$result.download, 1)
            Upload   = [math]::Round([double]$result.upload, 1)
            Ping     = [math]::Round([double]$result.ping)
            Jitter   = [math]::Round([double]$result.jitter, 1)
            Server   = $result.server.name
        }
    }
    catch {
        Write-Warning "The speed test failed: $($_.Exception.Message)"
        return $null
    }
}

# The addresses that answer a ping, with the TTL of their answer (about 128 for Windows, 64 for Linux
# and most devices, 255 for network equipment).
function Invoke-PingSweep {
    param(
        [long[]]$Targets,
        [int]$TimeoutMs = 1000
    )

    $answers = @{}
    for ($first = 0; $first -lt $Targets.Count; $first += 256) {
        $batch = @($Targets[$first..([math]::Min($first + 255, $Targets.Count - 1))] | ForEach-Object {
                $ping = New-Object System.Net.NetworkInformation.Ping
                [pscustomobject]@{ Number = $_; Ping = $ping; Task = $ping.SendPingAsync((ConvertTo-IPText $_), $TimeoutMs) }
            })
        try {
            [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($batch.Task), $TimeoutMs + 3000)
        }
        catch {
            # A ping that could not be sent: no answer from that address.
        }
        foreach ($item in $batch) {
            if ($item.Task.Status -eq 'RanToCompletion' -and "$($item.Task.Result.Status)" -eq 'Success') {
                $answers[$item.Number] = if ($item.Task.Result.Options) { $item.Task.Result.Options.Ttl } else { $null }
            }
            $item.Ping.Dispose()
        }
        Write-Progress -Id 20 -Activity 'Network audit' -Status "Ping: $([math]::Min($first + 256, $Targets.Count)) of $($Targets.Count) addresses" -PercentComplete (10 + 20 * [math]::Min($first + 256, $Targets.Count) / $Targets.Count)
    }
    return $answers
}

# The NetBIOS names of a Windows computer or NAS (node status, UDP 137): its name, its domain or
# workgroup, whether it is a domain controller, and its MAC address.
function Get-NetBiosInfo {
    param(
        [string]$Address,
        [int]$TimeoutMs = 1000
    )

    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        # Node status request of the name "*": ID, no flags, one question, the encoded name, type NBSTAT, class IN.
        $query = [byte[]](0x4D, 0x4F, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20) + [Text.Encoding]::ASCII.GetBytes('CK' + ('A' * 30)) + [byte[]](0, 0, 0x21, 0, 1)
        [void]$udp.Send($query, $query.Length, $Address, 137)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $answer = $udp.Receive([ref]$remote)
    }
    catch {
        return $null
    }
    finally {
        $udp.Close()
    }
    # Header (12), name (34), type, class, TTL and length (10): the number of names, then 18 bytes per name.
    if ($answer.Length -lt 57 -or $answer[12] -ne 0x20) {
        return $null
    }
    $count = [int]$answer[56]
    $names = @(for ($index = 0; $index -lt $count; $index++) {
            $offset = 57 + 18 * $index
            if ($offset + 18 -gt $answer.Length) {
                break
            }
            [pscustomobject]@{ Name = [Text.Encoding]::ASCII.GetString($answer, $offset, 15).Trim(); Suffix = [int]$answer[$offset + 15]; Group = [bool]($answer[$offset + 16] -band 0x80) }
        })
    $macOffset = 57 + 18 * $count
    $mac = if ($answer.Length -ge $macOffset + 6) { (@($answer[$macOffset..($macOffset + 5)] | ForEach-Object { $_.ToString('X2') })) -join ':' }
    return [pscustomobject]@{
        Name               = ($names | Where-Object { $_.Suffix -eq 0 -and -not $_.Group } | Select-Object -First 1).Name
        Domain             = ($names | Where-Object { $_.Suffix -eq 0 -and $_.Group } | Select-Object -First 1).Name
        DomainController   = [bool]($names | Where-Object { $_.Suffix -eq 0x1C -and $_.Group })
        Mac                = $(if ($mac -and $mac -ne '00:00:00:00:00:00') { $mac })
    }
}

# SNMP v2c, in BER: each item is a type, a length and its content.
function ConvertTo-Ber {
    param(
        [byte]$Type,
        [byte[]]$Content = @()
    )

    $length = $Content.Length
    $head = if ($length -lt 128) { @($Type, $length) } elseif ($length -lt 256) { @($Type, 0x81, $length) } else { @($Type, 0x82, [math]::Floor($length / 256), ($length % 256)) }
    return , [byte[]]($head + $Content)
}

function ConvertTo-BerInteger {
    param(
        [int]$Value
    )

    $bytes = [BitConverter]::GetBytes($Value)
    [array]::Reverse($bytes)
    # The shortest form: no leading byte that only repeats the sign.
    $start = 0
    while ($start -lt 3 -and (($bytes[$start] -eq 0 -and $bytes[$start + 1] -lt 0x80) -or ($bytes[$start] -eq 0xFF -and $bytes[$start + 1] -ge 0x80))) {
        $start++
    }
    return ConvertTo-Ber 0x02 ([byte[]]$bytes[$start..3])
}

# 1.3.6.1.2.1.1.5.0 as BER: the first two numbers in one byte, then each number in 7-bit groups.
function ConvertTo-BerOid {
    param(
        [string]$Oid
    )

    $parts = @($Oid.Trim('.') -split '\.' | ForEach-Object { [long]$_ })
    $bytes = New-Object System.Collections.Generic.List[byte]
    $bytes.Add([byte](40 * $parts[0] + $parts[1]))
    for ($index = 2; $index -lt $parts.Count; $index++) {
        $value = $parts[$index]
        $group = New-Object System.Collections.Generic.List[byte]
        $group.Add([byte]($value % 128))
        $value = [math]::Floor($value / 128)
        while ($value -gt 0) {
            $group.Insert(0, [byte](($value % 128) + 128))
            $value = [math]::Floor($value / 128)
        }
        $bytes.AddRange($group)
    }
    return ConvertTo-Ber 0x06 $bytes.ToArray()
}

# An SNMP v2c request of these OIDs: GetRequest (0xA0), or GetBulkRequest (0xA5) of the next
# MaxRepetitions values after each.
function New-SnmpRequest {
    param(
        [string]$Community,
        [byte]$Type = 0xA0,
        [string[]]$Oids,
        [int]$RequestId,
        [int]$MaxRepetitions = 0
    )

    $bindings = @()
    foreach ($oid in $Oids) {
        $bindings += ConvertTo-Ber 0x30 ((ConvertTo-BerOid $oid) + [byte[]](0x05, 0))
    }
    # Request ID, then error status and index (0 and 0), or for GetBulk non-repeaters (0) and max-repetitions.
    $pdu = (ConvertTo-BerInteger $RequestId) + (ConvertTo-BerInteger 0) + (ConvertTo-BerInteger $(if ($Type -eq 0xA5) { $MaxRepetitions } else { 0 })) + (ConvertTo-Ber 0x30 $bindings)
    $message = (ConvertTo-BerInteger 1) + (ConvertTo-Ber 0x04 ([Text.Encoding]::ASCII.GetBytes($Community))) + (ConvertTo-Ber $Type $pdu)
    return ConvertTo-Ber 0x30 $message
}

# The BER item at Offset: its type, where its content starts, its length and where the next item is.
function Read-BerItem {
    param(
        [byte[]]$Data,
        [int]$Offset
    )

    $length = [int]$Data[$Offset + 1]
    $start = $Offset + 2
    if ($length -band 0x80) {
        $count = $length -band 0x7F
        $length = 0
        for ($index = 0; $index -lt $count; $index++) {
            $length = $length * 256 + $Data[$start + $index]
        }
        $start += $count
    }
    if ($start + $length -gt $Data.Length) {
        throw 'The SNMP answer is cut short.'
    }
    return [pscustomobject]@{ Type = [int]$Data[$Offset]; Start = $start; Length = $length; Next = $start + $length }
}

function ConvertFrom-BerOid {
    param(
        [byte[]]$Data,
        $Item
    )

    $first = [int]$Data[$Item.Start]
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add([string][math]::Floor($first / 40))
    $parts.Add([string]($first % 40))
    $value = [long]0
    for ($index = $Item.Start + 1; $index -lt $Item.Next; $index++) {
        $value = $value * 128 + ($Data[$index] -band 0x7F)
        if (-not ($Data[$index] -band 0x80)) {
            $parts.Add([string]$value)
            $value = 0
        }
    }
    return $parts -join '.'
}

# A value of an SNMP answer: a number, a text (or the bytes as hex when it is not text), an OID or an
# IP address. $null for noSuchObject, noSuchInstance and endOfMibView.
function ConvertFrom-BerValue {
    param(
        [byte[]]$Data,
        $Item
    )

    # An empty value (an empty sysLocation is common): "$x = if ..." would make an empty array $null.
    if ($Item.Length -eq 0) {
        switch ($Item.Type) {
            0x02 { return [long]0 }
            0x04 { return '' }
        }
        return $null
    }
    $bytes = [byte[]]$Data[$Item.Start..($Item.Next - 1)]
    switch ($Item.Type) {
        0x02 {
            $value = [long]$(if ($bytes.Count -and $bytes[0] -ge 0x80) { -1 } else { 0 })
            foreach ($byte in $bytes) {
                $value = $value * 256 + $byte
            }
            return $value
        }
        0x04 {
            # Text, with or without trailing NULs; else bytes (a MAC address, a bitmap) as hex. Text that
            # is not UTF-8 is read as Windows-1252, unless it is 6 bytes long: a MAC address.
            $end = $bytes.Count
            while ($end -gt 0 -and $bytes[$end - 1] -eq 0) {
                $end--
            }
            $text = $null
            if (@($bytes[0..([math]::Max(0, $end - 1))] | Where-Object { $_ -lt 9 -or ($_ -gt 13 -and $_ -lt 32) -or $_ -eq 127 }).Count -eq 0) {
                try {
                    $text = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes, 0, $end)
                }
                catch {
                    if ($end -ne 6) {
                        $text = [Text.Encoding]::GetEncoding(1252).GetString($bytes, 0, $end)
                    }
                }
            }
            if ($null -eq $text -and $bytes.Count -gt 0) {
                return (@($bytes | ForEach-Object { $_.ToString('X2') })) -join ':'
            }
            return ("$text" -replace '[\x00-\x1F]+', ' ').Trim()
        }
        0x06 {
            return ConvertFrom-BerOid $Data $Item
        }
        0x40 {
            if ($bytes.Count -eq 4) {
                return ($bytes -join '.')
            }
            return $null
        }
        { $_ -in 0x41, 0x42, 0x43, 0x46, 0x47 } {
            $value = [decimal]0
            foreach ($byte in $bytes) {
                $value = $value * 256 + $byte
            }
            return $value
        }
    }
    return $null
}

# The variable bindings of an SNMP answer to this request: OID, value, the bytes of a text, and End at
# the end of the device's MIB.
function Read-SnmpResponse {
    param(
        [byte[]]$Data,
        [int]$RequestId
    )

    $message = Read-BerItem $Data 0
    $version = Read-BerItem $Data $message.Start
    $community = Read-BerItem $Data $version.Next
    $pdu = Read-BerItem $Data $community.Next
    if ($pdu.Type -ne 0xA2) {
        return
    }
    $id = Read-BerItem $Data $pdu.Start
    $status = Read-BerItem $Data $id.Next
    $errorIndex = Read-BerItem $Data $status.Next
    if ((ConvertFrom-BerValue $Data $id) -ne $RequestId -or (ConvertFrom-BerValue $Data $status) -ne 0) {
        return
    }
    $list = Read-BerItem $Data $errorIndex.Next
    $offset = $list.Start
    while ($offset -lt $list.Next) {
        $binding = Read-BerItem $Data $offset
        $name = Read-BerItem $Data $binding.Start
        $item = Read-BerItem $Data $name.Next
        [pscustomobject]@{
            Oid   = ConvertFrom-BerOid $Data $name
            Value = ConvertFrom-BerValue $Data $item
            Bytes = $(if ($item.Type -eq 0x04 -and $item.Length -gt 0) { , [byte[]]$Data[$item.Start..($item.Next - 1)] })
            End   = $item.Type -eq 0x82
        }
        $offset = $binding.Next
    }
}

# One SNMP v2c request to a device: its variable bindings, none when it doesn't answer.
function Invoke-SnmpRequest {
    param(
        [string]$Address,
        [string]$Community,
        [string[]]$Oids,
        [byte]$Type = 0xA0,
        [int]$MaxRepetitions = 0,
        [int]$TimeoutMs = 1000
    )

    $id = Get-Random -Minimum 1 -Maximum 2147483647
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $packet = [byte[]](New-SnmpRequest -Community $Community -Type $Type -Oids $Oids -RequestId $id -MaxRepetitions $MaxRepetitions)
        $udp.Client.ReceiveTimeout = $TimeoutMs
        [void]$udp.Send($packet, $packet.Length, $Address, 161)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $answer = $udp.Receive([ref]$remote)
        return @(Read-SnmpResponse -Data $answer -RequestId $id)
    }
    catch {
        return @()
    }
    finally {
        $udp.Close()
    }
}

# The rows of an SNMP table column: their index (the OID after the column's) and value, at most MaxRows.
function Invoke-SnmpWalk {
    param(
        [string]$Address,
        [string]$Community,
        [string]$Oid,
        [int]$MaxRows = 100,
        [int]$TimeoutMs = 1000
    )

    $rows = New-Object System.Collections.Generic.List[object]
    $next = $Oid
    while ($rows.Count -lt $MaxRows) {
        $bindings = @(Invoke-SnmpRequest -Address $Address -Community $Community -Type 0xA5 -Oids $next -MaxRepetitions 10 -TimeoutMs $TimeoutMs)
        if ($bindings.Count -eq 0) {
            break
        }
        $done = $false
        foreach ($binding in $bindings) {
            if ($binding.End -or -not $binding.Oid.StartsWith("$Oid.") -or $binding.Oid -eq $next) {
                $done = $true
                break
            }
            $rows.Add([pscustomobject]@{ Index = $binding.Oid.Substring($Oid.Length + 1); Value = $binding.Value; Bytes = $binding.Bytes })
            $next = $binding.Oid
            if ($rows.Count -ge $MaxRows) {
                break
            }
        }
        if ($done) {
            break
        }
    }
    return $rows.ToArray()
}

# What a device tells over SNMP v2c, trying "public" (which many keep by default), then the communities
# given: its description (model, firmware), name, location and object ID; its model, serial number and
# firmware (ENTITY-MIB); a UPS's identity and battery (UPS-MIB, APC PowerNet); a printer's model, serial
# number and page count (Printer-MIB); a switch's VLANs and neighbours (LLDP, else CDP); and a router's
# own addresses and masks. $null when no community answers.
function Get-SnmpInfo {
    param(
        [string]$Address,
        [string[]]$Communities = @('public'),
        [int]$TimeoutMs = 1000
    )

    $community = $null
    foreach ($candidate in $Communities) {
        $answer = @(Invoke-SnmpRequest -Address $Address -Community $candidate -Oids '1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.2.0', '1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.6.0' -TimeoutMs $TimeoutMs)
        if ($answer.Count -gt 0) {
            $community = $candidate
            break
        }
    }
    if (-not $community) {
        return $null
    }
    $get = {
        param([string[]]$Oids)
        $values = @{}
        foreach ($binding in @(Invoke-SnmpRequest -Address $Address -Community $community -Oids $Oids -TimeoutMs $TimeoutMs)) {
            $values[$binding.Oid] = $binding.Value
        }
        $values
    }
    $walk = {
        param([string]$Oid, [int]$MaxRows = 128)
        $rows = @{}
        foreach ($row in @(Invoke-SnmpWalk -Address $Address -Community $community -Oid $Oid -MaxRows $MaxRows -TimeoutMs $TimeoutMs)) {
            $rows[$row.Index] = $row
        }
        $rows
    }
    # The first value that is not empty, in the order of the index (the chassis comes first).
    $first = {
        param([hashtable]$Rows)
        @($Rows.Keys | Sort-Object { [long]($_ -replace '\..*$', '') } | ForEach-Object { "$($Rows[$_].Value)".Trim() } | Where-Object { $_ }) | Select-Object -First 1
    }

    $system = @{}
    foreach ($binding in $answer) {
        $system[$binding.Oid] = $binding.Value
    }
    $info = [ordered]@{
        Description      = $system['1.3.6.1.2.1.1.1.0']
        Name             = $system['1.3.6.1.2.1.1.5.0']
        Location         = $system['1.3.6.1.2.1.1.6.0']
        ObjectId         = $system['1.3.6.1.2.1.1.2.0']
        # Only whether a default community answered: the communities themselves stay out of the audit.
        DefaultCommunity = $community -in 'public', 'private'
        Model            = & $first (& $walk '1.3.6.1.2.1.47.1.1.1.1.13' 10)
        Serial           = & $first (& $walk '1.3.6.1.2.1.47.1.1.1.1.11' 10)
        Firmware         = & $first (& $walk '1.3.6.1.2.1.47.1.1.1.1.10' 10)
        Ups              = $null
        Printer          = $null
        Vlans            = @()
        Neighbors        = @()
        Networks         = @()
    }

    $ups = & $get '1.3.6.1.2.1.33.1.1.1.0', '1.3.6.1.2.1.33.1.1.2.0', '1.3.6.1.2.1.33.1.1.3.0', '1.3.6.1.2.1.33.1.2.1.0', '1.3.6.1.2.1.33.1.2.3.0', '1.3.6.1.2.1.33.1.2.4.0'
    $apc = '1.3.6.1.4.1.318.1.1.1'
    $apcValues = & $get "$apc.1.1.1.0", "$apc.1.2.1.0", "$apc.1.2.2.0", "$apc.1.2.3.0", "$apc.2.1.1.0", "$apc.2.1.3.0", "$apc.2.2.1.0", "$apc.2.2.3.0", "$apc.2.2.4.0"
    $isApc = [bool]$apcValues["$apc.1.1.1.0"]
    if ($isApc -or $ups['1.3.6.1.2.1.33.1.1.2.0'] -or $null -ne $ups['1.3.6.1.2.1.33.1.2.1.0']) {
        $status = if ($isApc) { $apcValues["$apc.2.1.1.0"] } else { $ups['1.3.6.1.2.1.33.1.2.1.0'] }
        $info.Ups = [pscustomobject]@{
            Manufacturer    = $(if ($isApc) { 'APC' } else { "$($ups['1.3.6.1.2.1.33.1.1.1.0'])".Trim() })
            Model           = $(if ($isApc) { $apcValues["$apc.1.1.1.0"] } else { "$($ups['1.3.6.1.2.1.33.1.1.2.0'])".Trim() })
            Firmware        = $(if ($isApc) { $apcValues["$apc.1.2.1.0"] } else { $ups['1.3.6.1.2.1.33.1.1.3.0'] })
            Serial          = $apcValues["$apc.1.2.3.0"]
            Manufactured    = $apcValues["$apc.1.2.2.0"]
            Battery         = $(switch ([int]$status) { 2 { 'Normal' } 3 { 'Low' } 4 { if ($isApc) { 'Fault' } else { 'Depleted' } } 5 { 'No battery' } default { 'Unknown' } })
            ChargePercent   = $(if ($isApc) { $apcValues["$apc.2.2.1.0"] } else { $ups['1.3.6.1.2.1.33.1.2.4.0'] })
            # APC gives the runtime in hundredths of a second.
            MinutesLeft     = $(if ($isApc -and $null -ne $apcValues["$apc.2.2.3.0"]) { [math]::Round($apcValues["$apc.2.2.3.0"] / 6000) } else { $ups['1.3.6.1.2.1.33.1.2.3.0'] })
            BatteryReplaced = $apcValues["$apc.2.1.3.0"]
            ReplaceBattery  = $apcValues["$apc.2.2.4.0"] -eq 2
        }
        if (-not $info.Model) {
            $info.Model = "$($info.Ups.Manufacturer) $($info.Ups.Model)".Trim()
        }
        if (-not $info.Serial) {
            $info.Serial = $info.Ups.Serial
        }
    }

    $printer = & $get '1.3.6.1.2.1.25.3.2.1.3.1', '1.3.6.1.2.1.43.5.1.1.17.1', '1.3.6.1.2.1.43.10.2.1.4.1.1'
    if ($printer['1.3.6.1.2.1.43.5.1.1.17.1'] -or $null -ne $printer['1.3.6.1.2.1.43.10.2.1.4.1.1']) {
        $info.Printer = [pscustomobject]@{ Model = $printer['1.3.6.1.2.1.25.3.2.1.3.1']; Serial = $printer['1.3.6.1.2.1.43.5.1.1.17.1']; Pages = $printer['1.3.6.1.2.1.43.10.2.1.4.1.1'] }
        if (-not $info.Model) {
            $info.Model = $info.Printer.Model
        }
        if (-not $info.Serial) {
            $info.Serial = $info.Printer.Serial
        }
    }

    # VLAN names of Q-BRIDGE-MIB, else of Cisco's VTP (whose 1002-1005 are always there).
    $vlans = & $walk '1.3.6.1.2.1.17.7.1.4.3.1.1'
    if ($vlans.Count -eq 0) {
        $vlans = & $walk '1.3.6.1.4.1.9.9.46.1.3.1.1.4.1'
        foreach ($id in 1002..1005) {
            $vlans.Remove("$id")
        }
    }
    $info.Vlans = @($vlans.Keys | Where-Object { $_ -match '^\d+$' } | Sort-Object { [int]$_ } | ForEach-Object { [pscustomobject]@{ Id = [int]$_; Name = "$($vlans[$_].Value)".Trim() } })

    # LLDP neighbours: index timeMark.localPort.remoteIndex; their management address follows it.
    $lldp = '1.0.8802.1.1.2.1.4.1.1'
    $chassis = & $walk "$lldp.5"
    $names = & $walk "$lldp.9"
    if ($chassis.Count -or $names.Count) {
        $portIds = & $walk "$lldp.7"
        $portDescriptions = & $walk "$lldp.8"
        $localIds = & $walk '1.0.8802.1.1.2.1.3.7.1.3'
        $localDescriptions = & $walk '1.0.8802.1.1.2.1.3.7.1.4'
        $addresses = @{}
        foreach ($index in (& $walk '1.0.8802.1.1.2.1.4.2.1.3').Keys) {
            $parts = $index -split '\.'
            if ($parts.Count -eq 9 -and $parts[3] -eq '1' -and $parts[4] -eq '4') {
                $addresses[($parts[0..2] -join '.')] = $parts[5..8] -join '.'
            }
        }
        $info.Neighbors = @(@($chassis.Keys) + @($names.Keys) | Select-Object -Unique | ForEach-Object {
                $port = ($_ -split '\.')[1]
                $localId = $localIds[$port]
                $remoteId = $portIds[$_]
                [pscustomobject]@{
                    Protocol  = 'LLDP'
                    # The port's name, else its description when the name is a MAC address.
                    LocalPort = $(if ("$($localId.Value)".Trim() -and "$($localId.Value)" -notmatch '^[0-9A-F]{2}(:[0-9A-F]{2}){5}$') { "$($localId.Value)" } elseif ($localDescriptions[$port]) { "$($localDescriptions[$port].Value)" } else { $port })
                    Name      = $(if ($names[$_]) { "$($names[$_].Value)" } elseif ($chassis[$_]) { "$($chassis[$_].Value)" })
                    Port      = $(if ($portDescriptions[$_] -and "$($portDescriptions[$_].Value)".Trim()) { "$($portDescriptions[$_].Value)" } elseif ($remoteId) { "$($remoteId.Value)" })
                    Address   = $addresses[$_]
                }
            })
    }
    else {
        # CDP neighbours (Cisco): index ifIndex.deviceIndex; the address is 4 bytes.
        $cdp = '1.3.6.1.4.1.9.9.23.1.2.1.1'
        $devices = & $walk "$cdp.6"
        if ($devices.Count) {
            $ports = & $walk "$cdp.7"
            $cdpAddresses = & $walk "$cdp.4"
            $interfaces = @{}
            foreach ($index in $devices.Keys) {
                $interface = ($index -split '\.')[0]
                if (-not $interfaces.ContainsKey($interface)) {
                    $interfaces[$interface] = (& $get "1.3.6.1.2.1.31.1.1.1.1.$interface")["1.3.6.1.2.1.31.1.1.1.1.$interface"]
                }
            }
            $info.Neighbors = @($devices.Keys | ForEach-Object {
                    $bytes = $cdpAddresses[$_].Bytes
                    [pscustomobject]@{
                        Protocol  = 'CDP'
                        LocalPort = $(if ($interfaces[($_ -split '\.')[0]]) { $interfaces[($_ -split '\.')[0]] } else { ($_ -split '\.')[0] })
                        Name      = "$($devices[$_].Value)"
                        Port      = $(if ($ports[$_]) { "$($ports[$_].Value)" })
                        Address   = $(if ($bytes -and $bytes.Count -eq 4) { $bytes -join '.' })
                    }
                })
        }
    }

    # The device's own addresses (ipAddrTable): a router's or firewall's networks.
    $masks = & $walk '1.3.6.1.2.1.4.20.1.3' 64
    $info.Networks = @($masks.Keys | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and "$($masks[$_].Value)" -match '^\d{1,3}(\.\d{1,3}){3}$' } | ForEach-Object { [pscustomobject]@{ Address = $_; Mask = "$($masks[$_].Value)" } })
    return [pscustomobject]$info
}

# The UPnP devices of this computer's networks (SSDP, UDP 1900): address -> where their description
# is, which tells their maker, model and serial number. Asked of every device (multicast), or of one
# address and port (the tests' fake device).
function Get-UpnpLocations {
    param(
        [int]$WaitMs = 3000,
        [string]$Address = '239.255.255.250',
        [int]$Port = 1900
    )

    $locations = @{}
    $request = [Text.Encoding]::ASCII.GetBytes("M-SEARCH * HTTP/1.1`r`nHOST: $($Address):$Port`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`nST: ssdp:all`r`n`r`n")
    $udp = New-Object System.Net.Sockets.UdpClient(0)
    try {
        $udp.Client.ReceiveTimeout = 300
        foreach ($try in 1, 2) {
            [void]$udp.Send($request, $request.Length, $Address, $Port)
        }
        $until = (Get-Date).AddMilliseconds($WaitMs)
        while ((Get-Date) -lt $until) {
            $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            try {
                $answer = $udp.Receive([ref]$remote)
            }
            catch {
                continue
            }
            if ([Text.Encoding]::ASCII.GetString($answer) -match '(?im)^LOCATION:\s*(\S+)') {
                $address = $remote.Address.ToString()
                if (-not $locations.ContainsKey($address)) {
                    $locations[$address] = New-Object System.Collections.Generic.List[string]
                }
                if ($locations[$address].Count -lt 3 -and -not $locations[$address].Contains($Matches[1])) {
                    $locations[$address].Add($Matches[1])
                }
            }
        }
    }
    catch {
        Write-Warning "UPnP devices could not be asked: $($_.Exception.Message)"
    }
    finally {
        $udp.Close()
    }
    return $locations
}

# The maker, model and serial number in a UPnP description, read only from the device's own address.
function Get-UpnpDescription {
    param(
        [string]$Address,
        [string]$Location
    )

    if ($Location -notmatch '^(?<scheme>https?)://(?<host>[^/:]+)(?::(?<port>\d+))?(?<path>/\S*)?$' -or $Matches.host -ne $Address) {
        return $null
    }
    $tls = $Matches.scheme -eq 'https'
    $port = if ($Matches.port) { [int]$Matches.port } elseif ($tls) { 443 } else { 80 }
    $path = if ($Matches.path) { $Matches.path } else { '/' }
    $page = Get-AuditWebInfo -HostName $Address -Port $port -Tls $tls -Path $path -TimeoutMs 3000 -KeepBody
    if (-not $page -or $page.Status -ne 200 -or -not $page.Body) {
        return $null
    }
    try {
        $xml = [xml]($page.Body.Trim().TrimStart([char]0xFEFF))
    }
    catch {
        return $null
    }
    $device = $xml.root.device
    if (-not $device) {
        return $null
    }
    $model = "$($device.modelName)".Trim()
    $number = "$($device.modelNumber)".Trim()
    if ($number -and $model -notlike "*$number*") {
        $model = "$model $number".Trim()
    }
    return [pscustomobject]@{
        Name         = "$($device.friendlyName)".Trim()
        Manufacturer = "$($device.manufacturer)".Trim()
        Model        = $model
        Serial       = "$($device.serialNumber)".Trim()
        DeviceType   = ("$($device.deviceType)" -replace '^urn:schemas-upnp-org:device:', '' -replace ':\d+$', '').Trim()
    }
}

# What a WS-Discovery answer (ProbeMatches) tells: the device's types (ONVIF cameras and recorders are
# NetworkVideoTransmitter, printers PrintDeviceType...) and, for cameras, the name and model in their
# ONVIF scopes.
function Read-WsdAnswer {
    param(
        [string]$Text
    )

    $types = if ($Text -match '<(?:\w+:)?Types>([^<]*)<') { @($Matches[1] -split '\s+' | Where-Object { $_ } | ForEach-Object { ($_ -split ':')[-1] }) } else { @() }
    $scopes = if ($Text -match '<(?:\w+:)?Scopes[^>]*>([^<]*)<') { @($Matches[1] -split '\s+' | Where-Object { $_ }) } else { @() }
    $scope = {
        param([string]$Name)
        @($scopes | Where-Object { $_ -like "onvif://www.onvif.org/$Name/*" } | ForEach-Object { [uri]::UnescapeDataString($_.Substring("onvif://www.onvif.org/$Name/".Length)) }) | Select-Object -First 1
    }
    return [pscustomobject]@{ Types = $types; Name = & $scope 'name'; Hardware = & $scope 'hardware' }
}

# The WS-Discovery devices of this computer's networks (UDP 3702): address -> what they tell. Asked of
# every device (multicast), or of one address and port (the tests' fake device).
function Get-WsdDevices {
    param(
        [int]$WaitMs = 3000,
        [string]$Address = '239.255.255.250',
        [int]$Port = 3702
    )

    $devices = @{}
    $udp = New-Object System.Net.Sockets.UdpClient(0)
    try {
        $udp.Client.ReceiveTimeout = 300
        # A probe of every type, and one of ONVIF cameras, which some answer only.
        foreach ($types in '', '<wsd:Types xmlns:dn="http://www.onvif.org/ver10/network/wsdl">dn:NetworkVideoTransmitter</wsd:Types>') {
            $probe = [Text.Encoding]::UTF8.GetBytes(('<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:{0}</wsa:MessageID><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To></soap:Header><soap:Body><wsd:Probe>{1}</wsd:Probe></soap:Body></soap:Envelope>' -f [guid]::NewGuid(), $types))
            [void]$udp.Send($probe, $probe.Length, $Address, $Port)
        }
        $until = (Get-Date).AddMilliseconds($WaitMs)
        while ((Get-Date) -lt $until) {
            $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            try {
                $answer = [Text.Encoding]::UTF8.GetString($udp.Receive([ref]$remote))
            }
            catch {
                continue
            }
            # A device answers each probe: what both say.
            $new = Read-WsdAnswer $answer
            $address = $remote.Address.ToString()
            $known = $devices[$address]
            $devices[$address] = [pscustomobject]@{
                Types    = @(@($known.Types) + @($new.Types) | Where-Object { $_ } | Select-Object -Unique)
                Name     = $(if ($known.Name) { $known.Name } else { $new.Name })
                Hardware = $(if ($known.Hardware) { $known.Hardware } else { $new.Hardware })
            }
        }
    }
    catch {
        Write-Warning "WS-Discovery devices could not be asked: $($_.Exception.Message)"
    }
    finally {
        $udp.Close()
    }
    return $devices
}

# Examines one device in a runspace of its own: names, SNMP, web pages and UPnP description.
$examineDevice = {
    param(
        [string]$Address,
        [int[]]$WebPorts,
        [int[]]$PlainHttpPorts,
        [string[]]$Communities,
        [string[]]$UpnpLocations
    )

    $dnsName = $null
    try {
        $task = [System.Net.Dns]::GetHostEntryAsync($Address)
        if ($task.Wait(2500) -and $task.Result.HostName -ne $Address) {
            $dnsName = $task.Result.HostName
        }
    }
    catch {
        # No name in DNS.
    }
    $web = @(foreach ($port in $WebPorts) {
            $tls = $port -notin $PlainHttpPorts
            $page = Get-AuditWebInfo -HostName $Address -Port $port -Tls $tls -TimeoutMs 3000
            # The other scheme when this one got nothing, or a plain request refused by an HTTPS port.
            if (-not $page -or ($page.Status -eq 400 -and -not $tls)) {
                $other = Get-AuditWebInfo -HostName $Address -Port $port -Tls (-not $tls) -TimeoutMs 3000
                if ($other) {
                    $page = $other
                }
            }
            if ($page) {
                $page
            }
        })
    $upnp = $null
    foreach ($location in @($UpnpLocations | Where-Object { $_ })) {
        $upnp = Get-UpnpDescription -Address $Address -Location $location
        if ($upnp) {
            break
        }
    }
    [pscustomobject]@{
        Address = $Address
        DnsName = $dnsName
        NetBios = Get-NetBiosInfo -Address $Address
        Snmp    = Get-SnmpInfo -Address $Address -Communities $Communities
        Web     = $web
        Upnp    = $upnp
    }
}

# MAC vendors from the Wireshark list, cached for 90 days: 24-bit prefixes, and the 28- and 36-bit
# blocks of vendors that share one.
function Get-MacVendors {
    $vendors = @{}
    $path = Get-AuditCacheFile -Name 'mac-vendors.txt' -Uri 'https://www.wireshark.org/download/automated/data/manuf' -MaxAgeDays 90
    if (-not $path) {
        return $vendors
    }
    foreach ($line in [System.IO.File]::ReadLines($path)) {
        if ($line -match '^(?<prefix>[0-9A-Fa-f:]{8,17})(?:/(?<bits>\d+))?\s*\t(?<short>[^\t]*)(?:\t(?<long>.*))?$') {
            $bits = if ($Matches.bits) { [int]$Matches.bits } else { 24 }
            $hex = ($Matches.prefix -replace ':', '').ToUpper()
            $key = $hex.Substring(0, [math]::Min($hex.Length, $bits / 4))
            $vendors[$key] = if ($Matches.long) { $Matches.long.Trim() } else { $Matches.short.Trim() }
        }
    }
    return $vendors
}

function Get-MacVendor {
    param(
        [hashtable]$Vendors,
        [string]$Mac
    )

    $hex = ($Mac -replace '[:-]', '').ToUpper()
    if ($hex.Length -lt 6) {
        return $null
    }
    # A locally administered address: a phone or computer hiding its own (private Wi-Fi address).
    if ([Convert]::ToInt32($hex.Substring(1, 1), 16) -band 2) {
        return 'Private address'
    }
    foreach ($length in 9, 7, 6) {
        $vendor = $Vendors[$hex.Substring(0, $length)]
        if ($vendor) {
            return ($vendor -replace ',?\s+(Inc\.?|Corporation|Corp\.?|Co\.,?\s*Ltd\.?|Ltd\.?|LLC|GmbH|S\.?A\.?|B\.?V\.?|AG|Limited|Incorporated)$', '').Trim()
        }
    }
    return $null
}

# The type of a device, from all it showed: the gateway, its ports, vendor, SNMP, UPnP and WS-Discovery,
# web pages and names.
function Get-DeviceType {
    param(
        $Device
    )

    $ports = @($Device.Ports)
    $text = (@($Device.Vendor, $Device.Model, $Device.Snmp.Description, $Device.Name, $Device.Upnp.Manufacturer, $Device.Upnp.Model, $Device.Upnp.Name, $Device.Wsd.Hardware, $Device.Wsd.Name) +
        @($Device.Web | ForEach-Object { $_.Title; $_.Server; $_.CertificateSubject; $_.CertificateIssuer }) | Where-Object { $_ }) -join ' '
    $wsdTypes = "$($Device.Wsd.Types)"
    switch -Regex ($text) {
        'iDRAC' { return 'Server management (iDRAC)' }
        # An iLO's own certificate is named ILO and its serial number.
        '\biLO\b|\bILO[0-9A-Z]{6,}\b|Integrated Lights' { return 'Server management (iLO)' }
        'XClarity|\bIMM2?\b' { return 'Server management (XClarity)' }
        'Supermicro|\bIPMI\b|\bBMC\b' { return 'Server management (BMC)' }
    }
    if ($Device.IsThisComputer) {
        return 'This computer'
    }
    if ($Device.IsGateway) {
        return 'Firewall / router'
    }
    switch -Regex ($text) {
        'ESXi|VMware ESX' { return 'Hypervisor (VMware ESXi)' }
        'vCenter|vSphere' { return 'VMware vCenter' }
        'Proxmox' { return 'Hypervisor (Proxmox)' }
        'Synology|DiskStation' { return 'NAS (Synology)' }
        'QNAP|\bQTS\b' { return 'NAS (QNAP)' }
        'TrueNAS|FreeNAS' { return 'NAS (TrueNAS)' }
        'Veeam' { return 'Backup server (Veeam)' }
        'Atempo|\bTina\b' { return 'Backup appliance' }
    }
    # A NAS can show the UPS plugged into it: it stays a NAS above.
    if ($Device.Snmp.Ups) {
        return 'UPS'
    }
    if ($Device.Snmp.Printer -or $wsdTypes -match 'Print') {
        return 'Printer'
    }
    if ($wsdTypes -match 'NetworkVideoTransmitter') {
        return 'Camera / recorder'
    }
    if ($ports -contains 902 -and $ports -contains 443) {
        return 'Hypervisor (VMware ESXi)'
    }
    if ($ports -contains 8006) {
        return 'Hypervisor (Proxmox)'
    }
    if ($ports -contains 9419) {
        return 'Backup server (Veeam)'
    }
    if ($ports -contains 88 -and $ports -contains 389) {
        return 'Domain controller'
    }
    switch -Regex ($text) {
        '\bAPC\b|American Power|Schneider Electric|Eaton|Powerware|Network Management Card|Riello|\bUPS\b|Socomec' { return 'UPS' }
        'Fortinet|FortiGate|SonicWall|WatchGuard|Sophos|pfSense|OPNsense|Stormshield|ZyWALL|USG FLEX|\bATP\d+|Palo Alto|Check Point' { return 'Firewall' }
        '\b(NWA|WAX|WAC)\d|Access Point|UniFi AP|\bU6\b|\bUAP\b|Aruba Instant|Ruckus|\bEAP\d|Omada' { return 'Wi-Fi access point' }
        'Switch|ProCurve|\bX?GS\d{3,4}|\bXS\d{4}|Catalyst|Aruba \d{4}|OfficeConnect|\bSG\d{3}|\bCBS\d{3}|\bUSW\b' { return 'Switch' }
        'Printer|LaserJet|OfficeJet|DeskJet|Ricoh|Kyocera|Brother|Canon|Xerox|Konica|Lexmark|Epson|\bSharp\b|Toshiba TEC' { return 'Printer' }
        'Hikvision|Dahua|Axis Communications|Reolink|Uniview|\bNVR\b|\bDVR\b|Camera' { return 'Camera / recorder' }
        'Yealink|\bSnom\b|Polycom|Grandstream|Gigaset|Panasonic.*KX|Cisco IP Phone|Fanvil' { return 'IP phone' }
        'ZKTeco|Suprema|Anviz|Horoquartz|Kelio|Bodet|Time ?clock' { return 'Time clock / access control' }
        'Sonos|\bBose\b|Denon|Yamaha' { return 'Audio device' }
        'Espressif|\bTuya\b|Shelly|Sonoff|Philips Lighting|Signify|\bNest\b|\bRing\b' { return 'IoT device' }
        'Ubiquiti' { return 'Network device (Ubiquiti)' }
        'Zyxel|Cisco|Aruba|HPE Networking|Juniper|MikroTik|TP-Link|D-Link|Netgear|Draytek|Teltonika|Huawei|Arista' { return 'Network device' }
        'Apple' { return 'Apple device' }
        'Private address' { return 'Phone / laptop' }
        'Microsoft' { if ($Device.Vendor -eq 'Microsoft') { return 'Hyper-V virtual machine' } }
        'VMware' { if ($Device.Vendor -match 'VMware') { return 'VMware virtual machine' } }
    }
    if ($Device.Upnp.DeviceType -match 'InternetGatewayDevice') {
        return 'Firewall / router'
    }
    if ($ports -contains 9100 -or $ports -contains 515 -or $ports -contains 631) {
        return 'Printer'
    }
    if ($ports -contains 554) {
        return 'Camera / recorder'
    }
    if ($ports -contains 5060) {
        return 'IP phone'
    }
    if ($ports -contains 3389 -or ($ports -contains 445 -and $ports -contains 135)) {
        if ($ports -contains 1433 -or $ports -contains 5985 -or "$($Device.Name)" -match '(?i)SRV|SERV|^DC|HV|HOST') {
            return 'Windows server'
        }
        return 'Windows computer'
    }
    if ($ports -contains 22 -and $Device.Ttl -and $Device.Ttl -le 64) {
        return 'Linux / Unix'
    }
    return 'Unknown'
}

# A short text that tells what the device is: its model, SNMP description, web page titles or certificate.
function Get-DeviceIdentification {
    param(
        $Device
    )

    $parts = @()
    if ($Device.Model) {
        $parts += $Device.Model
    }
    if ($Device.Snmp -and $Device.Snmp.Description) {
        $parts += ($Device.Snmp.Description -split '[\r\n]')[0]
    }
    $parts += @($Device.Web | ForEach-Object { $_.Title } | Where-Object { $_ })
    if ($parts.Count -eq 0 -and $Device.Upnp.Name) {
        $parts += $Device.Upnp.Name
    }
    if ($parts.Count -eq 0) {
        $parts += @($Device.Web | Where-Object { $_.CertificateSubject } | ForEach-Object { Get-AuditCommonName $_.CertificateSubject } | Where-Object { $_ -notmatch '^\d{1,3}(\.\d{1,3}){3}$' })
        $parts += @($Device.Web | ForEach-Object { $_.Server } | Where-Object { $_ })
    }
    $text = (@($parts | Select-Object -Unique) -join ' / ')
    if ($text.Length -gt 90) {
        $text = $text.Substring(0, 87) + '...'
    }
    return $text
}

# Finds the devices of these networks (but no address already scanned) and examines each one.
function Find-Devices {
    param(
        [object[]]$Ranges
    )

    $targets = @(foreach ($range in $Ranges) {
            foreach ($number in $range.Numbers) {
                if ($script:Scanned.Add($number)) {
                    $number
                }
            }
        })
    if ($targets.Count -eq 0) {
        return
    }
    $localAddresses = @($local | ForEach-Object { $_.Address })
    $gateways = @($local | ForEach-Object { $_.Gateway } | Where-Object { $_ })

    $pingAnswers = Invoke-PingSweep -Targets $targets
    # The ping asked ARP for each address of this computer's networks: those that answered it are there too.
    $neighbors = @{}
    foreach ($entry in @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        if ("$($entry.State)" -in 'Reachable', 'Stale', 'Delay', 'Probe', 'Permanent' -and $entry.LinkLayerAddress -and
            $entry.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF|01-00-5E)') {
            $neighbors[$entry.IPAddress] = $entry.LinkLayerAddress -replace '-', ':'
        }
    }
    $targetSet = New-Object 'System.Collections.Generic.HashSet[long]'
    foreach ($number in $targets) {
        [void]$targetSet.Add($number)
    }
    $found = @{}
    foreach ($number in $targets) {
        $address = ConvertTo-IPText $number
        if ($pingAnswers.ContainsKey($number) -or $neighbors.ContainsKey($address) -or $address -in $localAddresses) {
            $found[$address] = $number
        }
    }
    # Addresses that answered neither, e.g. behind a router: a few common ports.
    $silent = @($targets | ForEach-Object { ConvertTo-IPText $_ } | Where-Object { -not $found.ContainsKey($_) })
    if ($silent.Count -gt 0 -and $silent.Count -le 4096) {
        $quick = Test-TcpPorts -Addresses $silent -Ports $quickPorts -TimeoutMs 800 -Status 'Silent addresses'
        foreach ($address in $quick.Keys) {
            $found[$address] = ConvertTo-IPNumber $address
        }
    }
    $addresses = @($found.Keys | Sort-Object -Property { $found[$_] })
    if ($addresses.Count -eq 0) {
        return
    }

    Write-Progress -Id 20 -Activity 'Network audit' -Status "Ports of $($addresses.Count) devices" -PercentComplete 40
    $openPorts = Test-TcpPorts -Addresses $addresses -Ports ([int[]]@($portNames.Keys | Sort-Object)) -TimeoutMs 1500 -Status "Ports of $($addresses.Count) devices"

    # Names, SNMP, web pages and UPnP descriptions of each device, several at once.
    $state = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($name in 'Get-AuditWebInfo', 'Get-NetBiosInfo', 'Get-SnmpInfo', 'Invoke-SnmpRequest', 'Invoke-SnmpWalk', 'New-SnmpRequest', 'ConvertTo-Ber',
        'ConvertTo-BerInteger', 'ConvertTo-BerOid', 'Read-BerItem', 'ConvertFrom-BerOid', 'ConvertFrom-BerValue', 'Read-SnmpResponse', 'Get-UpnpDescription') {
        $state.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($name, (Get-Item "function:$name").Definition)))
    }
    # Not given $Host: the devices write nothing to it, and a pool given $Host where there is no console
    # (the audit window) loses every Write-Host that comes after it.
    $pool = [runspacefactory]::CreateRunspacePool($state)
    [void]$pool.SetMaxRunspaces($ThrottleLimit)
    $pool.Open()
    try {
        $jobs = @(foreach ($address in $addresses) {
                $shell = [powershell]::Create()
                $shell.RunspacePool = $pool
                $ports = @($webPorts | Where-Object { @($openPorts[$address]) -contains $_ })
                [void]$shell.AddScript($examineDevice).AddArgument($address).AddArgument([int[]]$ports).AddArgument([int[]]$plainHttpPorts).AddArgument([string[]]$communities).AddArgument([string[]]@($script:UpnpLocations[$address]))
                [pscustomobject]@{ Address = $address; Shell = $shell; Handle = $shell.BeginInvoke() }
            })
        while (($pending = @($jobs | Where-Object { -not $_.Handle.IsCompleted }).Count) -gt 0) {
            Write-Progress -Id 20 -Activity 'Network audit' -Status "Names, SNMP and web pages: $($jobs.Count - $pending) of $($jobs.Count) devices" -PercentComplete (50 + 45 * ($jobs.Count - $pending) / $jobs.Count)
            Start-Sleep -Milliseconds 300
        }
        $details = @{}
        foreach ($job in $jobs) {
            try {
                $details[$job.Address] = @($job.Shell.EndInvoke($job.Handle)) | Select-Object -First 1
            }
            catch {
                Write-Warning "$($job.Address) could not be examined: $($_.Exception.Message)"
            }
            $job.Shell.Dispose()
        }
    }
    finally {
        $pool.Close()
        $pool.Dispose()
    }

    $localMacs = @{}
    foreach ($network in $local) {
        $localMacs[$network.Address] = $network.Mac
    }
    foreach ($address in $addresses) {
        $detail = $details[$address]
        $mac = if ($neighbors[$address]) { $neighbors[$address] } elseif ($localMacs[$address]) { $localMacs[$address] } elseif ($detail -and $detail.NetBios) { $detail.NetBios.Mac }
        $netBios = if ($detail) { $detail.NetBios }
        $dnsName = if ($detail) { $detail.DnsName }
        $snmp = if ($detail) { $detail.Snmp }
        $upnp = if ($detail) { $detail.Upnp }
        $wsd = $script:WsdDevices[$address]
        $snmpVendor = if ("$($snmp.ObjectId)" -match '^1\.3\.6\.1\.4\.1\.(\d+)') { $snmpVendors[[int]$Matches[1]] }
        # Assigned here, since $(...) would make an empty list $null.
        $web = @()
        if ($detail) {
            $web = @($detail.Web | Where-Object { $_ })
        }
        $number = $found[$address]
        $device = [pscustomobject]@{
            Address            = $address
            Network            = (@($Ranges | Where-Object { $_.Set.Contains($number) }) | Select-Object -First 1).Name
            Name               = $(if ($netBios -and $netBios.Name) { $netBios.Name } elseif ($dnsName) { ($dnsName -split '\.')[0] } elseif ($snmp -and $snmp.Name) { $snmp.Name } elseif ($upnp -and $upnp.Name) { $upnp.Name } elseif ($wsd -and $wsd.Name) { $wsd.Name })
            DnsName            = $dnsName
            NetBiosDomain      = $(if ($netBios) { $netBios.Domain })
            Mac                = $mac
            Vendor             = $(if ($mac) { Get-MacVendor -Vendors $script:Vendors -Mac $mac } elseif ($snmpVendor) { $snmpVendor } elseif ($upnp -and $upnp.Manufacturer) { $upnp.Manufacturer })
            Ttl                = $pingAnswers[$number]
            Ports              = @($openPorts[$address] | Where-Object { $null -ne $_ } | Sort-Object)
            Snmp               = $snmp
            Upnp               = $upnp
            Wsd                = $wsd
            Web                = $web
            Model              = $(if ($snmp -and $snmp.Model) { $snmp.Model } elseif ($upnp -and $upnp.Model) { "$($upnp.Manufacturer) $($upnp.Model)".Trim() } elseif ($wsd -and $wsd.Hardware) { $wsd.Hardware })
            Serial             = $(if ($snmp -and $snmp.Serial) { $snmp.Serial } elseif ($upnp -and $upnp.Serial) { $upnp.Serial })
            Firmware           = $(if ($snmp) { $snmp.Firmware })
            IsGateway          = $address -in $gateways
            IsThisComputer     = $address -in $localAddresses
            IsDomainController = [bool]($netBios -and $netBios.DomainController)
            Type               = $null
            Identification     = $null
        }
        if (-not $device.Vendor -and $snmpVendor) {
            $device.Vendor = $snmpVendor
        }
        $device.Type = Get-DeviceType $device
        if ($device.IsDomainController -and $device.Type -match 'Windows|Unknown') {
            $device.Type = 'Domain controller'
        }
        $device.Identification = Get-DeviceIdentification $device
        $device
    }
}

# Networks seen from here but not scanned: routes of this computer through a router of its own
# networks (not those of a VPN), its DNS and DHCP servers elsewhere, the addresses of the routers and
# firewalls that answered SNMP, and the routers on the way to the Internet. Private networks only.
function Get-OtherNetworks {
    param(
        [object[]]$Devices,
        [object[]]$Hops
    )

    $seen = [ordered]@{}
    $add = {
        param([string]$Network, [string]$Address, [string]$Reason)
        if ((Get-AddressKind $Address) -ne 'Private' -or $script:Scanned.Contains((ConvertTo-IPNumber $Address))) {
            return
        }
        if (-not $seen.Contains($Network)) {
            $seen[$Network] = [pscustomobject]@{ Network = $Network; Seen = New-Object System.Collections.Generic.List[string] }
        }
        if (-not $seen[$Network].Seen.Contains($Reason)) {
            $seen[$Network].Seen.Add($Reason)
        }
    }
    $ownNetworks = @($local | Where-Object { $_.Gateway })
    foreach ($route in @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        if ("$($route.NextHop)" -eq '0.0.0.0' -or "$($route.DestinationPrefix)" -notmatch '^(?<ip>\d{1,3}(\.\d{1,3}){3})/(?<bits>\d{1,2})$') {
            continue
        }
        $ip = $Matches.ip
        $bits = [int]$Matches.bits
        $nextHop = "$($route.NextHop)"
        if ($bits -lt 16 -or $bits -gt 30 -or -not @($ownNetworks | Where-Object { (Get-NetworkName $_.Address $_.PrefixLength) -eq (Get-NetworkName $nextHop $_.PrefixLength) }).Count) {
            continue
        }
        & $add "$ip/$bits" (ConvertTo-IPText ((ConvertTo-IPNumber $ip) + 1)) "route of this computer via $nextHop"
    }
    foreach ($network in $ownNetworks) {
        foreach ($server in @($network.DnsServers | Where-Object { $_ })) {
            & $add (Get-NetworkName $server 24) $server "DNS server $server"
        }
        if ($network.DhcpServer) {
            & $add (Get-NetworkName $network.DhcpServer 24) $network.DhcpServer "DHCP server $($network.DhcpServer)"
        }
    }
    foreach ($device in $Devices) {
        foreach ($entry in @($device.Snmp.Networks | Where-Object { $_ })) {
            $bits = ConvertTo-PrefixLength $entry.Mask
            if ($bits -ge 16 -and $bits -le 30) {
                & $add (Get-NetworkName $entry.Address $bits) $entry.Address "address $($entry.Address) of $("$($device.Address) $($device.Name)".Trim()) (SNMP)"
            }
        }
    }
    foreach ($hop in @($Hops | Where-Object { $_ -and $_.Address })) {
        & $add (Get-NetworkName $hop.Address 24) $hop.Address "router $($hop.Hop) on the way to the Internet"
    }
    return @($seen.Values)
}

# A first network diagram for draw.io (diagrams.net), to complete on site: the Internet, the routers on
# the way to it, the firewall, then each network scanned with its devices, the network equipment first.
# Computers, phones and unknown devices are counted, not drawn one by one. A link is drawn between two
# devices where a switch told its neighbours (LLDP, CDP).
function Write-NetworkDiagram {
    param(
        [string]$Path,
        [object[]]$Devices,
        [object[]]$Ranges,
        [object[]]$Hops,
        $Public
    )

    $cells = New-Object System.Text.StringBuilder
    $state = @{ Id = 1 }
    $newId = {
        $state.Id++
        "c$($state.Id)"
    }
    $vertex = {
        param([string]$Id, [string[]]$Lines, [string]$Style, [int]$X, [int]$Y, [int]$Width, [int]$Height, [string]$Parent = '1')
        $label = (@($Lines | Where-Object { $_ } | ForEach-Object { [System.Net.WebUtility]::HtmlEncode("$_") })) -join '<br>'
        [void]$cells.AppendLine("        <mxCell id=`"$Id`" value=`"$([System.Security.SecurityElement]::Escape($label))`" style=`"$Style`" vertex=`"1`" parent=`"$Parent`"><mxGeometry x=`"$X`" y=`"$Y`" width=`"$Width`" height=`"$Height`" as=`"geometry`"/></mxCell>")
    }
    $edge = {
        param([string]$Source, [string]$Target, [string]$Label = '')
        $id = & $newId
        [void]$cells.AppendLine("        <mxCell id=`"$id`" value=`"$([System.Security.SecurityElement]::Escape([System.Net.WebUtility]::HtmlEncode($Label)))`" style=`"endArrow=none;html=1;rounded=0;fontSize=10;`" edge=`"1`" parent=`"1`" source=`"$Source`" target=`"$Target`"><mxGeometry relative=`"1`" as=`"geometry`"/></mxCell>")
    }
    $style = {
        param([string]$Type)
        $colors = switch -Regex ($Type) {
            'Firewall|router' { 'fillColor=#f8cecc;strokeColor=#b85450;'; break }
            'Switch|Network device' { 'fillColor=#dae8fc;strokeColor=#6c8ebf;'; break }
            'access point' { 'fillColor=#b1ddf0;strokeColor=#10739e;'; break }
            'Server management' { 'fillColor=#e1d5e7;strokeColor=#9673a6;'; break }
            'server|Domain controller|Hypervisor|vCenter|Linux' { 'fillColor=#d5e8d4;strokeColor=#82b366;'; break }
            'NAS|Backup' { 'fillColor=#ffe6cc;strokeColor=#d79b00;'; break }
            'UPS' { 'fillColor=#fff2cc;strokeColor=#d6b656;'; break }
            default { 'fillColor=#f5f5f5;strokeColor=#666666;' }
        }
        "rounded=1;whiteSpace=wrap;html=1;fontSize=11;$colors"
    }
    $short = {
        param([string]$Text)
        if ($Text.Length -gt 45) { $Text.Substring(0, 42) + '...' } else { $Text }
    }
    # Counted per network, not drawn one by one.
    $counted = '^(Windows computer|Phone / laptop|Apple device|IoT device|Audio device|Unknown|Hyper-V virtual machine|VMware virtual machine)$'
    $order = @('Firewall', 'Switch', 'Network device', 'Wi-Fi access point', 'Server management', 'Hypervisor', 'VMware vCenter', 'Domain controller', 'Windows server', 'Linux', 'NAS', 'Backup', 'UPS', 'Printer', 'Camera', 'IP phone', 'Time clock')
    $rank = {
        param([string]$Type)
        for ($index = 0; $index -lt $order.Count; $index++) {
            if ($Type -like "$($order[$index])*") { return $index }
        }
        return $order.Count
    }
    $ids = @{}

    $date = (Get-Date).ToString('yyyy-MM-dd')
    & $vertex (& $newId) @("Draft drawn by the MOSE audit on $date.", 'Devices found by the scan, by network; computers and phones are counted.', 'Links between devices come from the switches (LLDP, CDP) that answered SNMP: draw the others, and the switch ports, on site.') 'text;html=1;align=left;verticalAlign=top;whiteSpace=wrap;fontSize=11;' 900 20 380 90
    $internet = & $newId
    & $vertex $internet @('Internet', $(if ($Public) { $Public.Address }), $(if ($Public) { & $short "$($Public.Provider)" })) 'ellipse;shape=cloud;whiteSpace=wrap;html=1;fontSize=11;fillColor=#f5f5f5;strokeColor=#666666;' 40 20 220 110
    $previous = $internet
    $y = 160
    # The routers between the firewall and the Internet, from the Internet down.
    $routers = @($Hops | Where-Object { $_.Hop -gt 1 -and $_.Address -and $_.Kind -ne 'Public' })
    [array]::Reverse($routers)
    foreach ($router in $routers) {
        $id = & $newId
        & $vertex $id @("Router $($router.Address)", $(if ($router.Kind -eq 'Shared') { "provider's shared address (CGNAT)" } else { "router of the provider?" }), $router.Name) (& $style 'router') 40 $y 220 60
        & $edge $previous $id
        $previous = $id
        $y += 90
    }
    $gatewayDevices = @($Devices | Where-Object { $_.IsGateway })
    $firewalls = @(foreach ($gateway in $gatewayDevices) {
            $id = & $newId
            $ids[$gateway.Address] = $id
            & $vertex $id @("$(if ($gateway.Name) { $gateway.Name } else { $gateway.Address })", "Firewall / router $($gateway.Address)", (& $short "$($gateway.Identification)")) (& $style 'Firewall') 40 $y 220 70
            & $edge $previous $id
            $id
        })
    if ($firewalls.Count -eq 0) {
        $id = & $newId
        & $vertex $id @('Firewall / router', 'not found by the scan') (& $style 'Firewall') 40 $y 220 60
        & $edge $previous $id
        $firewalls = @($id)
    }
    $y += 110

    foreach ($range in $Ranges) {
        $members = @($Devices | Where-Object { $_.Network -eq $range.Name -and -not $_.IsGateway })
        $drawn = @($members | Where-Object { $_.Type -notmatch $counted } | Sort-Object -Property { & $rank $_.Type }, { ConvertTo-IPNumber $_.Address })
        $groups = @($members | Where-Object { $_.Type -match $counted } | Group-Object -Property Type | Sort-Object -Property Count -Descending)
        $count = $drawn.Count + $groups.Count
        $rows = [math]::Max(1, [math]::Ceiling($count / 4))
        $container = & $newId
        & $vertex $container @("Network $($range.Name): $($members.Count) devices") 'swimlane;html=1;startSize=26;fontStyle=1;align=left;spacingLeft=8;fillColor=#fafafa;strokeColor=#999999;' 40 $y 840 (36 + $rows * 90)
        & $edge $firewalls[0] $container
        $index = 0
        foreach ($device in $drawn) {
            $id = & $newId
            $ids[$device.Address] = $id
            & $vertex $id @("$(if ($device.Name) { $device.Name } else { $device.Address })", $device.Type, $(if ($device.Name) { $device.Address }), (& $short "$($device.Identification)")) (& $style $device.Type) (20 + ($index % 4) * 205) (36 + [math]::Floor($index / 4) * 90) 190 75 $container
            $index++
        }
        foreach ($group in $groups) {
            & $vertex (& $newId) @("$($group.Count) x $($group.Name)", 'their addresses are in the audit') (& $style $group.Name) (20 + ($index % 4) * 205) (36 + [math]::Floor($index / 4) * 90) 190 75 $container
            $index++
        }
        $y += 36 + $rows * 90 + 50
    }

    # Links told by the switches, once per pair of devices.
    $names = @{}
    foreach ($device in $Devices) {
        foreach ($name in @(@($device.Name, $device.DnsName, $device.Snmp.Name) | Where-Object { $_ })) {
            $names[("$name" -split '\.')[0].ToLower()] = $device.Address
        }
    }
    $linked = @{}
    foreach ($device in @($Devices | Where-Object { $ids[$_.Address] })) {
        foreach ($neighbor in @($device.Snmp.Neighbors | Where-Object { $_ })) {
            $other = if ($neighbor.Address -and $ids[$neighbor.Address]) { $neighbor.Address } elseif ($neighbor.Name) { $names[("$($neighbor.Name)" -split '\.')[0].ToLower()] }
            if (-not $other -or $other -eq $device.Address -or -not $ids[$other]) {
                continue
            }
            $key = (@($device.Address, $other) | Sort-Object) -join '-'
            if ($linked.ContainsKey($key)) {
                continue
            }
            $linked[$key] = $true
            & $edge $ids[$device.Address] $ids[$other] "$($neighbor.LocalPort) - $($neighbor.Port)"
        }
    }

    $xml = @"
<mxfile host="MOSE audit">
  <diagram id="network" name="Network">
    <mxGraphModel grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="0" pageScale="1" math="0" shadow="0">
      <root>
        <mxCell id="0"/>
        <mxCell id="1" parent="0"/>
$($cells.ToString().TrimEnd())
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
"@
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    [System.IO.File]::WriteAllText($fullPath, $xml, (New-Object System.Text.UTF8Encoding($false)))
    return $fullPath
}

Write-Progress -Id 20 -Activity 'Network audit' -Status 'This computer' -PercentComplete 0
$local = @(Get-LocalNetwork)
$wifi = @(Get-WifiConnection)
$wifiNearby = @(Get-WifiNetworks | Sort-Object -Property Signal -Descending)
$public = Get-PublicAddress
$computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
# "public" first: when it answers, that is a finding. The communities given are only kept in memory.
$communities = @(@('public') + @($SnmpCommunity | Where-Object { $_ -and $_ -ne 'public' }))

"### This computer"
"The audit ran on $env:COMPUTERNAME ($(if ($os) { "$($os.Caption) $($os.Version)" }), $(if ($computer -and $computer.PartOfDomain) { "domain $($computer.Domain)" } else { "workgroup $(if ($computer) { $computer.Workgroup })" })), as $([Security.Principal.WindowsIdentity]::GetCurrent().Name)."
""
if ($local.Count -gt 0) {
    Format-AuditTable -Rows ($local | ForEach-Object {
            [pscustomobject]@{
                Interface = "$($_.Interface) ($($_.Adapter))"
                Address   = "$($_.Address)/$($_.PrefixLength)"
                Gateway   = $_.Gateway
                Dns       = $_.DnsServers
                Dhcp      = $(if ($_.Dhcp) { "DHCP from $($_.DhcpServer)" } else { 'Fixed address' })
                Suffix    = $_.DnsSuffix
                Network   = $_.NetworkName
                Link      = $_.LinkSpeed
            }
        }) -Columns 'Interface', 'Address', 'Gateway', 'DNS servers=Dns', 'Address from=Dhcp', 'DNS suffix=Suffix', 'Network name=Network', 'Link'
}
else {
    "No connected network interface with an IPv4 address."
}

"`n### Wi-Fi"
if ($wifi.Count -gt 0) {
    Format-AuditTable -Rows $wifi -Columns 'Network=Ssid', 'Access point=Bssid', 'Security=Authentication', 'Encryption', 'Radio', 'Band', 'Channel', 'Signal'
}
else {
    "This computer is not connected to a Wi-Fi network."
}
if ($wifiNearby.Count -gt 0) {
    ""
    "Wi-Fi networks in range:"
    ""
    Format-AuditTable -Rows ($wifiNearby | Select-Object -Property *, @{ Name = 'SignalText'; Expression = { "$($_.Signal)%" } }) -Columns 'Network=Ssid', 'Security=Authentication', 'Encryption', 'Strongest signal=SignalText', 'Channels', 'Access points=AccessPoints'
}
elseif (@(netsh wlan show networks 2>$null) -match '(?i)location|emplacement|locatie') {
    ""
    "Windows hides the Wi-Fi networks in range: allow location services for desktop apps (Settings > Privacy & security > Location) to list them."
}
foreach ($connection in $wifi) {
    if ($connection.Authentication -match '(?i)open|ouvert|^WEP') {
        New-AuditFinding -Severity High -Area $area -Finding "The Wi-Fi '$($connection.Ssid)' is $($connection.Authentication): anyone near can join it or read it." -Recommendation 'Use WPA2/WPA3 with a long password, and a separate guest network.'
    }
    elseif ($connection.Authentication -match '(?i)WPA-|^WPA$' -or $connection.Encryption -match 'TKIP') {
        New-AuditFinding -Severity Medium -Area $area -Finding "The Wi-Fi '$($connection.Ssid)' uses $($connection.Authentication) $($connection.Encryption), which is outdated." -Recommendation 'Switch the access points to WPA2-AES or WPA3.'
    }
}

# The Internet line, before the scan so that its traffic doesn't slow the speed test.
Write-Progress -Id 20 -Activity 'Network audit' -Status 'Route to the Internet' -PercentComplete 2
$hops = @(Get-InternetPath)
$speed = $null
if (-not $SkipSpeedTest) {
    Write-Progress -Id 20 -Activity 'Network audit' -Status 'Speed test of the Internet line (about 30 seconds)' -PercentComplete 4
    $speed = Measure-InternetSpeed
}
$overWifi = $wifi.Count -gt 0 -and @($local | Where-Object { $_.Gateway -and $_.Adapter -notmatch '(?i)Wi-?Fi|Wireless|WLAN|802\.11' }).Count -eq 0
"`n### Internet line"
if ($public) {
    $addressType = Get-PublicAddressType $public.Name
    "Public address: $($public.Address)$(if ($public.Name) { " ($($public.Name))" })$(if ($public.Provider) { ", $($public.Provider)" })$(if ($public.Location) { ", $($public.Location)" }).$(if ($addressType) { " Its name says it is a $addressType address." })"
}
if ($speed) {
    "Speed measured from this computer$(if ($overWifi) { ' over Wi-Fi' }): $($speed.Download) Mbit/s down, $($speed.Upload) Mbit/s up, ping $($speed.Ping) ms (jitter $($speed.Jitter) ms), with the LibreSpeed server $($speed.Server). Over Wi-Fi or a 100 Mbit/s port this is the speed of that link, not of the line."
}
elseif ($SkipSpeedTest) {
    "No speed test (skipped)."
}
""
if ($hops.Count -gt 0) {
    "Route to the Internet (1.1.1.1):"
    ""
    Format-AuditTable -Rows ($hops | ForEach-Object {
            [pscustomobject]@{
                Hop     = $_.Hop
                Address = $(if ($_.Address) { $_.Address } else { 'no answer' })
                Name    = $_.Name
                Kind    = $(switch ($_.Kind) { 'Private' { 'private' } 'Shared' { "provider's shared address (CGNAT)" } 'Public' { 'Internet' } })
            }
        }) -Columns 'Hop', 'Address', 'Name', 'Network=Kind'
    $innerRouters = @($hops | Where-Object { $_.Hop -gt 1 -and $_.Address -and $_.Kind -eq 'Private' })
    if ($innerRouters.Count -gt 0) {
        ""
        "Between this computer's gateway and the Internet, $(if ($innerRouters.Count -eq 1) { 'another private router answers' } else { "$($innerRouters.Count) other private routers answer" }) ($(($innerRouters | ForEach-Object { $_.Address }) -join ', ')): a firewall behind the gateway, or the provider's router in front of the firewall (double NAT)."
        New-AuditFinding -Severity Info -Area $area -Finding "The Internet line goes through $(if ($innerRouters.Count -eq 1) { 'another private router' } else { "$($innerRouters.Count) private routers" }) after the gateway ($(($innerRouters | ForEach-Object { $_.Address }) -join ', ')): a firewall behind the gateway, or the provider's router in front of the firewall (double NAT)." -Recommendation "Note who manages each router; a provider's router in bridge mode gives the firewall the public address (simpler VPN and port forwarding)."
    }
    $shared = @($hops | Where-Object { $_.Kind -eq 'Shared' })
    if ($shared.Count -gt 0) {
        New-AuditFinding -Severity Low -Area $area -Finding "The Internet line goes through the provider's shared address $($shared[0].Address) (CGNAT): the office may have no public address of its own, so a VPN to the office or a port forwarding cannot work." -Recommendation 'If remote access to the office is needed, ask the provider for a public (fixed) address.'
    }
}
else {
    "No router answered on the way to the Internet (ICMP blocked): the route is unknown."
}

# The addresses to scan: the networks given, else those of this computer that have a gateway; and those added.
$ranges = @()
if ($Subnet) {
    foreach ($text in $Subnet) {
        $ranges += New-ScanRange $text
    }
}
else {
    foreach ($network in @($local | Where-Object { $_.Gateway })) {
        $name = "$($network.Address)/$($network.PrefixLength)"
        if ([math]::Pow(2, 32 - $network.PrefixLength) - 2 -gt $MaxHosts) {
            # A large network: only the /24 of this computer and of its gateway.
            $reduced = @(@(Get-AddressRange "$($network.Address)/24") + @(Get-AddressRange "$($network.Gateway)/24") | Sort-Object -Unique)
            Write-Warning "$(Get-NetworkName $network.Address $network.PrefixLength) is too large: only $($reduced.Count) addresses are scanned (the /24 of this computer and of its gateway). Give -Subnet or -AddSubnet to scan more."
            $ranges += New-ScanRange -Name "$(Get-NetworkName $network.Address $network.PrefixLength) (only the /24 of this computer and of its gateway)" -Numbers $reduced
        }
        else {
            $ranges += New-ScanRange -Text $name -Name (Get-NetworkName $network.Address $network.PrefixLength)
        }
    }
}
foreach ($text in @($AddSubnet | Where-Object { $_ })) {
    $ranges += New-ScanRange $text
}

$script:Scanned = New-Object 'System.Collections.Generic.HashSet[long]'
$devices = @()
$otherNetworks = @()
if ($ranges.Count -eq 0) {
    "`n### Devices"
    "No network to scan: this computer has no network with a gateway. Give one with -Subnet."
}
else {
    Write-Progress -Id 20 -Activity 'Network audit' -Status 'UPnP and WS-Discovery' -PercentComplete 6
    $script:UpnpLocations = Get-UpnpLocations
    $script:WsdDevices = Get-WsdDevices
    $script:Vendors = Get-MacVendors
    $devices = @(Find-Devices -Ranges $ranges)

    if ($ScanOtherNetworks) {
        # Once: the networks the second scan shows are listed under Other networks, not scanned.
        $seen = @(Get-OtherNetworks -Devices $devices -Hops $hops)
        $small = @($seen | Where-Object { [math]::Pow(2, 32 - [int]($_.Network -replace '^.*/', '')) -le 1024 })
        $large = @($seen | Where-Object { $_ -notin $small })
        if ($large.Count -gt 0) {
            Write-Warning "Other networks seen but too large to scan without being named: $(($large | ForEach-Object { $_.Network }) -join ', '). Give them with -AddSubnet."
        }
        if ($small.Count -gt 0) {
            Write-Host "Scanning the other networks seen: $(($small | ForEach-Object { $_.Network }) -join ', ')."
            $more = @($small | ForEach-Object { New-ScanRange $_.Network })
            $ranges += $more
            $devices += @(Find-Devices -Ranges $more)
        }
    }
    elseif ($AskSubnet) {
        Write-Progress -Id 20 -Activity 'Network audit' -Completed
        $other = @(Get-OtherNetworks -Devices $devices -Hops $hops)
        Write-Host ''
        if ($other.Count -gt 0) {
            Write-Host 'Other networks seen from here, not scanned yet:'
            for ($index = 0; $index -lt $other.Count; $index++) {
                Write-Host ('  {0,2}. {1,-18} {2}' -f ($index + 1), $other[$index].Network, ($other[$index].Seen -join '; '))
            }
            $question = 'Scan more networks? Numbers of the list (1,2), A for all of them, other networks (10.0.40.0/24, 10.0.50.10-50), or Enter for none'
        }
        else {
            $question = 'Scan other networks too, e.g. a server or camera VLAN? Networks (10.0.40.0/24, 10.0.50.10-50), or Enter for none'
        }
        $more = @()
        while ($true) {
            $answer = "$(Read-Host $question)".Trim()
            if (-not $answer) {
                break
            }
            try {
                $more = @(foreach ($token in @($answer -split '[,;\s]+' | Where-Object { $_ })) {
                        if ($token -match '^(a|all)$' -and $other.Count -gt 0) {
                            $other | ForEach-Object { New-ScanRange $_.Network }
                        }
                        elseif ($token -match '^\d+$' -and [int]$token -ge 1 -and [int]$token -le $other.Count) {
                            New-ScanRange $other[[int]$token - 1].Network
                        }
                        else {
                            New-ScanRange $token
                        }
                    })
                break
            }
            catch {
                Write-Host $_.Exception.Message -ForegroundColor Yellow
            }
        }
        if ($more.Count -gt 0) {
            $ranges += $more
            $devices += @(Find-Devices -Ranges $more)
        }
    }

    "`n### Devices"
    "Scanned: $(($ranges | ForEach-Object { $_.Name }) -join ', '). $($devices.Count) $(if ($devices.Count -eq 1) { 'device' } else { 'devices' }) answered, by type:"
    ""
    Format-AuditTable -Rows ($devices | Group-Object -Property Type | Sort-Object -Property Count -Descending | ForEach-Object { [pscustomobject]@{ Type = $_.Name; Count = $_.Count } }) -Columns 'Type', 'Count'
    ""
    Format-AuditTable -Rows ($devices | ForEach-Object {
            [pscustomobject]@{
                Address        = $_.Address
                Name           = $_.Name
                Type           = $_.Type
                Vendor         = $_.Vendor
                Mac            = $_.Mac
                Ports          = @($_.Ports | ForEach-Object { $portNames[[int]$_] })
                Identification = $_.Identification
            }
        }) -Columns 'Address', 'Name', 'Type', 'Vendor', 'MAC=Mac', 'Open ports=Ports', 'Identification'

    $described = @($devices | Where-Object { $_.Model -or $_.Serial -or $_.Firmware -or $_.Snmp.Location })
    if ($described.Count -gt 0) {
        "`n### Models and serial numbers"
        "What the devices tell over SNMP, UPnP and WS-Discovery: for the inventory and the warranties."
        ""
        Format-AuditTable -Rows ($described | ForEach-Object {
                [pscustomobject]@{ Address = $_.Address; Name = $_.Name; Type = $_.Type; Model = $_.Model; Serial = $_.Serial; Firmware = $_.Firmware; Location = $_.Snmp.Location }
            }) -Columns 'Address', 'Name', 'Type', 'Model', 'Serial number=Serial', 'Firmware', 'Location'
    }

    $upsDevices = @($devices | Where-Object { $_.Snmp.Ups })
    if ($upsDevices.Count -gt 0) {
        "`n### UPS"
        Format-AuditTable -Rows ($upsDevices | ForEach-Object {
                $ups = $_.Snmp.Ups
                [pscustomobject]@{
                    Device   = "$($_.Address) $($_.Name)".Trim()
                    Ups      = "$($ups.Manufacturer) $($ups.Model)".Trim()
                    Serial   = $ups.Serial
                    Firmware = $ups.Firmware
                    Battery  = "$($ups.Battery)$(if ($null -ne $ups.ChargePercent) { ", $($ups.ChargePercent)%" })$(if ($null -ne $ups.MinutesLeft) { ", $($ups.MinutesLeft) min" })$(if ($ups.ReplaceBattery) { ', to replace' })"
                    Replaced = $ups.BatteryReplaced
                    Made     = $ups.Manufactured
                }
            }) -Columns 'Device', 'UPS=Ups', 'Serial number=Serial', 'Firmware', 'Battery', 'Battery replaced=Replaced', 'Made=Made'
        "What shuts down on battery is not read: complete it on site."
    }

    $printers = @($devices | Where-Object { $_.Snmp.Printer })
    if ($printers.Count -gt 0) {
        "`n### Printers"
        Format-AuditTable -Rows ($printers | ForEach-Object { [pscustomobject]@{ Device = "$($_.Address) $($_.Name)".Trim(); Model = $_.Snmp.Printer.Model; Serial = $_.Snmp.Printer.Serial; Pages = $_.Snmp.Printer.Pages } }) -Columns 'Device', 'Model', 'Serial number=Serial', 'Pages printed=Pages'
    }

    $switches = @($devices | Where-Object { @($_.Snmp.Vlans | Where-Object { $_ }).Count -gt 0 -or @($_.Snmp.Neighbors | Where-Object { $_ }).Count -gt 0 })
    if ($switches.Count -gt 0) {
        "`n### VLANs and neighbours"
        $withVlans = @($switches | Where-Object { @($_.Snmp.Vlans | Where-Object { $_ }).Count -gt 0 })
        if ($withVlans.Count -gt 0) {
            Format-AuditTable -Rows ($withVlans | ForEach-Object { [pscustomobject]@{ Device = "$($_.Address) $($_.Name)".Trim(); Vlans = @($_.Snmp.Vlans | ForEach-Object { "$($_.Id)$(if ($_.Name) { " $($_.Name)" })" }) } }) -Columns 'Device', 'VLANs=Vlans'
            ""
        }
        $links = @($switches | ForEach-Object { $device = $_; @($_.Snmp.Neighbors | Where-Object { $_ }) | ForEach-Object { [pscustomobject]@{ Device = "$($device.Address) $($device.Name)".Trim(); Port = $_.LocalPort; Neighbor = $_.Name; NeighborPort = $_.Port; Address = $_.Address; Protocol = $_.Protocol } } })
        if ($links.Count -gt 0) {
            "The neighbours each switch sees on its ports (LLDP, CDP): how the network is cabled."
            ""
            Format-AuditTable -Rows $links -Columns 'Device', 'Port', 'Neighbour=Neighbor', 'Its port=NeighborPort', 'Its address=Address', 'Protocol'
        }
    }

    $pages = @($devices | ForEach-Object { $device = $_; @($_.Web) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Device = "$($device.Address) $($device.Name)".Trim(); Page = $_ } } })
    if ($pages.Count -gt 0) {
        "`n### Web interfaces"
        "The management pages found, as they show before any login: the address of each device's configuration."
        ""
        Format-AuditTable -Rows ($pages | ForEach-Object {
                [pscustomobject]@{
                    Device      = $_.Device
                    Url         = $_.Page.Url
                    Title       = $_.Page.Title
                    Server      = $_.Page.Server
                    Certificate = $(if ($_.Page.CertificateSubject) { "$(Get-AuditCommonName $_.Page.CertificateSubject)$(if ($_.Page.CertificateSelfSigned) { ' (self-signed)' } else { ", by $(Get-AuditCommonName $_.Page.CertificateIssuer)" }), until $($_.Page.CertificateExpires.ToString('yyyy-MM-dd'))" })
                }
            }) -Columns 'Device', 'Address=Url', 'Title', 'Server', 'Certificate'
    }

    $gatewayDevices = @($devices | Where-Object { $_.IsGateway })
    if ($gatewayDevices.Count -gt 0) {
        "`n### Firewall / gateway"
        foreach ($gateway in $gatewayDevices) {
            "- $($gateway.Address): $(if ($gateway.Vendor) { $gateway.Vendor } else { 'vendor unknown' })$(if ($gateway.Identification) { ", $($gateway.Identification)" })$(if ($gateway.Serial) { ", serial number $($gateway.Serial)" }). Open ports: $(if ($gateway.Ports.Count) { (@($gateway.Ports | ForEach-Object { $portNames[[int]$_] })) -join ', ' } else { 'none' })."
        }
    }

    $otherNetworks = @(Get-OtherNetworks -Devices $devices -Hops $hops)
    if ($otherNetworks.Count -gt 0) {
        "`n### Other networks"
        "Seen from here but not scanned: scan them with -AddSubnet, or pick them when the audit asks."
        ""
        Format-AuditTable -Rows ($otherNetworks | ForEach-Object { [pscustomobject]@{ Network = $_.Network; Seen = @($_.Seen) } }) -Columns 'Network', 'Seen as=Seen'
    }

    # Findings.
    $telnet = @($devices | Where-Object { $_.Ports -contains 23 })
    if ($telnet.Count -gt 0) {
        New-AuditFinding -Severity High -Area $area -Finding "Telnet is open on $(($telnet | ForEach-Object { "$($_.Address) $($_.Name)".Trim() }) -join ', '): logins cross the network unencrypted." -Recommendation 'Turn Telnet off; manage these devices over SSH or HTTPS.'
    }
    $ftp = @($devices | Where-Object { $_.Ports -contains 21 })
    if ($ftp.Count -gt 0) {
        New-AuditFinding -Severity Medium -Area $area -Finding "FTP is open on $(($ftp | ForEach-Object { "$($_.Address) $($_.Name)".Trim() }) -join ', '): logins and files cross the network unencrypted." -Recommendation 'Turn FTP off where it is not used, or use SFTP/FTPS.'
    }
    $vnc = @($devices | Where-Object { $_.Ports -contains 5900 })
    if ($vnc.Count -gt 0) {
        New-AuditFinding -Severity Medium -Area $area -Finding "VNC is open on $(($vnc | ForEach-Object { "$($_.Address) $($_.Name)".Trim() }) -join ', ')." -Recommendation 'Check that it is needed and protected by a strong password; prefer the remote support tool of the company.'
    }
    $remoteTools = @($devices | Where-Object { $_.Ports -contains 5938 -or $_.Ports -contains 7070 })
    if ($remoteTools.Count -gt 0) {
        New-AuditFinding -Severity Low -Area $area -Finding "Remote access tools accept direct connections on $(($remoteTools | ForEach-Object { "$($_.Address) $($_.Name) ($((@($_.Ports | Where-Object { $_ -in 5938, 7070 } | ForEach-Object { $portNames[[int]$_] })) -join ', '))".Trim() }) -join ', ')." -Recommendation 'Check that they are the tools the company uses, under its own account, and turn direct (LAN) connections off where they are not needed.'
    }
    $snmp = @($devices | Where-Object { $_.Snmp -and $_.Snmp.DefaultCommunity })
    if ($snmp.Count -gt 0) {
        New-AuditFinding -Severity Medium -Area $area -Finding "SNMP answers with the default community 'public' on $(($snmp | ForEach-Object { "$($_.Address) $($_.Name)".Trim() }) -join ', '): anyone on the network reads their configuration." -Recommendation 'Change the community, or use SNMPv3, or turn SNMP off where nothing monitors it.'
    }
    $replaced = [datetime]::MinValue
    foreach ($device in $upsDevices) {
        $ups = $device.Snmp.Ups
        if ($ups.ReplaceBattery -or $ups.Battery -in 'Low', 'Fault', 'Depleted', 'No battery') {
            New-AuditFinding -Severity Medium -Area $area -Finding "The UPS $("$($device.Address) $($device.Name)".Trim()) says its battery $(if ($ups.ReplaceBattery) { 'needs replacing' } else { "is $($ups.Battery.ToLower())" })." -Recommendation 'Replace the battery: on a power cut, the servers would stop at once.'
        }
        elseif ($ups.BatteryReplaced -and [datetime]::TryParse("$($ups.BatteryReplaced)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$replaced) -and $replaced -lt (Get-Date).AddYears(-4)) {
            New-AuditFinding -Severity Low -Area $area -Finding "The battery of the UPS $("$($device.Address) $($device.Name)".Trim()) was replaced on $($replaced.ToString('yyyy-MM-dd')); UPS batteries last 3 to 5 years." -Recommendation 'Plan its replacement, and test the UPS (a self-test from its web page).'
        }
    }
    $infrastructure = 'Firewall|router|Switch|access point|Network device|NAS|UPS|Server management|Hypervisor|vCenter|Backup'
    $plainOnly = @($devices | Where-Object { $_.Type -match $infrastructure -and @($_.Web | Where-Object { $_.Url -like 'http:*' -and $_.Status }).Count -gt 0 -and @($_.Web | Where-Object { $_.Url -like 'https:*' }).Count -eq 0 })
    if ($plainOnly.Count -gt 0) {
        New-AuditFinding -Severity Medium -Area $area -Finding "The management page of $(($plainOnly | ForEach-Object { "$($_.Address) $($_.Name) ($($_.Type))".Trim() }) -join ', ') is only on plain HTTP: its password crosses the network unencrypted." -Recommendation 'Turn HTTPS on for management and HTTP off.'
    }
    $expired = @($pages | Where-Object { $_.Page.CertificateExpires -and $_.Page.CertificateExpires -lt (Get-Date) })
    if ($expired.Count -gt 0) {
        New-AuditFinding -Severity Low -Area $area -Finding "Expired certificate on $(($expired | ForEach-Object { $_.Page.Url } | Select-Object -Unique) -join ', ')." -Recommendation 'Renew it, or the firmware that comes with it, so that users stop clicking through certificate warnings.'
    }
    $management = @($devices | Where-Object { $_.Type -like 'Server management*' })
    if ($management.Count -gt 0) {
        New-AuditFinding -Severity Low -Area $area -Finding "The server management boards $(($management | ForEach-Object { "$($_.Address) ($($_.Type))" }) -join ', ') are reachable from this network." -Recommendation 'Keep them on a separate management network or VLAN, with their own passwords.'
    }
    $unknown = @($devices | Where-Object { $_.Type -eq 'Unknown' })
    if ($unknown.Count -gt 0) {
        New-AuditFinding -Severity Info -Area $area -Finding "$($unknown.Count) devices could not be identified: $(($unknown | ForEach-Object { $_.Address }) -join ', ')." -Recommendation 'Identify them on site (MAC address, switch port) and note what they are.'
    }
}
Write-Progress -Id 20 -Activity 'Network audit' -Completed

$diagram = $null
if ($DiagramPath -and $ranges.Count -gt 0) {
    try {
        $diagram = Write-NetworkDiagram -Path $DiagramPath -Devices $devices -Ranges $ranges -Hops $hops -Public $public
        "`n### Network diagram"
        "A first diagram is in $(Split-Path $diagram -Leaf): open it in draw.io (diagrams.net, or the Draw.io Integration of VS Code) and complete it on site."
    }
    catch {
        Write-Warning "The network diagram could not be written: $($_.Exception.Message)"
    }
}

New-AuditData -Name 'Network' -Value ([pscustomobject]@{
        Computer       = $env:COMPUTERNAME
        Interfaces     = $local
        Wifi           = $wifi
        WifiInRange    = $wifiNearby
        PublicAddress  = $public
        InternetPath   = $hops
        Speed          = $speed
        Scanned        = @($ranges | ForEach-Object { $_.Name })
        Devices        = $devices
        OtherNetworks  = @($otherNetworks | ForEach-Object { [pscustomobject]@{ Network = $_.Network; Seen = @($_.Seen) } })
        Diagram        = $diagram
    })
