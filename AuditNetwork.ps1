[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'Networks to scan: 192.0.2.0/24, a range 192.0.2.10-50, or one address. Default: the networks of this computer that have a gateway.')]
    [string[]]$Subnet,

    [Parameter(HelpMessage = 'Most addresses scanned per network: a larger network of this computer is reduced to its /24 and that of its gateway.')]
    [ValidateRange(1, 65536)]
    [int]$MaxHosts = 1024,

    [Parameter(HelpMessage = 'Devices examined at once.')]
    [ValidateRange(1, 128)]
    [int]$ThrottleLimit = 32
)

# Audit of the network this computer is on, with no login anywhere: its own network settings, its
# Wi-Fi, the public address, then the devices of the local network. A device is found when it
# answers a ping, ARP (on this computer's own networks) or a common TCP port; it is then named from
# its DNS and NetBIOS names, its MAC vendor, SNMP (community "public"), and the title and certificate
# of its web pages, which also tell its type (firewall, switch, NAS, printer, UPS...).

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'AuditCommon.ps1')
$area = 'Network'

# The ports tried on every device found, with the name shown. Not [ordered]: its [135] would be the
# 136th entry, not port 135.
$portNames = @{
    21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 25 = 'SMTP'; 53 = 'DNS'; 80 = 'HTTP'; 88 = 'Kerberos'; 135 = 'RPC'
    139 = 'NetBIOS'; 389 = 'LDAP'; 443 = 'HTTPS'; 444 = 'HTTPS 444'; 445 = 'SMB'; 515 = 'LPD'; 631 = 'IPP'; 636 = 'LDAPS'
    902 = 'VMware'; 1433 = 'SQL Server'; 1723 = 'PPTP'; 2049 = 'NFS'; 3260 = 'iSCSI'; 3306 = 'MySQL'; 3389 = 'RDP'
    4433 = 'HTTPS 4433'; 5000 = 'HTTP 5000'; 5001 = 'HTTPS 5001'; 5480 = 'HTTPS 5480'; 5900 = 'VNC'; 5985 = 'WinRM'
    8000 = 'HTTP 8000'; 8006 = 'Proxmox'; 8080 = 'HTTP 8080'; 8443 = 'HTTPS 8443'; 9100 = 'Printing'; 9419 = 'Veeam API'
    9443 = 'HTTPS 9443'; 10443 = 'HTTPS 10443'
}
# Web pages are read on these ports, HTTPS first unless the port is a plain HTTP one.
$webPorts = @(80, 443, 444, 4433, 5000, 5001, 5480, 8000, 8006, 8080, 8443, 9443, 10443)
$plainHttpPorts = @(80, 5000, 8000, 8080)
# Asked of addresses that answered neither a ping nor ARP, e.g. on a network behind a router.
$quickPorts = @(22, 80, 443, 445, 3389)

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
# byte (192.0.2.10-50) or of addresses (192.0.2.10-192.0.2.20), or one address.
function Get-AddressRange {
    param(
        [string]$Text
    )

    $Text = $Text.Trim()
    if ($Text -match '^(?<ip>\d{1,3}(\.\d{1,3}){3})/(?<bits>\d{1,2})$') {
        $bits = [int]$Matches.bits
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
        return @(Get-NumberRange (ConvertTo-IPNumber $Matches.first) (ConvertTo-IPNumber $Matches.last))
    }
    if ($Text -match '^\d{1,3}(\.\d{1,3}){3}$') {
        return @(ConvertTo-IPNumber $Text)
    }
    throw "'$Text' is not a network (192.0.2.0/24), a range (192.0.2.10-50) or an address."
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

# The open TCP ports of these addresses: address -> ports.
function Test-TcpPorts {
    param(
        [string[]]$Addresses,
        [int[]]$Ports,
        [int]$TimeoutMs = 1000,
        [string]$Status = 'Ports'
    )

    $open = @{}
    $pairs = @(foreach ($address in $Addresses) { foreach ($port in $Ports) { [pscustomobject]@{ Address = $address; Port = $port } } })
    for ($first = 0; $first -lt $pairs.Count; $first += 512) {
        $batch = @($pairs[$first..([math]::Min($first + 511, $pairs.Count - 1))] | ForEach-Object {
                $client = New-Object System.Net.Sockets.TcpClient
                [pscustomobject]@{ Pair = $_; Client = $client; Task = $client.ConnectAsync($_.Address, $_.Port) }
            })
        try {
            [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($batch.Task), $TimeoutMs)
        }
        catch {
            # Refused connections: closed ports.
        }
        foreach ($item in $batch) {
            if ($item.Task.Status -eq 'RanToCompletion' -and $item.Client.Connected) {
                if (-not $open.ContainsKey($item.Pair.Address)) {
                    $open[$item.Pair.Address] = New-Object System.Collections.Generic.List[int]
                }
                $open[$item.Pair.Address].Add($item.Pair.Port)
            }
            $item.Client.Close()
        }
        Write-Progress -Id 20 -Activity 'Network audit' -Status "$($Status): $([math]::Min($first + 512, $pairs.Count)) of $($pairs.Count)" -PercentComplete 40
    }
    return $open
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

# What a device tells over SNMP v2c with the community "public", which many keep by default: its
# description (model, firmware), name and location. $null when it doesn't answer.
function Get-SnmpInfo {
    param(
        [string]$Address,
        [int]$TimeoutMs = 1000
    )

    # GetRequest of sysDescr.0, sysName.0 and sysLocation.0 (1.3.6.1.2.1.1.x.0), in BER.
    $oids = @{ Description = 1; Name = 5; Location = 6 }
    $bindings = [byte[]]@()
    foreach ($number in 1, 5, 6) {
        $bindings += [byte[]](0x30, 12, 0x06, 8, 0x2B, 6, 1, 2, 1, 1, $number, 0, 0x05, 0)
    }
    $pdu = [byte[]](0x02, 1, 1, 0x02, 1, 0, 0x02, 1, 0, 0x30, $bindings.Length) + $bindings
    $community = [Text.Encoding]::ASCII.GetBytes('public')
    $message = [byte[]](0x02, 1, 1, 0x04, $community.Length) + $community + [byte[]](0xA0, $pdu.Length) + $pdu
    $packet = [byte[]](0x30, $message.Length) + $message

    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        [void]$udp.Send($packet, $packet.Length, $Address, 161)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $answer = $udp.Receive([ref]$remote)
    }
    catch {
        return $null
    }
    finally {
        $udp.Close()
    }

    # Each value follows its OID in the answer: an OCTET STRING (0x04), with a short or long length.
    $hex = [BitConverter]::ToString($answer)
    $values = [ordered]@{}
    foreach ($key in $oids.Keys) {
        $oid = '06-08-2B-06-01-02-01-01-{0:X2}-00' -f $oids[$key]
        $at = $hex.IndexOf($oid)
        if ($at -lt 0) {
            continue
        }
        $offset = ($at + $oid.Length + 1) / 3
        if ($offset + 2 -gt $answer.Length -or $answer[$offset] -ne 0x04) {
            continue
        }
        $length = [int]$answer[$offset + 1]
        $start = $offset + 2
        if ($length -band 0x80) {
            $bytes = $length -band 0x7F
            $length = 0
            for ($index = 0; $index -lt $bytes; $index++) {
                $length = $length * 256 + $answer[$start + $index]
            }
            $start += $bytes
        }
        if ($start + $length -le $answer.Length) {
            $values[$key] = ([Text.Encoding]::UTF8.GetString($answer, $start, $length) -replace '[\x00-\x1F]+', ' ').Trim()
        }
    }
    if ($values.Count -eq 0) {
        return $null
    }
    return [pscustomobject]$values
}

# Examines one device in a runspace of its own: names, SNMP and web pages.
$examineDevice = {
    param(
        [string]$Address,
        [int[]]$WebPorts,
        [int[]]$PlainHttpPorts
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
    [pscustomobject]@{
        Address = $Address
        DnsName = $dnsName
        NetBios = Get-NetBiosInfo -Address $Address
        Snmp    = Get-SnmpInfo -Address $Address
        Web     = $web
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

# The type of a device, from all it showed: the gateway, its ports, vendor, SNMP description, web
# pages and names.
function Get-DeviceType {
    param(
        $Device
    )

    $ports = @($Device.Ports)
    $text = (@($Device.Vendor, $Device.Snmp.Description, $Device.Name) + @($Device.Web | ForEach-Object { $_.Title; $_.Server; $_.CertificateSubject; $_.CertificateIssuer }) | Where-Object { $_ }) -join ' '
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
        'Fortinet|FortiGate|SonicWall|WatchGuard|Sophos|pfSense|OPNsense|Stormshield|ZyWALL|USG FLEX|\bATP\d+' { return 'Firewall' }
        '\b(NWA|WAX|WAC)\d|Access Point|UniFi AP|\bU6\b|\bUAP\b|Aruba Instant|Ruckus|\bEAP\d|Omada' { return 'Wi-Fi access point' }
        'Switch|ProCurve|\bX?GS\d{3,4}|\bXS\d{4}|Catalyst|Aruba \d{4}|OfficeConnect|\bSG\d{3}|\bCBS\d{3}|\bUSW\b' { return 'Switch' }
        'Printer|LaserJet|OfficeJet|DeskJet|Ricoh|Kyocera|Brother|Canon|Xerox|Konica|Lexmark|Epson|\bSharp\b|Toshiba TEC' { return 'Printer' }
        'Hikvision|Dahua|Axis Communications|Reolink|Uniview|\bNVR\b|\bDVR\b|Camera' { return 'Camera / recorder' }
        'Yealink|\bSnom\b|Polycom|Grandstream|Gigaset|Panasonic.*KX|Cisco IP Phone|Fanvil' { return 'IP phone' }
        'ZKTeco|Suprema|Anviz|Horoquartz|Kelio|Bodet|Time ?clock' { return 'Time clock / access control' }
        'Sonos|\bBose\b|Denon|Yamaha' { return 'Audio device' }
        'Espressif|\bTuya\b|Shelly|Sonoff|Philips Lighting|Signify|\bNest\b|\bRing\b' { return 'IoT device' }
        'Ubiquiti' { return 'Network device (Ubiquiti)' }
        'Zyxel|Cisco|Aruba|HPE Networking|Juniper|MikroTik|TP-Link|D-Link|Netgear|Draytek|Teltonika' { return 'Network device' }
        'Apple' { return 'Apple device' }
        'Private address' { return 'Phone / laptop' }
        'Microsoft' { if ($Device.Vendor -eq 'Microsoft') { return 'Hyper-V virtual machine' } }
        'VMware' { if ($Device.Vendor -match 'VMware') { return 'VMware virtual machine' } }
    }
    if ($ports -contains 9100 -or $ports -contains 515 -or $ports -contains 631) {
        return 'Printer'
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

# A short text that tells what the device is: its SNMP description, web page titles or certificate.
function Get-DeviceIdentification {
    param(
        $Device
    )

    $parts = @()
    if ($Device.Snmp -and $Device.Snmp.Description) {
        $parts += ($Device.Snmp.Description -split '[\r\n]')[0]
    }
    $parts += @($Device.Web | ForEach-Object { $_.Title } | Where-Object { $_ })
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

Write-Progress -Id 20 -Activity 'Network audit' -Status 'This computer' -PercentComplete 0
$local = @(Get-LocalNetwork)
$wifi = @(Get-WifiConnection)
$wifiNearby = @(Get-WifiNetworks | Sort-Object -Property Signal -Descending)
$public = Get-PublicAddress
$computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

"### This computer"
"The audit ran on $env:COMPUTERNAME ($(if ($os) { "$($os.Caption) $($os.Version)" }), $(if ($computer -and $computer.PartOfDomain) { "domain $($computer.Domain)" } else { "workgroup $(if ($computer) { $computer.Workgroup })" })), as $env:USERDOMAIN\$env:USERNAME."
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
            }
        }) -Columns 'Interface', 'Address', 'Gateway', 'DNS servers=Dns', 'Address from=Dhcp', 'DNS suffix=Suffix', 'Network name=Network'
}
else {
    "No connected network interface with an IPv4 address."
}
if ($public) {
    ""
    "Public address: $($public.Address)$(if ($public.Name) { " ($($public.Name))" })$(if ($public.Provider) { ", $($public.Provider)" })$(if ($public.Location) { ", $($public.Location)" })."
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

# The addresses to scan: the networks given, else those of this computer that have a gateway.
$ranges = @()
if ($Subnet) {
    foreach ($text in $Subnet) {
        $ranges += [pscustomobject]@{ Name = $text; Numbers = @(Get-AddressRange $text) }
    }
}
else {
    foreach ($network in @($local | Where-Object { $_.Gateway })) {
        $name = "$($network.Address)/$($network.PrefixLength)"
        $numbers = @(Get-AddressRange $name)
        if ($numbers.Count -gt $MaxHosts) {
            # A large network: only the /24 of this computer and of its gateway.
            $reduced = @(Get-AddressRange "$($network.Address)/24") + @(Get-AddressRange "$($network.Gateway)/24") | Select-Object -Unique
            Write-Warning "$name has $($numbers.Count) addresses: only $($reduced.Count) are scanned (the /24 of this computer and of its gateway). Give -Subnet to scan more."
            $name = "$name (only the /24 of this computer and of its gateway)"
            $numbers = $reduced
        }
        $ranges += [pscustomobject]@{ Name = $name; Numbers = $numbers }
    }
}
$targets = @($ranges | ForEach-Object { $_.Numbers } | Select-Object -Unique)
$devices = @()
if ($targets.Count -eq 0) {
    "`n### Devices"
    "No network to scan: this computer has no network with a gateway. Give one with -Subnet."
}
else {
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

    Write-Progress -Id 20 -Activity 'Network audit' -Status "Ports of $($addresses.Count) devices" -PercentComplete 40
    $openPorts = Test-TcpPorts -Addresses $addresses -Ports ([int[]]@($portNames.Keys | Sort-Object)) -TimeoutMs 1500 -Status "Ports of $($addresses.Count) devices"

    # Names, SNMP and web pages of each device, several at once.
    $state = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($name in 'Get-AuditWebInfo', 'Get-NetBiosInfo', 'Get-SnmpInfo') {
        $state.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($name, (Get-Item "function:$name").Definition)))
    }
    $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit, $state, $Host)
    $pool.Open()
    try {
        $jobs = @(foreach ($address in $addresses) {
                $shell = [powershell]::Create()
                $shell.RunspacePool = $pool
                $ports = @($webPorts | Where-Object { @($openPorts[$address]) -contains $_ })
                [void]$shell.AddScript($examineDevice).AddArgument($address).AddArgument([int[]]$ports).AddArgument([int[]]$plainHttpPorts)
                [pscustomobject]@{ Address = $address; Shell = $shell; Handle = $shell.BeginInvoke() }
            })
        while (($pending = @($jobs | Where-Object { -not $_.Handle.IsCompleted }).Count) -gt 0) {
            Write-Progress -Id 20 -Activity 'Network audit' -Status "Names and web pages: $($jobs.Count - $pending) of $($jobs.Count) devices" -PercentComplete (50 + 45 * ($jobs.Count - $pending) / $jobs.Count)
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

    $vendors = Get-MacVendors
    $localMacs = @{}
    foreach ($network in $local) {
        $localMacs[$network.Address] = $network.Mac
    }
    $devices = @(foreach ($address in $addresses) {
            $detail = $details[$address]
            $mac = if ($neighbors[$address]) { $neighbors[$address] } elseif ($localMacs[$address]) { $localMacs[$address] } elseif ($detail -and $detail.NetBios) { $detail.NetBios.Mac }
            $netBios = if ($detail) { $detail.NetBios }
            $dnsName = if ($detail) { $detail.DnsName }
            # Assigned here, since $(...) would make an empty list $null.
            $web = @()
            if ($detail) {
                $web = @($detail.Web | Where-Object { $_ })
            }
            $device = [pscustomobject]@{
                Address        = $address
                Name           = $(if ($netBios -and $netBios.Name) { $netBios.Name } elseif ($dnsName) { ($dnsName -split '\.')[0] } elseif ($detail -and $detail.Snmp -and $detail.Snmp.Name) { $detail.Snmp.Name })
                DnsName        = $dnsName
                NetBiosDomain  = $(if ($netBios) { $netBios.Domain })
                Mac            = $mac
                Vendor         = $(if ($mac) { Get-MacVendor -Vendors $vendors -Mac $mac })
                Ttl            = $pingAnswers[$found[$address]]
                Ports          = @($openPorts[$address] | Where-Object { $null -ne $_ } | Sort-Object)
                Snmp           = $(if ($detail) { $detail.Snmp })
                Web            = $web
                IsGateway      = $address -in $gateways
                IsThisComputer = $address -in $localAddresses
                IsDomainController = [bool]($netBios -and $netBios.DomainController)
                Type           = $null
                Identification = $null
            }
            $device.Type = Get-DeviceType $device
            if ($device.IsDomainController -and $device.Type -match 'Windows|Unknown') {
                $device.Type = 'Domain controller'
            }
            $device.Identification = Get-DeviceIdentification $device
            $device
        })

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
            "- $($gateway.Address): $(if ($gateway.Vendor) { $gateway.Vendor } else { 'vendor unknown' })$(if ($gateway.Identification) { ", $($gateway.Identification)" }). Open ports: $(if ($gateway.Ports.Count) { (@($gateway.Ports | ForEach-Object { $portNames[[int]$_] })) -join ', ' } else { 'none' })."
        }
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
    $snmp = @($devices | Where-Object { $_.Snmp })
    if ($snmp.Count -gt 0) {
        New-AuditFinding -Severity Medium -Area $area -Finding "SNMP answers with the default community 'public' on $(($snmp | ForEach-Object { "$($_.Address) $($_.Name)".Trim() }) -join ', '): anyone on the network reads their configuration." -Recommendation 'Change the community, or use SNMPv3, or turn SNMP off where nothing monitors it.'
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

New-AuditData -Name 'Network' -Value ([pscustomobject]@{
        Computer       = $env:COMPUTERNAME
        Interfaces     = $local
        Wifi           = $wifi
        WifiInRange    = $wifiNearby
        PublicAddress  = $public
        Scanned        = @($ranges | ForEach-Object { $_.Name })
        Devices        = $devices
    })
