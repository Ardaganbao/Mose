[CmdletBinding()]
param(
    # Not -SpeedTest: AuditNetwork.ps1's $speedTest, loaded below, would replace it.
    [Parameter(HelpMessage = 'Also run the speed test: librespeed-cli uses the Internet line for about 30 seconds.')]
    [switch]$RunSpeedTest,

    [Parameter(HelpMessage = 'Keep the test folder, with the audits written, instead of deleting it.')]
    [switch]$Keep,

    [Parameter(HelpMessage = 'Branch, tag or commit that the update test downloads from GitHub. Default: the branch of this repository, else main.')]
    [string]$Branch,

    [Parameter(HelpMessage = 'No update test from GitHub (offline, or before pushing).')]
    [switch]$SkipGitHub
)

# Tests of the IT audit (Audit.ps1 and its parts) on this computer only: no other device of the network
# is scanned. The SNMP, UPnP and WS-Discovery devices are fakes on 127.0.0.1; the network scans cover
# this computer's own address and 127.0.0.1; the inventory reads this computer over DCOM. Then: why a
# computer was not read in the languages of Windows, Start.ps1 giving the audit its options, the update
# from GitHub into a new folder, the Script Manager's IT audit button, the audit window (with a stand-in
# audit, then the real one), the other networks scanned without a question, the findings of made-up
# computers and routes to the Internet. The full audit then runs twice in a PowerShell of its own, in strict mode
# as Start.ps1 runs it, with each of its questions answered by the test: an unexpected question fails
# it. The second run has a stand-in Active Directory, whose computers the inventory is asked to read.
#
# It needs the Internet for the public address, the route to 1.1.1.1, the MAC vendors, the update test
# (-SkipGitHub leaves it out) and the speed test's download (checked, run only with -RunSpeedTest). In
# Windows PowerShell, from the repository:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Audit.ps1

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
$repository = Split-Path -Parent $PSScriptRoot
$started = Get-Date
if (-not $Branch) {
    $Branch = $(try { "$(git -C $repository rev-parse --abbrev-ref HEAD 2>$null)".Trim() } catch { '' })
    if (-not $Branch -or $Branch -eq 'HEAD') {
        $Branch = 'main'
    }
}
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:Passed = 0

function Test-Value {
    param(
        [string]$Name,
        $Actual,
        $Expected
    )

    if ("$Actual" -ceq "$Expected") {
        $script:Passed++
        Write-Host "  ok    $Name" -ForegroundColor DarkGray
    }
    else {
        $script:Failures.Add($Name)
        Write-Host "  FAIL  $Name`n        got:      $Actual`n        expected: $Expected" -ForegroundColor Red
    }
}

function Test-That {
    param(
        [string]$Name,
        [bool]$Condition,
        [string]$Detail
    )

    Test-Value -Name $Name -Actual $(if ($Condition) { 'yes' } else { "no$(if ($Detail) { ": $Detail" })" }) -Expected 'yes'
}

function Write-Section {
    param(
        [string]$Title
    )

    Write-Host "`n$Title" -ForegroundColor Cyan
}

# The scripts are tested in a folder of their own, so that the repository's audit-cache is not touched.
$work = Join-Path ([System.IO.Path]::GetTempPath()) "mose-audit-test-$(Get-Random)"
New-Item -ItemType Directory -Path $work | Out-Null
Copy-Item -Path (Join-Path $repository 'Audit*.ps1') -Destination $work
$network = Join-Path $work 'AuditNetwork.ps1'
# Not a word of the test folder's name: the test looks for it in the audit written.
$community = 'snmp-test-community'
$own = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4DefaultGateway -and "$($_.NetAdapter.Status)" -eq 'Up' } | ForEach-Object { $_.IPv4Address.IPAddress } | Where-Object { $_ -notlike '169.254.*' }) | Select-Object -First 1
if (-not $own) {
    $own = '127.0.0.1'
}
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$inDomain = [bool]$computerSystem.PartOfDomain

# The functions and tables of AuditNetwork.ps1, without running it.
. (Join-Path $work 'AuditCommon.ps1')
$ast = [System.Management.Automation.Language.Parser]::ParseFile($network, [ref]$null, [ref]$null)
foreach ($text in @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | ForEach-Object { $_.Extent.Text })) {
    . ([scriptblock]::Create($text))
}
foreach ($name in 'portNames', 'webPorts', 'plainHttpPorts', 'quickPorts', 'snmpVendors', 'speedTest', 'examineDevice') {
    $assignment = $ast.Find({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and $args[0].Left.Extent.Text -eq "`$$name" }, $false)
    . ([scriptblock]::Create($assignment.Extent.Text))
}

# The fake devices: SNMP (a job, 127.0.0.1:161), a UPnP description (HTTP, 127.0.0.1:8766), and the
# answers of SSDP (127.0.0.1:19000) and WS-Discovery (127.0.0.1:37020) to a search sent to them.
$description = '<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceType>urn:schemas-upnp-org:device:Printer:1</deviceType><friendlyName>Office printer</friendlyName><manufacturer>Brother</manufacturer><modelName>MFC-L8900CDW</modelName><modelNumber>L8900</modelNumber><serialNumber>E78123A9N123456</serialNumber></device></root>'
$ssdpAnswer = "HTTP/1.1 200 OK`r`nCACHE-CONTROL: max-age=1800`r`nLOCATION: http://127.0.0.1:8766/description.xml`r`nST: upnp:rootdevice`r`nUSN: uuid:test::upnp:rootdevice`r`n`r`n"
$wsdAnswer = '<?xml version="1.0"?><s:Envelope><s:Body><d:ProbeMatches><d:ProbeMatch><d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types><d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/name/Camera%20Entrance onvif://www.onvif.org/hardware/DS-2CD2143G2-I</d:Scopes></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>'
$control = [hashtable]::Synchronized(@{ Stop = $false; 19000 = 0; 37020 = 0 })
$responder = {
    param([int]$Port, [string]$Answer, $Control)
    $udp = New-Object System.Net.Sockets.UdpClient((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, $Port)))
    $udp.Client.ReceiveTimeout = 300
    try {
        while (-not $Control.Stop) {
            $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            try {
                [void]$udp.Receive([ref]$remote)
            }
            catch {
                continue
            }
            $Control[$Port]++
            $bytes = [Text.Encoding]::UTF8.GetBytes($Answer)
            [void]$udp.Send($bytes, $bytes.Length, $remote)
        }
    }
    finally {
        $udp.Close()
    }
}
$fakes = @()
$agent = Start-Job -FilePath (Join-Path $PSScriptRoot 'FakeSnmpAgent.ps1') -ArgumentList $network, 900, $community
$http = New-Object System.Net.HttpListener
$http.Prefixes.Add('http://127.0.0.1:8766/')
$http.Start()
$fakes += [powershell]::Create().AddScript({
        param($Listener, [string]$Body)
        while ($Listener.IsListening) {
            try {
                $context = $Listener.GetContext()
            }
            catch {
                break
            }
            $bytes = [Text.Encoding]::UTF8.GetBytes([string][char]0xFEFF + $Body)
            $context.Response.ContentType = 'text/xml'
            $context.Response.ContentLength64 = $bytes.Length
            $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $context.Response.Close()
        }
    }).AddArgument($http).AddArgument($description)
$fakes += [powershell]::Create().AddScript($responder).AddArgument(19000).AddArgument($ssdpAnswer).AddArgument($control)
$fakes += [powershell]::Create().AddScript($responder).AddArgument(37020).AddArgument($wsdAnswer).AddArgument($control)
$handles = @($fakes | ForEach-Object { $_.BeginInvoke() })

try {
    # Until the job listens, Windows refuses each request at once: wait between the tries.
    $ready = $false
    for ($try = 0; $try -lt 60 -and -not $ready; $try++) {
        $ready = @(Invoke-SnmpRequest -Address 127.0.0.1 -Community $community -Oids '1.3.6.1.2.1.1.5.0' -TimeoutMs 1000).Count -gt 0
        if (-not $ready) {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $ready) {
        throw "The fake SNMP agent did not start: $((Receive-Job $agent -ErrorAction SilentlyContinue) -join ' ')"
    }

    Write-Section 'SNMP encoding'
    $hex = { param([byte[]]$Bytes) (@($Bytes | ForEach-Object { $_.ToString('X2') })) -join ' ' }
    Test-Value 'OID of sysDescr.0' (& $hex (ConvertTo-BerOid '1.3.6.1.2.1.1.1.0')) '06 08 2B 06 01 02 01 01 01 00'
    Test-Value 'OID of LLDP-MIB' (& $hex (ConvertTo-BerOid '1.0.8802.1.1.2')) '06 06 28 C4 62 01 01 02'
    Test-Value 'OID with a number of two bytes' (& $hex (ConvertTo-BerOid '1.3.6.1.4.1.318')) '06 07 2B 06 01 04 01 82 3E'
    Test-Value 'INTEGER 0' (& $hex (ConvertTo-BerInteger 0)) '02 01 00'
    Test-Value 'INTEGER 128' (& $hex (ConvertTo-BerInteger 128)) '02 02 00 80'
    Test-Value 'INTEGER 300' (& $hex (ConvertTo-BerInteger 300)) '02 02 01 2C'
    Test-Value 'long length' (& $hex ((ConvertTo-Ber 0x04 ([byte[]](1..200 | ForEach-Object { 65 })))[0..2])) '04 81 C8'
    # The GetRequest of sysDescr, sysName and sysLocation, as the first version of the audit wrote it by hand.
    $bindings = [byte[]]@()
    foreach ($number in 1, 5, 6) {
        $bindings += [byte[]](0x30, 12, 0x06, 8, 0x2B, 6, 1, 2, 1, 1, $number, 0, 0x05, 0)
    }
    $pdu = [byte[]](0x02, 1, 1, 0x02, 1, 0, 0x02, 1, 0, 0x30, $bindings.Length) + $bindings
    $public = [Text.Encoding]::ASCII.GetBytes('public')
    $message = [byte[]](0x02, 1, 1, 0x04, $public.Length) + $public + [byte[]](0xA0, $pdu.Length) + $pdu
    Test-Value 'GetRequest as written by hand' (& $hex (New-SnmpRequest -Community 'public' -Oids '1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.6.0' -RequestId 1)) (& $hex ([byte[]](0x30, $message.Length) + $message))
    $value = { param([byte[]]$Item) ConvertFrom-BerValue $Item (Read-BerItem $Item 0) }
    Test-Value 'text with a trailing NUL' (& $value (ConvertTo-Ber 0x04 ([Text.Encoding]::ASCII.GetBytes("Hello`0")))) 'Hello'
    Test-Value 'empty text' "[$(& $value ([byte[]](0x04, 0)))]" '[]'
    Test-Value 'MAC address (not UTF-8)' (& $value (ConvertTo-Ber 0x04 ([byte[]](0xF8, 0xB4, 0x6A, 0xC8, 0xE9, 0xA5)))) 'F8:B4:6A:C8:E9:A5'
    Test-Value 'Windows-1252 text' (& $value (ConvertTo-Ber 0x04 ([byte[]](0x42, 0xFC, 0x72, 0x6F, 0x20, 0x31, 0x32)))) "B$([char]0xFC)ro 12"
    Test-Value 'negative INTEGER' (& $value ([byte[]](0x02, 0x01, 0xFE))) '-2'
    Test-Value 'IpAddress' (& $value ([byte[]](0x40, 4, 192, 0, 2, 1))) '192.0.2.1'

    Write-Section 'SNMP of the fake UPS'
    Test-That 'no answer to "public" alone' ($null -eq (Get-SnmpInfo -Address 127.0.0.1 -Communities 'public' -TimeoutMs 500))
    $snmp = Get-SnmpInfo -Address 127.0.0.1 -Communities 'public', $community -TimeoutMs 2000
    Test-That 'answers the community given' ($null -ne $snmp)
    Test-Value 'description' $snmp.Description 'APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.8.2)'
    Test-Value 'object ID' $snmp.ObjectId '1.3.6.1.4.1.318.1.3.27'
    Test-Value 'name' $snmp.Name 'UPS-SRV'
    Test-Value 'empty location' "[$($snmp.Location)]" '[]'
    Test-Value 'not a default community' $snmp.DefaultCommunity 'False'
    Test-That 'the community is not in what it returns' (-not (($snmp | ConvertTo-Json -Depth 6) -match [regex]::Escape($community)))
    Test-Value 'model: the first not empty of the entity table' $snmp.Model 'SMT1500RMI2U'
    Test-Value 'serial number' $snmp.Serial 'AS1234567890'
    Test-Value 'UPS' "$($snmp.Ups.Manufacturer) $($snmp.Ups.Model)" 'APC Smart-UPS 1500'
    Test-Value 'UPS battery' $snmp.Ups.Battery 'Normal'
    Test-Value 'UPS runtime (TimeTicks to minutes)' $snmp.Ups.MinutesLeft '45'
    Test-Value 'UPS charge' $snmp.Ups.ChargePercent '100'
    Test-Value 'UPS battery to replace' $snmp.Ups.ReplaceBattery 'True'
    Test-Value 'UPS battery replaced on' $snmp.Ups.BatteryReplaced '03/01/2020'
    Test-That 'not a printer' ($null -eq $snmp.Printer)
    Test-Value 'VLANs (three GetBulk answers)' @($snmp.Vlans).Count '25'
    Test-Value 'VLAN 10' (@($snmp.Vlans | Where-Object { $_.Id -eq 10 }).Name) 'VLAN10'
    $neighbor = @($snmp.Neighbors)[0]
    Test-Value 'LLDP neighbours' @($snmp.Neighbors).Count '1'
    Test-Value 'LLDP local port' $neighbor.LocalPort 'eth0'
    Test-Value 'LLDP neighbour' $neighbor.Name 'core-switch.contoso.local'
    Test-Value 'LLDP neighbour port (empty description, so its ID)' $neighbor.Port 'Gi1/0/24'
    Test-Value 'LLDP neighbour address' $neighbor.Address '192.0.2.2'
    Test-Value 'own networks' (@($snmp.Networks | ForEach-Object { "$($_.Address)/$($_.Mask)" } | Sort-Object) -join ', ') '10.0.20.1/255.255.255.0, 127.0.0.1/255.0.0.0'
    Test-Value 'walk stops at MaxRows' @(Invoke-SnmpWalk -Address 127.0.0.1 -Community $community -Oid '1.3.6.1.2.1.17.7.1.4.3.1.1' -MaxRows 12).Count '12'

    Write-Section 'UPnP and WS-Discovery'
    $locations = Get-UpnpLocations -Address 127.0.0.1 -Port 19000 -WaitMs 1500
    Test-Value 'SSDP: where the description is' (@($locations['127.0.0.1']) -join ', ') 'http://127.0.0.1:8766/description.xml'
    $upnp = Get-UpnpDescription -Address 127.0.0.1 -Location 'http://127.0.0.1:8766/description.xml'
    Test-Value 'UPnP maker' $upnp.Manufacturer 'Brother'
    Test-Value 'UPnP model (its number not repeated)' $upnp.Model 'MFC-L8900CDW'
    Test-Value 'UPnP serial number' $upnp.Serial 'E78123A9N123456'
    Test-Value 'UPnP type' $upnp.DeviceType 'Printer'
    Test-That 'UPnP description of another host refused' ($null -eq (Get-UpnpDescription -Address 127.0.0.1 -Location 'http://192.0.2.99:8766/description.xml'))
    $wsd = Get-WsdDevices -Address 127.0.0.1 -Port 37020 -WaitMs 1500
    Test-Value 'WS-Discovery: answers of both probes merged' (@($wsd['127.0.0.1'].Types) -join ', ') 'NetworkVideoTransmitter, Device'
    Test-Value 'WS-Discovery: camera name' $wsd['127.0.0.1'].Name 'Camera Entrance'
    Test-Value 'WS-Discovery: camera model' $wsd['127.0.0.1'].Hardware 'DS-2CD2143G2-I'

    Write-Section 'Device types, networks and addresses'
    $type = { param([hashtable]$Properties) Get-DeviceType ([pscustomobject]$Properties) }
    Test-Value 'UPS by SNMP' (& $type @{ Snmp = [pscustomobject]@{ Ups = [pscustomobject]@{ Model = 'X' } } }) 'UPS'
    Test-Value 'a NAS with a UPS stays a NAS' (& $type @{ Vendor = 'Synology'; Snmp = [pscustomobject]@{ Ups = [pscustomobject]@{ Model = 'X' } } }) 'NAS (Synology)'
    Test-Value 'printer by WS-Discovery' (& $type @{ Wsd = [pscustomobject]@{ Types = @('PrintDeviceType') } }) 'Printer'
    Test-Value 'camera by WS-Discovery' (& $type @{ Wsd = $wsd['127.0.0.1'] }) 'Camera / recorder'
    Test-Value 'camera by RTSP' (& $type @{ Ports = @(80, 554) }) 'Camera / recorder'
    Test-Value 'IP phone by SIP' (& $type @{ Ports = @(5060) }) 'IP phone'
    Test-Value 'firewall by its SNMP maker' (& $type @{ Vendor = 'Fortinet' }) 'Firewall'
    Test-Value 'router by UPnP' (& $type @{ Upnp = [pscustomobject]@{ DeviceType = 'InternetGatewayDevice' } }) 'Firewall / router'
    Test-Value 'printer by its UPnP maker' (& $type @{ Upnp = $upnp }) 'Printer'
    Test-Value 'range /24' @(Get-AddressRange '192.0.2.0/24').Count '254'
    Test-Value 'range of the last byte' @(Get-AddressRange '192.0.2.10-20').Count '11'
    Test-Value 'range of more than a /16 refused' $(try { [void](Get-AddressRange '10.0.0.0/8'); 'accepted' } catch { 'refused' }) 'refused'
    Test-Value 'prefix of 255.255.240.0' (ConvertTo-PrefixLength '255.255.240.0') '20'
    Test-Value 'network of an address' (Get-NetworkName '10.0.20.77' 20) '10.0.16.0/20'
    Test-Value 'CGNAT address' (Get-AddressKind '100.72.1.1') 'Shared'
    Test-Value 'private address' (Get-AddressKind '172.20.1.1') 'Private'
    Test-Value 'public address' (Get-AddressKind '172.32.1.1') 'Public'
    Test-Value 'public address named static' (Get-PublicAddressType 'static-198-51-100-7.example.net') 'fixed'
    Test-Value 'public address named otherwise' "[$(Get-PublicAddressType 'ip-198-51-100-7.example.net')]" '[]'
    # Other networks: a DNS server elsewhere, a router's own network (SNMP) and a router before the Internet.
    $script:Scanned = New-Object 'System.Collections.Generic.HashSet[long]'
    foreach ($number in @(Get-AddressRange '192.168.1.0/24')) {
        [void]$script:Scanned.Add($number)
    }
    $local = @([pscustomobject]@{ Address = '192.168.1.20'; PrefixLength = 24; Gateway = '192.168.1.1'; DnsServers = @('10.0.30.5', '192.168.1.1'); DhcpServer = '192.168.1.1' })
    $firewall = [pscustomobject]@{ Address = '192.168.1.1'; Name = 'FW01'; Snmp = [pscustomobject]@{ Networks = @([pscustomobject]@{ Address = '10.0.20.1'; Mask = '255.255.255.0' }, [pscustomobject]@{ Address = '192.168.1.1'; Mask = '255.255.255.0' }, [pscustomobject]@{ Address = '127.0.0.1'; Mask = '255.0.0.0' }) } }
    $hops = @([pscustomobject]@{ Hop = 1; Address = '192.168.1.1'; Kind = 'Private' }, [pscustomobject]@{ Hop = 2; Address = '172.16.0.1'; Kind = 'Private' }, [pscustomobject]@{ Hop = 3; Address = '198.51.100.1'; Kind = 'Public' })
    $other = @(Get-OtherNetworks -Devices @($firewall) -Hops $hops)
    Test-Value 'other networks seen' (($other | ForEach-Object { $_.Network }) -join ', ') '10.0.30.0/24, 10.0.20.0/24, 172.16.0.0/24'
    Test-Value 'other network: seen as' (($other | Where-Object { $_.Network -eq '10.0.20.0/24' }).Seen -join '') 'address 10.0.20.1 of 192.168.1.1 FW01 (SNMP)'

    Write-Section 'Network diagram'
    $ranges = @((New-ScanRange '192.168.1.0/24'), (New-ScanRange '10.0.20.0/24'))
    $diagramDevices = @(
        [pscustomobject]@{ Address = '192.168.1.1'; Network = '192.168.1.0/24'; Name = 'FW01'; Type = 'Firewall / router'; Identification = 'FortiGate 60F'; IsGateway = $true }
        [pscustomobject]@{ Address = '192.168.1.2'; Network = '192.168.1.0/24'; Name = 'core-switch'; Type = 'Switch'; Identification = 'Aruba 2930F & <test>'; IsGateway = $false; Snmp = [pscustomobject]@{ Neighbors = @([pscustomobject]@{ LocalPort = '1/1'; Name = 'AP-1'; Port = 'eth0'; Address = $null }) } }
        [pscustomobject]@{ Address = '192.168.1.3'; Network = '192.168.1.0/24'; Name = 'AP-1'; Type = 'Wi-Fi access point'; IsGateway = $false }
        [pscustomobject]@{ Address = '10.0.20.10'; Network = '10.0.20.0/24'; Name = 'SRV01'; Type = 'Windows server'; IsGateway = $false }
    ) + @(1..5 | ForEach-Object { [pscustomobject]@{ Address = "192.168.1.$(100 + $_)"; Network = '192.168.1.0/24'; Name = "PC$_"; Type = 'Windows computer'; IsGateway = $false } })
    $diagram = Write-NetworkDiagram -Path (Join-Path $work 'unit.drawio') -Devices $diagramDevices -Ranges $ranges -Hops $hops -Public ([pscustomobject]@{ Address = '198.51.100.7'; Provider = 'AS64500 Example Telecom' })
    $cells = @(([xml](Get-Content -LiteralPath $diagram -Raw -Encoding UTF8)).mxfile.diagram.mxGraphModel.root.mxCell)
    Test-Value 'a container per network' @($cells | Where-Object { $_.style -like 'swimlane*' }).Count '2'
    Test-Value 'computers counted, not drawn' @($cells | Where-Object { $_.value -like '5 x Windows computer*' }).Count '1'
    Test-Value 'the link told by LLDP' @($cells | Where-Object { $_.edge -eq '1' -and $_.value -eq '1/1 - eth0' }).Count '1'
    Test-Value 'the router before the Internet' @($cells | Where-Object { $_.value -like 'Router 172.16.0.1*' }).Count '1'
    Test-Value 'text escaped for draw.io' @($cells | Where-Object { $_.value -like '*Aruba 2930F &amp; &lt;test&gt;*' }).Count '1'

    Write-Section 'Scan of 127.0.0.1: SNMP, UPnP and WS-Discovery together'
    $local = @(Get-LocalNetwork)
    $communities = @('public', $community)
    $ThrottleLimit = 8
    $script:Scanned = New-Object 'System.Collections.Generic.HashSet[long]'
    $script:UpnpLocations = $locations
    $script:WsdDevices = $wsd
    $script:Vendors = @{}
    $found = @(Find-Devices -Ranges @(New-ScanRange '127.0.0.1'))
    Test-Value 'devices found' $found.Count '1'
    $device = $found[0]
    Test-Value 'its type: UPS (SNMP first)' $device.Type 'UPS'
    Test-Value 'its model' $device.Model 'SMT1500RMI2U'
    Test-Value 'its serial number' $device.Serial 'AS1234567890'
    Test-Value 'its UPnP description, read in its runspace' $device.Upnp.Manufacturer 'Brother'
    Test-Value 'its WS-Discovery types' (@($device.Wsd.Types) -join ', ') 'NetworkVideoTransmitter, Device'
    Test-Value 'its network' $device.Network '127.0.0.1'

    Write-Section 'Speed test program'
    $tool = Get-AuditTool @speedTest
    Test-That 'downloaded and checked against its SHA-256' ([bool]$tool) 'no Internet, or a different file'
    if ($tool) {
        Test-That 'kept in audit-cache' ($tool -like "*\audit-cache\$($speedTest.Name)\$($speedTest.Program)")
        Test-Value 'the copy is used the next time' (Get-AuditTool @speedTest) $tool
        if ($RunSpeedTest) {
            $speed = Measure-InternetSpeed
            Test-That 'the speed test measured the line' ($speed -and $speed.Download -gt 0) "$($speed | Out-String)"
            if ($speed) {
                Write-Host "        $($speed.Download) Mbit/s down, $($speed.Upload) up, ping $($speed.Ping) ms ($($speed.Server))" -ForegroundColor DarkGray
            }
        }
        Set-Content -LiteralPath $tool -Value 'changed'
        Test-That 'a changed copy is refused' ($null -eq (Get-AuditTool @speedTest 3>$null))
        Test-That 'and deleted' (-not (Test-Path -LiteralPath (Split-Path $tool)))
    }

    # Runs a script in a PowerShell of its own, in strict mode as Start.ps1 runs it, with Read-Host and
    # Get-Credential answered from a list of (question pattern, answer), after a setup script if given.
    # Its text, the findings it returned and the questions it asked come back.
    $runner = Join-Path $work 'Invoke-WithAnswers.ps1'
    Set-Content -LiteralPath $runner -Encoding ASCII -Value @'
param([string]$Script, [string]$Answers, [string]$Arguments, [string]$Setup)
Set-StrictMode -Version Latest
if ($Setup) { . $Setup }
# Windows PowerShell gives a JSON list as one object: ForEach-Object takes its items out.
$global:TestAnswers = @(Get-Content -LiteralPath $Answers -Raw | ConvertFrom-Json | ForEach-Object { $_ })
$global:TestQuestions = New-Object System.Collections.Generic.List[string]
function global:New-TestSecret([string]$Text) {
    $secure = New-Object System.Security.SecureString
    foreach ($character in $Text.ToCharArray()) { $secure.AppendChar($character) }
    $secure
}
function global:Read-Host {
    param([Parameter(Position = 0)][object]$Prompt, [switch]$AsSecureString)
    $global:TestQuestions.Add("$Prompt")
    $match = @($global:TestAnswers | Where-Object { "$Prompt" -match $_.Question }) | Select-Object -First 1
    if (-not $match) { throw "Unexpected question: $Prompt" }
    if ($AsSecureString) { return New-TestSecret "$($match.Answer)" }
    return "$($match.Answer)"
}
# Never a real sign-in to a tenant from the tests, whatever the answers.
function global:Connect-MgGraph { throw 'The tests never sign in to Microsoft 365.' }
function global:Get-Credential {
    param([string]$Message, [string]$UserName)
    $global:TestQuestions.Add("Get-Credential: $Message")
    New-Object System.Management.Automation.PSCredential($(if ($UserName) { $UserName } else { 'TEST\reader' }), (New-TestSecret 'not-a-real-one'))
}
$parameters = @{}
foreach ($pair in (Get-Content -LiteralPath $Arguments -Raw | ConvertFrom-Json).PSObject.Properties) { $parameters[$pair.Name] = $pair.Value }
$result = @(& $Script @parameters)
$result | Where-Object { $_ -is [string] }
'FINDINGS: ' + (ConvertTo-Json -Compress -InputObject @($result | Where-Object { $_ -isnot [string] -and $_.PSObject.Properties['AuditFinding'] } | ForEach-Object { [pscustomobject]@{ Severity = $_.AuditFinding; Finding = $_.Finding } }))
'QUESTIONS: ' + ($global:TestQuestions -join ' || ')
'@
    $invoke = {
        param([string]$Script, [object[]]$Answers, [hashtable]$Arguments, [string]$Setup)
        # In files: a command line would lose the quotes of the JSON.
        $answersFile = Join-Path $work "answers-$(Get-Random).json"
        ConvertTo-Json -InputObject @($Answers | ForEach-Object { [pscustomobject]@{ Question = $_[0]; Answer = $_[1] } }) | Set-Content -LiteralPath $answersFile -Encoding UTF8
        $argumentsFile = Join-Path $work "arguments-$(Get-Random).json"
        ConvertTo-Json -InputObject ([pscustomobject]$Arguments) | Set-Content -LiteralPath $argumentsFile -Encoding UTF8
        # Its errors are kept with its output: with Stop, the first one would end the tests.
        $ErrorActionPreference = 'Continue'
        $setupArguments = if ($Setup) { @('-Setup', $Setup) } else { @() }
        $output = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner -Script $Script -Answers $answersFile -Arguments $argumentsFile @setupArguments 2>&1 | ForEach-Object { "$_" })
        $questions = @(($output | Where-Object { $_ -like 'QUESTIONS: *' } | Select-Object -Last 1) -replace '^QUESTIONS: ', '' -split ' \|\| ' | Where-Object { $_ })
        $findingsLine = $output | Where-Object { $_ -like 'FINDINGS: *' } | Select-Object -Last 1
        $findings = @(if ($findingsLine) { $findingsLine -replace '^FINDINGS: ', '' | ConvertFrom-Json | ForEach-Object { $_ } })
        [pscustomobject]@{ Output = $output; Text = ($output -join "`n"); Findings = $findings; Questions = $questions }
    }
    # The finding of this severity whose text matches, or $null.
    $finding = {
        param([object[]]$Findings, [string]$Severity, [string]$Pattern)
        @($Findings | Where-Object { $_.Severity -eq $Severity -and $_.Finding -match $Pattern }) | Select-Object -First 1
    }
    # A copy of a script with some of its text replaced, for a test; a replacement that no longer fits the
    # script stops the tests, so that they never test a script other than the one meant.
    $patch = {
        param([string]$Source, [string]$Destination, [object[]]$Replacements)
        $text = [IO.File]::ReadAllText($Source)
        foreach ($pair in $Replacements) {
            if (-not $text.Contains($pair[0])) {
                throw "The test's patch of $(Split-Path -Leaf $Source) no longer fits: $($pair[0])"
            }
            $text = $text.Replace($pair[0], $pair[1])
        }
        [IO.File]::WriteAllText($Destination, $text)
    }

    Write-Section 'Inventory of this computer (DCOM)'
    $inventoryRun = & $invoke (Join-Path $work 'AuditInventory.ps1') @() @{ Computer = $env:COMPUTERNAME }
    $text = $inventoryRun.Output -join "`n"
    Test-That 'read' ($text -match '1 of 1 read \((0|1) over WinRM, (0|1) over DCOM\)') ((@($inventoryRun.Output) | Select-Object -First 6) -join ' / ')
    Test-That 'listed with its model and serial number' ($text -match "(?m)^\| $([regex]::Escape($env:COMPUTERNAME)) \|")
    Test-That 'its antivirus found' ($text -notmatch ':x: none')
    Test-That 'no question asked' ($inventoryRun.Questions.Count -eq 0) ($inventoryRun.Questions -join '; ')

    Write-Section 'Why a computer was not read, in the languages of Windows'
    $inventoryAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $work 'AuditInventory.ps1'), [ref]$null, [ref]$null)
    . ([scriptblock]::Create($inventoryAst.Find({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq 'Format-ReadError' }, $false).Extent.Text))
    $denied = 'access denied for this account'
    Test-Value 'English' (Format-ReadError 'Access is denied.') $denied
    Test-Value 'French' (Format-ReadError "Acc$([char]0xE8)s refus$([char]0xE9).") $denied
    Test-Value 'Dutch' (Format-ReadError 'Toegang geweigerd.') $denied
    Test-Value 'German' (Format-ReadError 'Zugriff verweigert') $denied
    Test-Value 'the error code alone' (Format-ReadError 'WinRM cannot complete the operation. HRESULT 0x80070005') $denied
    Test-Value 'RPC, English' (Format-ReadError 'The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)') 'DCOM blocked by its firewall'
    Test-Value 'RPC, French' (Format-ReadError "Le serveur RPC n'est pas disponible.") 'DCOM blocked by its firewall'
    Test-Value 'RPC, Dutch' (Format-ReadError 'De RPC-server is niet beschikbaar.') 'DCOM blocked by its firewall'
    Test-Value 'RPC, German' (Format-ReadError "Der RPC-Server ist nicht verf$([char]0xFC)gbar.") 'DCOM blocked by its firewall'
    Test-Value 'TrustedHosts' (Format-ReadError 'The WinRM client cannot process the request. ... the destination machine must be added to the TrustedHosts configuration setting.') 'WinRM needs TrustedHosts for it, and DCOM did not answer'
    $long = Format-ReadError (('An error nobody planned for. ' * 10) + "`nSecond line")
    Test-That 'another error: its first line, cut at 120 characters' ($long.Length -eq 120 -and $long.EndsWith('...') -and $long -notmatch 'Second line') $long

    Write-Section 'Start.ps1 gives the audit its options'
    $startFolder = Join-Path $work 'start-options'
    New-Item -ItemType Directory -Path $startFolder | Out-Null
    Copy-Item -LiteralPath (Join-Path $repository 'Start.ps1'), (Join-Path $repository 'updater.config.json') -Destination $startFolder
    # A stand-in Audit.ps1 that only tells what it was given.
    Set-Content -LiteralPath (Join-Path $startFolder 'Audit.ps1') -Encoding ASCII -Value @'
param([string]$Client, [string[]]$Domain, [string[]]$Subnet, [string[]]$AddSubnet, [string[]]$SnmpCommunity, [string[]]$Skip, [string]$ADServer, [pscredential]$ADCredential, [pscredential]$AdminCredential, [string]$Tenant, [switch]$NonInteractive, [switch]$ScanOtherNetworks, [switch]$Microsoft365, [switch]$Gui)
'AUDIT GOT: ' + (($PSBoundParameters.Keys | Sort-Object | ForEach-Object { "$_=$(@($PSBoundParameters[$_]) -join ',')" }) -join '; ')
'@
    $startRun = & $invoke (Join-Path $startFolder 'Start.ps1') @() @{ SkipUpdate = $true; Audit = $true; Client = 'Contoso'; AddSubnet = @('192.0.2.0/24', '198.51.100.0/24'); Skip = @('SpeedTest'); NonInteractive = $true }
    Test-Value 'the options reach Audit.ps1' (@($startRun.Output | Where-Object { $_ -like 'AUDIT GOT: *' }) -join '') 'AUDIT GOT: AddSubnet=192.0.2.0/24,198.51.100.0/24; Client=Contoso; NonInteractive=True; Skip=SpeedTest'
    $startRun = & $invoke (Join-Path $startFolder 'Start.ps1') @() @{ SkipUpdate = $true; Audit = $true; Gui = $true; ScanOtherNetworks = $true; Microsoft365 = $true }
    Test-Value '-Gui and the switches reach Audit.ps1' (@($startRun.Output | Where-Object { $_ -like 'AUDIT GOT: *' }) -join '') 'AUDIT GOT: Gui=True; Microsoft365=True; ScanOtherNetworks=True'
    $startRun = & $invoke (Join-Path $startFolder 'Start.ps1') @() @{ SkipUpdate = $true; AddSubnet = @('192.0.2.0/24') }
    Test-That 'an audit option without -Audit is refused' ($startRun.Text -match '-AddSubnet is an option of the IT audit: add -Audit') (($startRun.Output | Select-Object -First 4) -join ' / ')
    Test-That 'and nothing else runs' ($startRun.Text -notmatch 'AUDIT GOT|Report')

    if ($SkipGitHub) {
        Write-Section "Update from GitHub: skipped (-SkipGitHub)"
    }
    else {
        Write-Section "Update from GitHub ($Branch): a new folder, then -Audit"
        $installFolder = Join-Path $work 'install'
        New-Item -ItemType Directory -Path $installFolder | Out-Null
        Copy-Item -LiteralPath (Join-Path $repository 'Start.ps1') -Destination $installFolder
        $updateRun = & $invoke (Join-Path $installFolder 'Start.ps1') @() @{ Branch = $Branch; UpdateOnly = $true }
        $config = if (Test-Path -LiteralPath (Join-Path $installFolder 'updater.config.json')) { Get-Content -LiteralPath (Join-Path $installFolder 'updater.config.json') -Raw | ConvertFrom-Json }
        Test-That 'the first run downloads the files every computer has' ($config -and @($config.Files | Where-Object { -not (Test-Path -LiteralPath (Join-Path $installFolder $_)) }).Count -eq 0) (($updateRun.Output | Select-Object -Last 6) -join ' / ')
        Test-That 'no question asked (the repository gives its files without a token)' ($updateRun.Questions.Count -eq 0) ($updateRun.Questions -join '; ')
        Test-That 'but not the audit scripts' (@(Get-ChildItem -LiteralPath $installFolder -Filter 'Audit*.ps1').Count -eq 0)
        $updateRun = & $invoke (Join-Path $installFolder 'Start.ps1') @() @{ Branch = $Branch; UpdateOnly = $true; Audit = $true }
        $auditFiles = @(if ($config) { $config.Audit })
        Test-That "AuditInventory.ps1 is one of the audit scripts of $Branch" ($auditFiles -contains 'AuditInventory.ps1') ($auditFiles -join ', ')
        Test-That 'with -Audit, every audit script is downloaded' ($auditFiles.Count -gt 0 -and @($auditFiles | Where-Object { -not (Test-Path -LiteralPath (Join-Path $installFolder $_)) }).Count -eq 0) (($updateRun.Output | Select-Object -Last 6) -join ' / ')
        Test-That 'and the audit did not run (-UpdateOnly)' ($updateRun.Questions.Count -eq 0 -and @(Get-ChildItem -LiteralPath $installFolder -Filter '*_Audit_*').Count -eq 0)
        $differ = @(@($config.Files) + $auditFiles | Where-Object { (Test-Path -LiteralPath (Join-Path $installFolder $_)) -and (Test-Path -LiteralPath (Join-Path $repository $_)) -and (Get-FileHash -LiteralPath (Join-Path $installFolder $_)).Hash -ne (Get-FileHash -LiteralPath (Join-Path $repository $_)).Hash })
        if ($differ.Count -gt 0) {
            Write-Host "        Not pushed yet, so GitHub's copy differs: $($differ -join ', ')" -ForegroundColor Yellow
        }
    }

    Write-Section 'Script Manager: the IT audit button'
    $managerFolder = Join-Path $work 'manager'
    New-Item -ItemType Directory -Path $managerFolder | Out-Null
    # Start.ps1 only has to be there: the button checks it, and its process is not started.
    Copy-Item -LiteralPath (Join-Path $repository 'updater.config.json'), (Join-Path $repository 'Start.ps1') -Destination $managerFolder
    # The window opens out of sight, its button is clicked, and the process it would start is only kept.
    & $patch (Join-Path $repository 'Manager.ps1') (Join-Path $managerFolder 'Manager.ps1') @(
        , @('$job.Process = [System.Diagnostics.Process]::Start($info)', '$global:TestStarted.Add($info); $job.Process = [pscustomobject]@{ HasExited = $true; ExitCode = 0 }')
        , @('[void]$form.ShowDialog()', @'
$global:TestStarted = New-Object System.Collections.Generic.List[object]
$form.StartPosition = 'Manual'
$form.Location = New-Object System.Drawing.Point(-3000, -3000)
$form.ShowInTaskbar = $false
$form.Opacity = 0
$form.Show()
[System.Windows.Forms.Application]::DoEvents()
'BUTTONS: ' + (@($buttons.Controls | ForEach-Object { $_.Text }) -join ' | ')
@($buttons.Controls | Where-Object { $_.Text -eq 'IT audit' })[0].PerformClick()
[System.Windows.Forms.Application]::DoEvents()
foreach ($info in $global:TestStarted) { 'STARTED: ' + ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(($info.Arguments -split ' ')[-1])) -replace '\r?\n', ' ; ') + ' WINDOW: ' + $info.UseShellExecute }
$form.Close()
'@)
    )
    $managerRun = & $invoke (Join-Path $managerFolder 'Manager.ps1') @() @{}
    $buttonsLine = "$($managerRun.Output | Where-Object { $_ -like 'BUTTONS: *' })"
    Test-That 'the button is there, after Keeper import/export' ($buttonsLine -match 'Keeper import/export \| IT audit \|') $buttonsLine
    $startedJobs = @($managerRun.Output | Where-Object { $_ -like 'STARTED: *' })
    Test-Value 'one click starts one script' $startedJobs.Count '1'
    Test-That 'Start.ps1 -Audit -Gui, of the Script Manager''s folder: the audit window' ("$startedJobs" -match [regex]::Escape("& '$(Join-Path $managerFolder 'Start.ps1')' -Audit -Gui ")) "$startedJobs"
    Test-That 'in its own window, for its questions' ("$startedJobs" -match 'WINDOW: True') "$startedJobs"

    Write-Section 'The audit window'
    $windowFolder = Join-Path $work 'window'
    New-Item -ItemType Directory -Path $windowFolder | Out-Null
    # Audit.ps1 -Gui opens the window with the options given: a stand-in window tells what it got.
    Copy-Item -LiteralPath (Join-Path $work 'Audit.ps1'), (Join-Path $work 'AuditCommon.ps1') -Destination $windowFolder
    Set-Content -LiteralPath (Join-Path $windowFolder 'AuditWindow.ps1') -Encoding ASCII -Value @'
param([string]$Client, [string[]]$Domain, [string[]]$Subnet, [string[]]$AddSubnet, [string[]]$SnmpCommunity, [string[]]$Skip, [string]$ADServer, [pscredential]$ADCredential, [pscredential]$AdminCredential, [string]$Tenant, [string]$OutputPath, [switch]$ScanOtherNetworks, [switch]$Microsoft365, [switch]$NonInteractive, [switch]$NoOpen)
'WINDOW GOT: ' + (($PSBoundParameters.Keys | Sort-Object | ForEach-Object { "$_=$(@($PSBoundParameters[$_]) -join ',')" }) -join '; ')
'@
    $guiRun = & $invoke (Join-Path $windowFolder 'Audit.ps1') @() @{ Gui = $true; Client = 'Contoso'; AddSubnet = @('192.0.2.0/24') }
    Test-Value 'Audit.ps1 -Gui opens the window with the options given' (@($guiRun.Output | Where-Object { $_ -like 'WINDOW GOT: *' }) -join '') 'WINDOW GOT: AddSubnet=192.0.2.0/24; Client=Contoso'
    Test-That 'and asks nothing in the console' ($guiRun.Questions.Count -eq 0) ($guiRun.Questions -join '; ')
    # The real window, opened out of sight and filled in by the test, runs a stand-in Audit.ps1 that
    # tells what it got, shows progress, a warning, and writes an audit and a diagram. Its message
    # boxes are kept instead of shown.
    $windowFolder = Join-Path $work 'window-real'
    New-Item -ItemType Directory -Path $windowFolder | Out-Null
    Set-Content -LiteralPath (Join-Path $windowFolder 'Audit.ps1') -Encoding ASCII -Value @'
param([string]$Client, [string[]]$Domain, [string[]]$Subnet, [string[]]$AddSubnet, [string[]]$SnmpCommunity, [string[]]$Skip, [string]$ADServer, [pscredential]$ADCredential, [pscredential]$AdminCredential, [string]$Tenant, [string]$OutputPath, [switch]$NonInteractive, [switch]$NoOpen, [switch]$ScanOtherNetworks, [switch]$Microsoft365, [switch]$Gui)
Write-Host ('AUDIT GOT: ' + (($PSBoundParameters.Keys | Sort-Object | ForEach-Object { $value = $PSBoundParameters[$_]; if ($value -is [pscredential]) { $value = "$($value.UserName) with a password of $($value.GetNetworkCredential().Password.Length) characters" }; "$_=$(@($value) -join ',')" }) -join '; '))
Write-Progress -Id 20 -Activity 'Network audit' -Status 'Ping: 10 of 254 addresses'
Write-Warning 'A warning of the stand-in.'
Start-Sleep -Milliseconds 900
Set-Content -LiteralPath (Join-Path $OutputPath 'Window_test_Audit_2026-01-01.md') -Encoding UTF8 -Value @('# Window test IT audit', '', '## To complete on site', 'What this audit could not read.', '', '- [ ] Network diagram: first item.', '- [ ] Internet line: second item.', '- [ ] UPS: third item.', '', '## About this audit', '- Written by the stand-in.')
Set-Content -LiteralPath (Join-Path $OutputPath 'Window_test_Audit_2026-01-01.drawio') -Value '<mxfile/>'
Write-Host 'Written by the stand-in.'
'@
    & $patch (Join-Path $repository 'AuditWindow.ps1') (Join-Path $windowFolder 'AuditWindow.ps1') @(
        , @("[void][System.Windows.Forms.MessageBox]::Show(`$form, `$Text, 'MOSE IT audit', 'OK', `$Icon)", '$global:TestMessages.Add($Text)')
        , @('[void]$form.ShowDialog()', @'
$global:TestMessages = New-Object System.Collections.Generic.List[string]
$form.StartPosition = 'Manual'
$form.Location = New-Object System.Drawing.Point(-3000, -3000)
$form.ShowInTaskbar = $false
$form.Opacity = 0
$form.Show()
[System.Windows.Forms.Application]::DoEvents()
'FOLDER: ' + $folderBox.Text
$runButton.PerformClick()
$clientBox.Text = 'Window test'
$addSubnetBox.Text = '192.0.2.0/24 not-a-network'
$runButton.PerformClick()
$addSubnetBox.Text = '192.0.2.0/24, 198.51.100.10-20'
$adminUser.Text = 'TEST\admin'
$runButton.PerformClick()
$adminPassword.Text = 'not-a-real-one'
$partSpeed.Checked = $false
$partM365.Checked = $false
'TENANT DISABLED: ' + (-not $tenantBox.Enabled)
$scanOthers.Checked = $true
$snmpBox.Text = 'snmp-window-test'
$domainsBox.Text = 'example.com, example.net'
$runButton.PerformClick()
'WHILE RUNNING: run ' + $runButton.Enabled + ', stop ' + $stopButton.Enabled + ', fields ' + $net.Enabled
$until = (Get-Date).AddSeconds(60)
while ($ui.Shell -and (Get-Date) -lt $until) {
    [System.Windows.Forms.Application]::DoEvents()
    Start-Sleep -Milliseconds 50
}
foreach ($message in $global:TestMessages) { 'MESSAGE: ' + $message }
'LOG: ' + ($log.Text -replace '\r?\n', ' || ')
'STATUS: ' + $status.Text
'AFTER: run ' + $runButton.Enabled + ', open audit ' + $openAudit.Enabled + ', open diagram ' + $openDiagram.Enabled + ', fields ' + $net.Enabled
$tabs.SelectedTab = $checkPage
[System.Windows.Forms.Application]::DoEvents()
'CHECK LOADED: ' + $checkGrid.Rows.Count + ' rows, ' + $countLabel.Text
$checkGrid.Rows[0].Cells[0].Value = $true
$checkGrid.Rows[0].Cells[3].Value = 'Drawn with the client'
$checkGrid.Rows[1].Cells[1].Value = $true
$checkGrid.Rows[1].Cells[3].Value = "No fixed`r`naddress"
$checkGrid.Rows[2].Cells[1].Value = $true
$checkGrid.Rows[2].Cells[0].Value = $true
[System.Windows.Forms.Application]::DoEvents()
'CHECK ROW 3: done ' + $checkGrid.Rows[2].Cells[0].Value + ', skipped ' + $checkGrid.Rows[2].Cells[1].Value
'CHECK COUNT: ' + $countLabel.Text
'CHECK VISIBLE: ' + @($checkGrid.Rows | Where-Object { $_.Visible }).Count
$hideBox.Checked = $true
[System.Windows.Forms.Application]::DoEvents()
'CHECK HIDDEN: ' + @($checkGrid.Rows | Where-Object { $_.Visible }).Count
'CHECK FILE: ' + ([System.IO.File]::ReadAllText($ui.Checklist) -replace '\r?\n', ' || ')
$hideBox.Checked = $false
& $showChecklist
'CHECK READ BACK: ' + (@($checkGrid.Rows | ForEach-Object { "$($_.Cells[0].Value)/$($_.Cells[1].Value)/$($_.Cells[3].Value)" }) -join '; ')
$form.Close()
'@)
    )
    $windowRun = & $invoke (Join-Path $windowFolder 'AuditWindow.ps1') @() @{}
    $line = { param([string]$Prefix) "$(@($windowRun.Output | Where-Object { $_ -like "$Prefix*" }) -join ' / ')" }
    Test-Value 'the folder: the scripts''' (& $line 'FOLDER: ') "FOLDER: $windowFolder"
    $messages = @($windowRun.Output | Where-Object { $_ -like 'MESSAGE: *' })
    Test-That 'no client: said, nothing run' ($messages.Count -ge 1 -and $messages[0] -like 'MESSAGE: Enter the name of the client*') ($messages -join ' / ')
    Test-That 'a wrong network: said' ($messages.Count -ge 2 -and $messages[1] -like 'MESSAGE: Not a network, range or address: not-a-network.*') ($messages -join ' / ')
    Test-That 'an account without password: said' ($messages.Count -ge 3 -and $messages[2] -eq 'MESSAGE: The administrator account has no password.') ($messages -join ' / ')
    Test-Value 'then no other message' $messages.Count '3'
    Test-Value 'the tenant is off with Microsoft 365' (& $line 'TENANT DISABLED: ') 'TENANT DISABLED: True'
    Test-Value 'while running: only Stop' (& $line 'WHILE RUNNING: ') 'WHILE RUNNING: run False, stop True, fields False'
    $logLine = & $line 'LOG: '
    Test-That 'the answers given as the audit''s options' ($logLine -match [regex]::Escape("AUDIT GOT: AddSubnet=192.0.2.0/24,198.51.100.10-20; AdminCredential=TEST\admin with a password of 14 characters; Client=Window test; Domain=example.com,example.net; NonInteractive=True; NoOpen=True; OutputPath=$windowFolder; ScanOtherNetworks=True; Skip=SpeedTest,Microsoft365; SnmpCommunity=snmp-window-test ||")) $logLine
    Test-That 'its warnings in the log' ($logLine -match 'WARNING: A warning of the stand-in\.')
    Test-That 'its messages in the log, to the end' ($logLine -match 'Written by the stand-in\.')
    Test-That 'done: the audit named' ((& $line 'STATUS: ') -match '^STATUS: Done in [\d.]+ minutes: Window_test_Audit_2026-01-01\.md\. Its on-site checklist is in the second tab\.$') (& $line 'STATUS: ')
    Test-Value 'then the audit and the diagram can be opened' (& $line 'AFTER: ') 'AFTER: run True, open audit True, open diagram True, fields True'
    Test-Value 'checklist: the audit just written, its items' (& $line 'CHECK LOADED: ') 'CHECK LOADED: 3 rows, 0 of 3 done, 0 skipped, 3 left.'
    Test-Value 'checklist: done and skipped exclude each other' (& $line 'CHECK ROW 3: ') 'CHECK ROW 3: done True, skipped False'
    Test-Value 'checklist: counted' (& $line 'CHECK COUNT: ') 'CHECK COUNT: 2 of 3 done, 1 skipped, 0 left.'
    Test-Value 'checklist: all shown until hidden' (& $line 'CHECK VISIBLE: ') 'CHECK VISIBLE: 3'
    Test-Value 'checklist: what is done or skipped hidden' (& $line 'CHECK HIDDEN: ') 'CHECK HIDDEN: 0'
    $fileLine = & $line 'CHECK FILE: '
    Test-That 'checklist: saved in the audit, ticked, struck through, notes on one line' ($fileLine -match [regex]::Escape('## To complete on site || What this audit could not read. ||  || - [x] Network diagram: first item. ||   - Note: Drawn with the client || - [ ] ~~Internet line: second item.~~ (skipped) ||   - Note: No fixed address || - [x] UPS: third item. ||  || ## About this audit || - Written by the stand-in.')) $fileLine
    Test-Value 'checklist: read back from the audit' (& $line 'CHECK READ BACK: ') 'CHECK READ BACK: True/False/Drawn with the client; False/True/No fixed address; True/False/'

    Write-Section 'The audit window runs the real audit'
    # The network part only, of this computer's own address: the audit in the window's runspace.
    $windowFolder = Join-Path $work 'window-audit'
    New-Item -ItemType Directory -Path $windowFolder | Out-Null
    Copy-Item -Path (Join-Path $work 'Audit*.ps1') -Destination $windowFolder
    Remove-Item -LiteralPath (Join-Path $windowFolder 'AuditWindow.ps1')
    & $patch (Join-Path $repository 'AuditWindow.ps1') (Join-Path $windowFolder 'AuditWindow.ps1') @(
        , @("[void][System.Windows.Forms.MessageBox]::Show(`$form, `$Text, 'MOSE IT audit', 'OK', `$Icon)", '$global:TestMessages.Add($Text)')
        , @('[void]$form.ShowDialog()', @"
`$global:TestMessages = New-Object System.Collections.Generic.List[string]
`$form.StartPosition = 'Manual'
`$form.Location = New-Object System.Drawing.Point(-3000, -3000)
`$form.ShowInTaskbar = `$false
`$form.Opacity = 0
`$form.Show()
[System.Windows.Forms.Application]::DoEvents()
`$clientBox.Text = 'Window audit'
`$subnetBox.Text = '$own'
foreach (`$box in `$partSpeed, `$partAD, `$partInventory, `$partM365, `$partDomains) { `$box.Checked = `$false }
`$runButton.PerformClick()
`$statuses = New-Object System.Collections.Generic.List[string]
`$until = (Get-Date).AddSeconds(240)
while (`$ui.Shell -and (Get-Date) -lt `$until) {
    [System.Windows.Forms.Application]::DoEvents()
    if (`$statuses -notcontains `$status.Text) { `$statuses.Add(`$status.Text) }
    Start-Sleep -Milliseconds 50
}
foreach (`$message in `$global:TestMessages) { 'MESSAGE: ' + `$message }
'PROGRESS: ' + (@(`$statuses | Where-Object { `$_ -like 'Network audit: *' }).Count)
`$tabs.SelectedTab = `$checkPage
[System.Windows.Forms.Application]::DoEvents()
'CHECKLIST: ' + `$checkGrid.Rows.Count + ' ' + `$countLabel.Text
'LOG: ' + (`$log.Text -replace '\r?\n', ' || ')
'STATUS: ' + `$status.Text
`$form.Close()
"@)
    )
    $windowRun = & $invoke (Join-Path $windowFolder 'AuditWindow.ps1') @() @{}
    $line = { param([string]$Prefix) "$(@($windowRun.Output | Where-Object { $_ -like "$Prefix*" }) -join ' / ')" }
    Test-That 'no message' (@($windowRun.Output | Where-Object { $_ -like 'MESSAGE: *' }).Count -eq 0) (& $line 'MESSAGE: ')
    Test-That 'done, the audit written' ((& $line 'STATUS: ') -match '^STATUS: Done in [\d.]+ minutes: Window_audit_Audit_\d{4}-\d{2}-\d{2}\.md\. Its on-site checklist is in the second tab\.$') ((& $line 'STATUS: ') + ' ' + (& $line 'LOG: '))
    Test-That 'its progress shown in the status line' ([int]((& $line 'PROGRESS: ') -replace '\D', '') -gt 0) (& $line 'PROGRESS: ')
    Test-That 'the parts and where the audit went, in the log' ((& $line 'LOG: ') -match '== Network' -and (& $line 'LOG: ') -match 'Active Directory skipped: skipped with -Skip' -and (& $line 'LOG: ') -match 'audit written to ')
    $windowAudit = Get-ChildItem -LiteralPath $windowFolder -Filter 'Window_audit_Audit_*.md' | Select-Object -First 1
    Test-That 'the audit has the network scanned' ($windowAudit -and (Get-Content -LiteralPath $windowAudit.FullName -Raw) -match "Scanned: $([regex]::Escape($own))\.")
    Test-That 'and its diagram' ($windowAudit -and (Test-Path -LiteralPath ($windowAudit.FullName -replace '\.md$', '.drawio')))
    Test-Value 'its 16 on-site items in the checklist tab' (& $line 'CHECKLIST: ') 'CHECKLIST: 16 0 of 16 done, 0 skipped, 16 left.'
    # The checklist of an audit whose section is the last one, and of one without it.
    $windowAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repository 'AuditWindow.ps1'), [ref]$null, [ref]$null)
    foreach ($name in 'Read-AuditChecklist', 'Write-AuditChecklist') {
        . ([scriptblock]::Create($windowAst.Find({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq $name }, $false).Extent.Text))
    }
    $lastSection = Join-Path $work 'checklist-last.md'
    [System.IO.File]::WriteAllText($lastSection, "# T`r`nText`r`n`r`n## To complete on site`r`nIntro.`r`n`r`n- [ ] A: first.`r`n- [x] B: second.`r`n  - Note: kept`r`n", (New-Object System.Text.UTF8Encoding($true)))
    $read = Read-AuditChecklist $lastSection
    Test-Value 'a last section read' (@($read.Items | ForEach-Object { "$($_.Text)|$($_.Done)|$($_.Skipped)|$($_.Note)" }) -join '; ') 'A: first.|False|False|; B: second.|True|False|kept'
    Write-AuditChecklist -Path $lastSection -Items @([pscustomobject]@{ Text = 'A: first.'; Done = $false; Skipped = $true; Note = 'n/a' }, [pscustomobject]@{ Text = 'B: second.'; Done = $false; Skipped = $false; Note = '' })
    $written = [System.IO.File]::ReadAllBytes($lastSection)
    Test-That 'written in UTF-8 with its mark, as Audit.ps1 writes' ($written[0] -eq 0xEF -and $written[1] -eq 0xBB -and $written[2] -eq 0xBF)
    Test-Value 'a last section written, the rest kept' ([System.IO.File]::ReadAllText($lastSection) -replace '\r?\n', ' || ') '# T || Text ||  || ## To complete on site || Intro. ||  || - [ ] ~~A: first.~~ (skipped) ||   - Note: n/a || - [ ] B: second. || '
    $noSection = Join-Path $work 'checklist-none.md'
    Set-Content -LiteralPath $noSection -Value '# No checklist here'
    Test-That 'an audit without the section: none read' ($null -eq (Read-AuditChecklist $noSection))
    Test-That 'and none written' ($(try { Write-AuditChecklist -Path $noSection -Items @(); $false } catch { $_.Exception.Message -match 'no "To complete on site" section' }))

    Write-Section 'The other networks seen, scanned without a question'
    $othersCopy = Join-Path $work 'AuditNetwork-others.ps1'
    & $patch $network $othersCopy @(
        , @('$hops = @(Get-InternetPath)', '$hops = @()')
        , @('$script:UpnpLocations = Get-UpnpLocations', '$script:UpnpLocations = @{}')
        , @('$script:WsdDevices = Get-WsdDevices', '$script:WsdDevices = @{}')
        , @('$seen = @(Get-OtherNetworks -Devices $devices -Hops $hops)', '$seen = @($global:TestOtherNetworks)')
    )
    $othersSetup = Join-Path $work 'other-networks.ps1'
    Set-Content -LiteralPath $othersSetup -Encoding ASCII -Value "`$global:TestOtherNetworks = @([pscustomobject]@{ Network = '127.0.0.2/32'; Seen = @('test') }, [pscustomobject]@{ Network = '10.0.0.0/16'; Seen = @('test') })"
    $othersRun = & $invoke $othersCopy @() @{ Subnet = @('127.0.0.1'); SkipSpeedTest = $true; ScanOtherNetworks = $true } $othersSetup
    Test-That 'the small one scanned' ($othersRun.Text -match 'Scanning the other networks seen: 127\.0\.0\.2/32\.' -and $othersRun.Text -match 'Scanned: 127\.0\.0\.1, 127\.0\.0\.2/32\.') (($othersRun.Output | Where-Object { $_ -match 'Scann' }) -join ' / ')
    Test-That 'the /16 named, not scanned' ($othersRun.Text -match 'too large to scan without being named: 10\.0\.0\.0/16')
    Test-That 'no question asked' ($othersRun.Questions.Count -eq 0) ($othersRun.Questions -join '; ')

    Write-Section 'Servers and computers: the findings of made-up computers'
    $inventoryCopy = Join-Path $work 'AuditInventory-made-up.ps1'
    $reading = $inventoryAst.Find({ $args[0] -is [System.Management.Automation.Language.IfStatementAst] -and $args[0].Clauses[0].Item1.Extent.Text -eq '$reachable.Count -gt 0' }, $false)
    & $patch (Join-Path $work 'AuditInventory.ps1') $inventoryCopy @(
        , @("`$open = Test-TcpPorts -Addresses `$names -Ports 5985, 135 -TimeoutMs 1500 -Status 'Which computers answer' -Activity 'Servers and computers' -ProgressId 40 -Percent 5", '$open = $global:TestOpen')
        , @($reading.Extent.Text, '$results = @($global:TestResults)')
    )
    $setup = Join-Path $work 'made-up-computers.ps1'
    Set-Content -LiteralPath $setup -Encoding ASCII -Value @'
$now = Get-Date
function global:New-TestComputer([hashtable]$Values) {
    $computer = [ordered]@{
        Computer = $null; Protocol = 'WinRM'; Error = $null; Warnings = @()
        Name = $null; Kind = 'Computer'; Manufacturer = 'Dell Inc.'; Model = 'OptiPlex 7010'; Serial = 'TEST0001'; Chassis = 'Desktop'; Virtual = $false
        Processor = 'Intel(R) Core(TM) i5-13500, 14 cores'; MemoryGB = 16
        Disks = @([pscustomobject]@{ Name = 'NVMe SSD'; SizeGB = 512; Type = 'SSD'; Health = 'Healthy' })
        Volumes = @([pscustomobject]@{ Drive = 'C:'; Label = ''; SizeGB = 476; FreeGB = 200; FreePercent = 42 })
        Os = 'Windows 11 Pro'; Version = '10.0.26100'; Installed = $now.AddYears(-1); LastBoot = $now.AddDays(-2); LastUpdate = $now.AddDays(-5); User = 'CONTOSO\user'
        Licence = [pscustomobject]@{ Channel = 'OEM'; Activated = $true; Status = 'activated'; Key = 'ABCDE' }
        Office = @(); Roles = @(); Antivirus = @('Microsoft Defender'); Defender = $null; BitLocker = 'On'
        Administrators = @([pscustomobject]@{ Name = 'PC\Administrator'; Sid = 'S-1-5-21-1-2-3-500' }, [pscustomobject]@{ Name = 'CONTOSO\Domain Admins'; Sid = 'S-1-5-21-4-5-6-512' })
        Services = @(); ServicesRead = $true; Software = @(); SqlInstances = @(); UsbUps = @()
    }
    foreach ($key in $Values.Keys) { $computer[$key] = $Values[$key] }
    $computer.Computer = $computer.Name
    [pscustomobject]$computer
}
$global:TestOpen = @{ 'DC01' = @(5985); 'SRV01' = @(5985, 135); 'PC01' = @(135); 'PC02' = @(135); 'PC04' = @(135) }
$global:TestResults = @(
    New-TestComputer @{ Name = 'DC01'; Kind = 'Domain controller'; Manufacturer = 'VMware, Inc.'; Model = 'VMware Virtual Platform'; Virtual = $true; Chassis = 'Virtual'; Os = 'Windows Server 2019 Standard'; Version = '10.0.17763'; Roles = @('Active Directory Domain Services', 'DNS Server') }
    New-TestComputer @{
        Name = 'SRV01'; Kind = 'Server'; Model = 'PowerEdge R740'; Chassis = 'Server'; Os = 'Windows Server 2016 Standard'; Version = '10.0.14393'
        LastUpdate = $now.AddDays(-120); Antivirus = @()
        Disks = @([pscustomobject]@{ Name = 'PERC H730'; SizeGB = 1800; Type = 'HDD'; Health = 'Warning' })
        Volumes = @([pscustomobject]@{ Drive = 'C:'; Label = ''; SizeGB = 120; FreeGB = 14; FreePercent = 12 }, [pscustomobject]@{ Drive = 'D:'; Label = 'Data'; SizeGB = 1700; FreeGB = 85; FreePercent = 5 })
        Licence = [pscustomobject]@{ Channel = 'Retail'; Activated = $false; Status = 'grace period'; Key = 'FGHIJ' }
        Services = @([pscustomobject]@{ Kind = 'Remote access'; Product = 'TeamViewer'; Running = $true }, [pscustomobject]@{ Kind = 'Database'; Product = 'SQL Server'; Running = $true })
        SqlInstances = @([pscustomobject]@{ Instance = 'OLD'; Edition = 'Express Edition'; Version = '12.0.6024.0' }, [pscustomobject]@{ Instance = 'APP'; Edition = 'Standard Edition'; Version = '14.0.3456.2' }, [pscustomobject]@{ Instance = 'NEW'; Edition = 'Standard Edition'; Version = '16.0.1000.6' })
        Software = @([pscustomobject]@{ Name = 'Accounting Suite'; Publisher = 'Example Software'; Version = '9.1' })
        UsbUps = @('American Power Conversion USB UPS')
    }
    New-TestComputer @{
        Name = 'PC01'; Protocol = 'DCOM'; Manufacturer = 'HP'; Model = 'HP EliteBook 840 G8'; Chassis = 'Laptop'; BitLocker = 'Off'
        Defender = [pscustomobject]@{ Mode = 'Normal'; Enabled = $true; RealTime = $true; Signatures = $now.AddDays(-10) }
        Administrators = @([pscustomobject]@{ Name = 'PC01\Administrator'; Sid = 'S-1-5-21-7-8-9-500' }, [pscustomobject]@{ Name = 'CONTOSO\jdoe'; Sid = 'S-1-5-21-4-5-6-1105' })
        Services = @([pscustomobject]@{ Kind = 'Remote management'; Product = 'Datto RMM'; Running = $true })
        Office = @([pscustomobject]@{ Name = 'Office19StandardVL_KMS_Client_AE'; Channel = 'Volume (KMS)'; Activated = $true; Status = 'activated'; Key = 'KLMNO' })
    }
    New-TestComputer @{ Name = 'PC02'; Protocol = 'DCOM'; BitLocker = 'Off'; Antivirus = @(); ServicesRead = $false }
    [pscustomobject]@{ Computer = 'PC04'; Protocol = $null; Error = "Acc$([char]0xE8)s refus$([char]0xE9)." }
)
'@
    $made = & $invoke $inventoryCopy @() @{ Computer = @('DC01', 'SRV01', 'PC01', 'PC02', 'PC03', 'PC04') } $setup
    $text = $made.Text
    Test-That 'four of six read' ($text -match '4 of 6 read \(2 over WinRM, 2 over DCOM\): 2 servers, 2 computers') (($made.Output | Select-Object -First 4) -join ' / ')
    Test-That 'one did not answer' ($text -match '\| PC03 \| no answer on WinRM \(5985\) or RPC \(135\)')
    Test-That 'one refused the account (French Windows)' ($text -match '\| PC04 \| access denied for this account \|')
    Test-That 'a virtual machine named once' ($text -match '\| DC01 \| Domain controller, Active Directory Domain Services, DNS Server \| Virtual machine \(VMware Virtual Platform\) \|')
    Test-That 'the maker without "Inc."' ($text -match '\| SRV01 \| Server \| Dell PowerEdge R740 \|')
    Test-That 'the business software listed' ($text -match '\| Accounting Suite \| 9\.1 \| Example Software \| SRV01 \|')
    Test-That 'the UPS on USB listed' ($text -match '\| SRV01 \| American Power Conversion USB UPS \|')
    Test-That 'the Office key listed' ($text -match '\| PC01 \| Office19StandardVL_KMS_Client_AE \| Volume \(KMS\), activated, key \.\.\.KLMNO \|')
    Test-That 'C: at 12% in the disk space table' ($text -match '\| SRV01 \| C: \| 120 GB \| 14 GB \(12%\) \|')
    $noAntivirus = & $finding $made.Findings 'High' 'No antivirus found running on 1 computer'
    Test-That 'High: no antivirus on SRV01' ($noAntivirus -and $noAntivirus.Finding -match 'SRV01')
    Test-That 'not on PC02, whose services were not read' ($noAntivirus -and $noAntivirus.Finding -notmatch 'PC02')
    Test-That "Medium: Defender's signatures 10 days old on PC01" ([bool](& $finding $made.Findings 'Medium' "Defender's signatures are more than a week old on PC01"))
    Test-That 'Medium: no update for 120 days on SRV01, not PC01' ([bool](& $finding $made.Findings 'Medium' 'No update installed for more than 60 days on SRV01 \([^)]+\)\.$'))
    Test-That 'Medium: D: at 5%, not C: at 12%' ([bool](& $finding $made.Findings 'Medium' 'Less than 10% free on SRV01 D: Data \(85 GB \(5%\)\)\.$'))
    Test-That 'High: the disk Windows reports as failing' ([bool](& $finding $made.Findings 'High' 'failing: SRV01 PERC H730 \(Warning\)'))
    $bitLocker = & $finding $made.Findings 'Medium' '1 laptop has no BitLocker'
    Test-That 'Medium: the laptop without BitLocker, not the desktop' ($bitLocker -and $bitLocker.Finding -match 'PC01' -and $bitLocker.Finding -notmatch 'PC02')
    Test-That 'Low: Windows not activated on SRV01' ([bool](& $finding $made.Findings 'Low' 'not activated on SRV01 \(grace period\)'))
    Test-That 'Medium: a user is local administrator of PC01' ([bool](& $finding $made.Findings 'Medium' 'local administrators on 1 computer: PC01 \(CONTOSO\\jdoe\)'))
    Test-That 'Medium: two remote access tools' ([bool](& $finding $made.Findings 'Medium' '2 remote access or management tools are installed: Datto RMM, TeamViewer'))
    Test-That 'Low: no backup software on the two servers' ([bool](& $finding $made.Findings 'Low' 'No backup software found on the 2 servers read'))
    Test-That 'High: SQL Server 2014, ended' ([bool](& $finding $made.Findings 'High' 'SQL Server 2014 \(12\.0\.6024\.0\) Express Edition on SRV01\\OLD: its support ended on 2024-07-09'))
    $sql2017 = if ((Get-Date) -ge [datetime]'2027-10-12') { 'High' } else { 'Medium' }
    Test-That "$($sql2017): SQL Server 2017, ending on 2027-10-12" ([bool](& $finding $made.Findings $sql2017 'SQL Server 2017 .* on SRV01\\APP: its support (ends|ended) on 2027-10-12'))
    Test-That 'nothing about SQL Server 2022' (-not (@($made.Findings | Where-Object { $_.Finding -match 'SRV01\\NEW' }).Count))
    Test-Value 'no other finding' $made.Findings.Count '12'
    $glued = @($made.Findings | Where-Object { $_.Finding -cmatch '[a-z]:[A-Za-z]' } | ForEach-Object { $_.Finding })
    Test-That 'no colon glued to the next word' ($glued.Count -eq 0) ($glued -join ' / ')

    Write-Section 'Route to the Internet: double NAT, CGNAT, no answer'
    $networkCopy = Join-Path $work 'AuditNetwork-route.ps1'
    # The route comes from the test; no UPnP or WS-Discovery search is sent, and only 127.0.0.1 is scanned.
    & $patch $network $networkCopy @(
        , @('$hops = @(Get-InternetPath)', '$hops = @($global:TestHops)')
        , @('$script:UpnpLocations = Get-UpnpLocations', '$script:UpnpLocations = @{}')
        , @('$script:WsdDevices = Get-WsdDevices', '$script:WsdDevices = @{}')
    )
    $routes = [ordered]@{
        'double NAT' = "@([pscustomobject]@{ Hop = 1; Address = '192.168.1.1'; Name = `$null; Kind = 'Private' }, [pscustomobject]@{ Hop = 2; Address = '172.16.0.1'; Name = `$null; Kind = 'Private' }, [pscustomobject]@{ Hop = 3; Address = '198.51.100.1'; Name = 'edge.example.net'; Kind = 'Public' })"
        'CGNAT'      = "@([pscustomobject]@{ Hop = 1; Address = '192.168.1.1'; Name = `$null; Kind = 'Private' }, [pscustomobject]@{ Hop = 2; Address = '100.64.12.1'; Name = `$null; Kind = 'Shared' }, [pscustomobject]@{ Hop = 3; Address = '198.51.100.1'; Name = `$null; Kind = 'Public' })"
        'no answer'  = '@()'
    }
    $routeRuns = @{}
    foreach ($name in $routes.Keys) {
        $routeSetup = Join-Path $work "route-$($name -replace ' ', '-').ps1"
        Set-Content -LiteralPath $routeSetup -Encoding ASCII -Value "`$global:TestHops = $($routes[$name])"
        $routeRuns[$name] = & $invoke $networkCopy @() @{ Subnet = @('127.0.0.1'); SkipSpeedTest = $true } $routeSetup
    }
    $run = $routeRuns['double NAT']
    Test-That 'double NAT: an Info finding names the second router' ([bool](& $finding $run.Findings 'Info' 'another private router after the gateway \(172\.16\.0\.1\)'))
    Test-That 'double NAT: no CGNAT finding' (-not (& $finding $run.Findings 'Low' 'CGNAT'))
    Test-That 'double NAT: the route table' ($run.Text -match '\| 3 \| 198\.51\.100\.1 \| edge\.example\.net \| Internet \|')
    $run = $routeRuns['CGNAT']
    Test-That 'CGNAT: a Low finding names the shared address' ([bool](& $finding $run.Findings 'Low' "provider's shared address 100\.64\.12\.1 \(CGNAT\)"))
    Test-That 'CGNAT: no double NAT finding' (-not (& $finding $run.Findings 'Info' 'private router'))
    Test-That "CGNAT: shown as the provider's shared address" ($run.Text -match "\| 2 \| 100\.64\.12\.1 \|  \| provider's shared address \(CGNAT\) \|")
    $run = $routeRuns['no answer']
    Test-That 'no answer: said so' ($run.Text -match 'No router answered on the way to the Internet')
    Test-That 'no answer: no route finding' (-not (@($run.Findings | Where-Object { $_.Finding -match 'CGNAT|private router' }).Count))

    Write-Section 'Full audit 1: questions, fake UPS on 127.0.0.1 added after the scan'
    $folder1 = Join-Path $work 'audit1'
    New-Item -ItemType Directory -Path $folder1 | Out-Null
    Copy-Item -Path (Join-Path $work 'Audit*.ps1') -Destination $folder1
    $answers = @(
        , @('^Client name', 'Test client')
        , @('SNMP community', $community)
        , @('Scan more networks|Scan other networks', '127.0.0.1')
        , @('Domain controller', '')
        , @('^Administrator account to read', '-')
        , @('^Sign in to Microsoft 365', 'n')
        , @('Other public domains', '')
    )
    $run = & $invoke (Join-Path $folder1 'Audit.ps1') $answers @{ Subnet = $own; Skip = @('SpeedTest'); OutputPath = $folder1; NoOpen = $true }
    $markdownFile = Get-ChildItem -Path $folder1 -Filter 'Test_client_Audit_*.md' | Select-Object -First 1
    Test-That 'audit written' ([bool]$markdownFile) (($run.Output | Select-Object -Last 8) -join ' / ')
    if ($markdownFile) {
        $markdown = Get-Content -LiteralPath $markdownFile.FullName -Raw -Encoding UTF8
        $json = Get-Content -LiteralPath ($markdownFile.FullName -replace '\.md$', '.json') -Raw -Encoding UTF8
        $drawio = $markdownFile.FullName -replace '\.md$', '.drawio'
        $asked = $run.Questions -join ' | '
        Test-That 'asked the client' ($asked -match 'Client name')
        Test-That 'asked the SNMP community' ($asked -match 'SNMP community')
        Test-That 'asked for more networks after the scan' ($asked -match 'Scan more networks|Scan other networks')
        if (-not $inDomain) {
            Test-That 'asked for a domain controller' ($asked -match 'Domain controller')
            Test-That 'no administrator account asked: no Windows computer to read' ($asked -notmatch 'Administrator account to read') $asked
        }
        Test-That 'asked about Microsoft 365' ($asked -match 'Sign in to Microsoft 365')
        Test-That 'Microsoft 365 skipped on "n": no sign-in tried' ($markdown -match 'Microsoft 365: skipped, no sign-in\.')
        Test-That 'asked for more public domains' ($asked -match 'Other public domains')
        Test-That 'no part failed' ($markdown -notmatch ':warning: Not read:') (([regex]::Matches($markdown, ':warning: Not read: [^\n]*') | ForEach-Object { $_.Value }) -join ' / ')
        Test-That 'the fake UPS scanned' ($markdown -match '(?s)### UPS.*Smart-UPS 1500')
        Test-That 'its battery to replace is a finding' ($markdown -match 'says its battery needs replacing')
        Test-That 'its model and serial number listed' ($markdown -match '(?s)### Models and serial numbers.*SMT1500RMI2U.*AS1234567890')
        Test-That 'its VLANs and neighbour listed' ($markdown -match '(?s)### VLANs and neighbours.*VLAN25.*core-switch\.contoso\.local')
        Test-That 'its own network offered for the next audit' ($markdown -match '(?s)### Other networks.*10\.0\.20\.0/24')
        Test-That 'the community is nowhere in the audit' (-not ($markdown -match [regex]::Escape($community) -or $json -match [regex]::Escape($community) -or (Get-Content -LiteralPath $drawio -Raw) -match [regex]::Escape($community)))
        Test-That 'the diagram has the fake UPS' ((Test-Path -LiteralPath $drawio) -and (Get-Content -LiteralPath $drawio -Raw) -match 'SMT1500RMI2U')
        Test-That 'the checklist says where the UPS is' ($markdown -match '- \[ \] UPS: what shuts down on battery')
        Test-That 'the checklist says where the VLANs are' ($markdown -match '- \[ \] Switches and Wi-Fi: management')
        Test-That 'the route to the Internet read' (@(($json | ConvertFrom-Json).Data.Network.InternetPath).Count -gt 0) 'no Internet?'
    }

    Write-Section 'Full audit 2: questions, stand-in Active Directory, inventory with an account'
    $folder2 = Join-Path $work 'audit2'
    New-Item -ItemType Directory -Path $folder2 | Out-Null
    Copy-Item -Path (Join-Path $work 'Audit*.ps1') -Destination $folder2
    Set-Content -LiteralPath (Join-Path $folder2 'AuditAD.ps1') -Encoding ASCII -Value @'
param([string]$Server, [pscredential]$Credential)
# Stand-in of the tests for AuditAD.ps1: Active Directory as if a domain controller had answered.
Set-StrictMode -Off
. (Join-Path $PSScriptRoot 'AuditCommon.ps1')
'### Domain'
"Stand-in of the tests, asked of $Server as $(if ($Credential) { $Credential.UserName } else { 'this user' })."
New-AuditData -Name 'ActiveDirectory' -Value ([pscustomobject]@{
        Domain      = 'test.local'
        UpnSuffixes = @()
        Computers   = @(
            [pscustomobject]@{ Name = 'TESTPC1'; DnsName = 'localhost'; Os = 'Windows 11 Pro'; Enabled = $true; LastLogon = (Get-Date) }
            [pscustomobject]@{ Name = 'OLDPC'; DnsName = 'oldpc.test.local'; Os = 'Windows 10 Pro'; Enabled = $true; LastLogon = (Get-Date).AddDays(-200) }
            [pscustomobject]@{ Name = 'NAS1'; DnsName = 'nas1.test.local'; Os = 'Synology DSM'; Enabled = $true; LastLogon = (Get-Date) }
        )
    })
'@
    $answers = @(
        , @('^Client name', 'Test client 2')
        , @('SNMP community', '')
        , @('Scan more networks|Scan other networks', '')
        , @('Domain controller', 'dc.test.local')
        , @('^Administrator account to read', 'TEST\admin')
        , @('^Sign in to Microsoft 365', 'n')
        , @('Other public domains', '')
    )
    $run = & $invoke (Join-Path $folder2 'Audit.ps1') $answers @{ Subnet = $own; Skip = @('SpeedTest'); OutputPath = $folder2; NoOpen = $true }
    $markdownFile = Get-ChildItem -Path $folder2 -Filter 'Test_client_2_Audit_*.md' | Select-Object -First 1
    Test-That 'audit written' ([bool]$markdownFile) (($run.Output | Select-Object -Last 8) -join ' / ')
    if ($markdownFile -and -not $inDomain) {
        $markdown = Get-Content -LiteralPath $markdownFile.FullName -Raw -Encoding UTF8
        $asked = $run.Questions -join ' | '
        Test-That 'asked for a domain account for the domain controller given' ($asked -match 'Get-Credential: Domain account to read Active Directory on dc\.test\.local')
        Test-That 'the stand-in Active Directory read' ($markdown -match 'Stand-in of the tests, asked of dc\.test\.local as TEST\\reader')
        Test-That 'asked for an administrator account for the computers found' ($asked -match 'Administrator account to read the 1 Windows servers and computers found')
        Test-That 'asked for its password' ($asked -match "Get-Credential: Administrator of the client's Windows")
        Test-That 'the computer of Active Directory tried' ($markdown -match '(?s)## Servers and computers.*0 of 1 read.*\| localhost \|')
        Test-That 'not the old computer nor the NAS' ($markdown -notmatch 'oldpc|nas1')
        Test-That 'the checklist keeps the whole servers item' ($markdown -match '- \[ \] Servers: model, serial number')
        Test-That 'Microsoft 365 skipped on "n": no sign-in tried' ($markdown -match 'Microsoft 365: skipped, no sign-in\.')
        Test-That 'no part failed' ($markdown -notmatch ':warning: Not read:') (([regex]::Matches($markdown, ':warning: Not read: [^\n]*') | ForEach-Object { $_.Value }) -join ' / ')
    }
    elseif ($inDomain) {
        Write-Host '  (this computer is in a domain: the stand-in Active Directory is not asked for, so its checks are skipped)' -ForegroundColor Yellow
    }
}
finally {
    $control.Stop = $true
    $http.Stop()
    $http.Close()
    for ($index = 0; $index -lt $fakes.Count; $index++) {
        [void]$handles[$index].AsyncWaitHandle.WaitOne(3000)
        $fakes[$index].Dispose()
    }
    Stop-Job -Job $agent -ErrorAction SilentlyContinue
    Remove-Job -Job $agent -Force -ErrorAction SilentlyContinue
}

Write-Host "`n$($script:Passed) passed, $($script:Failures.Count) failed, in $([math]::Round(((Get-Date) - $started).TotalMinutes, 1)) minutes." -ForegroundColor $(if ($script:Failures.Count) { 'Red' } else { 'Green' })
if ($Keep -or $script:Failures.Count) {
    Write-Host "The test folder, with the audits written: $work" -ForegroundColor Yellow
}
else {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
if ($script:Failures.Count) {
    exit 1
}
