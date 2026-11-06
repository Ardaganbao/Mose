[CmdletBinding()]
param(
    # Not -SpeedTest: AuditNetwork.ps1's $speedTest, loaded below, would replace it.
    [Parameter(HelpMessage = 'Also run the speed test: librespeed-cli uses the Internet line for about 30 seconds.')]
    [switch]$RunSpeedTest,

    [Parameter(HelpMessage = 'Keep the test folder, with the audits written, instead of deleting it.')]
    [switch]$Keep
)

# Tests of the IT audit (Audit.ps1 and its parts) on this computer only: no other device of the network
# is scanned. The SNMP, UPnP and WS-Discovery devices are fakes on 127.0.0.1; the network scans cover
# this computer's own address and 127.0.0.1; the inventory reads this computer over DCOM. The full
# audit then runs twice in a PowerShell of its own, in strict mode as Start.ps1 runs it, with each of
# its questions answered by the test: an unexpected question fails it. The second run has a stand-in
# Active Directory, whose computers the inventory is asked to read.
#
# It needs the Internet for the public address, the route to 1.1.1.1, the MAC vendors and the speed
# test's download (checked, run only with -RunSpeedTest). In Windows PowerShell, from the repository:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Audit.ps1

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
$repository = Split-Path -Parent $PSScriptRoot
$started = Get-Date
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
    # Get-Credential answered from a list of (question pattern, answer). The questions it asked come back.
    $runner = Join-Path $work 'Invoke-WithAnswers.ps1'
    Set-Content -LiteralPath $runner -Encoding ASCII -Value @'
param([string]$Script, [string]$Answers, [string]$Arguments)
Set-StrictMode -Version Latest
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
& $Script @parameters
'QUESTIONS: ' + ($global:TestQuestions -join ' || ')
'@
    $invoke = {
        param([string]$Script, [object[]]$Answers, [hashtable]$Arguments)
        # In files: a command line would lose the quotes of the JSON.
        $answersFile = Join-Path $work "answers-$(Get-Random).json"
        ConvertTo-Json -InputObject @($Answers | ForEach-Object { [pscustomobject]@{ Question = $_[0]; Answer = $_[1] } }) | Set-Content -LiteralPath $answersFile -Encoding UTF8
        $argumentsFile = Join-Path $work "arguments-$(Get-Random).json"
        ConvertTo-Json -InputObject ([pscustomobject]$Arguments) | Set-Content -LiteralPath $argumentsFile -Encoding UTF8
        # Its errors are kept with its output: with Stop, the first one would end the tests.
        $ErrorActionPreference = 'Continue'
        $output = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner -Script $Script -Answers $answersFile -Arguments $argumentsFile 2>&1 | ForEach-Object { "$_" })
        $questions = @(($output | Where-Object { $_ -like 'QUESTIONS: *' } | Select-Object -Last 1) -replace '^QUESTIONS: ', '' -split ' \|\| ' | Where-Object { $_ })
        [pscustomobject]@{ Output = $output; Questions = $questions }
    }

    Write-Section 'Inventory of this computer (DCOM)'
    $inventoryRun = & $invoke (Join-Path $work 'AuditInventory.ps1') @() @{ Computer = $env:COMPUTERNAME }
    $text = $inventoryRun.Output -join "`n"
    Test-That 'read' ($text -match '1 of 1 read \((0|1) over WinRM, (0|1) over DCOM\)') ((@($inventoryRun.Output) | Select-Object -First 6) -join ' / ')
    Test-That 'listed with its model and serial number' ($text -match "(?m)^\| $([regex]::Escape($env:COMPUTERNAME)) \|")
    Test-That 'its antivirus found' ($text -notmatch ':x: none')
    Test-That 'no question asked' ($inventoryRun.Questions.Count -eq 0) ($inventoryRun.Questions -join '; ')

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
