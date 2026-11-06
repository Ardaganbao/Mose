[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'AuditNetwork.ps1, whose BER functions encode and decode the answers.')]
    [string]$NetworkScript,

    [Parameter(HelpMessage = 'Seconds before the agent stops by itself.')]
    [int]$Seconds = 600,

    [Parameter(HelpMessage = 'The only community the agent answers.')]
    [string]$Community = 'snmp-test-community'
)

# A fake SNMP v2c device on 127.0.0.1:161 for tests\Test-Audit.ps1: an APC UPS with an entity table,
# LLDP neighbour, 25 VLANs and two addresses, which answers GetRequest and GetBulkRequest to one
# community only. Its values are made up; nothing is read from a real device.

Set-StrictMode -Off
$ast = [System.Management.Automation.Language.Parser]::ParseFile($NetworkScript, [ref]$null, [ref]$null)
foreach ($text in @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | ForEach-Object { $_.Extent.Text })) {
    . ([scriptblock]::Create($text))
}

function New-Value {
    param(
        [string]$Type,
        $Value
    )

    switch ($Type) {
        'Text' { return ConvertTo-Ber 0x04 ([Text.Encoding]::ASCII.GetBytes($Value)) }
        'Bytes' { return ConvertTo-Ber 0x04 ([byte[]]$Value) }
        'Integer' { return ConvertTo-BerInteger $Value }
        'Oid' { return ConvertTo-BerOid $Value }
        'IpAddress' { return ConvertTo-Ber 0x40 ([byte[]]@($Value -split '\.' | ForEach-Object { [byte]$_ })) }
        'Gauge' { return ConvertTo-Ber 0x42 ([byte[]]@([byte]$Value)) }
        'TimeTicks' {
            $bytes = [BitConverter]::GetBytes([int]$Value)
            [array]::Reverse($bytes)
            return ConvertTo-Ber 0x43 ([byte[]]$bytes)
        }
    }
}

# The OIDs in their order: each number padded, so that a text comparison orders them.
function Get-SortKey {
    param(
        [string]$Oid
    )

    return ($Oid -split '\.' | ForEach-Object { $_.PadLeft(10, '0') }) -join '.'
}

$mib = @{}
$mib['1.3.6.1.2.1.1.1.0'] = New-Value Text 'APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.8.2)'
$mib['1.3.6.1.2.1.1.2.0'] = New-Value Oid '1.3.6.1.4.1.318.1.3.27'
$mib['1.3.6.1.2.1.1.5.0'] = New-Value Text 'UPS-SRV'
# An empty sysLocation, as many devices have.
$mib['1.3.6.1.2.1.1.6.0'] = New-Value Text ''
$apc = '1.3.6.1.4.1.318.1.1.1'
$mib["$apc.1.1.1.0"] = New-Value Text 'Smart-UPS 1500'
$mib["$apc.1.2.1.0"] = New-Value Text 'UPS 09.3'
$mib["$apc.1.2.2.0"] = New-Value Text '05/12/2019'
$mib["$apc.1.2.3.0"] = New-Value Text 'AS1234567890'
$mib["$apc.2.1.1.0"] = New-Value Integer 2
$mib["$apc.2.1.3.0"] = New-Value Text '03/01/2020'
$mib["$apc.2.2.1.0"] = New-Value Gauge 100
$mib["$apc.2.2.3.0"] = New-Value TimeTicks 270000
$mib["$apc.2.2.4.0"] = New-Value Integer 2
$mib['1.3.6.1.2.1.47.1.1.1.1.13.1'] = New-Value Text ''
$mib['1.3.6.1.2.1.47.1.1.1.1.13.2'] = New-Value Text 'SMT1500RMI2U'
$mib['1.3.6.1.2.1.47.1.1.1.1.11.1'] = New-Value Text 'AS1234567890'
$mib['1.0.8802.1.1.2.1.4.1.1.5.0.3.1'] = New-Value Bytes @(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
$mib['1.0.8802.1.1.2.1.4.1.1.7.0.3.1'] = New-Value Text 'Gi1/0/24'
$mib['1.0.8802.1.1.2.1.4.1.1.8.0.3.1'] = New-Value Text ''
$mib['1.0.8802.1.1.2.1.4.1.1.9.0.3.1'] = New-Value Text 'core-switch.contoso.local'
$mib['1.0.8802.1.1.2.1.3.7.1.3.3'] = New-Value Text 'eth0'
$mib['1.0.8802.1.1.2.1.4.2.1.3.0.3.1.1.4.192.0.2.2'] = New-Value Integer 2
foreach ($vlan in 1..25) {
    $mib["1.3.6.1.2.1.17.7.1.4.3.1.1.$vlan"] = New-Value Text "VLAN$vlan"
}
$mib['1.3.6.1.2.1.4.20.1.3.10.0.20.1'] = New-Value IpAddress '255.255.255.0'
$mib['1.3.6.1.2.1.4.20.1.3.127.0.0.1'] = New-Value IpAddress '255.0.0.0'

$keys = @{}
foreach ($oid in $mib.Keys) {
    $keys[$oid] = Get-SortKey $oid
}
$order = @($mib.Keys | Sort-Object { $keys[$_] })

$udp = New-Object System.Net.Sockets.UdpClient((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, 161)))
$udp.Client.ReceiveTimeout = 1000
$until = (Get-Date).AddSeconds($Seconds)
$served = 0
try {
    while ((Get-Date) -lt $until) {
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        try {
            $data = $udp.Receive([ref]$remote)
        }
        catch {
            continue
        }
        try {
            $message = Read-BerItem $data 0
            $version = Read-BerItem $data $message.Start
            $communityItem = Read-BerItem $data $version.Next
            if ([Text.Encoding]::ASCII.GetString($data, $communityItem.Start, $communityItem.Length) -cne $Community) {
                continue
            }
            $pdu = Read-BerItem $data $communityItem.Next
            $id = Read-BerItem $data $pdu.Start
            $second = Read-BerItem $data $id.Next
            $third = Read-BerItem $data $second.Next
            $list = Read-BerItem $data $third.Next
            $repetitions = [int](ConvertFrom-BerValue $data $third)
            $oids = @()
            $offset = $list.Start
            while ($offset -lt $list.Next) {
                $binding = Read-BerItem $data $offset
                $oids += ConvertFrom-BerOid $data (Read-BerItem $data $binding.Start)
                $offset = $binding.Next
            }
            $bindings = @()
            foreach ($oid in $oids) {
                if ($pdu.Type -eq 0xA0) {
                    # GetRequest: the value, or noSuchObject.
                    $value = if ($mib.ContainsKey($oid)) { $mib[$oid] } else { [byte[]](0x80, 0) }
                    $bindings += ConvertTo-Ber 0x30 ((ConvertTo-BerOid $oid) + $value)
                    continue
                }
                # GetBulkRequest: the next values, then endOfMibView.
                $key = Get-SortKey $oid
                $next = @(foreach ($candidate in $order) { if ($keys[$candidate] -gt $key) { $candidate } }) | Select-Object -First $repetitions
                foreach ($candidate in $next) {
                    $bindings += ConvertTo-Ber 0x30 ((ConvertTo-BerOid $candidate) + $mib[$candidate])
                }
                if (@($next).Count -lt $repetitions) {
                    $bindings += ConvertTo-Ber 0x30 ((ConvertTo-BerOid $oid) + [byte[]](0x82, 0))
                }
            }
            $response = (ConvertTo-BerInteger ([int](ConvertFrom-BerValue $data $id))) + (ConvertTo-BerInteger 0) + (ConvertTo-BerInteger 0) + (ConvertTo-Ber 0x30 $bindings)
            $packet = [byte[]](ConvertTo-Ber 0x30 ((ConvertTo-BerInteger 1) + (ConvertTo-Ber 0x04 ([Text.Encoding]::ASCII.GetBytes($Community))) + (ConvertTo-Ber 0xA2 $response)))
            [void]$udp.Send($packet, $packet.Length, $remote)
            $served++
        }
        catch {
            "Fake agent: $($_.Exception.Message)"
        }
    }
}
finally {
    $udp.Close()
}
"Fake agent: $served answers."
