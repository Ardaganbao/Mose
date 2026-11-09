[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'The client audited: the title and file name of the audit.')]
    [string]$Client,

    [Parameter(HelpMessage = 'Public domains of the client, e.g. example.be. Those found in Active Directory and Microsoft 365 are added.')]
    [string[]]$Domain,

    [Parameter(HelpMessage = 'Networks to scan instead of those of this computer: 192.0.2.0/24, 192.0.2.10-50 or an address.')]
    [string[]]$Subnet,

    [Parameter(HelpMessage = 'Networks to scan as well as those of this computer, e.g. a server or camera VLAN: 10.0.20.0/24, 10.0.30.10-50.')]
    [string[]]$AddSubnet,

    [Parameter(HelpMessage = 'SNMP communities of the client''s devices, from the password manager, tried after "public". Never written to the audit.')]
    [string[]]$SnmpCommunity,

    [Parameter(HelpMessage = 'Parts of the audit not to run. SpeedTest: no speed test of the Internet line.')]
    [ValidateSet('Network', 'SpeedTest', 'ActiveDirectory', 'Inventory', 'Microsoft365', 'Domains')]
    [string[]]$Skip,

    [Parameter(HelpMessage = 'A domain controller or the domain name, when this computer is not in the domain.')]
    [string]$ADServer,

    [Parameter(HelpMessage = 'Domain account for Active Directory (DOMAIN\user). Default: the Windows user running the audit.')]
    [pscredential]$ADCredential,

    [Parameter(HelpMessage = 'Administrator account to read the Windows servers and computers (DOMAIN\admin). Default: the Windows user running the audit.')]
    [pscredential]$AdminCredential,

    [Parameter(HelpMessage = 'Microsoft 365 tenant to sign in to: one of its domains or its ID.')]
    [string]$Tenant,

    [Parameter(HelpMessage = 'Folder of the audit files. Default: the folder of this script.')]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter(HelpMessage = 'Ask nothing: run what needs no answer, skip what needs one (Microsoft 365 sign-in).')]
    [switch]$NonInteractive,

    [Parameter(HelpMessage = "Don't open the audit in Notepad.")]
    [switch]$NoOpen,

    [Parameter(HelpMessage = 'After the network scan, scan the other networks seen too (those of at most 1024 addresses), instead of asking which ones.')]
    [switch]$ScanOtherNetworks,

    [Parameter(HelpMessage = 'Sign in to Microsoft 365 without asking first, also with -NonInteractive: its sign-in window opens during the audit.')]
    [switch]$Microsoft365,

    [Parameter(HelpMessage = 'Open the audit window: every answer in one place, then the audit runs there.')]
    [switch]$Gui
)

# IT audit of a client, from nothing: run on a computer plugged into the client's network, it reads
# the network and its devices, Active Directory, the Windows servers and computers, Microsoft 365 and
# the public domains, and writes <Client>_Audit_<yyyy-MM-dd>.md: the findings first, by severity, then
# what each part found, then what is left to complete on site. <Client>_Audit_<yyyy-MM-dd>.json has
# all the data read, for the client's documentation or to compare with a later audit, and
# <Client>_Audit_<yyyy-MM-dd>.drawio a first network diagram. They stay on this computer: they
# describe the client's network (see .gitignore). None holds a password.
#
# Independent of the monthly report (Report.ps1): no vault, no configuration. Each part is a script
# of its own (AuditNetwork.ps1, AuditAD.ps1, AuditInventory.ps1, AuditM365.ps1, AuditDomain.ps1) that
# can also run alone.

$ErrorActionPreference = 'Stop'
# Start.ps1 runs in strict mode, where a property or regex group that is missing is an error; the
# audit expects $null for it. Off for the audit and its parts only.
Set-StrictMode -Off
. (Join-Path $PSScriptRoot 'AuditCommon.ps1')
# Windows PowerShell leaves $PSScriptRoot empty in a parameter's default when run with -File.
if (-not $OutputPath) {
    $OutputPath = $PSScriptRoot
}

# The window asks everything first, then runs this script again with the answers (-NonInteractive).
if ($Gui) {
    [void]$PSBoundParameters.Remove('Gui')
    & (Join-Path $PSScriptRoot 'AuditWindow.ps1') @PSBoundParameters
    return
}

function Read-Answer {
    param(
        [string]$Prompt
    )

    if ($NonInteractive) {
        return ''
    }
    return (Read-Host $Prompt).Trim()
}

if (-not $Client) {
    $Client = Read-Answer 'Client name'
    if (-not $Client) {
        $Client = 'Client'
    }
}
$clientFileName = $Client -replace '[\\/:*?"<>|\s]', '_'
$started = Get-Date
$baseName = "$($clientFileName)_Audit_$($started.ToString('yyyy-MM-dd'))"
if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$inDomain = [bool]($computer -and $computer.PartOfDomain)
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name

$script:Sections = New-Object System.Collections.Generic.List[object]
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Data = [ordered]@{}
$script:Log = New-Object System.Collections.Generic.List[string]

# What a part run in a PowerShell of its own runs there: the part, then its output, warnings and error
# serialized on one line of its standard output. The script and its parameters come in Base64.
$partProcessCode = @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Read-Base64([string]$Text) { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Text)) }
[hashtable]$parameters = [System.Management.Automation.PSSerializer]::Deserialize((Read-Base64 '<<PARAMETERS>>'))
$result = [pscustomobject]@{ Output = @(); Warnings = @(); Error = $null }
try {
    $result.Output = @(& (Read-Base64 '<<SCRIPT>>') @parameters -WarningVariable warnings)
    $result.Warnings = @($warnings | ForEach-Object { "$_" })
}
catch {
    $result.Error = "$($_.Exception.Message)"
}
[Console]::Out.WriteLine('AUDIT PART RESULT: ' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([System.Management.Automation.PSSerializer]::Serialize($result, 20))))
[Console]::Out.Flush()
'@

# Runs a part in a PowerShell of its own, which shares this console: a module that ends its process
# ends only that part. Its lines are shown as they come; its output, warnings and error come back.
function Invoke-AuditPartProcess {
    param(
        [string]$Path,
        [hashtable]$Parameters,
        [string]$WhenEnded
    )

    # Switches go as booleans, which come back as booleans.
    $plain = @{}
    foreach ($key in $Parameters.Keys) {
        $plain[$key] = if ($Parameters[$key] -is [switch]) { [bool]$Parameters[$key] } else { $Parameters[$key] }
    }
    $code = $partProcessCode.Replace('<<PARAMETERS>>', [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([System.Management.Automation.PSSerializer]::Serialize($plain)))).Replace('<<SCRIPT>>', [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Path)))
    # Not -EncodedCommand, after which PowerShell writes its messages to the console as XML.
    $bootstrap = "& ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{0}'))))" -f [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($code))
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = (Get-Process -Id $PID).Path
    $start.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"$bootstrap`""
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $process = [System.Diagnostics.Process]::Start($start)
    $result = $null
    try {
        # Read in steps, so that Stop (the window's, or Ctrl+C) can end the wait.
        $line = $process.StandardOutput.ReadLineAsync()
        while ($true) {
            if (-not $line.Wait(300)) {
                continue
            }
            if ($null -eq $line.Result) {
                break
            }
            if ($line.Result.StartsWith('AUDIT PART RESULT: ')) {
                $result = [System.Management.Automation.PSSerializer]::Deserialize([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($line.Result.Substring(19))))
            }
            else {
                Write-Host $line.Result
            }
            $line = $process.StandardOutput.ReadLineAsync()
        }
        $process.WaitForExit()
    }
    finally {
        if (-not $process.HasExited) {
            $process.Kill()
        }
    }
    if (-not $result) {
        throw "its PowerShell ended without finishing (exit code $($process.ExitCode))$WhenEnded"
    }
    if ($result.Error) {
        throw $result.Error
    }
    return $result
}

# Runs one part: its Markdown goes under its own heading, its findings and data are kept, and a part
# that fails says why without stopping the others. -OwnProcess: in a PowerShell of its own (see
# Invoke-AuditPartProcess), with -WhenEnded added to the reason when that PowerShell ends.
function Invoke-AuditPart {
    param(
        [string]$Title,
        [string]$Script,
        [hashtable]$Parameters = @{},
        [switch]$OwnProcess,
        [string]$WhenEnded
    )

    Write-Host "`n== $Title" -ForegroundColor Cyan
    $partStarted = Get-Date
    $warnings = $null
    try {
        if ($OwnProcess) {
            $result = Invoke-AuditPartProcess -Path (Join-Path $PSScriptRoot $Script) -Parameters $Parameters -WhenEnded $WhenEnded
            $output = @($result.Output)
            $warnings = @($result.Warnings)
        }
        else {
            $output = @(& (Join-Path $PSScriptRoot $Script) @Parameters -WarningVariable warnings)
        }
        foreach ($item in $output) {
            if ($item -is [string]) {
                continue
            }
            if ($item.PSObject.Properties['AuditFinding']) {
                $script:Findings.Add($item)
            }
            elseif ($item.PSObject.Properties['AuditData']) {
                $script:Data[$item.AuditData] = $item.Value
            }
        }
        $script:Sections.Add([pscustomobject]@{ Title = $Title; Text = (@($output | Where-Object { $_ -is [string] }) -join "`n") })
        $script:Log.Add("$($Title): read in $([math]::Round(((Get-Date) - $partStarted).TotalSeconds)) s.")
    }
    catch {
        $script:Sections.Add([pscustomobject]@{ Title = $Title; Text = ":warning: Not read: $($_.Exception.Message)" })
        $script:Log.Add("$($Title): failed: $($_.Exception.Message)")
        Write-Warning "$Title failed: $($_.Exception.Message)"
    }
    foreach ($warning in @($warnings)) {
        $script:Log.Add("$($Title): $warning")
    }
}

function Skip-AuditPart {
    param(
        [string]$Title,
        [string]$Reason
    )

    Write-Host "`n== $Title skipped: $Reason" -ForegroundColor DarkGray
    $script:Sections.Add([pscustomobject]@{ Title = $Title; Text = "Not read: $Reason" })
    $script:Log.Add("$($Title): skipped, $Reason")
}

# 1. The network: no login needed. SNMP communities, when the client has some, make switches, UPS and
#    printers tell more; after the scan, the other networks seen are offered.
if ($Skip -contains 'Network') {
    Skip-AuditPart 'Network' 'skipped with -Skip.'
}
else {
    $parameters = @{ DiagramPath = Join-Path $OutputPath "$baseName.drawio" }
    if ($Subnet) {
        $parameters.Subnet = $Subnet
    }
    # The networks seen during the scan are scanned with -ScanOtherNetworks, else offered, unless
    # -AddSubnet already named the others.
    if ($AddSubnet) {
        $parameters.AddSubnet = $AddSubnet
    }
    if ($ScanOtherNetworks) {
        $parameters.ScanOtherNetworks = $true
    }
    elseif (-not $AddSubnet -and -not $NonInteractive) {
        $parameters.AskSubnet = $true
    }
    if (-not $SnmpCommunity -and -not $NonInteractive) {
        $secure = Read-Host 'SNMP community of the client''s switches, UPS and printers, from the password manager (Enter to try only "public")' -AsSecureString
        $plain = [Net.NetworkCredential]::new('', $secure).Password
        if ($plain) {
            $SnmpCommunity = @($plain)
        }
    }
    if ($SnmpCommunity) {
        $parameters.SnmpCommunity = $SnmpCommunity
    }
    if ($Skip -contains 'SpeedTest') {
        $parameters.SkipSpeedTest = $true
    }
    Invoke-AuditPart -Title 'Network' -Script 'AuditNetwork.ps1' -Parameters $parameters
}

# 2. Active Directory: as this computer's user when it is in the domain, else with a domain account
#    on a domain controller given, or found by the network scan.
if ($Skip -contains 'ActiveDirectory') {
    Skip-AuditPart 'Active Directory' 'skipped with -Skip.'
}
else {
    $server = $ADServer
    if (-not $server -and -not $inDomain) {
        $controllers = @()
        if ($script:Data['Network']) {
            $controllers = @($script:Data['Network'].Devices | Where-Object { $_.Type -eq 'Domain controller' })
        }
        if ($controllers.Count -gt 0) {
            $found = ($controllers | ForEach-Object { "$($_.Address)$(if ($_.Name) { " ($($_.Name)$(if ($_.NetBiosDomain) { ", domain $($_.NetBiosDomain)" }))" })" }) -join ', '
            Write-Host "Domain controllers found on the network: $found. This computer is not in that domain." -ForegroundColor Yellow
            $server = Read-Answer "Domain controller to read Active Directory from (Enter for $($controllers[0].Address), - to skip)"
            if (-not $server) {
                $server = $controllers[0].Address
            }
            elseif ($server -eq '-') {
                $server = $null
            }
        }
        elseif (-not $NonInteractive) {
            $server = Read-Answer 'This computer is not in a domain and the scan found no domain controller. Domain controller or domain name to read Active Directory from (Enter to skip)'
        }
    }
    if (-not $server -and -not $inDomain) {
        Skip-AuditPart 'Active Directory' 'this computer is not in a domain and no domain controller was given (-ADServer).'
    }
    else {
        $parameters = @{}
        if ($server) {
            $parameters.Server = $server
            if (-not $ADCredential -and -not $inDomain -and -not $NonInteractive) {
                $ADCredential = Get-Credential -Message "Domain account to read Active Directory on $server (DOMAIN\user, no administrator rights needed)"
            }
        }
        if ($ADCredential) {
            $parameters.Credential = $ADCredential
        }
        Invoke-AuditPart -Title 'Active Directory' -Script 'AuditAD.ps1' -Parameters $parameters
    }
}

# 3. The Windows servers and computers, with an administrator account: those Active Directory used in
#    the last 90 days, and the Windows devices of the scan that it doesn't know (a workgroup).
if ($Skip -contains 'Inventory') {
    Skip-AuditPart 'Servers and computers' 'skipped with -Skip.'
}
else {
    $targets = [ordered]@{}
    if ($script:Data['ActiveDirectory']) {
        $since = (Get-Date).AddDays(-90)
        foreach ($item in @($script:Data['ActiveDirectory'].Computers | Where-Object { $_.Enabled -and "$($_.Os)" -like 'Windows*' -and $_.LastLogon -and $_.LastLogon -ge $since })) {
            $targets["$($item.Name)".ToUpper()] = $(if ($item.DnsName) { $item.DnsName } else { $item.Name })
        }
    }
    if ($script:Data['Network']) {
        foreach ($device in @($script:Data['Network'].Devices | Where-Object { $_.Type -in 'Windows server', 'Windows computer', 'Domain controller' })) {
            $short = if ($device.Name) { "$($device.Name)".ToUpper() } else { $device.Address }
            if (-not $targets.Contains($short)) {
                $targets[$short] = $(if ($device.DnsName) { $device.DnsName } else { $device.Address })
            }
        }
    }
    # Not the computer running the audit.
    $targets.Remove($env:COMPUTERNAME.ToUpper())
    if ($targets.Count -eq 0) {
        Skip-AuditPart 'Servers and computers' 'no Windows computer found (in Active Directory or by the network scan).'
    }
    else {
        $credential = $AdminCredential
        $answer = ''
        if (-not $credential -and -not $NonInteractive) {
            $default = if ($inDomain) { "Enter for $currentUser, " } else { '' }
            $answer = Read-Answer "Administrator account to read the $($targets.Count) Windows servers and computers found (model, serial number, disks, software, antivirus, backup): DOMAIN\admin, $($default)- to skip"
            if ($answer -and $answer -ne '-') {
                $credential = Get-Credential -UserName $answer -Message "Administrator of the client's Windows servers and computers"
            }
        }
        if ($answer -eq '-') {
            Skip-AuditPart 'Servers and computers' 'no administrator account given.'
        }
        elseif (-not $credential -and -not $inDomain) {
            Skip-AuditPart 'Servers and computers' 'this computer is not in the domain and no administrator account was given (-AdminCredential).'
        }
        else {
            $parameters = @{ Computer = @($targets.Values) }
            if ($credential) {
                $parameters.Credential = $credential
            }
            Invoke-AuditPart -Title 'Servers and computers' -Script 'AuditInventory.ps1' -Parameters $parameters
        }
    }
}

# 4. Microsoft 365: someone signs in with an administrator account of the client.
if ($Skip -contains 'Microsoft365') {
    Skip-AuditPart 'Microsoft 365' 'skipped with -Skip.'
}
elseif ($NonInteractive -and -not $Microsoft365) {
    Skip-AuditPart 'Microsoft 365' 'its sign-in needs someone (run without -NonInteractive, or with -Microsoft365).'
}
else {
    $answer = if ($Tenant -or $Microsoft365) { 'y' } else { Read-Answer 'Sign in to Microsoft 365 of the client now, with an administrator account (Global Reader is enough)? [Y/n]' }
    # Its module is installed here, from where its question can be answered: the part runs in a
    # PowerShell of its own.
    $graphMissing = -not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)
    if ($answer -notmatch '^(n|no|non|nee)$' -and $graphMissing -and -not $NonInteractive) {
        if ((Read-Answer 'Microsoft 365 is read with the Microsoft Graph PowerShell module (Microsoft.Graph.Authentication), not installed here. Install it for this Windows user from the PowerShell Gallery? [Y/n]') -notmatch '^(n|no|non|nee)$') {
            Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
            $graphMissing = $false
        }
    }
    if ($answer -match '^(n|no|non|nee)$') {
        Skip-AuditPart 'Microsoft 365' 'no sign-in.'
    }
    elseif ($graphMissing) {
        Skip-AuditPart 'Microsoft 365' 'the module Microsoft.Graph.Authentication is not installed (Install-Module Microsoft.Graph.Authentication -Scope CurrentUser).'
    }
    else {
        $parameters = @{}
        # Without it, a partner (CSP) account would sign in to the partner's own tenant.
        if (-not $Tenant) {
            $Tenant = Read-Answer 'Microsoft 365 tenant of the client: one of its domains, e.g. contoso.be, needed with a partner (CSP) account (Enter: the tenant of the account you sign in with)'
        }
        if ($Tenant) {
            $parameters.Tenant = $Tenant
        }
        # In Windows PowerShell, the Graph module ends the whole process when its sign-in times out:
        # in a PowerShell of its own, that loses only this part.
        $where = if ($Tenant) { $Tenant } else { '<its domain>' }
        Invoke-AuditPart -Title 'Microsoft 365' -Script 'AuditM365.ps1' -Parameters $parameters -OwnProcess -WhenEnded ": the Graph module ends Windows PowerShell when its sign-in page is closed, or not completed within about 2 minutes. With a partner (CSP) account, that page shows AADSTS90099 until the client has consented: a Global Administrator of the client signs in once with .\AuditM365.ps1 -Tenant $where and ticks 'Consent on behalf of your organization'."
    }
}

# 5. The public domains: given, and those of Active Directory and Microsoft 365.
if ($Skip -contains 'Domains') {
    Skip-AuditPart 'Domains and e-mail' 'skipped with -Skip.'
}
else {
    $known = @($Domain)
    if ($script:Data['ActiveDirectory']) {
        $known += @($script:Data['ActiveDirectory'].Domain) + @($script:Data['ActiveDirectory'].UpnSuffixes)
    }
    if ($script:Data['Microsoft365']) {
        $known += @($script:Data['Microsoft365'].Domains | Where-Object { $_.Verified } | ForEach-Object { $_.Name })
    }
    $domains = @(Select-PublicDomain -Name $known)
    if ($domains.Count -gt 0) {
        Write-Host "Public domains found: $($domains -join ', ')"
    }
    $more = Read-Answer 'Other public domains of the client, comma-separated (website, e-mail; Enter for none)'
    $domains = @(Select-PublicDomain -Name ($domains + @($more -split '[,;\s]+')))
    if ($domains.Count -eq 0) {
        Skip-AuditPart 'Domains and e-mail' 'no public domain given or found (-Domain).'
    }
    else {
        Invoke-AuditPart -Title 'Domains and e-mail' -Script 'AuditDomain.ps1' -Parameters @{ Domain = $domains }
    }
}

# The audit document.
$severities = [ordered]@{ High = ':x: High'; Medium = ':warning: Medium'; Low = 'Low'; Info = 'Info' }
$order = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
$findings = @($script:Findings | Sort-Object -Property { $order[$_.AuditFinding] }, Area)
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# $Client IT audit")
$lines.Add("$($started.ToString('yyyy-MM-dd')), from $env:COMPUTERNAME by $([Security.Principal.WindowsIdentity]::GetCurrent().Name). This document holds no password: keep every login in the password manager.")
$lines.Add('')
$lines.Add('## Findings')
if ($findings.Count -eq 0) {
    $lines.Add('No finding.')
}
else {
    $counts = @($severities.Keys | ForEach-Object { $severity = $_; $count = @($findings | Where-Object { $_.AuditFinding -eq $severity }).Count; if ($count) { "$count $($severity.ToLower())" } })
    $lines.Add("$($findings.Count) findings: $($counts -join ', '). High: fix now. Medium: plan it. Low: worth doing. Info: for the record.")
    $lines.Add('')
    $lines.Add((Format-AuditTable -Rows ($findings | ForEach-Object { [pscustomobject]@{ Severity = $severities[$_.AuditFinding]; Area = $_.Area; Finding = $_.Finding; Recommendation = $_.Recommendation } }) -Columns 'Severity', 'Area', 'Finding', 'Recommendation'))
}
foreach ($section in $script:Sections) {
    $lines.Add('')
    $lines.Add("## $($section.Title)")
    $lines.Add($section.Text.Trim())
}
$lines.Add('')
$lines.Add('## To complete on site')
$lines.Add('What this audit could not read. Logins go to the password manager, not here.')
$lines.Add('')
# Each item says only what is left once a part read the rest, and where that part put it.
$network = $script:Data['Network']
$inventory = $script:Data['Inventory']
$networkDevices = @(if ($network) { $network.Devices | Where-Object { $_ } })
$computersRead = @(if ($inventory) { $inventory.Computers | Where-Object { $_ } })
$serversRead = @($computersRead | Where-Object { $_.Kind -ne 'Computer' })
$workstationsRead = @($computersRead | Where-Object { $_.Kind -eq 'Computer' })
$choose = {
    param([bool]$Read, [string]$Left, [string]$Full)
    if ($Read) { $Left } else { $Full }
}
foreach ($item in @(
        & $choose ([bool]($network -and $network.Diagram)) "Network diagram: complete $(if ($network) { Split-Path -Leaf "$($network.Diagram)" }), the draft drawn from the scan (open it in draw.io): the links between the devices, the switch ports, and what the scan did not find." 'Network diagram: how the Internet line, firewall, switches, access points and servers are connected.'
        & $choose ([bool]($network -and $network.PublicAddress)) 'Internet line: type (fibre, VDSL...), contract speed, customer number, fixed IP addresses (the provider, public address, measured speed and route are under Network > Internet line).' 'Internet line: provider, type and speed, customer number, fixed IP addresses, the provider''s router.'
        & $choose (@($networkDevices | Where-Object { $_.IsGateway -and $_.Identification }).Count -gt 0) 'Firewall: firmware, local or cloud management, administration from the Internet (port, allowed addresses), VPN accounts, NAT rules, a backup of its configuration (what it shows on the network is under Network > Firewall / gateway).' 'Firewall: model, firmware, local or cloud management, administration from the Internet (port, allowed addresses), VPN accounts, NAT rules, a backup of its configuration.'
        & $choose (@($networkDevices | Where-Object { @($_.Snmp.Vlans | Where-Object { $_ }).Count -or @($_.Snmp.Neighbors | Where-Object { $_ }).Count }).Count -gt 0) 'Switches and Wi-Fi: management (cloud, controller or local), Wi-Fi networks for staff and guests, and the switches that did not answer SNMP (the models, VLANs and neighbours of those that did are under Network).' 'Switches and Wi-Fi: models, management (cloud, controller or local), VLANs, Wi-Fi networks for staff and guests.'
        & $choose (@($networkDevices | Where-Object { $_.Snmp.Ups }).Count -gt 0 -or @($serversRead | Where-Object { @($_.UsbUps).Count }).Count -gt 0) 'UPS: what shuts down on battery, warranty and registration, and the UPS not found (brand, model, serial number and battery of those found are under Network > UPS or Servers and computers).' 'UPS: brand, model, serial number, USB or network connection, what shuts down on battery, battery date, warranty and registration.'
        & $choose ($serversRead.Count -gt 0) 'Servers: purchase date, warranty, iDRAC/iLO access, and the servers not read (model, serial number, processor, memory, disks, roles and licence are under Servers and computers).' 'Servers: model, serial number (service tag), purchase date, warranty, processor, memory, disks, role, Windows Server licence, iDRAC/iLO access.'
        & $choose ($serversRead.Count -gt 0) 'Backup: what is backed up and how often, a copy outside the building, the last restore test (the backup software found is under Servers and computers).' 'Backup: solution, what is backed up and how often, a copy outside the building, the last restore test.'
        & $choose ($workstationsRead.Count -gt 0) 'Computers: purchase date, the local administrator password (LAPS or password manager), and the computers that were off (user, model, serial number, Windows, antivirus and BitLocker of the others are under Servers and computers).' 'Computers: user, model, serial number, purchase date, Windows edition, antivirus, remote support agent, local administrator password (LAPS or password manager).'
        & $choose (@($networkDevices | Where-Object { $_.Type -match 'Printer|phone|Time clock|Camera' -and $_.Model }).Count -gt 0) 'Printers, phones, time clock, cameras: supplier, how they are managed, and those without a model in the audit (the models found are under Network).' 'Printers, phones, time clock, cameras: model, supplier, how they are managed.'
        & $choose (@($serversRead | Where-Object { @($_.Software).Count }).Count -gt 0) 'Business applications (ERP, accounting, time recording...): supplier, contact, who administers them (the software installed on the servers is under Servers and computers).' 'Business applications (ERP, accounting, time recording...): supplier, contact, where they run, who administers them.'
        'Domain names and website: registrar and hosting accounts, who manages the website.'
        'Microsoft 365: shared mailboxes, forwarding rules, external sharing in SharePoint and OneDrive (not read by this audit).'
        & $choose ($computersRead.Count -gt 0) 'Licences: the keys of Windows Server, Office and other software, kept in the password manager or the documentation (the licence type and the last 5 characters of each key are under Servers and computers).' 'Licences: Windows Server, Office and other keys, kept in the password manager or the documentation.'
        & $choose ($computersRead.Count -gt 0) 'Remote access tools: who can connect with them, under which account (the tools found are under Servers and computers).' 'Remote access tools in use (TeamViewer, AnyDesk...) and who can connect with them.'
        'Systems no longer used, to switch off or remove.'
        'Contacts: the client''s contact persons, and the suppliers (Internet, telephony, website, business software).'
    )) {
    $lines.Add("- [ ] $item")
}
$lines.Add('')
$lines.Add('## About this audit')
foreach ($entry in $script:Log) {
    $lines.Add("- $(Format-AuditCell $entry)")
}
$lines.Add("- Duration: $([math]::Round(((Get-Date) - $started).TotalMinutes, 1)) minutes.")

$markdownPath = Join-Path $OutputPath "$baseName.md"
Set-Content -LiteralPath $markdownPath -Value ($lines -join [Environment]::NewLine) -Encoding UTF8

# The data as JSON, with ISO dates (Windows PowerShell would write \/Date(...)\/).
function ConvertTo-JsonValue {
    param(
        $Value,
        [int]$Depth = 0
    )

    if ($null -eq $Value -or $Depth -gt 12) {
        return $null
    }
    if ($Value -is [datetime]) {
        return $Value.ToString('o')
    }
    if ($Value -is [string] -or $Value -is [ValueType]) {
        return $Value
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $result["$key"] = ConvertTo-JsonValue $Value[$key] ($Depth + 1)
        }
        return $result
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return , @(foreach ($item in $Value) { ConvertTo-JsonValue $item ($Depth + 1) })
    }
    $result = [ordered]@{}
    foreach ($property in $Value.PSObject.Properties) {
        if ($property.MemberType -in 'NoteProperty', 'Property') {
            $result[$property.Name] = ConvertTo-JsonValue $property.Value ($Depth + 1)
        }
    }
    return $result
}
$json = [ordered]@{
    Client   = $Client
    Date     = $started.ToString('o')
    Computer = $env:COMPUTERNAME
    Findings = @($findings | ForEach-Object { [ordered]@{ Severity = $_.AuditFinding; Area = $_.Area; Finding = $_.Finding; Recommendation = $_.Recommendation } })
    Data     = ConvertTo-JsonValue $script:Data
}
$jsonPath = Join-Path $OutputPath "$baseName.json"
Set-Content -LiteralPath $jsonPath -Value (ConvertTo-Json -InputObject $json -Depth 20) -Encoding UTF8

Write-Host "`n$Client audit written to $markdownPath, its data to $jsonPath$(if ($network -and $network.Diagram) { ", its network diagram to $($network.Diagram)" })." -ForegroundColor Green
Write-Host 'They describe the client''s network: keep them with the client''s documentation, not in a shared or public place.' -ForegroundColor Yellow
if (-not $NoOpen) {
    Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$markdownPath`""
}
