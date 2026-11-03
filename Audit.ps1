[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'The client audited: the title and file name of the audit.')]
    [string]$Client,

    [Parameter(HelpMessage = 'Public domains of the client, e.g. example.be. Those found in Active Directory and Microsoft 365 are added.')]
    [string[]]$Domain,

    [Parameter(HelpMessage = 'Networks to scan: 192.0.2.0/24, 192.0.2.10-50 or an address. Default: the networks of this computer.')]
    [string[]]$Subnet,

    [Parameter(HelpMessage = 'Parts of the audit not to run.')]
    [ValidateSet('Network', 'ActiveDirectory', 'Microsoft365', 'Domains')]
    [string[]]$Skip,

    [Parameter(HelpMessage = 'A domain controller or the domain name, when this computer is not in the domain.')]
    [string]$ADServer,

    [Parameter(HelpMessage = 'Domain account for Active Directory (DOMAIN\user). Default: the Windows user running the audit.')]
    [pscredential]$ADCredential,

    [Parameter(HelpMessage = 'Microsoft 365 tenant to sign in to: one of its domains or its ID.')]
    [string]$Tenant,

    [Parameter(HelpMessage = 'Folder of the audit files. Default: the folder of this script.')]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter(HelpMessage = 'Ask nothing: run what needs no answer, skip what needs one (Microsoft 365 sign-in).')]
    [switch]$NonInteractive,

    [Parameter(HelpMessage = "Don't open the audit in Notepad.")]
    [switch]$NoOpen
)

# IT audit of a client, from nothing: run on a computer plugged into the client's network, it reads
# the network and its devices, Active Directory, Microsoft 365 and the public domains, and writes
# <Client>_Audit_<yyyy-MM-dd>.md: the findings first, by severity, then what each part found, then
# what to complete on site. <Client>_Audit_<yyyy-MM-dd>.json has all the data read, for the client's
# documentation or to compare with a later audit. Both stay on this computer: they describe the
# client's network (see .gitignore). Neither holds a password.
#
# Independent of the monthly report (Report.ps1): no vault, no configuration. Each part is a script
# of its own (AuditNetwork.ps1, AuditAD.ps1, AuditM365.ps1, AuditDomain.ps1) that can also run alone.

$ErrorActionPreference = 'Stop'
# Start.ps1 runs in strict mode, where a property or regex group that is missing is an error; the
# audit expects $null for it. Off for the audit and its parts only.
Set-StrictMode -Off
. (Join-Path $PSScriptRoot 'AuditCommon.ps1')

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

$script:Sections = New-Object System.Collections.Generic.List[object]
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Data = [ordered]@{}
$script:Log = New-Object System.Collections.Generic.List[string]

# Runs one part: its Markdown goes under its own heading, its findings and data are kept, and a part
# that fails says why without stopping the others.
function Invoke-AuditPart {
    param(
        [string]$Title,
        [string]$Script,
        [hashtable]$Parameters = @{}
    )

    Write-Host "`n== $Title" -ForegroundColor Cyan
    $partStarted = Get-Date
    $warnings = $null
    try {
        $output = @(& (Join-Path $PSScriptRoot $Script) @Parameters -WarningVariable warnings)
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

# 1. The network: no login needed.
if ($Skip -contains 'Network') {
    Skip-AuditPart 'Network' 'skipped with -Skip.'
}
else {
    $parameters = @{}
    if ($Subnet) {
        $parameters.Subnet = $Subnet
    }
    Invoke-AuditPart -Title 'Network' -Script 'AuditNetwork.ps1' -Parameters $parameters
}

# 2. Active Directory: as this computer's user when it is in the domain, else with a domain account
#    on a domain controller given, or found by the network scan.
if ($Skip -contains 'ActiveDirectory') {
    Skip-AuditPart 'Active Directory' 'skipped with -Skip.'
}
else {
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $server = $ADServer
    if (-not $server -and -not ($computer -and $computer.PartOfDomain)) {
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
    if (-not $server -and -not ($computer -and $computer.PartOfDomain)) {
        Skip-AuditPart 'Active Directory' 'this computer is not in a domain and no domain controller was given (-ADServer).'
    }
    else {
        $parameters = @{}
        if ($server) {
            $parameters.Server = $server
            if (-not $ADCredential -and -not ($computer -and $computer.PartOfDomain) -and -not $NonInteractive) {
                $ADCredential = Get-Credential -Message "Domain account to read Active Directory on $server (DOMAIN\user, no administrator rights needed)"
            }
        }
        if ($ADCredential) {
            $parameters.Credential = $ADCredential
        }
        Invoke-AuditPart -Title 'Active Directory' -Script 'AuditAD.ps1' -Parameters $parameters
    }
}

# 3. Microsoft 365: someone signs in with an administrator account of the client.
if ($Skip -contains 'Microsoft365') {
    Skip-AuditPart 'Microsoft 365' 'skipped with -Skip.'
}
elseif ($NonInteractive) {
    Skip-AuditPart 'Microsoft 365' 'its sign-in needs someone (run without -NonInteractive).'
}
else {
    $answer = if ($Tenant) { 'y' } else { Read-Answer 'Sign in to Microsoft 365 of the client now, with an administrator account (Global Reader is enough)? [Y/n]' }
    if ($answer -match '^(n|no|non|nee)$') {
        Skip-AuditPart 'Microsoft 365' 'no sign-in.'
    }
    else {
        $parameters = @{}
        if ($Tenant) {
            $parameters.Tenant = $Tenant
        }
        Invoke-AuditPart -Title 'Microsoft 365' -Script 'AuditM365.ps1' -Parameters $parameters
    }
}

# 4. The public domains: given, and those of Active Directory and Microsoft 365.
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
$lines.Add('What this audit cannot read. Logins go to the password manager, not here.')
$lines.Add('')
foreach ($item in @(
        'Network diagram: how the Internet line, firewall, switches, access points and servers are connected.'
        'Internet line: provider, type and speed, customer number, fixed IP addresses, the provider''s router.'
        'Firewall: model, firmware, local or cloud management, administration from the Internet (port, allowed addresses), VPN accounts, NAT rules, a backup of its configuration.'
        'Switches and Wi-Fi: models, management (cloud, controller or local), VLANs, Wi-Fi networks for staff and guests.'
        'UPS: brand, model, serial number, USB or network connection, what shuts down on battery, battery date, warranty and registration.'
        'Servers: model, serial number (service tag), purchase date, warranty, processor, memory, disks, role, Windows Server licence, iDRAC/iLO access.'
        'Backup: solution, what is backed up and how often, a copy outside the building, the last restore test.'
        'Computers: user, model, serial number, purchase date, Windows edition, antivirus, remote support agent, local administrator password (LAPS or password manager).'
        'Printers, phones, time clock, cameras: model, supplier, how they are managed.'
        'Business applications (ERP, accounting, time recording...): supplier, contact, where they run, who administers them.'
        'Domain names and website: registrar and hosting accounts, who manages the website.'
        'Microsoft 365: shared mailboxes, forwarding rules, external sharing in SharePoint and OneDrive (not read by this audit).'
        'Licences: Windows Server, Office and other keys, kept in the password manager or the documentation.'
        'Remote access tools in use (TeamViewer, AnyDesk...) and who can connect with them.'
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

if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$baseName = "$($clientFileName)_Audit_$($started.ToString('yyyy-MM-dd'))"
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

Write-Host "`n$Client audit written to $markdownPath, its data to $jsonPath." -ForegroundColor Green
Write-Host 'They describe the client''s network: keep them with the client''s documentation, not in a shared or public place.' -ForegroundColor Yellow
if (-not $NoOpen) {
    Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$markdownPath`""
}
