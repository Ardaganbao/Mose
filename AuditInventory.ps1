[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'The Windows servers and computers to read: names or addresses.')]
    [string[]]$Computer,

    [Parameter(HelpMessage = 'An administrator account of those computers (DOMAIN\admin). Default: the Windows user running the audit.')]
    [pscredential]$Credential,

    [Parameter(HelpMessage = 'Computers read at once.')]
    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = 16
)

# Inventory of the Windows servers and computers over CIM, with an administrator account: WinRM, else
# DCOM. For each one: its model and serial number, processor, memory, disks and free space, Windows and
# its licence, the server roles, the last update installed and the last restart, the user logged on,
# the other members of its Administrators group, antivirus and BitLocker, and the remote access,
# backup, database and UPS software found in its services; for servers also the software installed
# (not Microsoft's), the SQL Server instances and a UPS on USB. Nothing is changed on them, and no
# password or key is read (a licence shows only the last 5 characters of its key, as Windows does).
#
# A computer that is off or refuses the account is listed as not read. TrustedHosts is not changed:
# a computer given by its address, or read from a computer outside its domain, is read over DCOM.

$ErrorActionPreference = 'Stop'
# Start.ps1 runs in strict mode, where a property that a CIM answer lacks is an error; this script
# expects $null for it. Off for this script only.
Set-StrictMode -Off
. (Join-Path $PSScriptRoot 'AuditCommon.ps1')
$area = 'Servers and computers'

# Software found by its services (name or display name). A disabled service doesn't count.
$serviceCatalog = @(
    @{ Kind = 'Antivirus'; Product = 'Microsoft Defender'; Pattern = '^WinDefend$' }
    @{ Kind = 'Antivirus'; Product = 'Microsoft Defender for Endpoint'; Pattern = '^Sense$' }
    @{ Kind = 'Antivirus'; Product = 'Sophos'; Pattern = 'Sophos|^SAVService$|^hmpalertsvc$' }
    @{ Kind = 'Antivirus'; Product = 'ESET'; Pattern = '^ekrn$|^ESET' }
    @{ Kind = 'Antivirus'; Product = 'SentinelOne'; Pattern = 'SentinelAgent|SentinelOne' }
    @{ Kind = 'Antivirus'; Product = 'CrowdStrike'; Pattern = 'CSFalconService|CrowdStrike' }
    @{ Kind = 'Antivirus'; Product = 'Bitdefender'; Pattern = 'Bitdefender|^EPSecurityService$|^bdservicehost$' }
    @{ Kind = 'Antivirus'; Product = 'Trend Micro'; Pattern = 'Trend Micro|^ntrtscan$|^ds_agent$' }
    @{ Kind = 'Antivirus'; Product = 'Kaspersky'; Pattern = 'Kaspersky|^AVP\d|^klnagent$' }
    @{ Kind = 'Antivirus'; Product = 'Symantec'; Pattern = 'Symantec Endpoint|^SepMasterService$' }
    @{ Kind = 'Antivirus'; Product = 'Malwarebytes'; Pattern = 'Malwarebytes|^MBAMService$' }
    @{ Kind = 'Antivirus'; Product = 'WithSecure / F-Secure'; Pattern = 'WithSecure|F-Secure|^fshoster' }
    @{ Kind = 'Antivirus'; Product = 'Trellix / McAfee'; Pattern = 'McAfee|Trellix|^mfefire$|^masvc$' }
    @{ Kind = 'Antivirus'; Product = 'Avast / AVG'; Pattern = '^Avast|^AVG Antivirus|^AvastSvc$|^AVGSvc$' }
    @{ Kind = 'Antivirus'; Product = 'WatchGuard / Panda'; Pattern = 'Panda|^PSUAService$|WatchGuard EPDR' }
    @{ Kind = 'Antivirus'; Product = 'Webroot'; Pattern = 'Webroot|^WRSVC$' }
    @{ Kind = 'Antivirus'; Product = 'Cortex XDR'; Pattern = 'Cortex XDR|^cyserver$' }
    @{ Kind = 'Antivirus'; Product = 'Cisco Secure Endpoint'; Pattern = 'Cisco Secure Endpoint|Cisco AMP|^ImmunetProtect' }
    @{ Kind = 'Antivirus'; Product = 'G DATA'; Pattern = '^G DATA' }
    @{ Kind = 'Antivirus'; Product = 'Huntress'; Pattern = 'Huntress' }
    @{ Kind = 'Remote access'; Product = 'TeamViewer'; Pattern = 'TeamViewer' }
    @{ Kind = 'Remote access'; Product = 'AnyDesk'; Pattern = 'AnyDesk' }
    @{ Kind = 'Remote access'; Product = 'ConnectWise ScreenConnect'; Pattern = 'ScreenConnect' }
    @{ Kind = 'Remote access'; Product = 'Splashtop'; Pattern = 'Splashtop' }
    @{ Kind = 'Remote access'; Product = 'RustDesk'; Pattern = 'RustDesk' }
    @{ Kind = 'Remote access'; Product = 'Chrome Remote Desktop'; Pattern = '^chromoting$|Chrome Remote Desktop' }
    @{ Kind = 'Remote access'; Product = 'LogMeIn'; Pattern = 'LogMeIn' }
    @{ Kind = 'Remote access'; Product = 'GoTo'; Pattern = 'GoToAssist|GoTo Resolve' }
    @{ Kind = 'Remote access'; Product = 'VNC'; Pattern = '^tvnserver$|^uvnc_service$|^vncserver$|TightVNC|UltraVNC|RealVNC|VNC Server' }
    @{ Kind = 'Remote access'; Product = 'BeyondTrust'; Pattern = 'Bomgar|BeyondTrust' }
    @{ Kind = 'Remote access'; Product = 'Zoho Assist'; Pattern = 'Zoho Assist' }
    @{ Kind = 'Remote access'; Product = 'DameWare'; Pattern = 'DameWare' }
    @{ Kind = 'Remote access'; Product = 'NetSupport'; Pattern = 'NetSupport' }
    @{ Kind = 'Remote access'; Product = 'MeshCentral'; Pattern = 'Mesh ?Agent' }
    @{ Kind = 'Remote management'; Product = 'Atera'; Pattern = 'Atera' }
    @{ Kind = 'Remote management'; Product = 'NinjaOne'; Pattern = 'NinjaRMM|NinjaOne' }
    @{ Kind = 'Remote management'; Product = 'N-able'; Pattern = 'Advanced Monitoring Agent|N-able|N-central|SolarWinds MSP' }
    @{ Kind = 'Remote management'; Product = 'Datto RMM'; Pattern = '^CagService$|Datto RMM' }
    @{ Kind = 'Remote management'; Product = 'Kaseya'; Pattern = 'Kaseya' }
    @{ Kind = 'Remote management'; Product = 'Action1'; Pattern = 'Action1' }
    @{ Kind = 'Remote management'; Product = 'Syncro'; Pattern = '^Syncro' }
    @{ Kind = 'Remote management'; Product = 'Pulseway'; Pattern = 'Pulseway|^PCMonitorSrv$' }
    @{ Kind = 'Remote management'; Product = 'Tactical RMM'; Pattern = 'tacticalrmm|Tactical RMM' }
    @{ Kind = 'Remote management'; Product = 'ConnectWise Automate'; Pattern = '^LTService$|LabTech|ConnectWise Automate' }
    @{ Kind = 'Remote management'; Product = 'ManageEngine'; Pattern = 'ManageEngine|Desktop ?Central' }
    @{ Kind = 'Backup'; Product = 'Veeam Backup & Replication'; Pattern = '^VeeamBackupSvc$|^Veeam Backup Service$' }
    @{ Kind = 'Backup'; Product = 'Veeam Agent'; Pattern = '^VeeamEndpointBackupSvc$|Veeam Agent' }
    @{ Kind = 'Backup'; Product = 'Commvault'; Pattern = '^GxCVD|Commvault' }
    @{ Kind = 'Backup'; Product = 'Acronis'; Pattern = 'Acronis' }
    @{ Kind = 'Backup'; Product = 'Synology Active Backup'; Pattern = 'Active ?Backup' }
    @{ Kind = 'Backup'; Product = 'Hornetsecurity / Altaro VM Backup'; Pattern = 'Altaro|Hornetsecurity VM Backup' }
    @{ Kind = 'Backup'; Product = 'NAKIVO'; Pattern = 'NAKIVO' }
    @{ Kind = 'Backup'; Product = 'N-able Cove'; Pattern = 'Backup Service Controller|Cove Data Protection' }
    @{ Kind = 'Backup'; Product = 'Datto / ShadowProtect'; Pattern = 'Datto Backup|ShadowProtect|StorageCraft' }
    @{ Kind = 'Backup'; Product = 'Arcserve'; Pattern = 'Arcserve|^CASAD2D' }
    @{ Kind = 'Backup'; Product = 'Veritas Backup Exec'; Pattern = 'Backup ?Exec' }
    @{ Kind = 'Backup'; Product = 'Macrium Reflect'; Pattern = 'Macrium' }
    @{ Kind = 'Backup'; Product = 'Iperius'; Pattern = 'Iperius' }
    @{ Kind = 'Backup'; Product = 'Cobian'; Pattern = 'Cobian' }
    @{ Kind = 'Backup'; Product = 'UrBackup'; Pattern = 'UrBackup' }
    @{ Kind = 'Backup'; Product = 'Duplicati'; Pattern = 'Duplicati' }
    @{ Kind = 'Backup'; Product = 'Atempo Tina'; Pattern = '^tina_|Atempo' }
    @{ Kind = 'Backup'; Product = 'Druva'; Pattern = 'Druva|inSync' }
    @{ Kind = 'Backup'; Product = 'Carbonite'; Pattern = 'Carbonite' }
    @{ Kind = 'Backup'; Product = 'Rubrik'; Pattern = 'Rubrik' }
    @{ Kind = 'Backup'; Product = 'Cohesity'; Pattern = 'Cohesity' }
    @{ Kind = 'Backup'; Product = 'BackupAssist'; Pattern = 'BackupAssist' }
    @{ Kind = 'Database'; Product = 'SQL Server'; Pattern = '^MSSQLSERVER$|^MSSQL\$' }
    @{ Kind = 'Database'; Product = 'MySQL / MariaDB'; Pattern = 'MySQL|MariaDB' }
    @{ Kind = 'Database'; Product = 'PostgreSQL'; Pattern = 'postgresql' }
    @{ Kind = 'Database'; Product = 'Oracle'; Pattern = '^OracleService' }
    @{ Kind = 'Database'; Product = 'Firebird'; Pattern = 'Firebird' }
    @{ Kind = 'Database'; Product = 'Actian / Pervasive PSQL'; Pattern = 'Pervasive|^psqlWGE$|^psqlBSS$|Actian' }
    @{ Kind = 'Database'; Product = 'Progress OpenEdge'; Pattern = 'OpenEdge' }
    @{ Kind = 'UPS'; Product = 'APC PowerChute'; Pattern = 'PowerChute|APC PBE' }
    @{ Kind = 'UPS'; Product = 'Eaton Intelligent Power'; Pattern = 'Eaton|Intelligent Power' }
    @{ Kind = 'UPS'; Product = 'CyberPower PowerPanel'; Pattern = 'PowerPanel|CyberPower' }
    @{ Kind = 'UPS'; Product = 'Riello PowerShield'; Pattern = 'PowerShield|Riello' }
    @{ Kind = 'UPS'; Product = 'Network UPS Tools'; Pattern = '^upsmon$|Network UPS Tools' }
)

# When Microsoft stops the security updates of each SQL Server version, by its major version number.
$sqlVersions = @{
    10 = '2008', '2019-07-09'
    11 = '2012', '2022-07-12'
    12 = '2014', '2024-07-09'
    13 = '2016', '2026-07-14'
    14 = '2017', '2027-10-12'
    15 = '2019', '2030-01-08'
    16 = '2022', '2033-01-11'
}

# Reads one computer in a runspace of its own. Each query that fails is noted in Warnings and the
# others go on.
$readComputer = {
    param(
        [string]$Name,
        [pscredential]$Credential,
        [string[]]$Protocols,
        [object[]]$Catalog
    )

    Import-Module CimCmdlets -ErrorAction SilentlyContinue
    $result = [ordered]@{
        Computer = $Name; Protocol = $null; Error = $null; Warnings = @()
        Name = $null; Kind = $null; Manufacturer = $null; Model = $null; Serial = $null; Chassis = $null; Virtual = $false
        Processor = $null; MemoryGB = $null; Disks = @(); Volumes = @()
        Os = $null; Version = $null; Installed = $null; LastBoot = $null; LastUpdate = $null; User = $null
        Licence = $null; Office = @(); Roles = @(); Antivirus = @(); Defender = $null; BitLocker = $null
        Administrators = @(); Services = @(); ServicesRead = $false; Software = @(); SqlInstances = @(); UsbUps = @()
    }
    $session = $null
    foreach ($protocol in $Protocols) {
        try {
            # DCOM's options (impersonation, encryption) make a DCOM session; -Protocol is not allowed with them.
            $options = if ($protocol -eq 'Dcom') { New-CimSessionOption -Impersonation Impersonate -PacketPrivacy } else { New-CimSessionOption -Protocol Wsman }
            $arguments = @{ ComputerName = $Name; SessionOption = $options; OperationTimeoutSec = 60; ErrorAction = 'Stop' }
            if ($Credential) {
                $arguments.Credential = $Credential
            }
            $session = New-CimSession @arguments
            $result.Protocol = if ($protocol -eq 'Dcom') { 'DCOM' } else { 'WinRM' }
            $result.Error = $null
            break
        }
        catch {
            $result.Error = "$($_.Exception.Message)".Trim()
        }
    }
    if (-not $session) {
        return [pscustomobject]$result
    }

    $query = {
        param([string]$Class, [string]$Namespace = 'root\cimv2', [string]$Filter, [string[]]$Property, [switch]$Quiet)
        $arguments = @{ CimSession = $session; ClassName = $Class; Namespace = $Namespace; ErrorAction = 'Stop' }
        if ($Filter) {
            $arguments.Filter = $Filter
        }
        if ($Property) {
            $arguments.Property = $Property
        }
        try {
            @(Get-CimInstance @arguments)
        }
        catch {
            # -Quiet: a class that only some Windows versions or roles have.
            if (-not $Quiet) {
                $result.Warnings += "$($Class): $("$($_.Exception.Message)".Trim())"
            }
            @()
        }
    }
    $hklm = [uint32]2147483650
    $registry = {
        param([string]$Method, [string]$Key, [string]$Value)
        $arguments = @{ hDefKey = $hklm; sSubKeyName = $Key }
        if ($Value) {
            $arguments.sValueName = $Value
        }
        try {
            Invoke-CimMethod -CimSession $session -Namespace root\default -ClassName StdRegProv -MethodName $Method -Arguments $arguments -ErrorAction Stop
        }
        catch {
            $null
        }
    }
    $channel = {
        param([string]$Description)
        switch -Regex ($Description) {
            'VIRTUAL_MACHINE_ACTIVATION' { 'AVMA (Hyper-V host)'; break }
            'VOLUME_KMSCLIENT' { 'Volume (KMS)'; break }
            'VOLUME_MAK' { 'Volume (MAK)'; break }
            'VOLUME_KMS' { 'KMS host'; break }
            'OEM' { 'OEM'; break }
            'RETAIL' { 'Retail'; break }
            'TIMEBASED|SUBSCRIPTION' { 'Subscription'; break }
            default { $Description }
        }
    }
    $licenceStatus = { param([int]$Status) switch ($Status) { 1 { 'activated' } 0 { 'not activated' } 4 { 'not genuine' } default { 'grace period' } } }

    try {
        $system = (& $query Win32_ComputerSystem -Property Manufacturer, Model, TotalPhysicalMemory, UserName) | Select-Object -First 1
        $bios = (& $query Win32_BIOS -Property SerialNumber) | Select-Object -First 1
        $os = (& $query Win32_OperatingSystem -Property Caption, Version, ProductType, InstallDate, LastBootUpTime, CSName, SystemDrive) | Select-Object -First 1
        $enclosure = (& $query Win32_SystemEnclosure -Property ChassisTypes, SerialNumber) | Select-Object -First 1
        $result.Name = if ($os.CSName) { "$($os.CSName)" } else { $Name }
        $result.Kind = switch ([int]$os.ProductType) { 1 { 'Computer' } 2 { 'Domain controller' } 3 { 'Server' } default { 'Unknown' } }
        $result.Manufacturer = "$($system.Manufacturer)".Trim()
        $result.Model = "$($system.Model)".Trim()
        $result.Serial = @("$($bios.SerialNumber)".Trim(), "$($enclosure.SerialNumber)".Trim()) | Where-Object { $_ -and $_ -notmatch '^(0+|None|Default string|To be filled by O\.E\.M\.|System Serial Number|Not Specified|Chassis Serial Number)$' } | Select-Object -First 1
        $result.Virtual = "$($result.Manufacturer) $($result.Model)" -match 'Virtual|VMware|KVM|QEMU|VirtualBox|Xen|HVM domU|Parallels'
        $chassis = @($enclosure.ChassisTypes | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ })
        $result.Chassis = if ($result.Virtual) { 'Virtual' } elseif (@($chassis | Where-Object { $_ -in 8, 9, 10, 14, 30, 31, 32 }).Count) { 'Laptop' } elseif (@($chassis | Where-Object { $_ -in 17, 23, 28 }).Count) { 'Server' } else { 'Desktop' }
        $result.MemoryGB = if ($system.TotalPhysicalMemory) { [math]::Round($system.TotalPhysicalMemory / 1GB) }
        $result.Os = ("$($os.Caption)" -replace '^Microsoft\s+', '').Trim()
        $result.Version = "$($os.Version)"
        $result.Installed = $os.InstallDate
        $result.LastBoot = $os.LastBootUpTime
        $result.User = $system.UserName
        $isServer = $result.Kind -ne 'Computer'

        $processors = @(& $query Win32_Processor -Property Name, NumberOfCores)
        if ($processors.Count -gt 0) {
            $result.Processor = "$(if ($processors.Count -gt 1) { "$($processors.Count) x " })$(("$($processors[0].Name)" -replace '\s+', ' ').Trim()), $(($processors | Measure-Object -Property NumberOfCores -Sum).Sum) cores"
        }
        $physical = @(& $query MSFT_PhysicalDisk 'root\Microsoft\Windows\Storage' -Property FriendlyName, MediaType, Size, HealthStatus -Quiet)
        if ($physical.Count -gt 0) {
            $result.Disks = @($physical | ForEach-Object {
                    [pscustomobject]@{
                        Name   = "$($_.FriendlyName)".Trim()
                        SizeGB = [math]::Round($_.Size / 1GB)
                        Type   = $(switch ([int]$_.MediaType) { 3 { 'HDD' } 4 { 'SSD' } 5 { 'SCM' } default { '' } })
                        Health = $(switch ([int]$_.HealthStatus) { 0 { 'Healthy' } 1 { 'Warning' } 2 { 'Unhealthy' } default { 'Unknown' } })
                    }
                })
        }
        else {
            $result.Disks = @(& $query Win32_DiskDrive -Property Model, Size, Status | Where-Object { $_.Size } | ForEach-Object {
                    [pscustomobject]@{ Name = "$($_.Model)".Trim(); SizeGB = [math]::Round($_.Size / 1GB); Type = ''; Health = $(if ("$($_.Status)" -eq 'OK') { 'Healthy' } else { "$($_.Status)" }) }
                })
        }
        $result.Volumes = @(& $query Win32_LogicalDisk -Filter 'DriveType = 3' -Property DeviceID, Size, FreeSpace, VolumeName | Where-Object { $_.Size } | ForEach-Object {
                [pscustomobject]@{ Drive = $_.DeviceID; Label = $_.VolumeName; SizeGB = [math]::Round($_.Size / 1GB); FreeGB = [math]::Round($_.FreeSpace / 1GB, 1); FreePercent = [math]::Round(100 * $_.FreeSpace / $_.Size) }
            })

        if ($isServer) {
            # The roles and the features that say what the server does, not their management tools.
            $roles = 'Active Directory|DNS Server|DHCP Server|File Server|DFS |Data Deduplication|^Hyper-V$|Print|Remote Desktop|Web Server \(IIS\)|Windows Server Update Services|Failover Clustering|Network Policy|Windows Deployment|Fax Server|Volume Activation|Windows Server Backup|Remote Access|Routing|DirectAccess|Network Load Balancing|Host Guardian|Storage Replica|SMTP Server|Work Folders'
            $result.Roles = @(& $query Win32_ServerFeature -Property Name -Quiet | ForEach-Object { "$($_.Name)" } | Where-Object { $_ -match $roles -and $_ -notmatch '\bTools\b|Module for Windows PowerShell|Snap-?Ins|Client' } | Sort-Object -Unique)
        }

        $licences = @(& $query SoftwareLicensingProduct -Filter 'PartialProductKey IS NOT NULL' -Property Name, Description, LicenseStatus, PartialProductKey, ApplicationID)
        $windows = $licences | Where-Object { "$($_.ApplicationID)" -eq '55c92734-d682-4d71-983e-d6ec3f16059f' } | Select-Object -First 1
        if ($windows) {
            $result.Licence = [pscustomobject]@{ Channel = & $channel $windows.Description; Activated = [int]$windows.LicenseStatus -eq 1; Status = & $licenceStatus $windows.LicenseStatus; Key = $windows.PartialProductKey }
        }
        # Office with a key; not the grace licence of Microsoft 365 Apps, which its users license.
        $result.Office = @($licences | Where-Object { "$($_.ApplicationID)" -eq '0ff1ce15-a989-479d-af46-f275c6370663' -and "$($_.Name)" -notmatch 'O365|Grace' } | ForEach-Object {
                [pscustomobject]@{ Name = ("$($_.Name)" -replace '^Office \d+,\s*', '' -replace '\s*edition$', ''); Channel = & $channel $_.Description; Activated = [int]$_.LicenseStatus -eq 1; Status = & $licenceStatus $_.LicenseStatus; Key = $_.PartialProductKey }
            })

        # The newest update, from the install dates of the updates: a date, or a text in one of these forms.
        $formats = [string[]]@('M/d/yyyy', 'MM/dd/yyyy', 'yyyyMMdd', 'yyyy-MM-dd', 'dd.MM.yyyy', 'd-M-yyyy', 'd/M/yyyy')
        $updates = @(foreach ($fix in @(& $query Win32_QuickFixEngineering -Property HotFixID, InstalledOn)) {
                $date = [datetime]::MinValue
                if ($fix.InstalledOn -is [datetime]) {
                    $date = $fix.InstalledOn
                }
                elseif (-not [datetime]::TryParseExact((("$($fix.InstalledOn)".Trim()) -split ' ')[0], $formats, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$date)) {
                    continue
                }
                if ($date.Year -ge 2000 -and $date -le (Get-Date).AddDays(1)) {
                    $date
                }
            })
        $result.LastUpdate = $updates | Sort-Object -Descending | Select-Object -First 1

        $services = @(& $query Win32_Service -Property Name, DisplayName, State, StartMode)
        # Every Windows has services: none means they could not be read, so the antivirus is unknown.
        $result.ServicesRead = $services.Count -gt 0
        $result.Services = @(foreach ($entry in $Catalog) {
                $found = @($services | Where-Object { "$($_.StartMode)" -ne 'Disabled' -and ("$($_.Name)" -match $entry.Pattern -or "$($_.DisplayName)" -match $entry.Pattern) })
                if ($found.Count -gt 0) {
                    [pscustomobject]@{ Kind = $entry.Kind; Product = $entry.Product; Running = @($found | Where-Object { "$($_.State)" -eq 'Running' }).Count -gt 0 }
                }
            })

        # Antivirus: what the Security Center of a Windows computer says is on, and the antivirus services
        # running (servers have no Security Center). Defender in passive mode doesn't count.
        $antivirus = @()
        if (-not $isServer) {
            foreach ($product in @(& $query AntiVirusProduct 'root\SecurityCenter2' -Property displayName, productState -Quiet)) {
                if ([int]$product.productState -band 0x1000) {
                    $antivirus += "$($product.displayName)".Trim()
                }
            }
        }
        $defender = (& $query MSFT_MpComputerStatus 'root\Microsoft\Windows\Defender' -Property AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated -Quiet) | Select-Object -First 1
        if ($defender) {
            $result.Defender = [pscustomobject]@{ Mode = "$($defender.AMRunningMode)"; Enabled = [bool]$defender.AntivirusEnabled; RealTime = [bool]$defender.RealTimeProtectionEnabled; Signatures = $defender.AntivirusSignatureLastUpdated }
        }
        foreach ($service in @($result.Services | Where-Object { $_.Kind -eq 'Antivirus' -and $_.Running })) {
            if ($service.Product -eq 'Microsoft Defender' -and $defender -and (-not $defender.AntivirusEnabled -or "$($defender.AMRunningMode)" -match 'Passive')) {
                continue
            }
            $antivirus += $service.Product
        }
        $result.Antivirus = @($antivirus | Where-Object { $_ } | ForEach-Object { $_ -replace '^Windows Defender$', 'Microsoft Defender' } | Select-Object -Unique)

        $drive = if ($os.SystemDrive) { "$($os.SystemDrive)" } else { 'C:' }
        $volume = (& $query Win32_EncryptableVolume 'root\cimv2\Security\MicrosoftVolumeEncryption' -Filter "DriveLetter = '$drive'" -Property ProtectionStatus -Quiet) | Select-Object -First 1
        # Not read without administrator rights, or on a Windows without BitLocker.
        $result.BitLocker = if ($volume) { switch ([int]$volume.ProtectionStatus) { 0 { 'Off' } 1 { 'On' } default { 'Unknown' } } } else { 'not read' }

        # The members of the Administrators group (S-1-5-32-544, whose name depends on the language).
        # The query names the computer as domain: without it, Win32_Group goes through every group of
        # the domain.
        if ($result.Kind -ne 'Domain controller') {
            try {
                $group = Get-CimInstance -CimSession $session -ClassName Win32_Group -Filter "Domain = '$($result.Name)' AND SID = 'S-1-5-32-544'" -ErrorAction Stop | Select-Object -First 1
                if ($group) {
                    $result.Administrators = @(Get-CimAssociatedInstance -CimSession $session -InputObject $group -Association Win32_GroupUser -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = "$($_.Domain)\$($_.Name)"; Sid = "$($_.SID)" } })
                }
            }
            catch {
                $result.Warnings += "Administrators group: $("$($_.Exception.Message)".Trim())"
            }
        }

        if ($isServer) {
            $result.UsbUps = @(& $query Win32_Battery -Property Name -Quiet | ForEach-Object { "$($_.Name)".Trim() } | Where-Object { $_ })

            # The software installed, without Microsoft's and the drivers and runtimes.
            $hidden = 'Redistributable|Runtime|Driver|Chipset|\bUpdate for\b|Hotfix|Language Pack|\bMUI\b|^Intel\(R\)|^Realtek|^NVIDIA|^AMD '
            $software = @{}
            foreach ($root in 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
                foreach ($key in @((& $registry EnumKey $root).sNames | Where-Object { $_ })) {
                    $displayName = "$((& $registry GetStringValue "$root\$key" 'DisplayName').sValue)".Trim()
                    if (-not $displayName -or $software.ContainsKey($displayName) -or $displayName -match $hidden) {
                        continue
                    }
                    $publisher = "$((& $registry GetStringValue "$root\$key" 'Publisher').sValue)".Trim()
                    if ($publisher -match 'Microsoft' -or $displayName -match '^Microsoft') {
                        continue
                    }
                    $software[$displayName] = [pscustomobject]@{ Name = $displayName; Publisher = $publisher; Version = "$((& $registry GetStringValue "$root\$key" 'DisplayVersion').sValue)".Trim() }
                }
            }
            $result.Software = @($software.Values | Sort-Object -Property Name)
        }

        if (@($result.Services | Where-Object { $_.Product -eq 'SQL Server' }).Count -gt 0) {
            $names = 'SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
            foreach ($instance in @((& $registry EnumValues $names).sNames | Where-Object { $_ })) {
                $id = (& $registry GetStringValue $names $instance).sValue
                $setup = "SOFTWARE\Microsoft\Microsoft SQL Server\$id\Setup"
                $version = (& $registry GetStringValue $setup 'PatchLevel').sValue
                if (-not $version) {
                    $version = (& $registry GetStringValue $setup 'Version').sValue
                }
                $result.SqlInstances += [pscustomobject]@{ Instance = $instance; Edition = (& $registry GetStringValue $setup 'Edition').sValue; Version = $version }
            }
        }
    }
    catch {
        $result.Error = "$($_.Exception.Message)".Trim()
    }
    finally {
        Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue
    }
    return [pscustomobject]$result
}

# Why a computer could not be read, in a few words.
function Format-ReadError {
    param(
        [string]$Message
    )

    switch -Regex ($Message) {
        'Access is denied|Acc.s refus|Toegang geweigerd|Zugriff verweigert|0x80070005' { return 'access denied for this account' }
        'TrustedHosts' { return 'WinRM needs TrustedHosts for it, and DCOM did not answer' }
        'RPC server is unavailable|serveur RPC|RPC-server' { return 'DCOM blocked by its firewall' }
    }
    $line = ("$Message" -split '\r?\n')[0].Trim()
    if ($line.Length -gt 120) {
        $line = $line.Substring(0, 117) + '...'
    }
    return $line
}

function Format-Day {
    param(
        $Value
    )

    if ($Value) {
        return ([datetime]$Value).ToString('yyyy-MM-dd')
    }
    return ''
}

function Format-Size {
    param(
        [double]$Gigabytes
    )

    if ($Gigabytes -ge 1000) {
        return "$([math]::Round($Gigabytes / 1000, 1)) TB"
    }
    return "$([math]::Round($Gigabytes)) GB"
}

$names = @($Computer | Where-Object { $_ } | ForEach-Object { $_.Trim() } | Sort-Object -Unique)
Write-Progress -Id 40 -Activity 'Servers and computers' -Status "Which of the $($names.Count) computers answer" -PercentComplete 0
$open = Test-TcpPorts -Addresses $names -Ports 5985, 135 -TimeoutMs 1500 -Status 'Which computers answer' -Activity 'Servers and computers' -ProgressId 40 -Percent 5
$results = @()
$reachable = @($names | Where-Object { $open.ContainsKey($_) })
if ($reachable.Count -gt 0) {
    $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
    $pool.Open()
    try {
        $jobs = @(foreach ($name in $reachable) {
                $protocols = @(@(if (@($open[$name]) -contains 5985) { 'Wsman' }) + @(if (@($open[$name]) -contains 135) { 'Dcom' }))
                $shell = [powershell]::Create()
                $shell.RunspacePool = $pool
                [void]$shell.AddScript($readComputer).AddArgument($name).AddArgument($Credential).AddArgument([string[]]$protocols).AddArgument([object[]]$serviceCatalog)
                [pscustomobject]@{ Name = $name; Shell = $shell; Handle = $shell.BeginInvoke() }
            })
        while (($pending = @($jobs | Where-Object { -not $_.Handle.IsCompleted }).Count) -gt 0) {
            Write-Progress -Id 40 -Activity 'Servers and computers' -Status "Read: $($jobs.Count - $pending) of $($jobs.Count) computers" -PercentComplete (10 + 85 * ($jobs.Count - $pending) / $jobs.Count)
            Start-Sleep -Milliseconds 500
        }
        $results = @(foreach ($job in $jobs) {
                try {
                    @($job.Shell.EndInvoke($job.Handle)) | Select-Object -First 1
                }
                catch {
                    [pscustomobject]@{ Computer = $job.Name; Protocol = $null; Error = "$($_.Exception.Message)" }
                }
                $job.Shell.Dispose()
            })
    }
    finally {
        $pool.Close()
        $pool.Dispose()
    }
}
Write-Progress -Id 40 -Activity 'Servers and computers' -Completed

$read = @($results | Where-Object { $_.Protocol -and -not $_.Error } | Sort-Object -Property Name)
$notRead = @(@($names | Where-Object { -not $open.ContainsKey($_) } | ForEach-Object { [pscustomobject]@{ Computer = $_; Reason = 'no answer on WinRM (5985) or RPC (135): off, or blocked by its firewall' } }) +
    @($results | Where-Object { -not $_.Protocol -or $_.Error } | ForEach-Object { [pscustomobject]@{ Computer = $_.Computer; Reason = Format-ReadError $_.Error } }) | Sort-Object -Property Computer)
$servers = @($read | Where-Object { $_.Kind -ne 'Computer' })
$workstations = @($read | Where-Object { $_.Kind -eq 'Computer' })
foreach ($item in $read) {
    $item | Add-Member -NotePropertyName Support -NotePropertyValue (Get-WindowsSupportEnd -Name $item.Os -Version $item.Version)
}

"### Read"
"$($read.Count) of $($names.Count) read ($(@($read | Where-Object { $_.Protocol -eq 'WinRM' }).Count) over WinRM, $(@($read | Where-Object { $_.Protocol -eq 'DCOM' }).Count) over DCOM): $($servers.Count) $(if ($servers.Count -eq 1) { 'server' } else { 'servers' }), $($workstations.Count) $(if ($workstations.Count -eq 1) { 'computer' } else { 'computers' }). Only the computers on during the audit can be read."
if ($notRead.Count -gt 0) {
    ""
    Format-AuditTable -Rows $notRead -Columns 'Not read=Computer', 'Why=Reason'
}

# "Dell PowerEdge R740", not "Dell Inc. PowerEdge R740" or "HP HP EliteBook".
$model = {
    param($Item)
    $maker = "$($Item.Manufacturer)" -replace ',?\s+(Inc\.?|Corporation|Corp\.?|Co\.,?\s*Ltd\.?|Ltd\.?)$', ''
    $text = if ("$($Item.Model)" -like "$maker*") { "$($Item.Model)" } else { "$maker $($Item.Model)".Trim() }
    if ($Item.Virtual) { "Virtual machine ($text)" } else { $text }
}
$licence = {
    param($Item)
    if ($Item.Licence) { "$($Item.Licence.Channel), $($Item.Licence.Status), key ...$($Item.Licence.Key)" }
}
if ($servers.Count -gt 0) {
    "`n### Servers"
    Format-AuditTable -Rows ($servers | ForEach-Object {
            [pscustomobject]@{
                Name       = $_.Name
                Roles      = @(@($_.Kind) + @($_.Roles) | Where-Object { $_ } | Select-Object -Unique)
                Model      = & $model $_
                Serial     = $_.Serial
                Processor  = $_.Processor
                Memory     = $(if ($_.MemoryGB) { "$($_.MemoryGB) GB" })
                Disks      = @($_.Disks | Group-Object -Property { "$(Format-Size $_.SizeGB) $($_.Type)".Trim() } | ForEach-Object { "$($_.Count) x $($_.Name)" })
                Windows    = $_.Os
                Support    = Format-WindowsSupport $_.Support
                Licence    = & $licence $_
                LastUpdate = Format-Day $_.LastUpdate
                LastBoot   = Format-Day $_.LastBoot
            }
        }) -Columns 'Name', 'Roles', 'Model', 'Serial number=Serial', 'Processor', 'Memory', 'Disks', 'Windows', 'Support', 'Licence', 'Last update=LastUpdate', 'Last restart=LastBoot'
    "Purchase date and warranty: from the serial number on the maker's site (Dell, HPE, Lenovo)."
}

if ($workstations.Count -gt 0) {
    "`n### Computers"
    Format-AuditTable -Rows ($workstations | ForEach-Object {
            [pscustomobject]@{
                Name       = $_.Name
                User       = $_.User
                Model      = "$(& $model $_)$(if ($_.Chassis -eq 'Laptop') { ' (laptop)' })"
                Serial     = $_.Serial
                Windows    = $_.Os
                Support    = Format-WindowsSupport $_.Support
                Antivirus  = $(if ($_.Antivirus.Count) { $_.Antivirus } else { ':x: none' })
                BitLocker  = $_.BitLocker
                LastUpdate = Format-Day $_.LastUpdate
            }
        }) -Columns 'Name', 'User logged on=User', 'Model', 'Serial number=Serial', 'Windows', 'Support', 'Antivirus', 'BitLocker', 'Last update=LastUpdate'
}

$lowDisks = @($read | ForEach-Object { $item = $_; @($_.Volumes | Where-Object { $_ -and $_.FreePercent -lt 15 }) | ForEach-Object { [pscustomobject]@{ Computer = $item.Name; Drive = "$($_.Drive) $($_.Label)".Trim(); Size = Format-Size $_.SizeGB; Free = "$(Format-Size $_.FreeGB) ($($_.FreePercent)%)"; Percent = $_.FreePercent } } })
if ($lowDisks.Count -gt 0) {
    "`n### Disk space"
    "Volumes with less than 15% free:"
    ""
    Format-AuditTable -Rows ($lowDisks | Sort-Object -Property Percent) -Columns 'Computer', 'Drive', 'Size', 'Free'
}

$software = @($read | ForEach-Object { $item = $_; @($_.Services | Where-Object { $_ }) | ForEach-Object { [pscustomobject]@{ Kind = $_.Kind; Product = $_.Product; Computer = $item.Name } } })
if ($software.Count -gt 0) {
    "`n### Antivirus, remote access, backup"
    "Found in the services of the computers read (installed, not disabled)."
    ""
    $kinds = @{ 'Antivirus' = 0; 'Remote access' = 1; 'Remote management' = 2; 'Backup' = 3; 'Database' = 4; 'UPS' = 5 }
    Format-AuditTable -Rows ($software | Group-Object -Property Kind, Product | Sort-Object -Property { $kinds[$_.Group[0].Kind] }, Name | ForEach-Object {
            $where = @($_.Group | ForEach-Object { $_.Computer } | Sort-Object -Unique)
            [pscustomobject]@{ Kind = $_.Group[0].Kind; Product = $_.Group[0].Product; Count = $where.Count; Where = "$(($where | Select-Object -First 15) -join ', ')$(if ($where.Count -gt 15) { ', ...' })" }
        }) -Columns 'Kind', 'Product', 'Computers=Count', 'Where'
}

$expectedAdministrator = '-500$|-512$|-519$|^S-1-12-1-'
$extraAdministrators = @($read | Where-Object { $_.Kind -ne 'Domain controller' } | ForEach-Object {
        $others = @($_.Administrators | Where-Object { $_ -and $_.Sid -notmatch $expectedAdministrator } | ForEach-Object { $_.Name })
        if ($others.Count -gt 0) {
            [pscustomobject]@{ Computer = $_.Name; Kind = $_.Kind; Others = $others }
        }
    })
if ($extraAdministrators.Count -gt 0) {
    "`n### Local administrators"
    "Members of the Administrators group of each computer besides its own Administrator, Domain Admins and Enterprise Admins:"
    ""
    Format-AuditTable -Rows $extraAdministrators -Columns 'Computer', 'Other administrators=Others'
}

$sql = @($read | ForEach-Object { $item = $_; @($_.SqlInstances | Where-Object { $_ }) | ForEach-Object {
            $major = if ("$($_.Version)" -match '^(\d+)\.') { [int]$Matches[1] }
            $known = $sqlVersions[$major]
            $end = if ($known) { [datetime]$known[1] }
            [pscustomobject]@{
                Server   = $item.Name
                Instance = $_.Instance
                Edition  = $_.Edition
                Version  = "$(if ($known) { "SQL Server $($known[0]) " })($($_.Version))"
                End      = $end
                Support  = $(if ($end) { Format-WindowsSupport ([pscustomobject]@{ Status = $(if ($end -lt (Get-Date)) { 'Ended' } elseif ($end -lt (Get-Date).AddYears(1)) { 'Ending' } else { 'Supported' }); End = $end }) })
            }
        } })
if ($sql.Count -gt 0) {
    "`n### SQL Server"
    Format-AuditTable -Rows $sql -Columns 'Server', 'Instance', 'Edition', 'Version', 'Support'
}

$installed = @($servers | ForEach-Object { $item = $_; @($_.Software | Where-Object { $_ }) | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Publisher = $_.Publisher; Version = $_.Version; Server = $item.Name } } })
if ($installed.Count -gt 0) {
    "`n### Software on the servers"
    "Installed software, without Microsoft's, drivers and runtimes: the business applications are among them."
    ""
    Format-AuditTable -Rows ($installed | Group-Object -Property Name | Sort-Object -Property Name | Select-Object -First 300 | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Version = @($_.Group | ForEach-Object { $_.Version } | Where-Object { $_ } | Sort-Object -Unique); Publisher = $_.Group[0].Publisher; Servers = @($_.Group | ForEach-Object { $_.Server } | Sort-Object -Unique) }
        }) -Columns 'Software=Name', 'Version', 'Publisher', 'Servers'
}

$usbUps = @($servers | Where-Object { $_.UsbUps.Count -gt 0 -or @($_.Services | Where-Object { $_.Kind -eq 'UPS' }).Count -gt 0 })
if ($usbUps.Count -gt 0) {
    "`n### UPS seen by the servers"
    Format-AuditTable -Rows ($usbUps | ForEach-Object { [pscustomobject]@{ Server = $_.Name; Ups = @($_.UsbUps); Software = @($_.Services | Where-Object { $_.Kind -eq 'UPS' } | ForEach-Object { $_.Product }) } }) -Columns 'Server', 'UPS on USB=Ups', 'UPS software=Software'
}

$office = @($read | Where-Object { $_.Office.Count -gt 0 })
if ($office.Count -gt 0) {
    "`n### Office licences"
    "Office with a product key (volume or retail); Microsoft 365 Apps are licensed by their users instead."
    ""
    Format-AuditTable -Rows ($office | ForEach-Object { $item = $_; $_.Office | ForEach-Object { [pscustomobject]@{ Computer = $item.Name; Office = $_.Name; Licence = "$($_.Channel), $($_.Status), key ...$($_.Key)" } } }) -Columns 'Computer', 'Office', 'Licence'
}

# Findings.
$list = { param([object[]]$Items) "$(($Items | Select-Object -First 30 | ForEach-Object { $_.Name }) -join ', ')$(if ($Items.Count -gt 30) { ', ...' })" }
$noAntivirus = @($read | Where-Object { $_.ServicesRead -and $_.Antivirus.Count -eq 0 })
if ($noAntivirus.Count -gt 0) {
    New-AuditFinding -Severity High -Area $area -Finding "No antivirus found running on $($noAntivirus.Count) $(if ($noAntivirus.Count -eq 1) { 'computer' } else { 'computers' }) (Microsoft Defender off or passive, and no other known antivirus): $(& $list $noAntivirus)." -Recommendation 'Install the antivirus or EDR of the company, or turn Microsoft Defender back on.'
}
$oldSignatures = @($read | Where-Object { $_.Defender -and $_.Defender.Enabled -and "$($_.Defender.Mode)" -notmatch 'Passive' -and $_.Defender.Signatures -and $_.Defender.Signatures -lt (Get-Date).AddDays(-7) })
if ($oldSignatures.Count -gt 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding "Microsoft Defender's signatures are more than a week old on $(& $list $oldSignatures)." -Recommendation 'Check Windows Update or WSUS on them: Defender gets its signatures there.'
}
$notUpdated = @($read | Where-Object { $_.LastUpdate -and $_.LastUpdate -lt (Get-Date).AddDays(-60) })
if ($notUpdated.Count -gt 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding "No update installed for more than 60 days on $(($notUpdated | Select-Object -First 30 | ForEach-Object { "$($_.Name) ($(Format-Day $_.LastUpdate))" }) -join ', ')$(if ($notUpdated.Count -gt 30) { ', ...' })." -Recommendation 'Install the updates every month (Windows Update for Business, WSUS or the RMM), and restart.'
}
$full = @($lowDisks | Where-Object { $_.Percent -lt 10 })
if ($full.Count -gt 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding "Less than 10% free on $(($full | ForEach-Object { "$($_.Computer) $($_.Drive) ($($_.Free))" }) -join ', ')." -Recommendation 'Free space or enlarge the volume before it fills: updates, databases and backups fail on a full disk.'
}
$failingDisks = @($read | ForEach-Object { $item = $_; @($_.Disks | Where-Object { $_ -and $_.Health -in 'Warning', 'Unhealthy' }) | ForEach-Object { "$($item.Name) $($_.Name) ($($_.Health))" } })
if ($failingDisks.Count -gt 0) {
    New-AuditFinding -Severity High -Area $area -Finding "Disks that Windows reports as failing: $($failingDisks -join ', ')." -Recommendation 'Check them (the RAID controller or iDRAC/iLO) and replace them.'
}
$unencrypted = @($workstations | Where-Object { $_.Chassis -eq 'Laptop' -and $_.BitLocker -eq 'Off' })
if ($unencrypted.Count -gt 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding "$($unencrypted.Count) $(if ($unencrypted.Count -eq 1) { 'laptop has' } else { 'laptops have' }) no BitLocker on its Windows drive:$(& $list $unencrypted). A lost or stolen one gives away its data." -Recommendation 'Turn BitLocker on (by group policy or Intune), with the recovery keys saved in Active Directory or Entra ID.'
}
$notActivated = @($read | Where-Object { $_.Licence -and -not $_.Licence.Activated })
if ($notActivated.Count -gt 0) {
    New-AuditFinding -Severity Low -Area $area -Finding "Windows is not activated on $(($notActivated | ForEach-Object { "$($_.Name) ($($_.Licence.Status))" }) -join ', ')." -Recommendation 'Activate it with a valid licence (KMS, MAK or the key of the computer).'
}
$userAdministrators = @($extraAdministrators | Where-Object { $_.Kind -eq 'Computer' })
if ($userAdministrators.Count -gt 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding "Other accounts are local administrators on $($userAdministrators.Count) $(if ($userAdministrators.Count -eq 1) { 'computer' } else { 'computers' }):$(($userAdministrators | Select-Object -First 20 | ForEach-Object { "$($_.Computer) ($($_.Others -join ', '))" }) -join '; ')$(if ($userAdministrators.Count -gt 20) { '; ...' })." -Recommendation 'Give users a standard account; let IT install software (or use an elevation tool), so that malware run by a user cannot take the computer.'
}
$remote = @($software | Where-Object { $_.Kind -in 'Remote access', 'Remote management' } | ForEach-Object { $_.Product } | Sort-Object -Unique)
if ($remote.Count -gt 1) {
    New-AuditFinding -Severity Medium -Area $area -Finding "$($remote.Count) remote access or management tools are installed: $($remote -join ', '). Each one is a way into the network." -Recommendation 'Keep the one the company uses, under its own account with MFA, and uninstall the others.'
}
elseif ($remote.Count -eq 1) {
    New-AuditFinding -Severity Info -Area $area -Finding "Remote access tool installed: $($remote[0])." -Recommendation 'Note who has an account on it, and check that its account uses MFA.'
}
if ($servers.Count -gt 0 -and @($software | Where-Object { $_.Kind -eq 'Backup' }).Count -eq 0) {
    New-AuditFinding -Severity Low -Area $area -Finding "No backup software found on the $($servers.Count) servers read." -Recommendation 'Find where the backup runs (NAS, hypervisor, cloud) and note what it backs up; if nothing does, set one up.'
}
foreach ($instance in @($sql | Where-Object { $_.End -and $_.End -lt (Get-Date).AddYears(1) })) {
    $ended = $instance.End -lt (Get-Date)
    New-AuditFinding -Severity $(if ($ended) { 'High' } else { 'Medium' }) -Area $area -Finding "$($instance.Version) $($instance.Edition) on $($instance.Server)\$($instance.Instance): its support $(if ($ended) { 'ended' } else { 'ends' }) on $($instance.End.ToString('yyyy-MM-dd'))." -Recommendation 'Plan its upgrade with the supplier of the application that uses it.'
}

New-AuditData -Name 'Inventory' -Value ([pscustomobject]@{
        Computers = $read
        NotRead   = $notRead
    })
