[CmdletBinding()]
param(
    # Hyper-V host, or failover cluster name: every node of the cluster is reported.
    [Parameter(Mandatory)]
    [string]$Server,

    # Account for PowerShell remoting; the current Windows user when not given.
    [pscredential]$Credential,

    [string]$Site = 'main'
)

# Hyper-V report, built like vmwarereport.ps1: hosts, storage, virtual machines, their disks and
# checkpoints, as Markdown. Collects over PowerShell remoting (WinRM), on every cluster node at
# once, so the Hyper-V module is only needed on the hosts. The ``` blocks are the graphs.

$ErrorActionPreference = 'Stop'

# Runs on each Hyper-V host and returns plain values only, so they come back over remoting.
$collectHost = {
    param([bool]$IncludeVolumes)

    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $bios = Get-CimInstance -ClassName Win32_BIOS
    $processors = @(Get-CimInstance -ClassName Win32_Processor)
    $vmHost = Get-VMHost

    # The guest OS name comes from the integration services (KVP), when they run.
    $guestOs = @{}
    foreach ($kvp in @(Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_KvpExchangeComponent -ErrorAction SilentlyContinue)) {
        foreach ($item in @($kvp.GuestIntrinsicExchangeItems)) {
            $properties = ([xml]$item).INSTANCE.PROPERTY
            if (($properties | Where-Object { $_.NAME -eq 'Name' }).VALUE -eq 'OSName') {
                $guestOs[$kvp.SystemName] = ($properties | Where-Object { $_.NAME -eq 'Data' }).VALUE
            }
        }
    }

    $vms = foreach ($vm in @(Get-VM | Sort-Object -Property Name)) {
        $disks = foreach ($drive in @($vm | Get-VMHardDiskDrive)) {
            $vhd = Get-VHD -Path $drive.Path -ErrorAction SilentlyContinue
            [pscustomobject]@{
                Path     = $drive.Path
                Type     = if ($vhd) { "$($vhd.VhdType)" } else { 'Unknown' }
                Size     = if ($vhd) { [long]$vhd.Size } else { 0 }
                FileSize = if ($vhd) { [long]$vhd.FileSize } else { 0 }
            }
        }
        [pscustomobject]@{
            Name           = $vm.Name
            State          = "$($vm.State)"
            Cpu            = $vm.ProcessorCount
            MemoryAssigned = [long]$vm.MemoryAssigned
            MemoryStartup  = [long]$vm.MemoryStartup
            MemoryDemand   = [long]$vm.MemoryDemand
            DynamicMemory  = [bool]$vm.DynamicMemoryEnabled
            Generation     = $vm.Generation
            Version        = "$($vm.Version)"
            Uptime         = "$($vm.Uptime)"
            Os             = $guestOs["$($vm.Id)"]
            Disks          = @($disks)
        }
    }

    $checkpoints = foreach ($checkpoint in @(Get-VMSnapshot -VMName * -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{
            VM      = $checkpoint.VMName
            Name    = $checkpoint.Name
            Type    = "$($checkpoint.SnapshotType)"
            Created = $checkpoint.CreationTime
        }
    }

    $replications = foreach ($replication in @(Get-VMReplication -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{
            VM          = $replication.VMName
            Mode        = "$($replication.Mode)"
            State       = "$($replication.State)"
            Health      = "$($replication.Health)"
            Replica     = "$($replication.CurrentReplicaServerName)"
            LastReplica = $replication.LastReplicationTime
        }
    }

    # A cluster reports its Cluster Shared Volumes instead.
    $volumes = if ($IncludeVolumes) {
        foreach ($volume in @(Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.Size -gt 0 })) {
            [pscustomobject]@{ Name = "$($volume.DriveLetter):"; Path = "$($volume.DriveLetter):\"; Size = [long]$volume.Size; Free = [long]$volume.SizeRemaining }
        }
    }

    [pscustomobject]@{
        Name             = $env:COMPUTERNAME
        Manufacturer     = $computer.Manufacturer
        Model            = $computer.Model
        CpuModel         = ($processors | Select-Object -First 1).Name
        CpuMhz           = ($processors | Select-Object -First 1).MaxClockSpeed
        Sockets          = $processors.Count
        Cores            = ($processors | Measure-Object -Property NumberOfCores -Sum).Sum
        LogicalCpus      = $computer.NumberOfLogicalProcessors
        CpuUsage         = [math]::Round(($processors | Measure-Object -Property LoadPercentage -Average).Average)
        MemoryTotal      = [long]$computer.TotalPhysicalMemory
        MemoryFree       = [long]$os.FreePhysicalMemory * 1KB
        Os               = "$($os.Caption) ($($os.BuildNumber))"
        LastBoot         = $os.LastBootUpTime
        Serial           = $bios.SerialNumber
        BiosVersion      = $bios.SMBIOSBIOSVersion
        MigrationEnabled = [bool]$vmHost.VirtualMachineMigrationEnabled
        VirtualMachines  = @($vms)
        Checkpoints      = @($checkpoints)
        Replications     = @($replications)
        Volumes          = @($volumes)
    }
}

# Runs on the server given: the cluster, its nodes and Cluster Shared Volumes, if it is one.
$discover = {
    $cluster = $null
    if (Get-Command -Name Get-ClusterNode -ErrorAction SilentlyContinue) {
        try {
            $cluster = [pscustomobject]@{
                Name    = (Get-Cluster -ErrorAction Stop).Name
                Nodes   = @(Get-ClusterNode -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = $_.Name; State = "$($_.State)" } })
                Volumes = @(Get-ClusterSharedVolume -ErrorAction Stop | ForEach-Object {
                        $partition = $_.SharedVolumeInfo.Partition
                        [pscustomobject]@{ Name = $_.Name; Path = $_.SharedVolumeInfo.FriendlyVolumeName; Size = [long]$partition.Size; Free = [long]$partition.FreeSpace }
                    })
            }
        }
        catch {
            # Not a cluster node.
            $cluster = $null
        }
    }
    $cluster
}

function Get-Gb {
    param([double]$Bytes)
    return [math]::Round($Bytes / 1GB, 1)
}

function Get-Percent {
    param([double]$Part, [double]$Whole)
    if ($Whole -le 0) {
        return 0
    }
    return [math]::Round($Part * 100 / $Whole)
}

# Table cells must not contain a | or a line break.
function Format-Cell {
    param($Value)
    return ("$Value" -replace '\|', '/' -replace '\r?\n', ' ').Trim()
}

$isLocal = $Server -in 'localhost', '.', $env:COMPUTERNAME -and -not $Credential
$remoting = @{}
if ($Credential) {
    $remoting.Credential = $Credential
}

$activity = "Hyper-V report: $Site"
try {
    Write-Progress -Id 10 -Activity $activity -Status "Connecting to $Server" -PercentComplete 0
    $cluster = if ($isLocal) { & $discover } else { Invoke-Command -ComputerName $Server -ScriptBlock $discover @remoting }

    $hostNames = @($Server)
    $downNodes = @()
    if ($cluster) {
        $hostNames = @($cluster.Nodes | Where-Object { $_.State -eq 'Up' } | ForEach-Object { $_.Name })
        $downNodes = @($cluster.Nodes | Where-Object { $_.State -ne 'Up' })
    }

    Write-Progress -Id 10 -Activity $activity -Status "Collecting $($hostNames.Count) host(s)" -PercentComplete 20
    $failures = @()
    if ($isLocal -and -not $cluster) {
        $hosts = @(& $collectHost $true)
    }
    else {
        # Every node at once, each with the same login: no second hop through the server given.
        $hosts = @(Invoke-Command -ComputerName $hostNames -ScriptBlock $collectHost -ArgumentList (-not $cluster) @remoting `
                -ErrorAction SilentlyContinue -ErrorVariable remotingErrors)
        $failures = @($remotingErrors | ForEach-Object { "$($_.TargetObject): $($_.Exception.Message)" })
    }
    $hosts = @($hosts | Sort-Object -Property Name)
    Write-Progress -Id 10 -Activity $activity -Status 'Building the report' -PercentComplete 80

    $vms = @($hosts | ForEach-Object { $hostItem = $_; $_.VirtualMachines | ForEach-Object { $_ | Add-Member -NotePropertyName HostName -NotePropertyValue $hostItem.Name -PassThru } } |
        Sort-Object -Property Name)
    $volumes = if ($cluster) { @($cluster.Volumes) } else { @($hosts | ForEach-Object { $_.Volumes }) }

    $Body = "### Hyper-V`n"
    if ($cluster) {
        $Body += "- Failover cluster: $($cluster.Name), $($cluster.Nodes.Count) node(s)`n"
    }
    foreach ($node in $downNodes) {
        $Body += "- :warning: Node $($node.Name) is $($node.State) and was not reported`n"
    }
    foreach ($failure in $failures) {
        $Body += "- :x: Collection failed for $(Format-Cell $failure)`n"
    }

    # Host details, like the ESXi hosts of vmwarereport.ps1.
    $Body += "`n### Hyper-V hosts`n"
    foreach ($hostItem in $hosts) {
        $Body += "`n#### $($hostItem.Name)`n"
        $Body += "| Hardware            |                                  |`n"
        $Body += "|---------------------|----------------------------------|`n"
        $Body += "| Manufacturer        | $(Format-Cell $hostItem.Manufacturer) |`n"
        $Body += "| Model               | $(Format-Cell $hostItem.Model) |`n"
        $Body += "| CPU                 | $($hostItem.Cores) cores ( $($hostItem.Sockets) x $(Format-Cell $hostItem.CpuModel) ), $($hostItem.LogicalCpus) logical CPUs |`n"
        $Body += "| Memory              | $([math]::Round($hostItem.MemoryTotal / 1GB)) GB |`n"
        $Body += "`n"
        $Body += "| Configuration    |                                         |`n"
        $Body += "|------------------|-----------------------------------------|`n"
        $Body += "| OS               | $(Format-Cell $hostItem.Os) |`n"
        $Body += "| Live migration   | $($hostItem.MigrationEnabled) |`n"
        $Body += "| Virtual machines | $(@($hostItem.VirtualMachines).Count) |`n"
        $Body += "`n"
        $Body += "| System Information |                                        |`n"
        $Body += "|--------------------|----------------------------------------|`n"
        $Body += "| Service tag        | $(Format-Cell $hostItem.Serial) |`n"
        $Body += "| BIOS version       | $(Format-Cell $hostItem.BiosVersion) |`n"
        $Body += "| Boot time          | $($hostItem.LastBoot) |`n"
    }

    $Body += "`n### Check Host Hyper-V`n"
    $Body += "| Host | CPU Model | Speed | # Cores | CPU usage % | # Memory GB | Memory usage % |`n"
    $Body += "|------|-----------|-------|---------|-------------|-------------|----------------|`n"
    foreach ($hostItem in $hosts) {
        $memoryUsed = $hostItem.MemoryTotal - $hostItem.MemoryFree
        $Body += "| $($hostItem.Name) | $(Format-Cell $hostItem.CpuModel) | $($hostItem.CpuMhz) | $($hostItem.Cores) | $($hostItem.CpuUsage) | $([math]::Round($memoryUsed / 1GB)) | $(Get-Percent $memoryUsed $hostItem.MemoryTotal) |`n"
    }

    # Storage: Cluster Shared Volumes, or the host's volumes; VMs and disks counted by path.
    $storageTitle = if ($cluster) { 'Cluster Shared Volumes' } else { 'Volume Capacity' }
    $Body += "`n### $storageTitle`n"
    $Body += "| Name | # VMs total | Capacity GB | Provisioned GB | In Use GB | Free GB | Free % |`n"
    $Body += "|------|-------------|-------------|----------------|-----------|---------|--------|`n"
    # One graph for all the volumes: a column per volume, a row of free %.
    $volumeGraphL1 = '| Disk % |'
    $volumeGraphL2 = '|--------|'
    $volumeGraphL3 = '| Free   |'
    foreach ($volume in @($volumes | Sort-Object -Property Name)) {
        $prefix = $volume.Path.TrimEnd('\') + '\'
        $volumeDisks = @($vms | ForEach-Object { $vm = $_; $_.Disks | Where-Object { $_.Path -like "$prefix*" } | ForEach-Object { [pscustomobject]@{ VM = $vm.Name; Disk = $_ } } })
        $vmCount = @($volumeDisks | ForEach-Object { $_.VM } | Sort-Object -Unique).Count
        $provisioned = ($volumeDisks | ForEach-Object { $_.Disk.Size } | Measure-Object -Sum).Sum
        $freePercent = Get-Percent $volume.Free $volume.Size
        $Body += "| $(Format-Cell $volume.Name) | $vmCount | $(Get-Gb $volume.Size) | $(Get-Gb $provisioned) | $(Get-Gb ($volume.Size - $volume.Free)) | $(Get-Gb $volume.Free) | $freePercent |`n"

        $volumeGraphL1 += " $(Format-Cell $volume.Name) |"
        $volumeGraphL2 += '------------|'
        $volumeGraphL3 += "  $freePercent        |"
    }
    $Body += "`n"
    if (@($volumes).Count -gt 0) {
        $Body += "``````Volbarstacked`n$volumeGraphL1`n$volumeGraphL2`n$volumeGraphL3`n```````n`n"
    }

    $Body += "`n### Vm Info`n"
    $Body += "| Name | Host | State | CPU | RAM GB | Dynamic memory | Memory demand GB | Memory demand % | Generation | OS |`n"
    $Body += "|------|------|-------|-----|--------|----------------|------------------|-----------------|------------|----|`n"
    foreach ($vm in $vms) {
        $state = if ($vm.State -eq 'Running') { 'ON' } else { $vm.State.ToUpper() }
        # A stopped VM has no memory assigned; its startup memory is what it gets when it starts.
        $memory = if ($vm.MemoryAssigned -gt 0) { $vm.MemoryAssigned } else { $vm.MemoryStartup }
        $Body += "| $(Format-Cell $vm.Name) | $($vm.HostName) | $state | $($vm.Cpu) | $(Get-Gb $memory) | $($vm.DynamicMemory) | $(Get-Gb $vm.MemoryDemand) | $(Get-Percent $vm.MemoryDemand $memory) | $($vm.Generation) | $(Format-Cell $vm.Os) |`n"
    }
    $Body += "`n"
    $Body += "- Memory demand: memory the guest asks for, against the RAM assigned to it`n"
    $Body += "- OS: reported by the integration services, empty when they do not run`n"

    # Hyper-V cannot see the free space inside a guest: the disks show how full each virtual disk file is.
    $date = Get-Date -Format 'dd/MM/yyyy'
    $Body += "`n### Vm Disks $date`n"
    $Body += "| Disk | Type | Size GB | File GB | Free % |`n"
    $Body += "|------|------|---------|---------|--------|`n"
    $graphL1 = '|Disk (%) | '
    $graphL2 = '|--------|'
    $graphL3 = "| $date  |"
    foreach ($vm in $vms) {
        foreach ($disk in @($vm.Disks)) {
            $diskName = "$($vm.Name) $(Split-Path -Path $disk.Path -Leaf)"
            $freePercent = Get-Percent ($disk.Size - $disk.FileSize) $disk.Size
            $Body += "| $(Format-Cell $diskName) | $($disk.Type) | $(Get-Gb $disk.Size) | $(Get-Gb $disk.FileSize) | $freePercent |`n"
            # A fixed disk is always full size, so only dynamic disks can grow.
            if ($disk.Type -eq 'Dynamic') {
                $graphL1 += "$(Format-Cell $diskName)  |"
                $graphL2 += '--------|'
                $graphL3 += "  $freePercent       |"
            }
        }
    }
    $Body += "`n"
    $Body += "- Free %: room left before a dynamic disk reaches its size; a fixed disk always uses its full size`n"
    $Body += "`n``````Volbarstacked`n$graphL1`n$graphL2`n$graphL3`n```````n"

    $checkpoints = @($hosts | ForEach-Object { $_.Checkpoints } | Sort-Object -Property VM, Created)
    $Body += "`n### Checkpoint $date`n"
    if ($checkpoints.Count -eq 0) {
        $Body += "No checkpoint`n"
    }
    else {
        $Body += "| VM | Name | Type | Created | Age (days) |`n"
        $Body += "|----|------|------|---------|------------|`n"
        foreach ($checkpoint in $checkpoints) {
            $age = [math]::Floor(((Get-Date) - [datetime]$checkpoint.Created).TotalDays)
            # An old checkpoint keeps growing and slows the disk down.
            $warning = if ($age -gt 7) { ' :warning:' } else { '' }
            $Body += "| $(Format-Cell $checkpoint.VM) | $(Format-Cell $checkpoint.Name) | $($checkpoint.Type) | $($checkpoint.Created) | $age$warning |`n"
        }
    }

    $replications = @($hosts | ForEach-Object { $_.Replications } | Sort-Object -Property VM)
    if ($replications.Count -gt 0) {
        $Body += "`n### Replica`n"
        $Body += "| VM | Mode | State | Health | Replica server | Last replication |`n"
        $Body += "|----|------|-------|--------|----------------|------------------|`n"
        foreach ($replication in $replications) {
            $health = switch ($replication.Health) {
                'Normal' { ':heavy_check_mark: Normal' }
                'Warning' { ':warning: Warning' }
                'Critical' { ':x: Critical' }
                default { $replication.Health }
            }
            $Body += "| $(Format-Cell $replication.VM) | $($replication.Mode) | $($replication.State) | $health | $(Format-Cell $replication.Replica) | $($replication.LastReplica) |`n"
        }
    }

    Write-Progress -Id 10 -Activity $activity -Status 'Report complete' -PercentComplete 100
    $Body
}
catch {
    $hint = if ($_.Exception.Message -match 'WinRM|TrustedHosts|Kerberos') {
        ' PowerShell remoting must be enabled on the host (Enable-PSRemoting), and an IP address or a computer outside the domain must be in this computer''s TrustedHosts.'
    }
    else {
        ''
    }
    throw "Hyper-V report for $Server failed: $($_.Exception.Message)$hint"
}
finally {
    Write-Progress -Id 10 -Activity $activity -Completed
}
