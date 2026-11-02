[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'Number of days of Commvault backup and restore job history to include.')]
    [ValidateRange(1, 365)]
    [int]$CommvaultJobLookbackDays = 30,

    [Parameter(HelpMessage = 'Preview the report with sample data, without contacting any server.')]
    [switch]$DryRun,

    [Parameter(HelpMessage = 'Also write a debug log: the script line where each failed server stopped, with the call stack.')]
    [switch]$DebugLog,

    [Parameter(HelpMessage = 'Number of servers collected at the same time, each in a PowerShell process of its own (1: one after the other).')]
    [ValidateRange(1, 16)]
    [int]$ThrottleLimit = 4,

    # The modules: iLO, iDRAC, BMC, NAS, StorMagic, VMware, HyperV, Veeam (both Veeam modules), VeeamApi,
    # Commvault (Cloud and on-premises), CommvaultCloud, CommvaultOnPrem, SQL; or a server name or IP
    # address. Tab completes them (the list is the same in Start.ps1).
    [Parameter(HelpMessage = 'Only the servers whose module, module name or server name contains one of these words: iLO, iDRAC, BMC, NAS, StorMagic, VMware, HyperV, Veeam, VeeamApi, Commvault, CommvaultCloud, CommvaultOnPrem, SQL, or a server name or IP address (* and ? also work).')]
    [ArgumentCompleter({
            param($commandName, $parameterName, $wordToComplete)
            'iLO', 'iDRAC', 'BMC', 'NAS', 'StorMagic', 'VMware', 'HyperV', 'Veeam', 'VeeamApi', 'Commvault', 'CommvaultCloud', 'CommvaultOnPrem', 'SQL' |
                Where-Object { $_ -like "$wordToComplete*" }
        })]
    [string[]]$Only,

    [Parameter(HelpMessage = 'Pick the servers of the report from the list of configured servers.')]
    [switch]$Choose,

    # Set by Configure.ps1 to preview a configuration it has not saved yet.
    [Parameter(DontShow)]
    [object]$Config,

    [switch]$NoOpen
)

# Builds the report of the client configured on this computer (see Configure.ps1):
# runs every module on its servers and writes <Client>_Report_<yyyy-MM-dd>.md,
# with the section order, titles and groups of the client's report layout. Each server's module
# runs in a PowerShell process of its own, up to -ThrottleLimit (4) at once.
# -DryRun writes <Client>_Report_<yyyy-MM-dd>_sample.md with sample data instead, to see the
# layout quickly: no server, API or saved login is used.
# -Only veeam,sql or -Choose make a partial report of some servers, written to
# <Client>_Report_<yyyy-MM-dd>_part-veeam-sql.md (or _part.md) so the full report stays as it was.
# -DebugLog also writes <Client>_Debug_<yyyy-MM-dd_HHmmss>.log: for each server how long it took and
# its warnings and, when it failed, the error, the script line where it stopped and the call stack,
# then a summary. It contains the client's server names and addresses, so git ignores it like the report.

$ErrorActionPreference = 'Stop'
# Start.ps1 hides progress bars to download faster; the modules show theirs.
$ProgressPreference = 'Continue'
. (Join-Path $PSScriptRoot 'helper.ps1')

# Servers of a dry run on a computer with no client yet: one per module, at documentation addresses.
function Get-SampleConfig {
    $number = 10
    $sampleTargets = foreach ($module in $MoseModules.Keys) {
        $number++
        $target = [pscustomobject]@{ Module = $module; Server = "192.0.2.$number"; Secret = '' }
        if ($module -like 'Commvault*') {
            $target.Server = ''
            $target.Secret = "MOSE:${module}:1"
        }
        if ($module -in 'VMware', 'HyperV') {
            $target | Add-Member -NotePropertyName Site -NotePropertyValue 'main'
        }
        $target
    }
    return [pscustomobject]@{ Client = 'Sample client'; Targets = @($sampleTargets); Layout = $null }
}

if ($Config) {
    $config = $Config
}
else {
    Open-MoseVault
    $config = Get-MoseConfig
    if (-not $config -and $DryRun) {
        Write-Host "This computer has no client configuration yet: the sample report uses one server per module." -ForegroundColor Yellow
        $config = Get-SampleConfig
    }
    elseif (-not $config) {
        Write-Host "This computer has no client configuration yet." -ForegroundColor Yellow
        & (Join-Path $PSScriptRoot 'Configure.ps1') -VaultUnlocked
        $config = Get-MoseConfig
        if (-not $config) {
            throw "No client configuration was saved, so there is nothing to report. Run .\Start.ps1 -Configure."
        }
    }
}
if ($DryRun -and @($config.Targets | Where-Object { $_ }).Count -eq 0) {
    Write-Host "No server is configured yet: the sample report uses one server per module." -ForegroundColor Yellow
    $config = [pscustomobject]@{ Client = $config.Client; Targets = (Get-SampleConfig).Targets; Layout = Get-MoseProperty $config 'Layout' }
}
if (-not $DryRun) {
    # Also lists the modules of a configuration saved before Start.ps1 downloaded only those.
    Save-MoseModuleList -Targets @($config.Targets)
}

function Get-TargetCredential {
    param(
        [object]$Target
    )

    $credential = Get-Secret -Vault $MoseVaultName -Name $Target.Secret
    if ($credential -isnot [pscredential]) {
        throw "Secret '$($Target.Secret)' is not a saved login. Run .\Start.ps1 -Configure and add this server again."
    }
    return $credential
}

# Each server's module runs in a PowerShell process of its own (a background job): what a module
# changes for its whole process, like the certificate check or the TLS versions, cannot break the
# others, and several servers run at once (-ThrottleLimit). A run is one server: its job, how much
# of what the job wrote was shown, and the result.
function New-TargetRun {
    param(
        [object]$Section,
        [string]$Title,
        [int]$Index
    )

    [pscustomobject]@{
        Section       = $Section
        Target        = $Section.Target
        Title         = $Title
        # Progress bar Ids of its own, so the bars of servers running at once don't mix.
        ProgressBase  = 10000 * ($Index + 1)
        Job           = $null
        Timer         = $null
        Started       = $null
        LastBarUpdate = [datetime]::MinValue
        Read          = @{ Output = 0; Warning = 0; Information = 0; Progress = 0; Error = 0 }
        Activities    = @{}
        Output        = New-Object System.Collections.Generic.List[object]
        Log           = New-Object System.Collections.Generic.List[string]
        Lines         = @()
        Inventory     = @()
        Error         = $null
        Status        = ''
        Elapsed       = ''
        Where         = ''
    }
}

# Starts the module of one server in its own process. Logins are read here, where the vault is
# open; Commvault reads and saves its tokens itself, with the vault password asked at the start.
function Start-TargetRun {
    param(
        [object]$Run
    )

    $Run.Started = Get-Date
    $Run.Timer = [System.Diagnostics.Stopwatch]::StartNew()
    $Run.LastBarUpdate = [datetime]::MinValue
    foreach ($stream in @($Run.Read.Keys)) {
        $Run.Read[$stream] = 0
    }
    $Run.Activities.Clear()
    $Run.Output.Clear()
    $Run.Log.Clear()
    $Run.Lines = @()
    $Run.Inventory = @()
    $Run.Error = $null
    Write-Host "Collecting $($Run.Title)..." -ForegroundColor DarkGray

    $target = $Run.Target
    try {
        $credential = $null
        $vaultPassword = $null
        if ($target.Module -like 'Commvault*') {
            # Kept by Open-MoseVault.
            $vaultPassword = Get-Variable -Name MoseVaultPassword -ValueOnly -ErrorAction SilentlyContinue
        }
        elseif ($target.Module -notin 'Veeam', 'HyperV', 'SqlMaint' -or (Get-MoseProperty $target 'Secret')) {
            $credential = Get-TargetCredential $target
        }
        # With -DebugLog, what the server answered goes next to the debug log, for the modules that can write it.
        $dumpPath = ''
        if ($debugLogPath) {
            $dumpPath = $debugLogPath -replace '\.log$', "_$($target.Module)_$((Get-MoseTargetName $target) -replace '[\\/:*?"<>|\s]', '_').log"
        }
        $Run.Job = Start-TargetJob -Target $target -Credential $credential -VaultPassword $vaultPassword -DebugDumpPath $dumpPath
    }
    catch {
        $Run.Error = $_
    }
}

function Start-TargetJob {
    param(
        [object]$Target,
        [pscredential]$Credential,
        [securestring]$VaultPassword,
        [string]$DebugDumpPath
    )

    Start-Job -ArgumentList $PSScriptRoot, $Target, $Credential, $config.Client, $CommvaultJobLookbackDays, $VaultPassword, $DebugDumpPath -ScriptBlock {
        param([string]$Folder, [object]$Target, [pscredential]$Credential, [string]$Client, [int]$CommvaultJobLookbackDays, [securestring]$VaultPassword, [string]$DebugDumpPath)

        $ErrorActionPreference = 'Stop'
        # As Start.ps1 does: TLS 1.2 added to the versions allowed, unless Windows chooses them.
        if ([int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
        # The module scripts expect to run from their own folder.
        Set-Location -LiteralPath $Folder
        . (Join-Path $Folder 'helper.ps1')
        try {
            if ($VaultPassword) {
                Open-MoseVault -Password $VaultPassword
            }
            $moduleParameters = @{ Target = $Target; Client = $Client; CommvaultJobLookbackDays = $CommvaultJobLookbackDays }
            if ($Credential) {
                $moduleParameters.Credential = $Credential
            }
            if ($DebugDumpPath) {
                $moduleParameters.DebugDumpPath = $DebugDumpPath
            }
            # The Markdown lines, and what the module found for the inventory tables (MoseInventory objects).
            Invoke-MoseModule @moduleParameters | Where-Object { $_ -is [string] -or ($null -ne $_ -and $_.PSObject.Properties['MoseInventory']) }
        }
        catch {
            ConvertTo-MoseFailure $_
        }
    }
}

# Shows what the module of a running server wrote since the last look: its Write-Host lines,
# warnings and errors with the server's name in front, and its progress bars under one bar for the
# server. Its warnings and errors also wait in $Run.Log for the debug log.
function Receive-TargetRun {
    param(
        [object]$Run
    )

    $child = $Run.Job.ChildJobs[0]
    $prefix = "[$($Run.Title)]"
    if (((Get-Date) - $Run.LastBarUpdate).TotalSeconds -ge 1) {
        Write-Progress -Id $Run.ProgressBase -Activity $Run.Title -Status "Running for $($Run.Timer.Elapsed.ToString('m\:ss'))"
        $Run.LastBarUpdate = Get-Date
    }

    for ($i = $Run.Read.Output; $i -lt $child.Output.Count; $i++) {
        $Run.Output.Add($child.Output[$i])
    }
    $Run.Read.Output = $i

    for ($i = $Run.Read.Warning; $i -lt $child.Warning.Count; $i++) {
        $message = $child.Warning[$i].Message
        Write-Warning "$prefix $message"
        $Run.Log.Add("  WARNING: $message")
    }
    $Run.Read.Warning = $i

    for ($i = $Run.Read.Information; $i -lt $child.Information.Count; $i++) {
        # Write-Host lines, with their colours, each on a line of its own.
        $data = $child.Information[$i].MessageData
        $hostParameters = @{ Object = "$prefix $data" }
        if ($null -ne $data -and $data.PSObject.Properties['Message'] -and $data.PSObject.Properties['NoNewLine']) {
            $hostParameters.Object = "$prefix $($data.Message)"
            if ("$($data.ForegroundColor)") {
                $hostParameters.ForegroundColor = "$($data.ForegroundColor)"
            }
            if ("$($data.BackgroundColor)") {
                $hostParameters.BackgroundColor = "$($data.BackgroundColor)"
            }
        }
        Write-Host @hostParameters
    }
    $Run.Read.Information = $i

    for ($i = $Run.Read.Progress; $i -lt $child.Progress.Count; $i++) {
        $record = $child.Progress[$i]
        $id = $Run.ProgressBase + 1 + $record.ActivityId
        $parentId = $Run.ProgressBase
        if ($record.ParentActivityId -ge 0) {
            $parentId = $Run.ProgressBase + 1 + $record.ParentActivityId
        }
        if ("$($record.RecordType)" -eq 'Completed') {
            $Run.Activities.Remove($id)
            Write-Progress -Id $id -ParentId $parentId -Activity $record.Activity -Completed
            continue
        }
        $Run.Activities[$id] = $record.Activity
        $progressParameters = @{
            Id              = $id
            ParentId        = $parentId
            Activity        = $record.Activity
            Status          = if ($record.StatusDescription) { $record.StatusDescription } else { 'Processing' }
            PercentComplete = $record.PercentComplete
        }
        if ($record.CurrentOperation) {
            $progressParameters.CurrentOperation = $record.CurrentOperation
        }
        Write-Progress @progressParameters
    }
    $Run.Read.Progress = $i

    for ($i = $Run.Read.Error; $i -lt $child.Error.Count; $i++) {
        # Errors a module wrote without stopping.
        $message = "$($child.Error[$i])"
        Write-Host "$prefix ERROR: $message" -ForegroundColor Red
        $Run.Log.Add("  ERROR: $message")
    }
    $Run.Read.Error = $i
}

# After the module of a server ended: what it wrote last, its result (the Markdown, or the error
# with where it happened), the line saying how it went, and its block in the debug log.
function Complete-TargetRun {
    param(
        [object]$Run
    )

    if ($Run.Job) {
        Receive-TargetRun $Run
        $state = $Run.Job.State
        $reason = $Run.Job.ChildJobs[0].JobStateInfo.Reason
        foreach ($id in @($Run.Activities.Keys)) {
            Write-Progress -Id $id -Activity $Run.Activities[$id] -Completed
        }
        $Run.Activities.Clear()
        Write-Progress -Id $Run.ProgressBase -Activity $Run.Title -Completed
        Remove-Job -Job $Run.Job -Force
        $Run.Job = $null

        try {
            if ($state -eq 'Failed') {
                throw "The PowerShell process of the module failed: $($reason.Message)"
            }
            $failure = @($Run.Output | Where-Object { $_.PSObject.Properties['MoseFailure'] }) | Select-Object -First 1
            if ($failure) {
                $exception = [System.Exception]::new($failure.Message)
                $exception.Data['MoseLocation'] = $failure.Location
                $exception.Data['MoseDetail'] = @($failure.Detail)
                $exception.Data['RemotingAccessDenied'] = [bool]$failure.RemotingAccessDenied
                $exception.Data['LoginRefused'] = [bool]$failure.LoginRefused
                $exception.Data['UntrustedCertificate'] = "$($failure.UntrustedCertificate)"
                $exception.Data['CertificateSubject'] = "$($failure.CertificateSubject)"
                throw $exception
            }
            $Run.Lines = @($Run.Output | Where-Object { $_ -is [string] })
            $Run.Inventory = @($Run.Output | Where-Object { $_ -isnot [string] -and $_.PSObject.Properties['MoseInventory'] })
        }
        catch {
            $Run.Error = $_
        }
    }

    $Run.Elapsed = $Run.Timer.Elapsed.ToString('m\:ss')
    $Run.Where = ''
    if ($Run.Error) {
        $Run.Status = 'FAILED'
        $location = $Run.Error.Exception.Data['MoseLocation']
        if (-not $location) {
            $location = Get-MoseErrorLocation $Run.Error
        }
        if ($location) {
            $Run.Where = " ($location)"
        }
        Write-Warning "$($Run.Title) collection failed: $($Run.Error.Exception.Message)$($Run.Where)"
    }
    else {
        $Run.Status = 'OK'
        Write-Host "$($Run.Title) done in $($Run.Elapsed)." -ForegroundColor DarkGray
    }

    if ($DebugLog) {
        # One block per server, though several ran at once.
        Write-DebugLog "[$($Run.Started.ToString('HH:mm:ss'))] $($Run.Title)"
        if ($Run.Log.Count -gt 0) {
            Write-DebugLog $Run.Log.ToArray()
        }
        if ($Run.Error) {
            Write-DebugLog "  FAILED: $($Run.Error.Exception.Message)$($Run.Where)"
            Write-ErrorDetail $Run.Error
        }
        Write-DebugLog "  $($Run.Status) in $($Run.Elapsed)"
    }
}

# Runs the modules of the servers, at most $ThrottleLimit at once, starting them in report order.
function Invoke-TargetRuns {
    param(
        [object[]]$Runs
    )

    $waiting = New-Object 'System.Collections.Generic.Queue[object]'
    foreach ($run in $Runs) {
        $waiting.Enqueue($run)
    }
    $running = New-Object System.Collections.Generic.List[object]
    try {
        while ($waiting.Count -gt 0 -or $running.Count -gt 0) {
            while ($waiting.Count -gt 0 -and $running.Count -lt $ThrottleLimit) {
                $run = $waiting.Dequeue()
                Start-TargetRun $run
                if ($run.Job) {
                    $running.Add($run)
                }
                else {
                    Complete-TargetRun $run
                }
            }

            $index = 0
            while ($index -lt $running.Count) {
                $run = $running[$index]
                if ($run.Job.State -in 'NotStarted', 'Running') {
                    Receive-TargetRun $run
                    $index++
                }
                else {
                    Complete-TargetRun $run
                    $running.RemoveAt($index)
                }
            }
            if ($running.Count -gt 0) {
                Start-Sleep -Milliseconds 200
            }
        }
    }
    finally {
        # Stopped with Ctrl+C: no module keeps running in the background.
        foreach ($run in $running) {
            if ($run.Job) {
                Remove-Job -Job $run.Job -Force -ErrorAction SilentlyContinue
                Write-Progress -Id $run.ProgressBase -Activity $run.Title -Completed
            }
        }
    }
}

# The servers of the report, in its order and without the hidden sections, as Add-ReportSection
# writes them.
function Get-TargetSections {
    param(
        [object[]]$Sections
    )

    foreach ($section in $Sections) {
        if (-not (Test-ReportSectionShown $section)) {
            continue
        }
        if ($section.Children.Count -gt 0) {
            Get-TargetSections -Sections $section.Children
        }
        if ($section.Target) {
            $section
        }
    }
}

# Sample Markdown of a module for -DryRun, with the headings and tables the module writes,
# so the preview nests the same way as the real report.
function Get-SampleMarkdown {
    param(
        [object]$Target
    )

    $server = Get-MoseTargetName $Target
    switch ($Target.Module) {
        'iLO' {
            @"
- General Health status : OK

| Information               |                                          |
|---------------------------|------------------------------------------|
| Server Name               | SAMPLE-HOST-01                           |
| Product Name              | ProLiant DL380 Gen10                     |
| Server Serial Number      | CZ0000SAMPLE                             |
| iLO Firmware Version      | 2.81 (Jan 01 2026)                       |
| IPv4 Address              | $server                                  |

| Subsystems and Devices    | Status |
|---------------------------|--------|
| Power Supplies            | OK     |
| Fans                      | OK     |
| Memory                    | OK     |

#### Check Controlers Status
| controler ID | PartNumber | Brand | Model | Health | FirmwareVersion |
|-----------|-------|-------|---------------|--------|--------|
| 0 | 000000-B21 | HPE | Smart Array P408i-a | OK | 3.00 |

#### Check Disks  Status
| Disk Slot | Brand| Model |SerialNumber | MediaType| Capacity (GB) | Health |
|-----------|-------|-------|---------|------|------|--------|
| 1I:1:1 | HPE | EG000600JWJNP | SAMPLE01 | HDD | 600 | OK |
| 1I:1:2 | HPE | EG000600JWJNP | SAMPLE02 | HDD | 600 | OK |

#### Check Volumes  Status
| Name | Volume Raid type | Capacity (GB) | Health |
|-----------|-------------|---------------|--------|
| Logical Drive 1 | RAID1 | 558 | OK |
"@
        }
        { $_ -in 'iDRAC', 'BMC' } {
            @"
### Hardware status ($server)
- General Health status : OK

| Information               |                                          |
|---------------------------|------------------------------------------|
| Server Name               | SAMPLE-HOST-02                           |
| Product Name              | Sample server model                      |
| Server Serial Number      | SAMPLE000                                |
| IPv4 Address              | $server                                  |

| Subsystems and Devices    | Status |
|---------------------------|--------|
| Power Supplies            | OK     |
| Fans                      | OK     |
| Storage Controllers       | OK     |
"@
        }
        'NAS' {
            @"
#### Check NAS Synology DS920+ ( $server - SN: SAMPLE000) :
| disk | status | model | size_total | SMART status |
|------|--------|-------|------------|--------------|
| Drive 1 | normal | ST4000VN006 | 4 TB | normal |
| Drive 2 | normal | ST4000VN006 | 4 TB | normal |

- :white_check_mark: All disk normal!
- NAS version : DSM 7.2.2

| volume | status | Available | Used |
|--------|--------|-----------|------|
| volume_1 | normal | 2.4 TB | 1.2 TB |

``````NasVolume
| Volume (in TB) | free | used |
|----------------|------|------|
| volume_1       | 2.4 | 1.2 |
``````
"@
        }
        'StorMagic' {
            @"
## Check Stormagic
### System
#### Licences Info
- License Key: SAMPLE-0000
- Status: Valid
#### System Info
- hostname: sample-vsa-01
- version: 6.3
#### Targets
| Name | State | Size (Tb) | Sessions |
|------|-------|-----------|----------|
| sample-target-01 | Synchronized | 2 | 2 |
"@
        }
        'VMware' {
            @"
### VMware

### ESXi hosts

#### esx-01.sample.local
| Hardware            |                                 |
|---------------------|---------------------------------|
| Manufacturer        | Sample vendor                   |
| Memory              | 256  GB                         |
| Overall  Status     | green                           |

| Configuration    |                                         |
|------------------|-----------------------------------------|
| ESX Version      | 8.0.3 - 24022510                        |
| vMotion          | True                                    |
### Check Host Esx
| Host | CPU Model | Speed | # Cores | CPU usage % | # Memory GB | Memory usage % |
|------|-----------|-------|---------|-------------|-------------|----------------|
| esx-01.sample.local | Intel Xeon Gold 6230 | 2100 | 40 | 23 | 256 | 61 |
### Datastore Capacity
| Name | # VMs total | Capacity MiB | Provisioned GB | In Use MiB | Free MiB | Free % |
|------|-------------|--------------|----------------|------------|----------|--------|
| datastore1 | 12 | 3814400 | 2900 | 2500000 | 1314400 | 34 |
| datastore2 | 5 | 1907200 | 1100 | 1430400 | 476800 | 25 |

``````Volbarstacked
| Disk % | datastore1 | datastore2 |
|--------|------------|------------|
| Free   |  34        |  25        |
``````
### Vm Info
| Name | Power state | CPU | RAM GB | Provisioned RAM GB | Consumed RAM  MiB | Consumed RAM  % | OS |
|------|-------------|-----|--------|--------------------|-------------------|-----------------|----|
| SAMPLE-VM-01 | :green_circle: | 4 | 16384 | 16 | 9 | 56 | Microsoft Windows Server 2022 |
| SAMPLE-VM-02 | :green_circle: | 2 | 8192 | 8 | 3 | 38 | Ubuntu Linux (64-bit) |

- (1) guest Memory usage
- (2) Esxi Memory usage
### Vm Storage $(Get-Date -Format 'dd/MM/yyyy')
| Disk | Capacity GB | Free GB | Free % |
|------|-------------|---------|--------|
| SAMPLE-VM-01 C:\ | 100 | 38 | 38 |
| SAMPLE-VM-02 / | 50 | 31 | 62 |

``````Volbarstacked
|Disk (%) | SAMPLE-VM-01 C:\  |SAMPLE-VM-02 /  |
|--------|--------|--------|
| $(Get-Date -Format 'dd/MM/yyyy')  |  38       |  62       |
``````
### Snapshot
| VM | Name | Created | Size GB |
|----|------|---------|---------|
| SAMPLE-VM-01 | before-update | 2026-01-01 | 4 |
"@
        }
        'HyperV' {
            $date = Get-Date -Format 'dd/MM/yyyy'
            @"
### Hyper-V
- Failover cluster: sample-cluster, 2 node(s)

### Hyper-V hosts

#### HV-NODE-01
| Hardware            |                                  |
|---------------------|----------------------------------|
| Manufacturer        | Sample vendor |
| Model               | Sample server model |
| CPU                 | 32 cores ( 2 x Intel Xeon Gold 6338 ), 64 logical CPUs |
| Memory              | 512 GB |

| Configuration    |                                         |
|------------------|-----------------------------------------|
| OS               | Microsoft Windows Server 2022 Datacenter (20348) |
| Live migration   | True |
| Virtual machines | 2 |

#### HV-NODE-02
| Hardware            |                                  |
|---------------------|----------------------------------|
| Manufacturer        | Sample vendor |
| Model               | Sample server model |
| CPU                 | 32 cores ( 2 x Intel Xeon Gold 6338 ), 64 logical CPUs |
| Memory              | 512 GB |

### Check Host Hyper-V
| Host | CPU Model | Speed | # Cores | CPU usage % | # Memory GB | Memory usage % |
|------|-----------|-------|---------|-------------|-------------|----------------|
| HV-NODE-01 | Intel Xeon Gold 6338 | 2000 | 32 | 18 | 301 | 59 |
| HV-NODE-02 | Intel Xeon Gold 6338 | 2000 | 32 | 12 | 188 | 37 |

### Cluster Shared Volumes
| Name | # VMs total | Capacity GB | Provisioned GB | In Use GB | Free GB | Free % |
|------|-------------|-------------|----------------|-----------|---------|--------|
| Cluster Disk 1 | 2 | 4096 | 1100 | 2700 | 1396 | 34 |

``````Volbarstacked
| Disk % | Cluster Disk 1 |
|--------|------------|
| Free   |  34        |
``````

### Vm Info
| Name | Host | State | CPU | RAM GB | Dynamic memory | Memory demand GB | Memory demand % | Generation | OS |
|------|------|-------|-----|--------|----------------|------------------|-----------------|------------|----|
| SAMPLE-VM-01 | HV-NODE-01 | ON | 4 | 16 | False | 9.2 | 58 | 2 | Windows Server 2022 Standard |
| SAMPLE-VM-02 | HV-NODE-02 | ON | 2 | 6.1 | True | 5.4 | 89 | 2 | Ubuntu 22.04 LTS |

- Memory demand: memory the guest asks for, against the RAM assigned to it
- OS: reported by the integration services, empty when they do not run

### Vm Disks $date
| Disk | Type | Size GB | File GB | Free % |
|------|------|---------|---------|--------|
| SAMPLE-VM-01 SAMPLE-VM-01.vhdx | Dynamic | 127 | 61.4 | 52 |
| SAMPLE-VM-02 SAMPLE-VM-02.vhdx | Dynamic | 64 | 22.8 | 64 |

- Free %: room left before a dynamic disk reaches its size; a fixed disk always uses its full size

``````Volbarstacked
|Disk (%) | SAMPLE-VM-01 SAMPLE-VM-01.vhdx  |SAMPLE-VM-02 SAMPLE-VM-02.vhdx  |
|--------|--------|--------|
| $date  |  52       |  64       |
``````

### Checkpoint $date
| VM | Name | Type | Created | Age (days) |
|----|------|------|---------|------------|
| SAMPLE-VM-01 | Before update | Production | $((Get-Date).AddDays(-12)) | 12 :warning: |

### Replica
| VM | Mode | State | Health | Replica server | Last replication |
|----|------|-------|--------|----------------|------------------|
| SAMPLE-VM-01 | Primary | Replicating | :white_check_mark: Normal | hv-dr-01.sample.local | $((Get-Date).AddMinutes(-5)) |
"@
        }
        { $_ -in 'Veeam', 'VeeamApi' } {
            @"
## Check Backup Veeam VM's:
- Veeam version: 12.3
- :white_check_mark: Veeam license expires in 200 days (2027-05-20)

### Backup jobs

#### Daily backup (sample)
|$(Get-Date -Format 'dd/MM/yyyy') 22:00:10||||||Success|2 of 2 VMs processed |
|---|---|---|-----|---|----|----|----|
|Success|2| Start time |22:00:10| Total   size |1,2 TB |Backup size |420 GB|
|Warning|0| End time   |22:41:03| Data   read  |700 GB |Dedupe      |1,8x|
|Error|0| Duration     |00:40:53| Transferred  |362 GB |Compression |1,9x|

##### Details
| Name | Status | Start time | End time | Size | Read | Transferred | Duration |
|------|--------|------------|----------|------|------|-------------|----------|
| SAMPLE-VM-01 | Success | 22:00:10 | 22:41:03 | 600 GB | 349,8 GB | 181 GB | 00:40:53 |
| SAMPLE-VM-02 | Success | 22:00:12 | 22:35:40 | 600 GB | 350,2 GB | 181 GB | 00:35:28 |

### Check Backup Copy

#### Offsite copy (sample)
| Result |  |
|----|----|
| Status |  Success :white_check_mark: |
| Start | $(Get-Date -Format 'dd/MM/yyyy') 23:00:00 |
| Duration |  00:12:30 |

##### Details
| Name | Last Copy   | copy health | Number of RP |
|------|-------------|-------------|--------------|
| SAMPLE-VM-01 | $(Get-Date -Format 'dd/MM/yyyy') 23:12:30 | :white_check_mark: Ok | 7 |

### SureBackup verification

#### Weekly verification (sample)

| Last run | Result | State | Duration |
|---|---|---|---|
| $(Get-Date -Format 'dd/MM/yyyy') 06:00:00 | Success | Stopped | 00:25:00 |

##### VM verification details
| VM | Status |
|---|---|
| SAMPLE-VM-01 | Success |
"@
            # The REST API module also shows the repositories.
            if ($Target.Module -eq 'VeeamApi') {
                @"

### Repositories
| Name | Type | Host | Path | Capacity | Free | Used | Free space |
|------|------|------|------|----------|------|------|------------|
| Default Backup Repository | WinLocal | veeam-01.sample.local | D:\Backup | 4,00 TB | 1,60 TB | 2,40 TB | 40 % :white_check_mark: |
"@
            }
        }
        { $_ -in 'CommvaultCloud', 'CommvaultOnPrem' } {
            # Same job status table as New-JobStatusTable, over the last 7 days.
            $english = [cultureinfo]::GetCultureInfo('en-US')
            $days = @(6..0 | ForEach-Object { (Get-Date).Date.AddDays(-$_).ToString('ddd MMM d', $english) })
            $sampleJobTable = @(
                "| Job Status | $($days -join ' | ') |"
                "|---|$((@($days | ForEach-Object { '---:' })) -join '|')|"
                '| Completed | 5 | 5 | 5 | 5 | 5 | 4 | 2 |'
                '| Completed with Errors or Warnings | 0 | 0 | 0 | 0 | 0 | 0 | 0 |'
                '| Failed | 0 | 0 | 1 | 0 | 0 | 0 | 0 |'
                '| Killed | 0 | 0 | 0 | 0 | 0 | 0 | 0 |'
                '| Committed | 0 | 0 | 0 | 0 | 0 | 0 | 0 |'
            ) -join "`r`n"
            @"
# Commvault Health Report - $server - sample

## License and Subscription Usage

### Microsoft 365 licenses

| License | Used | Purchased |
|---|---:|---:|
| Users | 42 | 50 |

## Protected Item Health and SLA

SLA period: 1 day. 23 of 25 protected items met the SLA, 2 missed.

``````SLA
| Protected items within the SLA | Met | Missed |
|---|---|---|
| All protected items | 23 | 2 |
| File System | 9 | 2 |
| Virtual Server | 14 | 0 |
``````

| Client | Workload | Protected item | SLA status | Last completed backup |
|---|---|---|---|---|
| sample-client | File System | default | Met | 2026-01-01 22:00 |
| sample-client | File System | data | Missed (last backup 3.2 days ago) | 2025-12-29 22:00 |

## Job History

### Last 7 Days Summary

Jobs are counted on the day they started; today is partial.

``````CommVaultJob
$sampleJobTable
``````

$sampleJobTable
| Total | 5 | 5 | 6 | 5 | 5 | 4 | 2 |
| Success Rate (%) | 100 | 100 | 83.3 | 100 | 100 | 100 | 100 |

### Last 30 days Overview

- Data protected: 1.2 TB

#### Summary per Protected Item

| Client | Protected item | Jobs | Successful | Failed | Success rate |
|---|---|---:|---:|---:|---:|
| sample-client | default | 30 | 30 | 0 | 100% |

#### Jobs Not Completed Successfully

| Job ID | Client | Status | Reason |
|---:|---|---|---|
| All jobs in this period completed successfully. | | | |
"@
        }
        'SqlMaint' {
            $today = (Get-Date).ToString('dd/MM/yyyy')
            $yesterday = (Get-Date).AddDays(-1).ToString('dd/MM/yyyy')
            @"
## Maintenance plan - 16 Days:
| Date       | Severity | Plan Name |
|------------|----------|-----------|
| $today | Success :white_check_mark: | Daily maintenance (sample) |
| $today | Success :white_check_mark: | Weekly maintenance (sample) |
| $yesterday | error :x: | Daily maintenance (sample) - Reorganize Index 4hr |
"@
        }
        default {
            "_No sample data for module '$($Target.Module)'._"
        }
    }
}

# Sample of what a module gives the inventory tables for -DryRun, as its modules write it.
function Get-SampleInventory {
    param(
        [object]$Target
    )

    $server = Get-MoseTargetName $Target
    switch ($Target.Module) {
        'VMware' {
            foreach ($vm in @(
                    @('SAMPLE-VM-01', 'Production (sample)', 'Windows 2022'),
                    @('SAMPLE-VM-02', 'Production (sample)', 'CentOS 9'),
                    @('SAMPLE-VM-01_AC', 'Acceptance (sample)', 'Windows 2019'))) {
                [pscustomobject]@{ MoseInventory = 'VM'; Name = $vm[0]; Folder = $vm[1]; Os = $vm[2]; Server = $server }
            }
        }
        { $_ -in 'Veeam', 'VeeamApi' } {
            [pscustomobject]@{ MoseInventory = 'Software'; Name = 'Veeam'; Version = '12.3'; Purpose = 'Backup and restore'; Server = $server }
        }
        'SqlMaint' {
            [pscustomobject]@{ MoseInventory = 'Software'; Name = 'msSQL'; Version = '2019 CU20 (15.0.4298.1)'; Purpose = 'SQL database (with Always On)'; Server = $server }
        }
    }
}

# Moves the headings of a module under its server heading, however deep the server is in the
# sections: the heading levels the module uses, in order, become $TopLevel, $TopLevel + 1...
# whatever level each module starts at. With -DropTitle, a first line that is a heading only
# repeats the server title and is removed.
function Set-MarkdownHeadingLevel {
    param(
        [string]$Markdown,
        [int]$TopLevel,
        [switch]$DropTitle
    )

    $lines = [System.Collections.Generic.List[string]]($Markdown.Trim() -split '\r?\n')
    if ($DropTitle -and $lines[0] -match '^#{1,6}\s') {
        $lines.RemoveAt(0)
    }

    $headings = @()
    $fence = $null
    for ($i = 0; $i -lt $lines.Count; $i++) {
        # A # line inside a code block is not a heading.
        if ($lines[$i] -match '^\s{0,3}(`{3,}|~{3,})') {
            if (-not $fence) {
                $fence = $matches[1][0]
            }
            elseif ($matches[1][0] -eq $fence) {
                $fence = $null
            }
            continue
        }
        if (-not $fence -and $lines[$i] -match '^(#{1,6})\s+(.*?)\s*$') {
            $headings += [pscustomobject]@{ Index = $i; Level = $matches[1].Length; Text = $matches[2] }
        }
    }

    $levels = @($headings | ForEach-Object Level | Sort-Object -Unique)
    $headingIndexes = @{}
    # A heading goes at most one level below the one before it: Markdown has no gaps (### then #####).
    $previousLevel = $TopLevel - 1
    foreach ($heading in $headings) {
        $level = [Math]::Min($TopLevel + [array]::IndexOf($levels, $heading.Level), $previousLevel + 1)
        $lines[$heading.Index] = Format-MoseHeading -Level $level -Text $heading.Text
        $headingIndexes[$heading.Index] = $true
        $previousLevel = $level
    }
    return Add-MarkdownSpacing -Lines $lines -HeadingIndexes $headingIndexes
}

# Number of cells in a Markdown table row.
function Get-MarkdownCellCount {
    param(
        [string]$Row
    )

    $cells = $Row.Trim() -replace '^\|', '' -replace '\|$', ''
    return @($cells -split '\|').Count
}

# Markdown needs a blank line around a heading, a table, a --- rule and a ``` block, or it shows
# them as plain text (and turns text followed by --- into a heading); the modules often leave none.
# Adds them, keeps one blank line where there were several, gives a table's |---| row as many
# columns as its header (a table is not shown otherwise), and leaves the inside of ``` blocks
# (the graphs) as written.
function Add-MarkdownSpacing {
    param(
        [System.Collections.Generic.List[string]]$Lines,
        [hashtable]$HeadingIndexes
    )

    $result = New-Object System.Collections.Generic.List[string]
    $previous = 'blank'
    $fence = $null
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]
        if ($fence) {
            $result.Add($line)
            if ($line -match '^\s{0,3}(`{3,}|~{3,})\s*$' -and $matches[1][0] -eq $fence) {
                $fence = $null
                $previous = 'fence'
            }
            continue
        }

        if ($line -match '^\s{0,3}(`{3,}|~{3,})') {
            $kind = 'fence'
            $fence = $matches[1][0]
        }
        elseif (-not $line.Trim()) {
            $kind = 'blank'
        }
        elseif ($HeadingIndexes.ContainsKey($i)) {
            $kind = 'heading'
        }
        elseif ($line -match '^\s*\|') {
            $kind = 'table'
            $next = $i + 1
            if ($previous -ne 'table' -and $next -lt $Lines.Count -and $Lines[$next] -match '^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$') {
                $columns = Get-MarkdownCellCount $line
                if ((Get-MarkdownCellCount $Lines[$next]) -ne $columns) {
                    $Lines[$next] = '|' + ((@(1..$columns | ForEach-Object { '---' })) -join '|') + '|'
                }
            }
        }
        elseif ($line -match '^\s{0,3}(-{3,}|\*{3,}|_{3,})\s*$') {
            $kind = 'rule'
        }
        else {
            $kind = 'text'
        }

        if ($kind -eq 'blank') {
            if ($previous -ne 'blank') {
                $result.Add('')
                $previous = 'blank'
            }
            continue
        }
        $separate = $kind -in 'heading', 'fence', 'rule' -or $previous -in 'heading', 'fence', 'rule' -or
            (($kind -eq 'table') -ne ($previous -eq 'table'))
        if ($previous -ne 'blank' -and $separate) {
            $result.Add('')
        }
        $result.Add($line)
        $previous = $kind
    }
    return ($result -join [Environment]::NewLine).Trim()
}

# A group is shown when it has text or the inventory tables, or when one of its sections is shown.
function Test-ReportSectionShown {
    param(
        [object]$Section
    )

    if ($Section.Hide) {
        return $false
    }
    if ($Section.Target -or $Section.Text -or ($Section.Inventory -and $inventoryMarkdown)) {
        return $true
    }
    return @($Section.Children | Where-Object { Test-ReportSectionShown $_ }).Count -gt 0
}

# Lines of the -DebugLog file. Written here rather than by a transcript, which a module
# (PowerCLI) can stop.
function Write-DebugLog {
    param(
        [string[]]$Line
    )

    if ($debugLogPath) {
        Add-Content -LiteralPath $debugLogPath -Value $Line -Encoding UTF8
    }
}

# For -DebugLog: the error, the statement that failed and the calls that led to it. An error of a
# module comes from its own process with these already worked out.
function Write-ErrorDetail {
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $lines = @($ErrorRecord.Exception.Data['MoseDetail'])
    if ($lines.Count -eq 0 -or $null -eq $lines[0]) {
        $lines = @(Get-MoseErrorDetail $ErrorRecord)
    }
    $lines | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    Write-DebugLog $lines
}

# Veeam and Hyper-V given by IP address: PowerShell remoting needs the address in TrustedHosts and
# an explicit login. Offers to set what is missing before the server runs, instead of failing.
function Confirm-RemotingAccess {
    param(
        [object]$Target
    )

    $server = $Target.Server
    if ($Target.Module -notin 'Veeam', 'HyperV' -or -not (Test-MoseIPAddress $server) -or -not [Environment]::UserInteractive) {
        return
    }
    $trusted = Test-MoseTrustedHost $server
    $secret = Get-MoseProperty $Target 'Secret'
    if ($trusted -and $secret) {
        return
    }

    Write-Host "$server is an IP address: PowerShell remoting only connects to it when it is in this computer's TrustedHosts and a login is given." -ForegroundColor Yellow
    try {
        $name = [System.Net.Dns]::GetHostEntry($server).HostName
    }
    catch {
        $name = ''
    }
    if ($name -and $name -ne $server) {
        Write-Host "Its name is $($name). Configured by that name instead (.\Start.ps1 -Configure), Kerberos needs neither and checks the server's identity." -ForegroundColor Yellow
    }
    if (-not $trusted) {
        [void](Confirm-MoseTrustedHost $server)
    }
    if ($secret -or -not (Read-YesNo "Enter a Windows login for $server now? It is saved for the next reports")) {
        return
    }
    [void](Save-TargetLogin $Target)
}

# Asks for the login of a server and saves it with the client configuration. Returns $true when
# one was entered.
function Save-TargetLogin {
    param(
        [object]$Target,
        [string]$UserName = '',
        [string]$Use = 'PowerShell remoting'
    )

    $server = $Target.Server
    $message = "$($MoseModules[$Target.Module].Label) $server, $($Use): DOMAIN\user, or $server\user for an account of the server itself"
    $credential = if ($UserName) { Get-Credential -Message $message -UserName $UserName } else { Get-Credential -Message $message }
    if (-not $credential) {
        return $false
    }
    $secretName = "MOSE:$($Target.Module):$server"
    Set-Secret -Vault $MoseVaultName -Name $secretName -Secret $credential
    if ($Target.PSObject.Properties['Secret']) {
        $Target.Secret = $secretName
    }
    else {
        $Target | Add-Member -NotePropertyName Secret -NotePropertyValue $secretName
    }
    if ($configFromVault) {
        Save-MoseConfig -Client $config.Client -Targets @($config.Targets) -Layout (Get-MoseProperty $config 'Layout') -Software @(Get-MoseProperty $config 'Software' | Where-Object { $_ })
        Write-Host "Saved the login for $server in the client configuration." -ForegroundColor Green
    }
    return $true
}

# After a Veeam or Hyper-V server refused the login over PowerShell remoting: why, and the offer
# to enter another one. Returns $true when one was entered, to try once more.
function Request-RemotingLogin {
    param(
        [object]$Target
    )

    if ($Target.Module -notin 'Veeam', 'HyperV' -or -not [Environment]::UserInteractive) {
        return $false
    }
    $server = $Target.Server
    $account = "$env:USERDOMAIN\$env:USERNAME (this Windows session)"
    $userName = ''
    if (Get-MoseProperty $Target 'Secret') {
        $userName = (Get-TargetCredential $Target).UserName
        $account = $userName
    }
    Write-Host "$server refused the login $account over PowerShell remoting. Check:" -ForegroundColor Yellow
    Write-Host "  - the user name with its domain: DOMAIN\user, or $server\user for an account of the server itself, and the password;" -ForegroundColor Yellow
    Write-Host "  - the account is an administrator of $server, or a member of its Remote Management Users group;" -ForegroundColor Yellow
    Write-Host "  - a local account other than the built-in Administrator also needs LocalAccountTokenFilterPolicy = 1 on $server." -ForegroundColor Yellow
    if (-not (Read-YesNo "Enter another login for $server and try again?")) {
        return $false
    }
    return (Save-TargetLogin $Target -UserName $userName)
}

# After the Veeam REST API refused the login (the module said why): the offer to enter another one.
function Request-ApiLogin {
    param(
        [object]$Target
    )

    if (-not [Environment]::UserInteractive) {
        return $false
    }
    $userName = ''
    if (Get-MoseProperty $Target 'Secret') {
        $userName = (Get-TargetCredential $Target).UserName
    }
    if (-not (Read-YesNo "Enter another login for $($Target.Server) and try again?")) {
        return $false
    }
    return (Save-TargetLogin $Target -UserName $userName -Use 'Veeam account with a Veeam role')
}

# The certificate of a server that this computer does not trust: the offer to trust it, by its
# thumbprint, for this server only. Returns $true when it was saved, to try once more.
function Request-CertificateTrust {
    param(
        [object]$Target,
        [string]$Thumbprint,
        [string]$Subject
    )

    if (-not [Environment]::UserInteractive) {
        return $false
    }
    $server = $Target.Server
    Write-Host "This computer does not trust the certificate of $server ($Subject)." -ForegroundColor Yellow
    Write-Host "  SHA-1 thumbprint: $Thumbprint" -ForegroundColor Yellow
    Write-Host "  Compare it with the certificate on the server first: anyone in between could show another one." -ForegroundColor Yellow
    if (-not (Read-YesNo "Trust this certificate for $server and try again?" $false)) {
        return $false
    }
    if ($Target.PSObject.Properties['CertificateThumbprint']) {
        $Target.CertificateThumbprint = $Thumbprint
    }
    else {
        $Target | Add-Member -NotePropertyName CertificateThumbprint -NotePropertyValue $Thumbprint
    }
    if ($configFromVault) {
        Save-MoseConfig -Client $config.Client -Targets @($config.Targets) -Layout (Get-MoseProperty $config 'Layout') -Software @(Get-MoseProperty $config 'Software' | Where-Object { $_ })
        Write-Host "Saved the certificate of $server in the client configuration." -ForegroundColor Green
    }
    return $true
}

# After a server failed for a reason the user can fix here (a refused login, an untrusted
# certificate): the offer to fix it. Returns $true when the server should run again.
function Request-RunRetry {
    param(
        [object]$Run
    )

    $data = $Run.Error.Exception.Data
    try {
        if ($data['RemotingAccessDenied']) {
            return (Request-RemotingLogin $Run.Target)
        }
        if ($data['UntrustedCertificate']) {
            return (Request-CertificateTrust $Run.Target $data['UntrustedCertificate'] $data['CertificateSubject'])
        }
        if ($data['LoginRefused']) {
            return (Request-ApiLogin $Run.Target)
        }
    }
    catch {
        Write-Warning "Could not offer to fix $($Run.Title): $($_.Exception.Message)"
    }
    return $false
}

# Table cells must not contain a | or a line break.
function Format-InventoryCell {
    param($Value)
    return ("$Value" -replace '\|', '/' -replace '\r?\n', ' ').Trim()
}

# The tables of the layout's Inventory group (Infrastructure detail), from what the modules found
# ($Inventory): Virtual System, the VMs of the VMware modules in a table per VM folder, and
# Software, Veeam and msSQL as their modules read them with the lines entered in the configuration
# (Configure.ps1, I). A line with the name of one read gives its purpose, or a version to show
# instead; the other lines are only in a full report, not in a partial one.
function Get-InventoryMarkdown {
    param(
        [object[]]$Inventory,
        [object[]]$SoftwareLines,
        [switch]$Partial
    )

    $parts = New-Object System.Collections.Generic.List[string]

    $vms = @($Inventory | Where-Object { $_.MoseInventory -eq 'VM' })
    if ($vms.Count -gt 0) {
        $text = '### Virtual System'
        foreach ($folder in @($vms | Group-Object -Property Folder | Sort-Object -Property Name)) {
            $text += "`n`n#### $(Format-InventoryCell $folder.Name)`n| PC | Windows Version |`n|----|-----------------|"
            foreach ($vm in @($folder.Group | Sort-Object -Property Name)) {
                $text += "`n| $(Format-InventoryCell $vm.Name) | $(Format-InventoryCell $vm.Os) |"
            }
        }
        $parts.Add($text)
    }

    $read = @($Inventory | Where-Object { $_.MoseInventory -eq 'Software' })
    # With the fields a configuration edited by hand may lack.
    $lines = @($SoftwareLines | Where-Object { $_ } | ForEach-Object {
            [pscustomobject]@{ Name = "$(Get-MoseProperty $_ 'Name')"; Version = "$(Get-MoseProperty $_ 'Version')"; Purpose = "$(Get-MoseProperty $_ 'Purpose')" }
        } | Where-Object { $_.Name })
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($item in $read) {
        $line = $lines | Where-Object { $_.Name -eq "$($item.Name)" } | Select-Object -First 1
        $version = if ($line -and $line.Version) { $line.Version } else { "$($item.Version)" }
        $purpose = if ($line -and $line.Purpose) { $line.Purpose } else { "$($item.Purpose)" }
        $rows.Add([pscustomobject]@{ Name = "$($item.Name)"; Version = $version; Purpose = $purpose })
    }
    if (-not $Partial) {
        foreach ($line in $lines) {
            if (@($read | Where-Object { "$($_.Name)" -eq $line.Name }).Count -eq 0) {
                $rows.Add($line)
            }
        }
    }
    if ($rows.Count -gt 0) {
        $text = "### Software`n| Name | Version | Purpose |`n|------|---------|---------|"
        # Two Veeam servers of the same version: one line.
        foreach ($group in @($rows | Group-Object -Property Name, Version)) {
            $row = $group.Group[0]
            $text += "`n| $(Format-InventoryCell $row.Name) | $(Format-InventoryCell $row.Version) | $(Format-InventoryCell $row.Purpose) |"
        }
        $parts.Add($text)
    }

    return $parts -join "`n`n"
}

function Add-ReportSection {
    param(
        [object]$Section,
        [int]$Level
    )

    if (-not (Test-ReportSectionShown $Section)) {
        return
    }
    $title = Get-MoseSectionTitle -Section $Section -Client $config.Client -Date $reportDate
    $report.Add((Format-MoseHeading -Level $Level -Text $title))
    if ($Section.Text) {
        # Written in the layout menu; its own headings, if any, go below the section's.
        $text = Format-MoseTitle $Section.Text @{ Client = $config.Client; Date = $reportDate }
        $report.Add((Set-MarkdownHeadingLevel -Markdown $text -TopLevel ($Level + 1)))
    }
    if ($Section.Inventory -and $inventoryMarkdown) {
        $report.Add((Set-MarkdownHeadingLevel -Markdown $inventoryMarkdown -TopLevel ($Level + 1)))
    }
    foreach ($child in $Section.Children) {
        Add-ReportSection -Section $child -Level ($Level + 1)
    }
    if (-not $Section.Target) {
        return
    }

    # The servers were collected first (Invoke-TargetRuns); a dry run uses sample data.
    try {
        if ($DryRun) {
            $output = @(Get-SampleMarkdown $Section.Target)
        }
        elseif ($Section.Run.Error) {
            $report.Add("Collection failed: $($Section.Run.Error.Exception.Message)")
            return
        }
        else {
            $output = $Section.Run.Lines
        }
        $content = Set-MarkdownHeadingLevel -Markdown ($output -join [Environment]::NewLine) -TopLevel ($Level + 1) `
            -DropTitle:([bool]$MoseModules[$Section.Target.Module]['DropTitle'])
        if ($content) {
            $report.Add($content)
        }
        else {
            $report.Add('_No report data was returned._')
        }
    }
    catch {
        $report.Add("Collection failed: $($_.Exception.Message)")
        Write-Warning "$($title): $($_.Exception.Message)"
        $script:failedCount++
    }
}

# For -Only: a server matches a word by its module, its module's name or its own name. A plain word
# matches anywhere in them (veeam, sql); * and ? work as in -like.
function Test-TargetMatch {
    param(
        [object]$Target,
        [string[]]$Words
    )

    $label = if ($MoseModules.Contains($Target.Module)) { $MoseModules[$Target.Module].Label } else { '' }
    $names = @($Target.Module, $label, (Get-MoseTargetName $Target))
    foreach ($word in $Words) {
        $pattern = if ($word -match '[*?]') { $word } else { "*$word*" }
        if (@($names | Where-Object { "$_" -like $pattern }).Count -gt 0) {
            return $true
        }
    }
    return $false
}

# The servers of the report: all of them, those -Only names, or those picked from the list
# (-Choose). Label says which in the report, Tag in its file name.
function Select-ReportTargets {
    param(
        [object[]]$Targets
    )

    $words = @($Only | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($Choose) {
        Write-Host ''
        Write-Host "Servers of $($config.Client)" -ForegroundColor Cyan
        for ($i = 0; $i -lt $Targets.Count; $i++) {
            Write-Host ('  {0,2}. {1} {2}' -f ($i + 1), $MoseModules[$Targets[$i].Module].Label, (Get-MoseTargetName $Targets[$i]))
        }
        $answer = "$(Read-Host -Prompt 'Numbers (2,3 or 2-4) or words (veeam, sql), Enter for all')".Trim()
        if ($answer -match '^[\d\s,-]+$') {
            $numbers = foreach ($part in $answer -split ',') {
                if ($part -match '^\s*(\d+)\s*-\s*(\d+)\s*$') {
                    [int]$Matches[1]..[int]$Matches[2]
                }
                elseif ($part -match '^\s*(\d+)\s*$') {
                    [int]$Matches[1]
                }
            }
            $picked = @($numbers | Where-Object { $_ -ge 1 -and $_ -le $Targets.Count } | Sort-Object -Unique | ForEach-Object { $Targets[$_ - 1] })
            $names = @($picked | ForEach-Object { "$($MoseModules[$_.Module].Label) $(Get-MoseTargetName $_)" })
            return [pscustomobject]@{ Targets = $picked; Label = $names -join ', '; Tag = 'part' }
        }
        $words = @($answer -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    if ($words.Count -eq 0) {
        return [pscustomobject]@{ Targets = $Targets; Label = ''; Tag = '' }
    }
    $picked = @($Targets | Where-Object { Test-TargetMatch $_ $words })
    $tag = 'part-' + (@($words | ForEach-Object { $_.ToLowerInvariant() -replace '[^a-z0-9.]+', '' } | Where-Object { $_ }) -join '-')
    return [pscustomobject]@{ Targets = $picked; Label = $words -join ', '; Tag = $tag }
}

# A configuration passed by Configure.ps1 is not saved yet, so this script never saves it.
$configFromVault = -not $Config
$originalLocation = Get-Location
$clientFileName = $config.Client -replace '[\\/:*?"<>|\s]', '_'
$debugLogPath = ''
$debugSummary = New-Object System.Collections.Generic.List[string]
if ($DebugLog) {
    $path = Join-Path $PSScriptRoot "$($clientFileName)_Debug_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').log"
    $version = 'unknown'
    $versionPath = Join-Path $PSScriptRoot 'installed-version.txt'
    if (Test-Path -LiteralPath $versionPath) {
        $commit = "$(Get-Content -LiteralPath $versionPath -Raw)".Trim()
        $version = $commit.Substring(0, [math]::Min(7, $commit.Length))
    }
    $header = @(
        "MOSE debug log of the $($config.Client) report, started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        "MOSE version $version, Windows PowerShell $($PSVersionTable.PSVersion) on $env:COMPUTERNAME (Windows $([Environment]::OSVersion.Version)), user $env:USERDOMAIN\$env:USERNAME"
        ''
    )
    try {
        Set-Content -LiteralPath $path -Value $header -Encoding UTF8 -ErrorAction Stop
        $debugLogPath = $path
    }
    catch {
        Write-Warning "The debug log could not be written, the details are only shown here: $($_.Exception.Message)"
    }
}
$failedCount = 0
try {
    # The module scripts expect to run from their own folder.
    Set-Location -LiteralPath $PSScriptRoot

    $reportDate = Get-Date -Format 'yyyy-MM-dd'
    $layout = Get-MoseProperty $config 'Layout'
    # A partial report (-Only, -Choose): only its servers are laid out, the configuration stays whole.
    $selection = Select-ReportTargets -Targets @($config.Targets)
    $reportTargets = [object[]]$selection.Targets
    if ($reportTargets.Count -eq 0) {
        $configured = @($config.Targets | ForEach-Object { "$($MoseModules[$_.Module].Label) $(Get-MoseTargetName $_)" }) -join ', '
        throw "No configured server matches '$($selection.Label)'. The servers: $configured."
    }
    $sections = Get-MoseReportSections -Layout $layout -Targets $reportTargets

    $title = Get-MoseProperty $layout 'Title'
    if (-not $title) {
        $title = $MoseDefaultReportTitle
    }
    $report = New-Object System.Collections.Generic.List[string]
    $report.Add("# $(Format-MoseTitle $title @{ Client = $config.Client; Date = $reportDate })")
    if ($selection.Tag) {
        $report.Add("> Partial report: only $($selection.Label).")
    }
    # What the modules found, for the tables of the Inventory group, made once they all ran.
    $inventory = New-Object System.Collections.Generic.List[object]
    $inventoryMarkdown = ''
    if ($DryRun) {
        $report.Add('> Dry run: sample data, no server was contacted. Only the sections, titles and heading levels are real.')
        foreach ($section in @(Get-TargetSections -Sections $sections)) {
            foreach ($item in @(Get-SampleInventory $section.Target)) {
                $inventory.Add($item)
            }
        }
    }
    else {
        $runs = New-Object System.Collections.Generic.List[object]
        # The lists are passed as they are: @() around one returned by a function fails in Windows
        # PowerShell 5.1 ("Argument types do not match").
        foreach ($section in @(Get-TargetSections -Sections $sections)) {
            $runTitle = Get-MoseSectionTitle -Section $section -Client $config.Client -Date $reportDate
            $run = New-TargetRun -Section $section -Title $runTitle -Index $runs.Count
            $section | Add-Member -NotePropertyName Run -NotePropertyValue $run -Force
            $runs.Add($run)
        }

        # The questions first (TrustedHosts, a login), so none comes while servers are running.
        foreach ($run in $runs) {
            try {
                Confirm-RemotingAccess $run.Target
            }
            catch {
                Write-Warning "Could not check PowerShell remoting to $($run.Target.Server): $($_.Exception.Message)"
            }
        }

        $parallel = if ($ThrottleLimit -gt 1) { ", up to $ThrottleLimit at once" } else { '' }
        Write-Host "Collecting $($runs.Count) server(s)$parallel..." -ForegroundColor DarkGray
        Invoke-TargetRuns -Runs $runs.ToArray()

        # A refused login or an untrusted certificate: offered to fix once every server ended, then
        # that server runs again; twice at most, e.g. a certificate, then the login.
        foreach ($run in $runs) {
            for ($attempt = 1; $attempt -le 2 -and $run.Error; $attempt++) {
                if (-not (Request-RunRetry $run)) {
                    break
                }
                Write-Host "Trying $($run.Title) again..." -ForegroundColor DarkGray
                Write-DebugLog "  $($run.Title) runs again after: $($run.Error.Exception.Message)"
                Invoke-TargetRuns -Runs @($run)
            }
        }

        $failedCount = @($runs | Where-Object { $_.Error }).Count
        if ($DebugLog) {
            foreach ($run in $runs) {
                $debugSummary.Add(('{0,-6} {1,5}  {2}{3}' -f $run.Status, $run.Elapsed, $run.Title, $run.Where))
            }
        }
        foreach ($run in $runs) {
            foreach ($item in $run.Inventory) {
                $inventory.Add($item)
            }
        }
    }
    $inventoryMarkdown = Get-InventoryMarkdown -Inventory $inventory.ToArray() -SoftwareLines @(Get-MoseProperty $config 'Software' | Where-Object { $_ }) -Partial:([bool]$selection.Tag)
    foreach ($section in $sections) {
        Add-ReportSection -Section $section -Level 2
    }

    # A partial report gets a name of its own, so the full report of the day stays as it was.
    $suffix = ''
    if ($selection.Tag) {
        $suffix += "_$($selection.Tag)"
    }
    if ($DryRun) {
        $suffix += '_sample'
    }
    $fileName = "$($clientFileName)_Report_$(Get-Date -Format 'yyyy-MM-dd')$suffix.md"
    $outputPath = Join-Path $PSScriptRoot $fileName
    $reportText = $report -join ([Environment]::NewLine + [Environment]::NewLine)
    Set-Content -LiteralPath $outputPath -Value $reportText -Encoding UTF8
    $kind = if ($DryRun) { 'sample report (dry run)' } else { 'report' }
    if ($selection.Tag) {
        $kind = "partial $kind"
    }
    Write-Host "$($config.Client) $kind written to $outputPath" -ForegroundColor Green
    if ($failedCount -gt 0 -and -not $DebugLog) {
        Write-Host "$failedCount server(s) failed. To see where, with the call stack: .\Start.ps1 -DebugLog" -ForegroundColor Yellow
    }

    if (-not $NoOpen) {
        Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$outputPath`""
    }

    $reportText
}
finally {
    Set-Location -LiteralPath $originalLocation
    if ($debugSummary.Count -gt 0) {
        $summary = @('', "Summary: $($debugSummary.Count) server(s), $failedCount failed") + @($debugSummary | ForEach-Object { "  $_" })
        $summary | ForEach-Object { Write-Host $_ }
        Write-DebugLog $summary
    }
    if ($debugLogPath) {
        Write-Host "Debug log written to $debugLogPath (it contains the client's server names and addresses)." -ForegroundColor Green
    }
}
