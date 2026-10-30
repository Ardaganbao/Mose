[CmdletBinding()]
param (
    [Parameter(HelpMessage = 'Veeam Backup & Replication server; if the module is missing locally, this is also used as the remote execution host.')]
    [string]$Server = 'localhost',

    [Parameter(HelpMessage = 'Path where the Markdown report is saved on the computer running this script.')]
    [string]$OutputPath = 'C:\temp\veeam_temp.mq',

    [Parameter(HelpMessage = 'Do not open the completed report in Notepad.')]
    [switch]$NoOpen,

    [Parameter(HelpMessage = 'Run report generation on the Veeam server over PowerShell Remoting.')]
    [switch]$RunOnVbrServer,

    [Parameter(HelpMessage = 'Optional credential for PowerShell Remoting to the Veeam server.')]
    [System.Management.Automation.PSCredential]$RemotingCredential
)

$ErrorActionPreference = 'Stop'
$veeamModuleName = 'Veeam.Backup.PowerShell'

function Write-VeeamReportProgress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Status,
        [Parameter(Mandatory = $true)]
        [int]$PercentComplete
    )

    $percent = [math]::Max(0, [math]::Min(100, $PercentComplete))
    $barWidth = 24
    $filledWidth = [math]::Floor($barWidth * $percent / 100)
    $bar = ('#' * $filledWidth) + ('-' * ($barWidth - $filledWidth))

    Write-Progress -Activity 'Generating Veeam report' -Status $Status -PercentComplete $percent
    Write-Host ("[{0}] {1,3}% - {2}" -f $bar, $percent, $Status)
}

Write-VeeamReportProgress -Status 'Starting report' -PercentComplete 0

if ($RunOnVbrServer -or (-not (Get-Command Connect-VBRServer -ErrorAction SilentlyContinue) -and $Server -notin @('localhost', '.'))) {
    if (-not (Test-Path -LiteralPath $PSCommandPath -PathType Leaf)) {
        throw 'Remote execution requires running this from the saved VeeamReport.ps1 file.'
    }

    $scriptContent = [System.IO.File]::ReadAllText($PSCommandPath)
    $remoteCommand = {
        param([string]$Source)
        $reportScript = [scriptblock]::Create($Source)
        & $reportScript -Server 'localhost' -OutputPath '' -NoOpen
    }
    $invokeParameters = @{
        ComputerName = $Server
        ScriptBlock = $remoteCommand
        ArgumentList = @($scriptContent)
        ErrorAction = 'Stop'
    }
    if ($null -ne $RemotingCredential) {
        $invokeParameters.Credential = $RemotingCredential
    }

    try {
        $remoteOutput = Invoke-Command @invokeParameters
    }
    catch {
        throw "Could not run the Veeam report remotely on '$Server'. Verify PowerShell Remoting/WinRM is enabled and your account can access the Veeam server. $($_.Exception.Message)"
    }

    $Body = ($remoteOutput | Select-Object -Last 1)
    if ([string]::IsNullOrWhiteSpace([string]$Body)) {
        throw "Remote execution on '$Server' did not return a report."
    }

    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    $Body | Out-File -LiteralPath $OutputPath -Encoding UTF8 -ErrorAction Stop
    if (-not $NoOpen) {
        Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$OutputPath`"" -ErrorAction Stop
    }
    $Body
    return
}

$corePath = Get-ItemProperty -Path "HKLM:\Software\Veeam\Veeam Backup and Replication\" -Name "CorePath" -ErrorAction SilentlyContinue
$availableModule = Get-Module -ListAvailable -Name $veeamModuleName -ErrorAction SilentlyContinue |
    Sort-Object -Property PowerShellVersion -Descending |
    Select-Object -First 1
$moduleManifestCandidates = @()
if ($null -ne $availableModule -and -not [string]::IsNullOrWhiteSpace([string]$availableModule.Path)) {
    $moduleManifestCandidates += $availableModule.Path
}
if ($corePath -and -not [string]::IsNullOrWhiteSpace([string]$corePath.CorePath)) {
    $moduleManifestCandidates += Join-Path $corePath.CorePath 'Console\Veeam.Backup.PowerShell\Veeam.Backup.PowerShell.psd1'
}
$moduleManifestCandidates += Join-Path $env:ProgramFiles 'Veeam\Backup and Replication\Console\Veeam.Backup.PowerShell\Veeam.Backup.PowerShell.psd1'

$requiredPowerShellVersion = $null
$veeamModulePath = $null
$veeamVersion = $null
foreach ($manifestPath in $moduleManifestCandidates | Select-Object -Unique) {
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        continue
    }

    $moduleManifest = Import-PowerShellDataFile -LiteralPath $manifestPath -ErrorAction Stop
    if ($moduleManifest.ModuleVersion) {
        $veeamVersion = [string]$moduleManifest.ModuleVersion
    }
    if ($moduleManifest.RootModule -or $moduleManifest.ModuleToProcess) {
        $veeamModulePath = $manifestPath
    }
    if ($moduleManifest.PowerShellVersion) {
        $requiredPowerShellVersion = [version]$moduleManifest.PowerShellVersion
        break
    }
}
if ($null -eq $availableModule -and $veeamModulePath) {
    $availableModule = [pscustomobject]@{
        Path = $veeamModulePath
        Version = $veeamVersion
        PowerShellVersion = $requiredPowerShellVersion
    }
}
if ($null -ne $availableModule -and $availableModule.Version) {
    $veeamVersion = [string]$availableModule.Version
}
if ($null -ne $requiredPowerShellVersion -and
    $PSVersionTable.PSVersion -lt $requiredPowerShellVersion) {
    $pwshCommand = Get-Command -Name 'pwsh.exe' -All -ErrorAction SilentlyContinue
    $compatiblePwshPath = $null

    foreach ($candidate in @($pwshCommand | ForEach-Object { $_.Source }) + @(
        (Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe')
    ) | Select-Object -Unique) {
        if ([string]::IsNullOrWhiteSpace([string]$candidate) -or
            -not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            continue
        }

        $candidateVersionText = & $candidate -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null
        $candidateVersion = $null
        if ([version]::TryParse([string]$candidateVersionText, [ref]$candidateVersion) -and
            $candidateVersion -ge $requiredPowerShellVersion) {
            $compatiblePwshPath = $candidate
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($compatiblePwshPath)) {
        throw "The installed Veeam PowerShell module requires PowerShell $requiredPowerShellVersion or later, but this script is running under PowerShell $($PSVersionTable.PSVersion). Install a compatible PowerShell 7 runtime and run this script with pwsh.exe."
    }
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw "The installed Veeam PowerShell module requires PowerShell $requiredPowerShellVersion or later. This report was invoked from an in-memory script block, so it cannot relaunch itself; run VeeamReport.ps1 from a saved file with pwsh.exe."
    }

    $credentialFile = $null
    try {
        $quotePowerShellLiteral = {
            param([string]$Value)
            "'" + $Value.Replace("'", "''") + "'"
        }
        $commandParts = @(
            '&'
            (& $quotePowerShellLiteral $PSCommandPath)
            '-Server'
            (& $quotePowerShellLiteral $Server)
            '-OutputPath'
            (& $quotePowerShellLiteral $OutputPath)
        )
        if ($NoOpen) {
            $commandParts += '-NoOpen'
        }
        if ($RunOnVbrServer) {
            $commandParts += '-RunOnVbrServer'
        }
        if ($null -ne $RemotingCredential) {
            $credentialFile = Join-Path ([System.IO.Path]::GetTempPath()) ("VeeamReportCredential_{0}.xml" -f [guid]::NewGuid())
            $RemotingCredential | Export-Clixml -LiteralPath $credentialFile -ErrorAction Stop
            $commandParts += '-RemotingCredential'
            $commandParts += '$veeamReportCredential'
        }

        $childCommand = $commandParts -join ' '
        if ($credentialFile) {
            $childCommand = '$veeamReportCredential = Import-Clixml -LiteralPath ' +
                (& $quotePowerShellLiteral $credentialFile) + '; ' + $childCommand
        }
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childCommand))
        & $compatiblePwshPath -NoProfile -EncodedCommand $encodedCommand
        if ($LASTEXITCODE -ne 0) {
            throw "PowerShell $requiredPowerShellVersion exited with code $LASTEXITCODE while running the Veeam report."
        }
    }
    finally {
        if ($credentialFile -and (Test-Path -LiteralPath $credentialFile)) {
            Remove-Item -LiteralPath $credentialFile -Force -ErrorAction Stop
        }
    }
    return
}

$depDLLPath = $null
if ($corePath -and -not [string]::IsNullOrWhiteSpace([string]$corePath.CorePath)) {
    $depDLLPath = Join-Path -Path $corePath.CorePath -ChildPath "Packages\VeeamDeploymentDLL.dll" -Resolve -ErrorAction SilentlyContinue
}
if ($depDLLPath) {
    $file = Get-Item -LiteralPath $depDLLPath -ErrorAction Stop
    if ($file.VersionInfo.ProductMajorPart -ge 10) {
        Import-Module $veeamModuleName -ErrorAction Stop
    }
    
}
if (-not (Get-Command Connect-VBRServer -ErrorAction SilentlyContinue)) {
    if ($availableModule) {
        Import-Module $availableModule.Path -ErrorAction Stop
    }
}
if (-not (Get-Command Connect-VBRServer -ErrorAction SilentlyContinue)) {
    $registeredSnapin = Get-PSSnapin -Registered -Name 'VeeamPSSnapin' -ErrorAction SilentlyContinue
    if ($registeredSnapin) {
        Add-PSSnapin VeeamPSSnapin -ErrorAction Stop
    }
}
        if (Get-Command Connect-VBRServer -ErrorAction SilentlyContinue) {
                Write-Verbose "Connect-VBRServer is available"
        }
        else {
            If ((Get-PSSnapin "*Veeam*" -ErrorAction SilentlyContinue) -eq $null) {
                throw 'Unable to load Veeam PowerShell commands. Run this on a Veeam backup server with the Veeam console installed.'
            }
        }
$ErrorActionPreference = 'Stop'
 

## Connect-VBRServer -Server $server -User $user -Password $pass
$script:VbrConnected = $false
Write-VeeamReportProgress -Status "Connecting to Veeam server '$Server'" -PercentComplete 0
try {
    try {
        Connect-VBRServer -Server $Server -ErrorAction Stop | Out-Null
        $script:VbrConnected = $true
    }
    catch {
        $connectionError = $_
        $moduleVersion = if ($availableModule) { $availableModule.Version } else { 'unknown' }
        $diagnostics = @(
            "Target: $Server"
            "PowerShell: $($PSVersionTable.PSVersion)"
            "Veeam PowerShell module: $moduleVersion"
        )

        if ($Server -in @('localhost', '.')) {
            $backupService = Get-Service -Name 'VeeamBackupSvc' -ErrorAction SilentlyContinue
            if ($backupService) {
                $diagnostics += "Veeam Backup Service: $($backupService.Status)"
            }
            else {
                $diagnostics += 'Veeam Backup Service: not found on this computer'
            }
        }

        $errorId = if ($connectionError.FullyQualifiedErrorId) { $connectionError.FullyQualifiedErrorId } else { 'unavailable' }
        throw "Failed to connect to Veeam server '$Server'. Check that the Veeam Backup & Replication service is running, this account has permission to connect, and the installed console/module is compatible with the server version.`n$($diagnostics -join [Environment]::NewLine)`nError ID: $errorId`nDetails: $($connectionError.Exception.ToString())"
    }
 


function Convert-Bytes {
    param(
        [long]$bytes
    )
    if ($bytes -le 0) {
        return '0 MB'
    }
    if ($bytes -ge 1GB) {
        $check = '{0:N2} GB' -f ($bytes / 1GB)
    }
    else {
        $check = '{0:N2} MB' -f ($bytes / 1MB)
    }
    return $check
}

$Body = "## Check Backup Veeam VM's:`n"
$Body += "- Veeam version: $(if ($veeamVersion) { $veeamVersion } else { 'Unknown' })`n"
$Bodycopy = ""
$warn = 45
$crit = 15

##$username =  $user
#$password =  ConvertTo-SecureString   $pass -AsPlainText -Force

 
$veeamLicInfo = $null
try {
    $veeamLicInfo = Get-VBRInstalledLicense -ErrorAction Stop
}
catch {
    Write-Warning "Unable to retrieve Veeam license information: $($_.Exception.Message)"
}
$expirationDate = [datetime]::MinValue
if ($null -ne $veeamLicInfo -and [datetime]::TryParse([string]$veeamLicInfo.ExpirationDate, [ref]$expirationDate)) {
    $daysleft = ($expirationDate.Date - (Get-Date).Date).Days
    $expirationDescription = if ($veeamLicInfo.Type -eq 'Subscription') { 'License expires' } else { 'Support expires' }

    if ($daysleft -gt $warn) {
        $licenseStatus = ':heavy_check_mark:'
    }
    elseif ($daysleft -gt $crit) {
        $licenseStatus = ':warning:'
    }
    else {
        $licenseStatus = ':no_entry:'
    }
    $Body += "- $licenseStatus Veeam $expirationDescription in $daysleft days ($($expirationDate.ToString('yyyy-MM-dd')))`n"
}
else {
    $Body += "- :warning: UNKNOWN: Cannot get Veeam License information`n"
}
Write-VeeamReportProgress -Status 'Collecting backup jobs' -PercentComplete 0
$VbrJobs = Get-VBRJob
$backupJobCount = @($VbrJobs).Count
$backupJobIndex = 0

foreach ($Job in $VbrJobs) { 
    $backupJobIndex++
    $backupJobProgress = if ($backupJobCount -gt 0) { [math]::Floor(60 * $backupJobIndex / $backupJobCount) } else { 60 }
    Write-VeeamReportProgress -Status "Backup jobs: $backupJobIndex of $backupJobCount - $($Job.Info.Name)" -PercentComplete $backupJobProgress

    if ($Job.JobType -eq "Backup") {


        $s = $Job.FindLastSession()
        if ($null -eq $s) {
            $Body += "`n### $($Job.Info.Name)`nNo backup session found.`n"
            continue
        }

        $Body += "`n### "
        $Body += $Job.Info.Name + "`n"
        $totalsuccess = 0
        $totalwarning = 0
        $totalerror = 0


        $list = $s.GetTaskSessions()
        $totalVM = $list.Count

        $vmDetails = "`n#### Details`n"
        $vmDetails += "| Name | Status  | Start time   | End time | Size | Read | Transferred | Duration |`n"
        $vmDetails += "|------|---------|--------------|----------|------|------|-------------|----------|`n"

        foreach ($vm in $list) {
            if ($vm.Status -like "*Success*") { $totalsuccess++ }
            if ($vm.Status -like "*Warning*") { $totalwarning++ }
            if ($vm.Status -like "*Error*") { $totalerror++ }
            # | Name                                      | Status  | Start time   | End time | Size         | Read       | Transferred | Duration               |
            # |-------------------------------------------|---------|--------------|----------|--------------|------------|-------------|------------------------|
            # | SERVER-01.example.local                   | Success | 10:00:29     | 11:12:59 | 600 GB       | 349,8 GB   | 181 GB      | 01:12:30               |

            $vmDetails += "| $($vm.Name)| $($vm.Status)  | $('{0:HH:mm:ss}' -f $vm.Info.Progress.StartTimeLocal)   |  $('{0:HH:mm:ss}' -f $vm.Info.Progress.StopTimeLocal)| $(Convert-Bytes $vm.Info.Progress.TotalSize)        | $( Convert-Bytes $vm.Info.Progress.ReadSize)       | $(Convert-Bytes $vm.Info.Progress.TransferedSize) | $($vm.Info.Progress.Duration)  |`n"
        
        }
        $Success = "Success|" + $totalsuccess + ""
        $Warning = "Warning|" + $totalwarning + ""
        $Error_s = "Error|" + $totalerror + ""
        $TotalUsedSize = $s.Info.Progress.TotalUsedSize
        $ReadSize = $s.Info.Progress.ReadSize
        $TransferedSize = $s.Info.Progress.TransferedSize




        $TotalUsed = (Convert-Bytes $TotalUsedSize) + " |"
        $Read = (Convert-Bytes $ReadSize) + " |"
        $Transfered = (Convert-Bytes $TransferedSize) + " |"


        $duration = $s.Info.Progress.Duration
        $Body += "|" + $s.Info.CreationTime + "||||||" + $s.Info.Result + "|" + $s.Info.Progress.ProcessedObjects + " of " + $s.Info.Progress.TotalObjects + " VMs processed |`n"
        $Body += "|---|---|---|-----|---|----|----|----|`n"
        $Body += "|" + $Success + "| Start time |" + '{0:HH:mm:ss}' -f $s.Info.CreationTime + "| Total   size |" + $TotalUsed + "Backup size |" + (Convert-Bytes $s.Info.BackedUpSize) + "|`n"
        $Body += "|" + $Warning + "| End time   |" + '{0:HH:mm:ss}' -f $s.Info.EndTime + "| Data   read  |" + $Read + "Dedupe      |" + "$( [math]::Round($s.BackupStats.GetDedupeX(),2) )x" + "|`n"
        $Body += "|" + $Error_s + "| Duration     |" + $duration + "| Transferred  |" + $Transfered + "Compression |" + "$([math]::Round( $s.BackupStats.GetCompressX(),2) )x" + "|`n"
        $Body += $vmDetails
        ##| mardi 27 décembre 2022 23:30:02           |         |              |          |              |            | Success     | 1 of 1 VMs processed   |
        #|-------------------------------------------|---------|--------------|----------|--------------|------------|-------------|------------------------|
        #| Success                                   | 1       | Start   time | 23:30:02 | Total   size | 10   GB    | Backup size | 28,8 MB                |
        #| Warning                                   | 0       | End   time   | 23:31:53 | Data   read  | 81   MB    | Dedupe      | 1,0x                   |
        #| Error                                     | 0       | Duration     | 00:01:51 | Transferred  | 26,6   MB  | Compression | 3,0x                   |

    }
    else {
        if ($Job.JobType -eq "SimpleBackupCopyPolicy") {
      
        }
        else {
            if ($Job.JobType -eq "EpAgentPolicy") {


                $s = $Job.FindLastSession()
                if ($null -eq $s) {
                    $Body += "`n### $($Job.Info.Name)`nNo backup session found.`n"
                    continue
                }

                $Body += "`n### "
                $Body += $Job.Info.Name + "`n"
                $totalsuccess = 0
                $totalwarning = 0
                $totalerror = 0


                $list = $s.GetTaskSessions()
                $totalVM = $list.Count

                $vmDetails = "`n#### Details`n"
                $vmDetails += "| Name | Status  | Start time   | End time | Size | Read | Transferred | Duration |`n"
                $vmDetails += "|------|---------|--------------|----------|------|------|-------------|----------|`n"

                foreach ($vm in $list) {
                    if ($vm.Status -like "*Success*") { $totalsuccess++ }
                    if ($vm.Status -like "*Warning*") { $totalwarning++ }
                    if ($vm.Status -like "*Error*") { $totalerror++ }
                    # | Name                                      | Status  | Start time   | End time | Size         | Read       | Transferred | Duration               |
                    # |-------------------------------------------|---------|--------------|----------|--------------|------------|-------------|------------------------|
                    # | SERVER-01.example.local                   | Success | 10:00:29     | 11:12:59 | 600 GB       | 349,8 GB   | 181 GB      | 01:12:30               |

                    $vmDetails += "| $($vm.Name)| $($vm.Status)  | $('{0:HH:mm:ss}' -f $vm.Info.Progress.StartTimeLocal)   |  $('{0:HH:mm:ss}' -f $vm.Info.Progress.StopTimeLocal)| $(Convert-Bytes $vm.Info.Progress.TotalSize)        | $( Convert-Bytes $vm.Info.Progress.ReadSize)       | $(Convert-Bytes $vm.Info.Progress.TransferedSize) | $($vm.Info.Progress.Duration)  |`n"
        
                }
                $Success = "Success|" + $totalsuccess + ""
                $Warning = "Warning|" + $totalwarning + ""
                $Error_s = "Error|" + $totalerror + ""
                $TotalUsedSize = $s.Info.Progress.TotalUsedSize
                $ReadSize = $s.Info.Progress.ReadSize
                $TransferedSize = $s.Info.Progress.TransferedSize




                $TotalUsed = (Convert-Bytes $TotalUsedSize) + " |"
                $Read = (Convert-Bytes $ReadSize) + " |"
                $Transfered = (Convert-Bytes $TransferedSize) + " |"


                $duration = $s.Info.Progress.Duration
                $Body += "|" + $s.Info.CreationTime + "||||||" + $s.Info.Result + "|" + $s.Info.Progress.ProcessedObjects + " of " + $s.Info.Progress.TotalObjects + " VMs processed |`n"
                $Body += "|---|---|---|-----|---|----|----|----|`n"
                $Body += "|" + $Success + "| Start time |" + '{0:HH:mm:ss}' -f $s.Info.CreationTime + "| Total   size |" + $TotalUsed + "Backup size |" + (Convert-Bytes $s.Info.BackedUpSize) + "|`n"
                $Body += "|" + $Warning + "| End time   |" + '{0:HH:mm:ss}' -f $s.Info.EndTime + "| Data   read  |" + $Read + "Dedupe      |" + "$( [math]::Round($s.BackupStats.GetDedupeX(),2) )x" + "|`n"
                $Body += "|" + $Error_s + "| Duration     |" + $duration + "| Transferred  |" + $Transfered + "Compression |" + "$([math]::Round( $s.BackupStats.GetCompressX(),2) )x" + "|`n"
                $Body += $vmDetails
                ##| mardi 27 décembre 2022 23:30:02           |         |              |          |              |            | Success     | 1 of 1 VMs processed   |
                #|-------------------------------------------|---------|--------------|----------|--------------|------------|-------------|------------------------|
                #| Success                                   | 1       | Start   time | 23:30:02 | Total   size | 10   GB    | Backup size | 28,8 MB                |
                #| Warning                                   | 0       | End   time   | 23:31:53 | Data   read  | 81   MB    | Dedupe      | 1,0x                   |
                #| Error                                     | 0       | Duration     | 00:01:51 | Transferred  | 26,6   MB  | Compression | 3,0x                   |
        
            }
            else {
                if ($Job.JobType -eq "EpAgentBackup") {
        

                    $s = $Job.FindLastSession()
                    if ($null -eq $s) {
                        $Body += "`n### $($Job.Info.Name)`nNo backup session found.`n"
                        continue
                    }
                    $sessions = Get-VBRComputerBackupJobSession -Name "$($job.Name)" | Sort-Object –Property CreationTime –Descending | Select-Object -First 20
                    $list = @{}
                    foreach ($session in $sessions) {
                        $subtasks = Get-VBRTaskSession -Session $session
                        foreach ($subtask in $subtasks) {
                            if (!$list.ContainsKey($subtask.Name)) {
                                $list[$subtask.Name] = $subtask
                            }
                        }


                    }
                    $Body += "`n### "
                    $Body += $Job.Info.Name + "`n"
                    $totalsuccess = 0
                    $totalwarning = 0
                    $totalerror = 0
  
   
                    $totalVM = $list.Count
  
                    $vmDetails = "`n#### Details`n"
                    $vmDetails += "| Name | Status  | Start time   | End time | Size | Read | Transferred | Duration |`n"
                    $vmDetails += "|------|---------|--------------|----------|------|------|-------------|----------|`n"
  
                    foreach ($vmkey in $list.GetEnumerator()) {
                        $vm = $vmkey.value
                        if ($vm.Status -like "*Success*") { $totalsuccess++ }
                        if ($vm.Status -like "*Warning*") { $totalwarning++ }
                        if ($vm.Status -like "*Error*") { $totalerror++ }
                        # | Name                                      | Status  | Start time   | End time | Size         | Read       | Transferred | Duration               |
                        # |-------------------------------------------|---------|--------------|----------|--------------|------------|-------------|------------------------|
                        # | SERVER-01.example.local                   | Success | 10:00:29     | 11:12:59 | 600 GB       | 349,8 GB   | 181 GB      | 01:12:30               |
  
                        $vmDetails += "| $($vm.Name)| $($vm.Status)  | $('{0:HH:mm:ss}' -f $vm.Info.Progress.StartTimeLocal)   |  $('{0:HH:mm:ss}' -f $vm.Info.Progress.StopTimeLocal)| $(Convert-Bytes $vm.Info.Progress.TotalSize)        | $( Convert-Bytes $vm.Info.Progress.ReadSize)       | $(Convert-Bytes $vm.Info.Progress.TransferedSize) | $($vm.Info.Progress.Duration)  |`n"
          
                    }
                    $Success = "Success|" + $totalsuccess + ""
                    $Warning = "Warning|" + $totalwarning + ""
                    $Error_s = "Error|" + $totalerror + ""
                    $TotalUsedSize = $s.Info.Progress.TotalUsedSize
                    $ReadSize = $s.Info.Progress.ReadSize
                    $TransferedSize = $s.Info.Progress.TransferedSize
  
  
  
  
                    $TotalUsed = (Convert-Bytes $TotalUsedSize) + " |"
                    $Read = (Convert-Bytes $ReadSize) + " |"
                    $Transfered = (Convert-Bytes $TransferedSize) + " |"
  
  
                    $duration = $s.Info.Progress.Duration
                    $Body += "|" + $s.Info.CreationTime + "||||||" + $s.Info.Result + "|" + $s.Info.Progress.ProcessedObjects + " of " + $s.Info.Progress.TotalObjects + " VMs processed |`n"
                    $Body += "|---|---|---|-----|---|----|----|----|`n"
                    $Body += "|" + $Success + "| Start time |" + '{0:HH:mm:ss}' -f $s.Info.CreationTime + "| Total   size |" + $TotalUsed + "Backup size |" + (Convert-Bytes $s.Info.BackedUpSize) + "|`n"
                    $Body += "|" + $Warning + "| End time   |" + '{0:HH:mm:ss}' -f $s.Info.EndTime + "| Data   read  |" + $Read + "Dedupe      |" + "$( [math]::Round($s.BackupStats.GetDedupeX(),2) )x" + "|`n"
                    $Body += "|" + $Error_s + "| Duration     |" + $duration + "| Transferred  |" + $Transfered + "Compression |" + "$([math]::Round( $s.BackupStats.GetCompressX(),2) )x" + "|`n"
                    $Body += $vmDetails
                    ##| mardi 27 décembre 2022 23:30:02           |         |              |          |              |            | Success     | 1 of 1 VMs processed   |
                    #|-------------------------------------------|---------|--------------|----------|--------------|------------|-------------|------------------------|
                    #| Success                                   | 1       | Start   time | 23:30:02 | Total   size | 10   GB    | Backup size | 28,8 MB                |
                    #| Warning                                   | 0       | End   time   | 23:31:53 | Data   read  | 81   MB    | Dedupe      | 1,0x                   |
                    #| Error                                     | 0       | Duration     | 00:01:51 | Transferred  | 26,6   MB  | Compression | 3,0x                   |
          
                }
                else {
                    Write-Verbose "Skipping unsupported Veeam job type '$($Job.JobType)' for job '$($Job.Name)'."
                }      
            }
        }
    }


}
Write-VeeamReportProgress -Status 'Collecting Backup Copy jobs' -PercentComplete 60

 
$list = @()
$backupCopyJobs = @(Get-VBRBackupCopyJob)
$backupCopyJobCount = $backupCopyJobs.Count
$backupCopyJobIndex = 0
if ($backupCopyJobs.Count -eq 0) {
    $Bodycopy += "`n### Check Backup Copy`nNo Backup Copy jobs are configured.`n"
}
#$ListSession = [Veeam.Backup.Core.CBackupSession]::GetAll() | Sort-Object -Property EndTime
             
foreach ($BJob in $backupCopyJobs) {
    $backupCopyJobIndex++
    $backupCopyProgress = 60 + [math]::Floor(25 * $backupCopyJobIndex / $backupCopyJobCount)
    Write-VeeamReportProgress -Status "Backup Copy jobs: $backupCopyJobIndex of $backupCopyJobCount - $($BJob.Name)" -PercentComplete $backupCopyProgress

    $lastRestorepoint = @{}
    $proccessRestorePointID = @()
    $lastSession = Get-VBRSession -Job $BJob | Sort-Object CreationTime -Descending | Select-Object -First 1
    
    foreach ($BcJob in (($BJob.TargetRepository.GetBackups()) | Sort-Object –Property CreationTime –Descending)) {
        foreach ($RP in (Get-VBRRestorePoint -Backup $BcJob  | Sort-Object –Property EndTime –Descending) ) {
            #  | Where-Object -Property DisplayName -Like "<job name>"   $dp
            
            if ( !$lastRestorepoint.ContainsKey($RP.DisplayName)) {
                $lastRestorepoint[$RP.DisplayName] = @{}
                $lastRestorepoint[$RP.DisplayName]['count'] = 0
                $lastRestorepoint[$RP.DisplayName]['LastRP'] = $null
            } 
            if (!($proccessRestorePointID -contains $RP.Id.Guid)) { 
                $lastRestorepoint[$RP.DisplayName]['count'] = $lastRestorepoint[$RP.DisplayName]['count'] + 1
                if ($null -eq $lastRestorepoint[$RP.DisplayName]['LastRP'] -or $RP.CreationTime -gt $lastRestorepoint[$RP.DisplayName]['LastRP'].CreationTime) {
                    $lastRestorepoint[$RP.DisplayName]['LastRP'] = $RP
                }
                $proccessRestorePointID += $RP.Id.Guid 
            }
        } 
    } 
    $BCBackup = Get-VBRBackup -name  $BJob.name 
    $Session = if ($null -ne $lastSession) {
        Get-VBRBackupSession -Id $lastSession.Id
    }
    else {
        $null
    }

    $vmDetails = "`n##### Details`n"
    $vmDetails += "| Name | Last Copy   | copy health | Number of RP |`n"
    $vmDetails += "|------|---------|---------|---------|`n"
  
    foreach ($vmkey in $lastRestorepoint.GetEnumerator() | Sort-Object –Property name) {
        $vm = $vmkey.value['LastRP']
        if ($null -eq $vm) {
            continue
        }
        if ($vm.HealthStatus -eq "Ok") {
            $VmStatusCopy = ":heavy_check_mark: OK"
        }
        else {
            $VmStatusCopy = ":x: $($vm.HealthStatus)"
        }
        $vmDetails += "| $($vm.DisplayName) | $($vm.CreationTime) | $($VmStatusCopy)  | $($vmkey.value['Count']) |`n"
    }

    $Bodycopy += "`n"
    $Bodycopy += "### Check Backup Copy `n" 
    $Bodycopy += "#### " + $bJob.Name + "`n"
    if ($bJob.LastState -eq "Stopped" -and $null -ne $Session) {
        if ($Session.Result -eq "Success") { $status = ":heavy_check_mark:" }else { $status = ":x:" }
        $Bodycopy += "| Result |  |`n"
        $Bodycopy += "|----|----|`n"
        $Bodycopy += "| Status |  $($Session.Result) $status |`n"
        $Bodycopy += "| Start | $($Session.CreationTime) |`n"
        $Bodycopy += "| End |  $($Session.EndTime) |`n"
        $Bodycopy += "| Duration |  $($Session.Progress.Duration) |`n"
        if ($Session.BackupStats.BackupSize -gt 0) { $Bodycopy += "| Processed |  $( Convert-Bytes($Session.BackupStats.BackupSize)) |`n" }
        if ($Session.BackupStats.DataSize -gt 0) { $Bodycopy += "| Read |  $( Convert-Bytes($Session.BackupStats.DataSize)) |`n" }
        $Bodycopy += "| VM count |  $($BCBackup.VmCount) |`n"
    }
    elseif ($null -eq $Session) {
        $Bodycopy += "$($bJob.Name) has no backup session available :warning:`n"
    }
    else {
        $Bodycopy += "$($bJob.Name) is $($bJob.LastState) :exclamation: `n"
    }
    $Bodycopy += $vmDetails
}

Write-VeeamReportProgress -Status 'Collecting SureBackup jobs' -PercentComplete 85

$BodySureBackup = "`n### SureBackup verification`n"
$sureBackupCommands = @(
    'Get-VBRSureBackupJob',
    'Get-VBRSureBackupSession',
    'Get-VBRSureBackupTaskSession'
)
$missingSureBackupCommands = @($sureBackupCommands | Where-Object {
    -not (Get-Command -Name $_ -ErrorAction SilentlyContinue)
})
if ($missingSureBackupCommands.Count -gt 0) {
    $BodySureBackup += "SureBackup reporting is unavailable. Missing Veeam cmdlets: $($missingSureBackupCommands -join ', ').`n"
}
else {
    try {
        $sureBackupJobs = @(Get-VBRSureBackupJob -ErrorAction Stop)
        if ($sureBackupJobs.Count -eq 0) {
            $BodySureBackup += "No SureBackup jobs are configured.`n"
        }
        else {
            $sureBackupJobCount = $sureBackupJobs.Count
            $sureBackupJobIndex = 0
            foreach ($sureBackupJob in $sureBackupJobs | Sort-Object -Property Name) {
                $sureBackupJobIndex++
                $sureBackupProgress = 85 + [math]::Floor(15 * $sureBackupJobIndex / $sureBackupJobCount)
                Write-VeeamReportProgress -Status "SureBackup jobs: $sureBackupJobIndex of $sureBackupJobCount - $($sureBackupJob.Name)" -PercentComplete $sureBackupProgress

                $BodySureBackup += "`n#### $($sureBackupJob.Name)`n"
                $virtualLab = if ($sureBackupJob.VirtualLab.Name) { $sureBackupJob.VirtualLab.Name } elseif ($sureBackupJob.VirtualLab) { $sureBackupJob.VirtualLab } else { 'Not configured' }
                $applicationGroup = if ($sureBackupJob.ApplicationGroup.Name) { $sureBackupJob.ApplicationGroup.Name } elseif ($sureBackupJob.ApplicationGroup) { $sureBackupJob.ApplicationGroup } else { 'Not configured' }
                $linkedJobs = @($sureBackupJob.LinkedJob | ForEach-Object {
                    if ($_.Name) { $_.Name } elseif ($_.Info.Name) { $_.Info.Name } else { [string]$_ }
                }) -join ', '
                if ([string]::IsNullOrWhiteSpace($linkedJobs)) {
                    $linkedJobs = 'None'
                }
                $BodySureBackup += "| Configuration | Value |`n"
                $BodySureBackup += "|---|---|`n"
                $BodySureBackup += "| Enabled / scheduled | $($sureBackupJob.IsEnabled) / $($sureBackupJob.ScheduleEnabled) |`n"
                $BodySureBackup += "| Virtual lab | $virtualLab |`n"
                $BodySureBackup += "| Application group | $applicationGroup |`n"
                $BodySureBackup += "| Linked jobs | $linkedJobs |`n"

                try {
                    $sureBackupSessions = @(Get-VBRSureBackupSession -Name $sureBackupJob.Name -ErrorAction Stop |
                        Sort-Object -Property CreationTime -Descending)
                    $sureBackupSession = $sureBackupSessions | Select-Object -First 1
                    if ($null -eq $sureBackupSession) {
                        $BodySureBackup += "No SureBackup session found. Last configured status: $($sureBackupJob.LastResult) ($($sureBackupJob.LastState)).`n"
                        continue
                    }

                    $sessionResult = if ($sureBackupSession.Result) { $sureBackupSession.Result } else { $sureBackupJob.LastResult }
                    $sessionState = if ($sureBackupSession.State) { $sureBackupSession.State } else { $sureBackupJob.LastState }
                    $sessionStart = if ($sureBackupSession.CreationTime) { $sureBackupSession.CreationTime } elseif ($sureBackupSession.StartTime) { $sureBackupSession.StartTime } else { $sureBackupJob.LastRun }
                    $sessionEnd = if ($sureBackupSession.EndTime) { $sureBackupSession.EndTime } else { 'In progress or unavailable' }
                    $sessionDuration = $null
                    if ($sureBackupSession.Progress.Duration) {
                        $sessionDuration = $sureBackupSession.Progress.Duration
                    }
                    elseif ($sureBackupSession.Info.Progress.Duration) {
                        $sessionDuration = $sureBackupSession.Info.Progress.Duration
                    }
                    elseif ($sessionStart -is [datetime] -and $sureBackupSession.EndTime -is [datetime]) {
                        $sessionDuration = $sureBackupSession.EndTime - $sessionStart
                    }
                    if ($null -eq $sessionDuration) {
                        $sessionDuration = 'Unavailable'
                    }

                    $sureBackupTasks = @(Get-VBRSureBackupTaskSession -Session $sureBackupSession -ErrorAction Stop)
                    $successfulTasks = 0
                    $failedTasks = 0
                    $warningTasks = 0
                    $skippedTasks = 0
                    $otherTasks = 0
                    $taskRows = foreach ($sureBackupTask in $sureBackupTasks) {
                        $taskStatus = if ($sureBackupTask.Status) { [string]$sureBackupTask.Status } elseif ($sureBackupTask.Result) { [string]$sureBackupTask.Result } elseif ($sureBackupTask.State) { [string]$sureBackupTask.State } else { 'Unknown' }
                        if ($taskStatus -match '(?i)success|succeeded') {
                            $successfulTasks++
                        }
                        elseif ($taskStatus -match '(?i)warning') {
                            $warningTasks++
                        }
                        elseif ($taskStatus -match '(?i)failed|error|cancelled|canceled') {
                            $failedTasks++
                        }
                        elseif ($taskStatus -match '(?i)skip') {
                            $skippedTasks++
                        }
                        else {
                            $otherTasks++
                        }

                        "| $($sureBackupTask.Name) | $taskStatus |"
                    }
                    $processedTasks = $successfulTasks + $failedTasks + $warningTasks
                    if ($sureBackupTasks.Count -gt 0) {
                        $BodySureBackup += "`n| Last run | Result | State | Duration |`n"
                        $BodySureBackup += "|---|---|---|---|`n"
                        $BodySureBackup += "| $sessionStart | $sessionResult | $sessionState | $sessionDuration |`n"
                        $BodySureBackup += "`n| Task summary | Count |`n"
                        $BodySureBackup += "|---|---:|`n"
                        $BodySureBackup += "| Total tasks | $($sureBackupTasks.Count) |`n"
                        $BodySureBackup += "| Processed tasks | $processedTasks |`n"
                        $BodySureBackup += "| Successful tasks | $successfulTasks |`n"
                        $BodySureBackup += "| Failed tasks | $failedTasks |`n"
                        $BodySureBackup += "| Warning tasks | $warningTasks |`n"
                        $BodySureBackup += "| Skipped tasks | $skippedTasks |`n"
                        if ($otherTasks -gt 0) {
                            $BodySureBackup += "| Other or unclassified tasks | $otherTasks |`n"
                        }

                        $BodySureBackup += "`n##### VM verification details`n"
                        $BodySureBackup += "| VM | Status |`n"
                        $BodySureBackup += "|---|---|`n"
                        foreach ($taskRow in $taskRows) {
                            $BodySureBackup += "$taskRow`n"
                        }
                    }
                    else {
                        $BodySureBackup += "`n| Last run | Result | State | Duration |`n"
                        $BodySureBackup += "|---|---|---|---|`n"
                        $BodySureBackup += "| $sessionStart | $sessionResult | $sessionState | $sessionDuration |`n"
                        $BodySureBackup += "`nNo VM verification task details were returned for this session.`n"
                    }
                }
                catch {
                    $BodySureBackup += "Collection failed for this SureBackup job: $($_.Exception.Message)`n"
                }
            }
        }
    }
    catch {
        $BodySureBackup += "Unable to retrieve SureBackup jobs: $($_.Exception.Message)`n"
    }
}

Write-VeeamReportProgress -Status 'Finishing report' -PercentComplete 100
$Body += $Bodycopy
$Body += $BodySureBackup
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    $Body | Out-File -LiteralPath $OutputPath -Encoding UTF8 -ErrorAction Stop
    if (-not $NoOpen) {
        Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$OutputPath`"" -ErrorAction Stop
    }
}
$Body
}
finally {
    Write-Progress -Activity 'Generating Veeam report' -Completed
    if ($script:VbrConnected) {
        try {
            Disconnect-VBRServer -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Warning "Unable to disconnect from Veeam server '$Server': $($_.Exception.Message)"
        }
    }
}
