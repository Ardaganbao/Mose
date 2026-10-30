param ($server, $user, $pass, $Client , $Site)
# Save current directory
$SaveCurrentDir = (get-location).Path

$file = "$(Get-Date -format 'yyyy-MM-dd'   )_$($Client )_$($Site  )"
$rvtoolfile = "$file"
$root = "C:\Temp"


$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass)
$pass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
 
if ((Get-Command -Module *vmware*).Count -eq 0) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
  Install-Module PowerShellGet -RequiredVersion 2.2.4 -SkipPublisherCheck -Force

  Install-Module -Name VMware.PowerCLI -Scope CurrentUser -Force
  Import-Module VMware.PowerCLI
}
 

#$cmdArgList = @( 
#	"-s","$server", 
#	"-u","$user",
#	"-p","$pass",
#	"-c","ExportAll2xlsx",
#	"-d","$root\rvtool",
#	"-f","$rvtoolfile"
#	
#) 
#$cmdArgList
#Start-Process -FilePath "C:\Program Files (x86)\Dell\RVTools\RVTools.exe" -ArgumentList $cmdArgList -Wait
#$cmdArgList
 

function Convert-Bytes {
  param(
    [long]$bytes,
    [bool]$unit = $true
  )
  
  if (($bytes / 1TB) -gt 1) {
    $check = "{0:N2}" -f ($bytes / 1TB)
    $unit_s = " TB"
  }
  else {
    if (($bytes / 1GB) -gt 1) {
      $check = "{0:N2}" -f ($bytes / 1GB)
      $unit_s = " GB"
    }
    else {
      $check = "{0:N2}" -f ($bytes / 1MB)
      $unit_s = " MB"
    }
  }
  if ($unit) {
    $check += $unit_s
  }
  return $check
}
#Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $true
$connected = $false
try {
Write-Progress -Id 10 -Activity "VMware report: $Site" -Status 'Connecting to vCenter' -PercentComplete 0
Connect-VIServer -Server $server -User $user -Password $pass -Force
$connected = $true
Write-Progress -Id 10 -Activity "VMware report: $Site" -Status 'Loading inventory' -PercentComplete 5
#Import-Module -Name ImportExcel #-Scope CurrentUser -Force 

# import excel file and show in gridview (make sure file exists!)
#$Path = "$root\rvtool\$rvtoolfile.xlsx"
#$hostList = Import-Excel -Path $Path  -WorksheetName "vHost"
$hostlist = Get-VMHost | Sort-Object -Property "Name"
$datastoreList = Get-Datastore| Sort-Object -Property "Name"
#$datastoreList = Import-Excel -Path $Path  -WorksheetName "vDatastore"
#$vInfoList = Import-Excel -Path $Path  -WorksheetName "vInfo"|Sort-Object VM
$vInfoList = Get-VM| Sort-Object -Property "Name"

#$vMemoryList = Import-Excel -Path $Path  -WorksheetName "vMemory"
#$vPartitionList = Import-Excel -Path $Path  -WorksheetName "vPartition"|Sort-Object VM, Disk

 

$Body = "### VMware`n"
#$Body += "> :warning: You are running HPE Customized Image ESXi 6.0.0 Update 2 version 600.9.5.0.48 released on April 2016 and based on ESXi 6.0.0 Update 2 Vmkernel Release Build 3620759.`n"


$hostListMD = "### Check Host Esx`n"
$hostListMD += "| Host                      | CPU Model                                 | Speed | # Cores | CPU usage % | # Memory GB | Memory usage % |`n"
$hostListMD += "|---------------------------|-------------------------------------------|-------|---------|-------------|----------|----------------|`n"

$hostIndex = 0
foreach ($esxi in $hostList) { 
  $hostIndex++
  Write-Progress -Id 11 -ParentId 10 -Activity 'Collecting ESXi hosts' -Status $esxi.Name -PercentComplete ([math]::Round($hostIndex * 100 / [math]::Max(1, $hostList.Count)))
  $esxi = Get-VMHost $esxi.name
  $object = New-Object -TypeName PSObject
  $object | Add-Member -type NoteProperty -name HostName -value $esxi.Name
  $object | Add-Member -type NoteProperty -name Model -value $esxi.ExtensionData.summary.hardware.CPuModel
  $object | Add-Member -type NoteProperty -name CpuMhz -value $esxi.ExtensionData.summary.hardware.CpuMhz
  $object | Add-Member -type NoteProperty -name CpuSockets -value $esxi.ExtensionData.summary.hardware.NumCpuPkgs 
  $object | Add-Member -type NoteProperty -name CpuCores -value $esxi.ExtensionData.summary.hardware.NumCpuCores
  $object | Add-Member -type NoteProperty -name CpuThreds -value $esxi.ExtensionData.summary.hardware.NumCpuThreads

  $info = Get-VmHost $esxi.Name | Get-View 
  $Body += "`n#### $($esxi.ExtensionData.summary.config.name ) `n"

  $Body += "| Hardware            |                                                       |`n"
  $Body += "|---------------------|-------------------------------------------------------|`n"
  $Body += "| Manufacturer        | $($esxi.Manufacturer )                                                    |`n"
  $Body += "| Model               | $($esxi.Model )                                 |`n"
  $Body += "| CPU                 | $($object.CpuCores ) ( $($object.CpuCores/$object.CpuSockets) x $($object.CpuSockets) )  CPUs  x $( $esxi.ProcessorType ) |`n"
  $Body += "| Memory              | $( ([Math]::Round($esxi.MemoryTotalGB, 0)))  GB                                              |`n"
  $Body += "| Networking          | $($esxi.name )                            |`n"
  $Body += "| Overall  Status     |  $($info.OverallStatus)                                                      |`n"
  $Body += "| Storage             |                                                       |`n"
  $Body += "| - Nic | $(( $esxi | Get-VMHostNetworkAdapter).count )                                                      |`n"
  $Body += "`n"

  $Body += "| Configuration    |                                         |`n"
  $Body += "|------------------|-----------------------------------------|`n"
  $Body += "| ESX Version      | $($esxi.Version ) - $($esxi.Build ) |`n"
  $Body += "| vMotion          | $($esxi.ExtensionData.summary.config.VmotionEnabled)                           |`n"
  $Body += "`n"

  $Body += "| System Information |                                        |`n"
  $Body += "|--------------------|----------------------------------------|`n"

  $serviceTag = $($info.Hardware.SystemInfo.OtherIdentifyingInfo | Where-Object { $_.IdentifierType.Key -eq "ServiceTag"}).IdentifierValue


  $Body += "| Service tag        | $($serviceTag )                             |`n"
  $Body += "| BIOS version       | $($info.Hardware.BiosInfo.BiosVersion )                                    |`n"
  $Body += "| BIOS release date  | $($info.Hardware.BiosInfo.releaseDate)      |`n"
  $Body += "| Boot time          | $($Info.runtime.BootTime)     |`n"

  $object | Add-Member -type NoteProperty -name "CPU usage %" -value ([Math]::Round($esxi.CpuUsageMhz * 100 / $esxi.CpuTotalMhz))
  $object | Add-Member -type NoteProperty -name "Memory usage %" -value ([Math]::Round($esxi.MemoryUsageGB * 100 / $esxi.MemoryTotalGB))
    
  $hostListMD += "|$($esxi.ExtensionData.summary.config.name )|$( $object.Model )|$( $object.CpuMhz )|$($object.CpuCores)|$($object."CPU usage %" )|$([Math]::Round($esxi.MemoryUsageGB) )|$($object."Memory usage %" )|`n"

}
Write-Progress -Id 11 -ParentId 10 -Activity 'Collecting ESXi hosts' -Completed
Write-Progress -Id 10 -Activity "VMware report: $Site" -Status 'Collecting datastores' -PercentComplete 30

$Body += "`n"

$Body += $hostListMD

$datastoreListMD = "### Datastore Capacity`n"
$datastoreListMD += "| Name       | # VMs total | Capacity MiB | Provisioned GB | In Use MiB | Free MiB | Free % |`n"
$datastoreListMD += "|------------|-------------|--------------|-----------------|------------|----------|--------|`n"


 

$Volbarstacked = ""
$datastoreIndex = 0
foreach ($datastore in $datastoreList) {
  $datastoreIndex++
  Write-Progress -Id 12 -ParentId 10 -Activity 'Collecting datastores' -Status $datastore.Name -PercentComplete ([math]::Round($datastoreIndex * 100 / [math]::Max(1, $datastoreList.Count)))
  $VMs = $datastore | Get-VM
  $provisionGB = 0
  Foreach ($VM in $VMs) {
    $provisionGB += $VM.ProvisionedSpaceGB 

  }
  $datastoreListMD += "| $( $datastore.Name ) | $( ($datastore|get-vm).count  )         |  $( $datastore.CapacityMB )      |  $( [Math]::Round($provisionGB,2)  )         |  $( $datastore.CapacityMB- $datastore.FreeSpaceMB )    |  $($datastore.FreeSpaceMB  )   |  $( [Math]::Round($datastore.FreeSpaceMB*100/$datastore.CapacityMB)  )     |`n"
 
  $Volbarstacked += "``````Volbarstacked`n"
  $Volbarstacked += "| Disk % | $( $datastore.Name ) |`n"
  $Volbarstacked += "|--------|------------|`n"
  $Volbarstacked += "| Free   |  $( [Math]::Round($datastore.FreeSpaceMB*100/$datastore.CapacityMB))        |`n"
  $Volbarstacked += "```````n`n"
}
Write-Progress -Id 12 -ParentId 10 -Activity 'Collecting datastores' -Completed
Write-Progress -Id 10 -Activity "VMware report: $Site" -Status 'Collecting virtual machines and disks' -PercentComplete 45
$Body += "`n"

$Body += $datastoreListMD
$Body += "`n"
$Body += $Volbarstacked


$vInfoListMD = "### Vm Info`n" 
$vInfoListMD += "| Name       | Power state         | CPU         | RAM GB | Provisioned RAM GB |   Consumed RAM  MiB | Consumed RAM  % | OS|`n"
$vInfoListMD += "|------------|-------------|-------------|--------------------- |`n"

$vPartitionListMD = "### Vm Storage $(Get-Date -format 'dd/MM/yyyy'   )`n"
$vPartitionListMD += "| Disk   | Capacity GB |Free GB |Free %|`n"
$vPartitionListMD += "|------------|-------------|---------------------|------|`n"

$VolbarstackedL1 = "|Disk (%) | " 
$VolbarstackedL2 = "|--------|"
$VolbarstackedL3 = "| $(Get-Date -format 'dd/MM/yyyy'   )  |"
$vmIndex = 0
foreach ($vInfo in $vInfoList) {
  $vmIndex++
  Write-Progress -Id 13 -ParentId 10 -Activity 'Collecting virtual machines' -Status $vInfo.Name -PercentComplete ([math]::Round($vmIndex * 100 / [math]::Max(1, $vInfoList.Count)))
  $extra = Get-VMGuest $vInfo

  if ( $vInfo.Powerstate -eq "poweredOn") { 
    $Powerstate = "ON"
    # $vMemory = Get-Stat -Entity  $vInfo   -Memory   -IntervalMins 148  | Select-Object * -first 1
    $usage = ($vInfo | Get-Stat      -Realtime -MaxSamples 1 -Stat "mem.usage.average").Value
    $active = ($vInfo | Get-Stat      -Realtime -MaxSamples 1 -Stat "mem.active.average").Value
    $granted = ($vInfo | Get-Stat      -Realtime -MaxSamples 1 -Stat "mem.granted.average").Value
  }
  else {
    $usage = 0
    $active = 0
    $granted = 0
    $Powerstate = "OFF"
  }
  $vInfoListMD += "| $( $vInfo.Name )               |  $( $Powerstate  ) | $( $vInfo.NumCpu  )  |  $( $vInfo.MemoryMB  ) |   $( [Math]::Round(($granted/1024  ) ) )          |  $( [Math]::Round(($active/1024  ) ) )  |  $( [Math]::Round(($usage ) ) )       | $( $extra.OSFullName  )                |`n"
 

  $vPartitionList = $extra.Disks
  foreach ($vPartition in $vPartitionList) { 
  
    $vPartitionListMD += "| $( $vInfo.Name   ) $( $vPartition.Path   )   |$(  [Math]::Round( $vPartition.CapacityGB   )) | $([Math]::Round(  $vPartition.FreeSpaceGB   )) | $( [Math]::Round(($vPartition.FreeSpaceGB*100 / $vPartition.CapacityGB ) ) ) |`n"
 
  

    $VolbarstackedL1 += "$( $vInfo.Name   ) $( $vPartition.Path   )  |"
    $VolbarstackedL2 += "--------|"
    $VolbarstackedL3 += "  $( [Math]::Round(($vPartition.FreeSpaceGB*100 / $vPartition.CapacityGB ) ) )       |"

  }
}
Write-Progress -Id 13 -ParentId 10 -Activity 'Collecting virtual machines' -Completed
Write-Progress -Id 10 -Activity "VMware report: $Site" -Status 'Checking snapshots' -PercentComplete 90
$Body += "`n"

$Body += $vInfoListMD
$Body += "`n"
$Body += "(1) guest Memory usage`n"
$Body += "(2) Esxi Memory usage`n"


$Volbarstacked = "``````Volbarstacked`n" 
$Volbarstacked += "$VolbarstackedL1`n"
$Volbarstacked += "$VolbarstackedL2`n"
$Volbarstacked += "$VolbarstackedL3`n"
$Volbarstacked += "```````n`n"
$Body += "`n"

$Body += $vPartitionListMD
$Body += "`n"
$Body += $Volbarstacked
 

$vSnapshotListMD = "### Snapshot $(Get-Date -format 'dd/MM/yyyy'   )`n"
Write-Progress -Id 14 -ParentId 10 -Activity 'Checking snapshots' -Status 'Querying vCenter' -PercentComplete 0
$vsnapshotlist = get-vm | get-snapshot | Select-Object -property VM, Name, Created, @{Name='SizeGB';Expression={[math]::Round($_.SizeGB, 2)}}
$snapshotIndex = 0
$vsnapshotlist
if ($vsnapshotlist -eq $null) {$Body += "No snapshot"}

else {

$vSnapshotListMD += "| VM   | Name |Created |Size (GB)|`n"
$vSnapshotListMD += "|------------|-------------|---------------------|------|`n"

  foreach ($vSnapshot in $vSnapshotlist) { 
    $snapshotIndex++
    Write-Progress -Id 14 -ParentId 10 -Activity 'Checking snapshots' -Status $vSnapshot.VM -PercentComplete ([math]::Round($snapshotIndex * 100 / [math]::Max(1, $vsnapshotlist.Count)))
  
    $vSnapshotListMD += "| $( $vSnapshot.VM   ) | $( $vSnapshot.Name   )   | $($vSnapshot.Created) | $($vSnapshot.sizeGB) | `n"
    
 }
 }

$outfile = "$root\$file.md"
$Body
Write-Progress -Id 10 -Activity "VMware report: $Site" -Status 'Report complete' -PercentComplete 100
}
finally {
  Write-Progress -Id 11 -Activity 'Collecting ESXi hosts' -Completed
  Write-Progress -Id 12 -Activity 'Collecting datastores' -Completed
  Write-Progress -Id 13 -Activity 'Collecting virtual machines' -Completed
  Write-Progress -Id 14 -Activity 'Checking snapshots' -Completed
  Write-Progress -Id 10 -Activity "VMware report: $Site" -Completed
  if ($connected) {
    Disconnect-VIServer -Force -Server $server -Confirm:$false
  }
}
