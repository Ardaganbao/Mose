param (
    [Parameter(Mandatory = $true, HelpMessage = 'iDRAC admin credential')]
    [System.Management.Automation.PSCredential]$credential,

    [Parameter(Mandatory = $true, HelpMessage = 'iDRAC IP to connect to')]
    [string]$server
)

$retrycount = 3  
$script:IdracSessions = [System.Collections.Generic.List[object]]::new()

function New-IdracSession {
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'iDRAC admin credential')]
        [System.Management.Automation.PSCredential]$credential,

        [Parameter(Mandatory = $true, HelpMessage = 'iDRAC IP to connect to')]
        [string]$ip
    )

    # Convert SecureString to plain text (only in this context)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
    )

    $CredentialsJson = @{
        "UserName" = $($credential.UserName)
        "Password" = $($plainPassword)
    } | ConvertTo-Json

    $session = [PSCustomObject]@{
        session = $null
        version = 9
    }

    # Disable certificate checking
    if ([System.Net.ServicePointManager]::CertificatePolicy -ne "IDontCarePolicy") {
        add-type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class IDontCarePolicy : ICertificatePolicy {
                public IDontCarePolicy() {}
                public bool CheckValidationResult(ServicePoint sPoint, X509Certificate cert, WebRequest wRequest, int certProb) {
                    return true;
                }
            }
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object IDontCarePolicy
    }

    try {
        # Send the request to create a session
        $SessionJson = Invoke-WebRequest -Uri "https://$ip/redfish/v1/SessionService/Sessions/" `
            -Method Post `
            -Body $CredentialsJson `
            -ContentType "application/json" `
            -UseBasicParsing

        if ($SessionJson.StatusCode -eq 201) {
            $session.session = $SessionJson
            $sessionId = ($SessionJson.Content | ConvertFrom-Json).Id
            $script:IdracSessions.Add([PSCustomObject]@{
                Server = $ip
                SessionId = $sessionId
                Token = $SessionJson.Headers['X-Auth-Token']
            })
        }
        else {
            throw "Failed to create session: Status Code $($SessionJson.StatusCode)"
        }
    }
    catch {
        Write-Host "Error creating session: $_" -ForegroundColor Red
        throw "Failed to establish a session with iDRAC."
    }

    # Return the session details
    return $session
}

function Close-IdracSession {
    param (
        [Parameter(Mandatory = $true)]
        $session
    )

    $sessionId = ($session.sessionInfo.session.Content | ConvertFrom-Json).Id
    $sessionUri = "https://$($session.server)/redfish/v1/SessionService/Sessions/$sessionId"
    Invoke-WebRequest -Uri $sessionUri -Method Delete -Headers $session.auth -UseBasicParsing -ErrorAction Stop | Out-Null

    $token = $session.auth['X-Auth-Token']
    foreach ($trackedSession in @($script:IdracSessions)) {
        if ($trackedSession.Token -eq $token) {
            $script:IdracSessions.Remove($trackedSession) | Out-Null
        }
    }
}

function New-IdracSessionV2 {
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'iDRAC admin credential' )]
        [System.Management.Automation.PSCredential]$credential,

        [Parameter(Mandatory = $true, HelpMessage = 'iDRAC ip to connect to')]
        [string]$server
    )
    Write-Progress -Activity "creation session"

    # Create a new session with iDRAC
    $sessionInfo = New-IdracSession -ip $server -credential $credential
    if ($null -eq $sessionInfo) {
        Write-Error "Failed to establish a session with iDRAC."
        return
    }

    $AuthHeaders = @{
        "X-Auth-Token" = $sessionInfo.session.headers["X-Auth-Token"]
        "Content-Type" = "application/json"
    }
    Write-Progress -Activity "Determine the base URI based on the iDRAC version"
    # Determine the base URI based on the iDRAC version
    try {
        # Try Redfish v1 endpoint
        $baseUri = "https://$server/redfish/v1"
        Invoke-WebRequest -Uri "$baseUri" -Method Get -Headers $AuthHeaders -UseBasicParsing -ErrorAction Stop
        $version = 9
        $baseUri = "/redfish/v1"
    }
    catch {
        Write-Error "Failed to connect to iDRAC Redfish API: $_"
        throw $_

    }
    
    $session = @{}
    $session.add( 'auth', $AuthHeaders ) 
    $session.add( 'baseUri', $baseUri ) 
    $session.add( 'credential', $credential ) 
    $session.add( 'server', $server ) 
    $session.add( 'version', $version ) 
    $session.add( 'sessionInfo', $sessionInfo ) 
    
     $session
}

function Get-RedfishData {
    [CmdletBinding(DefaultParameterSetName = 'ServerEndpoint')]
    param(
        # First Parameter Set: Single endpoint 
        [Parameter(Mandatory, ParameterSetName = 'ServerEndpoint', Position = 0)]
        [string]$endpoint,

        # Second Parameter Set: Endpoint with server
        [Parameter(Mandatory = $true, ParameterSetName = 'ServerEndpoint')]
        [Parameter(Mandatory = $true, ParameterSetName = 'MultipleEndpoints')]
        [string]$server,

        # Third Parameter Set: Multiple endpoints with server
        [Parameter(Mandatory = $true, ParameterSetName = 'MultipleEndpoints')]
        [string[]]$endpoints,

        [Parameter(Mandatory, ParameterSetName = 'ServerEndpoint')]
        [Parameter(Mandatory, ParameterSetName = 'MultipleEndpoints')]
        $session,
        
        [Parameter( ParameterSetName = 'ServerEndpoint')]
        [Parameter(  ParameterSetName = 'MultipleEndpoints')]
        $retrynum = 0 

    )

   

    process {

        $return = $null
       
        Start-Sleep -Milliseconds 250

        switch ($PSCmdlet.ParameterSetName) {


            'ServerEndpoint' {

                try {
                    $URI = "https://$($server)$($endpoint)"
                    Write-Progress -Activity "Get-RedfishData ServerEndpoint : $URI   " -Id 4
                    $response = Invoke-WebRequest -Uri $URI -Method Get -Headers $session.auth -UseBasicParsing -ErrorAction Stop
                    $return = $response.Content | ConvertFrom-Json
                }
                catch {

                    if ($retrynum -le $retrycount ) {
                        $retrynum ++
                        Write-Error "retry login"
                        try {
                            Close-IdracSession -session $session
                        }
                        catch {
                            Write-Warning "Could not close expired iDRAC session: $($_.Exception.Message)"
                        }
                        Start-Sleep -Milliseconds 250
                        $session = New-IdracSessionV2 -server $server -credential $session.credential
                        Get-RedfishData $endpoint -server $server -session $session -retrynum  $retrynum

                    }
                    else {
                        Write-Error "retry done : Failed to retrieve data from $URI : $_"
                        throw $_

                    }
                }
            }

            'MultipleEndpoints' {
                $responses = @()
                Write-Progress -Activity "Get-RedfishData MultipleEndpoints : " -Id 2
                $index = 0
                foreach ($endpoint in $endpoints) {
                    Write-Progress -Activity "Endpoints : $($endpoint)" -Id 3 -PercentComplete (($index / $endpoints.Count) * 100)
                    $index = $index + 1
                    try {
                         
                        $response = Get-RedfishData $endpoint -server $server -session $session
                        
                        $responses += $response 
                    }
                    catch {
                        if ($retrynum -le $retrycount ) {
                            $retrynum ++
                            Write-Error "retry login"
                            try {
                                Close-IdracSession -session $session
                            }
                            catch {
                                Write-Warning "Could not close expired iDRAC session: $($_.Exception.Message)"
                            }
                            Start-Sleep -Milliseconds 250
                            $session = New-IdracSessionV2 -server $server -credential $session.credential
                            Get-RedfishData -endpoints $endpoints -server $server -session $session -retrynum  $retrynum

                        }
                        else {
                            Write-Error "retry done : Failed to retrieve data from $URI : $_"
                            throw $_

                        }
                    }
                }
                $return = $responses
            }
        }

        return  $return
    }
}
try {
$session = New-IDRACSessionV2 -server $server -credential $credential
$entrypoint = Get-RedfishData -server $server -endpoint $session.baseUri -session $session
$entrypointOB = Get-RedfishData  -server $server -endpoint $entrypoint.systems.'@odata.id' -session $session 
$ComputerSystems = Get-RedfishData  -server $server -endpoint $entrypointOB.Members.'@odata.id' -session $session 

# Retrieve data from various endpoints
 
$NetworkInterfaces = Get-RedfishData  -server $server -endpoint $ComputerSystems.NetworkInterfaces.'@odata.id' -session $session 
$NetworkInterfacesMembers = Get-RedfishData  -server $server -endpoints $NetworkInterfaces.Members.'@odata.id' -session $session 
$NetworkPorts = Get-RedfishData  -server $server -endpoints $NetworkInterfacesMembers.NetworkPorts.'@odata.id' -session $session 
$NetworkPortsMembers = Get-RedfishData  -server $server -endpoints $NetworkPorts.Members.'@odata.id' -session $session 

$ProcessorSummary = Get-RedfishData  -server $server -endpoints $ComputerSystems.Processors.'@odata.id' -session $session 
$ProcessorSummary = Get-RedfishData  -server $server -endpoints $ProcessorSummary.Members.'@odata.id' -session $session 

$Memories = Get-RedfishData  -server $server -endpoints $ComputerSystems.Memory.'@odata.id' -session $session 
$Memories = Get-RedfishData  -server $server -endpoints $Memories.Members.'@odata.id' -session $session 

$Storages = Get-RedfishData  -server $server -endpoints $ComputerSystems.Storage.'@odata.id' -session $session 
$Storagesall = Get-RedfishData  -server $server -endpoints $Storages.Members.'@odata.id' -session $session 

$Chassis = Get-RedfishData  -server $server -endpoint $ComputerSystems.Links.Chassis."@odata.id" -session $session 
$Thermal = Get-RedfishData  -server $server -endpoint $Chassis.Thermal."@odata.id" -session $session 

$Managers = Get-RedfishData  -server $server -endpoints $ComputerSystems.Links.ManagedBy."@odata.id"  -session $session 
$PowerMetrics_ = Get-RedfishData -server $server -endpoints $ComputerSystems.Links.PoweredBy."@odata.id" -session $session 
#$BiosSettings = Get-RedfishData -server $server -endpoint $ComputerSystems.Bios."@odata.id" 

$PowerMetrics = @{}

foreach ($PowerMetric_ in $PowerMetrics_) {
    $PowerMetrics[$PowerMetric_."@odata.id"] = $PowerMetric_
}
$PowerMetrics = $PowerMetrics.Values 


$fans = $Thermal.Fans
$fansstatus = ""
foreach ($fan in  $fans) {
    if ($fan.Status.Health -eq "OK") {
          
    }
    else {
        $fansstatus += "$($fan.FanName) $($fan.Status.Health) :x: - "
    }
}
if ($fansstatus -eq "") { $fansstatus = "All fans OK  :white_check_mark:" }

$PowerStatusHealth = "N/A"
if ( $null -ne $PowerMetrics.PowerSupplies[0]) {
    if ($PowerMetrics.PowerSupplies[0].Redundancy.Status.Health -eq "OK") {
        $PowerStatusHealth = "$($PowerMetrics.PowerSupplies[0].Redundancy.Status.Health) :white_check_mark:"
    }
    else {
        $PowerStatusHealth = "$($PowerMetrics.PowerSupplies[0].Redundancy.Status.Health) :x:"
    }
}
 
$Temperatures = $Thermal.Temperatures
$TemperaturesStatus = ""
foreach ($Temperature in  $Temperatures) {
    if ($null -ne $Temperature.Status.Health) {
        if ($Temperature.Status.Health -eq "OK") {
          
        }
        else {
         
            $TemperaturesStatus += "$($Temperature.Name) $($Temperature.Status.Health) :x: - "
        }
    }
}
if ($TemperaturesStatus -eq "") { $TemperaturesStatus = "All Temperature OK  :white_check_mark:" }

$NetworkPortStatus = ""
foreach ($NetworkPort in  $NetworkPortsMembers) {
    if ($null -ne $NetworkPort.Status.Health) {
        if ($NetworkPort.Status.Health -eq "OK") {
           
        }
        else {

            $NetworkPortStatus += "$($NetworkPort.Name) $($NetworkPort.Status.Health) :x: - "
        }
    }
    else { $NetworkPortStatus = $null }

}
if ($NetworkPortStatus -eq "") { $NetworkPortStatus = "All NetworkPort OK  :white_check_mark:" }

$StoragesStatus = "" 
$Storages = @()
foreach ($Storage in  $Storagesall) {
    if ($Storage.Drives.Count -gt 0) {
        $Storages += $Storage
    }
    if ($Storage.Status.Health -eq "OK") {

    }
    else {
        if ($Storage.Drives.Count -gt 0) {
            $StoragesStatus += "$($Storage.Name) $($Storage.Status.Health) :x: - "
        }
    }
}
if ($StoragesStatus -eq "") { $StoragesStatus = "All Storage OK  :white_check_mark:" }

$ProcessorsStatus = ""
foreach ($Processor in $ProcessorSummary) {
    if ($null -ne $Processor.Status.Health) {
        if ($Processor.Status.Health -eq "OK") {
           
        }
        else {

            $ProcessorsStatus += "$($Processor.ID) $($Processor.Status.Health) :x: - "
        }
    }
    else { $ProcessorsStatus = $null }

}
if ($ProcessorsStatus -eq "") { $ProcessorsStatus = "All Processors OK  :white_check_mark:" }

function Format-HealthStatus {
    param([AllowNull()][string]$Status)

    if ($Status -eq 'OK') {
        return 'OK :white_check_mark:'
    }

    if ([string]::IsNullOrWhiteSpace($Status)) {
        return 'Unknown :x:'
    }

    return "$Status :x:"
}

# Build the report body
$Body = "### Check Status Hardware (iDRAC:  $($server))`n"
$Body += "- General Health status : $(Format-HealthStatus $ComputerSystems.Status.Health)`n`n"

$Body += "| Information               |                                          |`n"
$Body += "|---------------------------|------------------------------------------|`n"
$Body += "| Server Name               | $($ComputerSystems.HostName)             |`n"
$Body += "| Product Name              | $($ComputerSystems.Model)                |`n"
$Body += "| Server Serial Number      | $($ComputerSystems.SerialNumber)         |`n"
$Body += "| Product ID                | $($ComputerSystems.SKU)                  |`n"
$Body += "| System BIOS Version       | $($ComputerSystems.BiosVersion)          |`n"
$Body += "| iDRAC Firmware Version    | $($Managers.FirmwareVersion)             |`n"
$Body += "| IPv4 Address              | $($server)                               |`n"

$Body += "`n"

# Check health status of subsystems
$Body += "| Subsystems and Devices    | Status                                                                                           |`n"
$Body += "|---------------------------|-----------------------------------------------------------------------------------------------|`n"


$Body += "| Power Supply Redundancy   | $($PowerStatusHealth) |`n"
foreach ($PowerSupplies in $PowerMetrics.PowerSupplies) {
    $Body += "| Power Supplie   $($PowerSupplies.MemberId)         | $(Format-HealthStatus $PowerSupplies.Status.Health) |`n"
}
$Body += "| Fans                      | $($fansstatus) |`n"
$Body += "| Temperatures              | $($TemperaturesStatus) |`n"
if ($null -ne $NetworkPortStatus) {
    $Body += "| Network Interfaces        | $($NetworkPortStatus) |`n"
}
$Body += "| Storage Controllers       | $($StoragesStatus) |`n"
$Body += "| Memory                    | $(Format-HealthStatus $ComputerSystems.MemorySummary.Status.Health) |`n"
$Body += "| Processors                | $(Format-HealthStatus $ComputerSystems.ProcessorSummary.Status.Health) |`n"

$temperatureValues = @($Temperatures | Where-Object { $null -ne $_.ReadingCelsius } | ForEach-Object { [double]$_.ReadingCelsius })
$Body += "`n#### Environmental and Power Readings`n"
if ($temperatureValues.Count -gt 0) {
    $averageTemperature = [math]::Round(($temperatureValues | Measure-Object -Average).Average, 1)
    $maximumTemperature = ($temperatureValues | Measure-Object -Maximum).Maximum
    $minimumTemperature = ($temperatureValues | Measure-Object -Minimum).Minimum
    $Body += "Temperature range: $minimumTemperature-$maximumTemperature C; average: $averageTemperature C.`n`n"
}

$Body += "| Temperature Sensor | Reading (C) | Health |`n"
$Body += "|--------------------|-------------|--------|`n"
if (@($Temperatures).Count -eq 0) {
    $Body += "| No temperature sensors reported | N/A | N/A |`n"
}
else {
    foreach ($Temperature in $Temperatures) {
        $reading = if ($null -ne $Temperature.ReadingCelsius) { $Temperature.ReadingCelsius } else { 'N/A' }
        $health = Format-HealthStatus $Temperature.Status.Health
        $Body += "| $($Temperature.Name) | $reading | $health |`n"
    }
}

$Body += "`n| Fan | Speed | Health |`n"
$Body += "|-----|-------|--------|`n"
if (@($fans).Count -eq 0) {
    $Body += "| No fans reported | N/A | N/A |`n"
}
else {
    foreach ($fan in $fans) {
        $speed = if ($null -ne $fan.Reading) { "$($fan.Reading) $($fan.ReadingUnits)".Trim() } else { 'N/A' }
        $health = Format-HealthStatus $fan.Status.Health
        $fanName = if ($fan.FanName) { $fan.FanName } else { $fan.Name }
        $Body += "| $fanName | $speed | $health |`n"
    }
}

$powerSupplies = @($PowerMetrics.PowerSupplies)
$Body += "`n| Power Supply | Capacity (W) | Input (W) | Output (W) | Input Voltage (V) | Health |`n"
$Body += "|--------------|--------------|-----------|------------|-------------------|--------|`n"
if ($powerSupplies.Count -eq 0) {
    $Body += "| No power supply readings reported | N/A | N/A | N/A | N/A | N/A |`n"
}
else {
    foreach ($powerSupply in $powerSupplies) {
        $capacity = if ($null -ne $powerSupply.PowerCapacityWatts) { $powerSupply.PowerCapacityWatts } else { 'N/A' }
        $inputWatts = if ($null -ne $powerSupply.PowerInputWatts) { $powerSupply.PowerInputWatts } else { 'N/A' }
        $output = if ($null -ne $powerSupply.PowerOutputWatts) { $powerSupply.PowerOutputWatts } else { 'N/A' }
        $voltage = if ($null -ne $powerSupply.LineInputVoltage) { $powerSupply.LineInputVoltage } else { 'N/A' }
        $health = Format-HealthStatus $powerSupply.Status.Health
        $powerSupplyName = if ($powerSupply.MemberId) { $powerSupply.MemberId } else { $powerSupply.Name }
        $Body += "| $powerSupplyName | $capacity | $inputWatts | $output | $voltage | $health |`n"
    }
}

 

$Body += "`n#### Check Processor Status  `n" 
# controler  Information Table
if ($null -ne $ProcessorSummary  ) {
    $Body += "| Model | Name | Brand | Total Cores | Health | Total Memory Size Gb  |`n"
    $Body += "|-----------|-------|-------|---------------|--------|--------|`n"
    foreach ($Processor  in $ProcessorSummary) {
        $ProcessorSummaryStatus = Format-HealthStatus $Processor.Status.Health

        
        $Body += "| $($Processor.Model) | $($Processor.Name) | $($Processor.Manufacturer) | $($Processor.TotalCores) | $($ProcessorSummaryStatus) | $([math]::Round($Processor.MemorySummary.TotalMemorySizeMiB /1024 , 2)) |`n"
    }
}
else {
    $Body += "No Processor data available.`n"
}
       
 
$Body += "`n#### Check Memories Status  `n" 
# controler  Information Table
if ($null -ne $Memories ) {
    $Body += "| PartNumber | Type | Position | Health | Total Memory Size Gb  |`n"
    $Body += "|-----------|-------|-------|---------------|--------|`n"
    foreach ($Memory  in $Memories) {
        $Memorystatus = Format-HealthStatus $Memory.Status.Health

        
        $Body += "| $($Memory.PartNumber) | $($Memory.MemoryDeviceType) | $($Memory.DeviceLocator) | $($Memorystatus) | $([math]::Round($Memory.CapacityMiB /1024 , 2)) |`n"
    }
}
else {
    $Body += "No Processor data available.`n"
}

# Function to retrieve   controller information
function Get-ControllerInfo {
    param (
        [string]$baseUri , 
        [string]$server, 
        $Storages
         
    )
    $ControllersInfo = @()
    $DrivesInfo = @()
    $VolumesInfo = @()
    foreach ($Storage in $Storages) {  
        $Controllers = Get-RedfishData -server $server -endpoint $Storage.Controllers.'@odata.id' -session $session 
        $Controller = Get-RedfishData -server $server -endpoints $Controllers.Members.'@odata.id' -session $session 
        $Assembly = Get-RedfishData -server $server -endpoint $Controller.Assembly.'@odata.id' -session $session 
        $drives = Get-RedfishData -server $server -endpoints $Storage.Drives.'@odata.id' -session $session 
        $Volumes = Get-RedfishData -server $server -endpoints $Storage.Volumes.'@odata.id' -session $session 
        $Volumes = Get-RedfishData -server $server -endpoints $Volumes.Members.'@odata.id' -session $session 


        
        $StatusHealth = if ($Controller.Status.Health -eq "OK") {
            "$( $Controller.Status.Health ) :white_check_mark:"
        }
        else {
            "$($Controller.Status.Health) :x:"
        }

        $ControllerInfo = [PSCustomObject]@{ ID = $Controller.Id  
            PartNumber                          = $Assembly.Assemblies[0].PartNumber
            Status                              = $StatusHealth 
            Model                               = $Controller.Model
            Vendor                              = $Assembly.Assemblies[0].Vendor
            FirmwareVersion                     = $Controller.FirmwareVersion
            SlotDisk                            = $Controller.InternalPortCount
        }  
        $ControllersInfo += $ControllerInfo
        foreach ($drive in $drives) {  
            $DriveStatusHealth = if ($drive.Status.Health -eq "OK") {
                "$($drive.Status.Health) :white_check_mark:"
            }
            else {
                "$($drive.Status.Health) :x:"
            }
            $DriveInfo = [PSCustomObject]@{ DiskSlot = $drive.Name  
                SerialNumber                         = $drive.SerialNumber
                DiskHealth                           = $DriveStatusHealth 
                DiskModel                            = $drive.Model
                DiskVendor                           = $drive.Manufacturer
                MediaType                            = $drive.MediaType 
                HotspareType                         = $drive.HotspareType
                DiskCapacityGB                       = [math]::Round($drive.CapacityBytes / 1GB , 2)
            } 
               


            $DrivesInfo += $DriveInfo
        }
        foreach ($Volume in $Volumes) {  
            $VolumeStatusHealth = if ($Volume.Status.Health -eq "OK") {
                "$($Volume.Status.Health) :white_check_mark:"
            }
            else {
                "$($Volume.Status.Health) :x:"
            }
            $VolumeInfo = [PSCustomObject]@{
                    
                Name        = $Volume.Name
                  
                DiskHealth  = $VolumeStatusHealth 
                Raid        = $Volume.RAIDType
                CapacityGiB = [math]::Round($Volume.CapacityBytes / 1GB , 2)
            }
            $VolumesInfo += $VolumeInfo
        }
    } 
    return @($ControllersInfo , $DrivesInfo, $VolumesInfo)
}

$returnInfo = Get-ControllerInfo $baseUri $server $Storages
$controlerInfo = $returnInfo[0]
$diskInfo = $returnInfo[1]
$volumeInfo = $returnInfo[2]

# Report Formatting
$Body += "`n#### Check Controlers Status  `n" 
# controler  Information Table
if ($null -ne $controlerInfo ) {
    $Body += "| controler ID | PartNumber | Brand | Model | Health | FirmwareVersion |`n"
    $Body += "|-----------|-------|-------|---------------|--------|--------|`n"
    foreach ($controler in $controlerInfo) {
     

        
        $Body += "| $($controler.ID) | $($controler.PartNumber) | $($controler.Vendor) | $($controler.Model) | $($controler.Status) | $($controler.FirmwareVersion) |`n"
    }
}
else {
    $Body += "No Controlers data available.`n"
}
$Body += "`n#### Check Disks  Status  `n" 

# Disk Information Table
if ($diskInfo.Count -gt 0) {
    $Body += "| Disk Slot | Brand| Model |SerialNumber | MediaType| Capacity (GB) | Health |`n"
    $Body += "|-----------|-------|-------|---------|------|------|--------|`n"
    foreach ($disk in $diskInfo) {
             
        $Body += "| $($disk.DiskSlot) | $($disk.DiskVendor) | $($disk.DiskModel) | $($disk.SerialNumber) | $($disk.MediaType) | $($disk.DiskCapacityGB) |$($disk.DiskHealth) |`n"
    }
}
else {
    $Body += "No physical disk data available.`n"
}
$Body += "`n#### Check Volumes  Status  `n" 

# Volume Information Table
if ($volumeInfo.Count -gt 0) { 
    $Body += "| Name | Volume Raid type | Capacity (GB) | Health |`n"
    $Body += "|-----------|-------------|---------------|--------|`n"
    foreach ($volume in $volumeInfo) {

          
        $Body += "| $($volume.Name) | $($volume.Raid) | $($volume.CapacityGiB) | $($Volume.DiskHealth) |`n"
    }
}
else {
    $Body += "No volume data available.`n"
}
 


# Output the report
return $Body
}
finally {
    foreach ($trackedSession in @($script:IdracSessions)) {
        try {
            $headers = @{ 'X-Auth-Token' = $trackedSession.Token }
            $sessionUri = "https://$($trackedSession.Server)/redfish/v1/SessionService/Sessions/$($trackedSession.SessionId)"
            Invoke-WebRequest -Uri $sessionUri -Method Delete -Headers $headers -UseBasicParsing -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Warning "Could not close iDRAC session for $($trackedSession.Server): $($_.Exception.Message)"
        }
    }
    $script:IdracSessions.Clear()
    Write-Progress -Activity 'iDRAC session setup' -Id 0 -Completed
    Write-Progress -Activity 'Redfish endpoint collection' -Id 2 -Completed
    Write-Progress -Activity 'Redfish endpoint iteration' -Id 3 -Completed
    Write-Progress -Activity 'Redfish endpoint request' -Id 4 -Completed
}
