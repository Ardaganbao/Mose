param (
    [Parameter(Mandatory = $true, HelpMessage = 'Lenovo BMC administrator credential')]
    [System.Management.Automation.PSCredential]$credential,

    [Parameter(Mandatory = $true, HelpMessage = 'Lenovo BMC IP address')]
    [string]$server
)

$retrycount = 3
$script:BmcSessions = [System.Collections.Generic.List[object]]::new()

if ([System.Net.ServicePointManager]::CertificatePolicy -ne "IDontCarePolicy") {
					add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
    
        public class IDontCarePolicy : ICertificatePolicy {
            public IDontCarePolicy() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@
					[System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy
				}

function Convert-Bytes
{
  param(
    [long]$bytes,
    [bool]$unit=$true
  )
  
  if (($bytes / 1TB) -gt 1) {
    $check = "{0:N2}" -f ($bytes / 1TB)
    $unit_s = " TB"
  } else {
      if (($bytes / 1GB) -gt 1) {
        $check = "{0:N2}" -f ($bytes / 1GB)
        $unit_s = " GB"
      } else {
        $check = "{0:N2}" -f ($bytes / 1MB)
        $unit_s = " MB"
      }
  }
  if($unit){
  $check += $unit_s
  }
  return $check
}
function New-BmcSession {
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Lenovo BMC administrator credential')]
        [System.Management.Automation.PSCredential]$credential,

        [Parameter(Mandatory = $true, HelpMessage = 'BMC object')]
        [object]$BMC
    )

    $passwordPointer = [IntPtr]::Zero
    try {
        $passwordPointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
        $credentialsJson = @{
            UserName = $credential.UserName
            Password = $plainPassword
        } | ConvertTo-Json

        $sessionServicePath = $BMC.SessionServicePath
        if ([string]::IsNullOrWhiteSpace([string]$sessionServicePath)) {
            $sessionServicePath = "$($BMC.root)/SessionService"
        }
        $sessionUri = "$($BMC.base)$($BMC.IP)$($sessionServicePath.TrimEnd('/'))/Sessions/"
        $sessionResponse = Invoke-WebRequest -Uri $sessionUri -Method Post -Body $credentialsJson -ContentType 'application/json' -UseBasicParsing -ErrorAction Stop -TimeoutSec 30

        if ($sessionResponse.StatusCode -ne 201) {
            throw "Failed to create Lenovo BMC session: Status Code $($sessionResponse.StatusCode)"
        }

        $sessionId = ($sessionResponse.Content | ConvertFrom-Json).Id
        if ([string]::IsNullOrWhiteSpace([string]$sessionId)) {
            throw 'The Lenovo BMC session response did not contain a session ID.'
        }
        $sessionToken = $sessionResponse.Headers['X-Auth-Token']
        if ([string]::IsNullOrWhiteSpace([string]$sessionToken)) {
            throw 'The Lenovo BMC session response did not contain an authentication token.'
        }

        $trackedSession = [PSCustomObject]@{
            Server = $BMC.IP
            SessionId = $sessionId
            Token = $sessionToken
            SessionUri = "$($sessionUri.TrimEnd('/'))/$sessionId"
        }
        $script:BmcSessions.Add($trackedSession)

        return [PSCustomObject]@{
            session = $sessionResponse
            version = 1
            sessionUri = $trackedSession.SessionUri
        }
    }
    finally {
        if ($passwordPointer -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
        }
        $plainPassword = $null
    }
}

function Close-BmcSession {
    param (
        [Parameter(Mandatory = $true)]
        [object]$trackedSession
    )

    $headers = @{ 'X-Auth-Token' = $trackedSession.Token }
    Invoke-WebRequest -Uri $trackedSession.SessionUri -Method Delete -Headers $headers -UseBasicParsing -ErrorAction Stop | Out-Null
    $script:BmcSessions.Remove($trackedSession) | Out-Null
}

function Invoke-BmcBootstrapRequest {
    param (
        [Parameter(Mandatory = $true)]
        [string]$uri
    )

    for ($attempt = 0; $attempt -le $retrycount; $attempt++) {
        try {
            return Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing -ErrorAction Stop -TimeoutSec 30
        }
        catch {
            if ($attempt -ge $retrycount) {
                throw "Failed to retrieve the Lenovo BMC entry point from $uri after $($retrycount + 1) attempts: $($_.Exception.Message)"
            }

            Write-Warning "Lenovo BMC entry point request failed; retrying ($($attempt + 1)/$retrycount): $($_.Exception.Message)"
            Start-Sleep -Milliseconds 500
        }
    }
}

function Invoke-BmcRedfishRequest {
    param (
        [Parameter(Mandatory = $true)]
        [string]$uri
    )

    for ($attempt = 0; $attempt -le $retrycount; $attempt++) {
        try {
            return Invoke-WebRequest -Uri $uri -Method Get -Headers $BMC.AuthHeaders -UseBasicParsing -ErrorAction Stop
        }
        catch {
            if ($attempt -ge $retrycount) {
                throw "Failed to retrieve data from $uri after $($retrycount + 1) attempts: $($_.Exception.Message)"
            }

            Write-Warning "Lenovo BMC request failed; renewing the session and retrying ($($attempt + 1)/$retrycount): $($_.Exception.Message)"
            $currentToken = $BMC.AuthHeaders['X-Auth-Token']
            foreach ($trackedSession in @($script:BmcSessions)) {
                if ($trackedSession.Token -eq $currentToken) {
                    try {
                        Close-BmcSession -trackedSession $trackedSession
                    }
                    catch {
                        Write-Warning "Could not close the expired Lenovo BMC session: $($_.Exception.Message)"
                    }
                    break
                }
            }

            $sessionInfo = New-BmcSession -credential $credential -BMC $BMC
            $BMC.session = $sessionInfo.session
            $BMC.AuthHeaders = @{
                Accept = 'application/json'
                'X-Auth-Token' = $sessionInfo.session.Headers['X-Auth-Token']
            }
        }
    }
}

try {
$BMC  = [PSCustomObject]@{

    session        = $null
    AuthHeaders = $null
    version        = $null
    Vendor = $null
    Product = $null
    SystemsPath = $null
    IP = $server
    root = "/redfish/v1"
    base = "https://"
    ManagersPath = $null
    ChassisPath = $null  
    SessionServicePath = $null
    ComputerSystems =  @()
    Chassis=  @()
    Managers=  @()
}

$url = "$($BMC.base)$($BMC.IP)$($BMC.root)"
$response = Invoke-BmcBootstrapRequest -Uri $url
$json = $response.Content 
$root =  (ConvertFrom-Json $json)


$BMC.version        = $root.RedfishVersion
$BMC.Vendor = $root.Vendor
$BMC.Product = $root.Product
$BMC.SystemsPath = $root.Systems.'@odata.id'
$BMC.ManagersPath = $root.Managers.'@odata.id'
$BMC.ChassisPath = $root.Chassis.'@odata.id' 
$BMC.SessionServicePath = $root.SessionService.'@odata.id'
   
#Chassis/1/Power
#Systems/1/Bios
$objsession = New-BmcSession -credential $credential -BMC $BMC
$BMC.session = $objsession.session
#$session = $objsession.session

#$AuthHeaders = @{ "X-Auth-Token" = $session.Headers.'X-Auth-Token' }
$BMC.AuthHeaders = @{"Accept"="application/json"; "X-Auth-Token" = $BMC.session.Headers.'X-Auth-Token' }
 
 
# Lenovo XClarity Controller exposes system, manager, chassis, and power data through Redfish.

if($BMC.SystemsPath -ne $null) {

    $url = "https://$($BMC.IP)$($BMC.SystemsPath)"
    $response = Invoke-BmcRedfishRequest -Uri $url
    $json = $response.Content 
 
  
    $paths =  (ConvertFrom-Json $json).Members
      
    foreach ($path in $paths) {
     
        $url = "https://$($BMC.IP)$($path."@odata.id")"
        $response = Invoke-BmcRedfishRequest -Uri $url
        $json = $response.Content          
        $currentComputerSystems = (ConvertFrom-Json $json)
        $BMC.ComputerSystems +=  $currentComputerSystems
    }
}

if($BMC.ChassisPath -ne $null) {

    $url = "https://$($BMC.IP)$($BMC.ChassisPath)"
    $response = Invoke-BmcRedfishRequest -Uri $url
    $json = $response.Content  
    $paths =  (ConvertFrom-Json $json).Members 
     
    foreach ($path in $paths) {
        $url = "https://$($BMC.IP)$($path."@odata.id")"
        $response = Invoke-BmcRedfishRequest -Uri $url
        $json = $response.Content 
        $currentChassis = (ConvertFrom-Json $json)
        $BMC.Chassis +=  $currentChassis
        $powerPaths = $currentChassis.power
        Add-Member -MemberType NoteProperty -Name 'Powers' -Value @()  -InputObject $currentChassis
        foreach ($powerPath in $powerPaths) {
            $url = "https://$($BMC.IP)$($powerPath."@odata.id")"
            $response = Invoke-BmcRedfishRequest -Uri $url
            $json = $response.Content 
            $currentpower = (ConvertFrom-Json $json)
            $currentChassis.Powers += $currentpower
             
        }
        $thermalPath = $currentChassis.Thermal.'@odata.id'
        Add-Member -MemberType NoteProperty -Name 'ThermalMetrics' -Value $null -InputObject $currentChassis
        if (-not [string]::IsNullOrWhiteSpace([string]$thermalPath)) {
            $url = "https://$($BMC.IP)$thermalPath"
            $response = Invoke-BmcRedfishRequest -Uri $url
            $currentChassis.ThermalMetrics = $response.Content | ConvertFrom-Json
        }
    }
}

 
if($BMC.ManagersPath -ne $null) {

    $url = "https://$($BMC.IP)$($BMC.ManagersPath)"
    $response = Invoke-BmcRedfishRequest -Uri $url
    $json = $response.Content 
 
  
    $paths =  (ConvertFrom-Json $json).Members
      
    foreach ($path in $paths) {
     
        $url = "https://$($BMC.IP)$($path."@odata.id")"
        $response = Invoke-BmcRedfishRequest -Uri $url
        $json = $response.Content 
        

        $currentManagers = (ConvertFrom-Json $json)
        $BMC.Managers +=  $currentManagers
        $ethernetinterfacesPaths = @()
        if ($currentManagers.EthernetInterfaces.'@odata.id') {
            $ethernetinterfacesPaths = @($currentManagers.EthernetInterfaces)
        }
        elseif ($currentManagers.EthernetInterfaces) {
            $ethernetinterfacesPaths = @($currentManagers.EthernetInterfaces)
        }
        Add-Member -MemberType NoteProperty -Name 'ethernetinterfacess' -Value @()  -InputObject $currentManagers
        foreach ($ethernetinterfacesPath in  $ethernetinterfacesPaths) {
            $interfacePath = $ethernetinterfacesPath.'@odata.id'
            if ([string]::IsNullOrWhiteSpace([string]$interfacePath)) {
                continue
            }
            $url = "https://$($BMC.IP)$interfacePath"
            $response = Invoke-BmcRedfishRequest -Uri $url
            $json = $response.Content 
            $current = (ConvertFrom-Json $json)
            foreach ($Member in  $current.Members) {
                
                $url = "https://$($BMC.IP)$($Member."@odata.id")"
                $response = Invoke-BmcRedfishRequest -Uri $url
                $json = $response.Content 
                $currentMember = (ConvertFrom-Json $json)
                $currentManagers.ethernetinterfacess += $currentMember
            }
            
             
        } 
 
  
 
 
    }
}  
 

 

function Format-BmcHealth {
    param (
        [AllowNull()]
        [string]$status
    )

    if ([string]::IsNullOrWhiteSpace($status)) {
        return 'N/A'
    }

    return $status
}

$computerSystem = @($BMC.ComputerSystems) | Select-Object -First 1
$manager = @($BMC.Managers) | Select-Object -First 1
$health = if ($computerSystem.Status.HealthRollup) { $computerSystem.Status.HealthRollup } else { $computerSystem.Status.Health }
$biosVersion = if ($computerSystem.BiosVersion) { $computerSystem.BiosVersion } else { 'N/A' }
$managerFirmware = if ($manager.FirmwareVersion) { $manager.FirmwareVersion } else { 'N/A' }
$managerHostname = @($manager.ethernetinterfacess | ForEach-Object { if ($_.FQDN) { $_.FQDN } elseif ($_.HostName) { $_.HostName } }) | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace([string]$managerHostname)) {
    $managerHostname = 'N/A'
}

$Body = "### Lenovo BMC Hardware Status ($($BMC.IP))`n"
$Body += "- General Health status : $(Format-BmcHealth $health)`n`n"
$Body += "| Information | Value |`n"
$Body += "|-------------|-------|`n"
$Body += "| Server Name | $($computerSystem.HostName) |`n"
$Body += "| Manufacturer | $($computerSystem.Manufacturer) |`n"
$Body += "| Product Name | $($computerSystem.Model) |`n"
$Body += "| Server Serial Number | $($computerSystem.SerialNumber) |`n"
$Body += "| Product ID | $($computerSystem.SKU) |`n"
$Body += "| BIOS Version | $biosVersion |`n"
$Body += "| BMC Firmware Version | $managerFirmware |`n"
$Body += "| BMC IP Address | $($BMC.IP) |`n"
$Body += "| BMC Hostname | $managerHostname |`n`n"

$Body += "| Subsystems and Devices | Status |`n"
$Body += "|------------------------|--------|`n"
$Body += "| System | $(Format-BmcHealth $health) |`n"
if (@($BMC.Managers).Count -gt 0) {
    foreach ($bmcManager in $BMC.Managers) {
        $managerHealth = if ($bmcManager.Status.HealthRollup) { $bmcManager.Status.HealthRollup } else { $bmcManager.Status.Health }
        $Body += "| Management Controller ($($bmcManager.Name)) | $(Format-BmcHealth $managerHealth) |`n"
    }
}
if (@($BMC.Chassis).Count -gt 0) {
    foreach ($chassis in $BMC.Chassis) {
        $chassisHealth = if ($chassis.Status.HealthRollup) { $chassis.Status.HealthRollup } else { $chassis.Status.Health }
        $Body += "| Chassis ($($chassis.Name)) | $(Format-BmcHealth $chassisHealth) |`n"

        foreach ($power in @($chassis.Powers)) {
            foreach ($redundancy in @($power.Redundancy)) {
                $Body += "| Power Redundancy ($($redundancy.Name)) | $(Format-BmcHealth $redundancy.Status.Health) |`n"
            }
            foreach ($powerSupply in @($power.PowerSupplies)) {
                $Body += "| Power Supply ($($powerSupply.Name)) | $(Format-BmcHealth $powerSupply.Status.Health) |`n"
            }
        }

        foreach ($fan in @($chassis.ThermalMetrics.Fans)) {
            $fanName = if ($fan.Name) { $fan.Name } else { $fan.FanName }
            $Body += "| Fan ($fanName) | $(Format-BmcHealth $fan.Status.Health) |`n"
        }
        foreach ($temperature in @($chassis.ThermalMetrics.Temperatures)) {
            $Body += "| Temperature ($($temperature.Name)) | $(Format-BmcHealth $temperature.Status.Health) |`n"
        }
    }
}


return $Body
}
finally {
    foreach ($trackedSession in @($script:BmcSessions)) {
        try {
            Close-BmcSession -trackedSession $trackedSession
        }
        catch {
            Write-Warning "Could not close Lenovo BMC session for $($trackedSession.Server): $($_.Exception.Message)"
        }
    }
    $script:BmcSessions.Clear()
}