[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'ILO admin credential')]
    [System.Management.Automation.PSCredential]$credential,

    [Parameter(Mandatory = $true, HelpMessage = 'ILO IP to connect to')]
    [string]$server,

    [Parameter(HelpMessage = 'File path for storage diagnostics. Supplying this also enables storage debug logging.')]
    [string]$StorageDebugPath
)

$script:StorageDebugEnabled = $PSBoundParameters.ContainsKey('Debug') -or
    -not [string]::IsNullOrWhiteSpace($StorageDebugPath)
if ($script:StorageDebugEnabled) {
    $DebugPreference = 'Continue'
    if ([string]::IsNullOrWhiteSpace($StorageDebugPath)) {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $StorageDebugPath = Join-Path $PSScriptRoot "iLO_Storage_Debug_${server}_$timestamp.log"
    }

    $debugDirectory = Split-Path -Path $StorageDebugPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($debugDirectory) -and -not (Test-Path -LiteralPath $debugDirectory)) {
        New-Item -Path $debugDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    [System.IO.File]::WriteAllText(
        $StorageDebugPath,
        "iLO storage diagnostics for $server`r`nStarted: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')`r`n`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    Write-Host "iLO storage debug log: $StorageDebugPath" -ForegroundColor Cyan
}

$retrycount = 3  
$script:HpSessions = [System.Collections.Generic.List[object]]::new()
$script:OriginalServerCertificateValidationCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback

function Write-StorageDebugSnapshot {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [AllowNull()]
        [object]$Data
    )

    if (-not $script:StorageDebugEnabled) {
        return
    }

    $snapshot = ConvertTo-Json -InputObject $Data -Depth 20 -Compress
    $record = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')] [iLO storage] $Label`r`n$snapshot`r`n`r`n"
    Write-Debug $record.TrimEnd()
    if ($script:StorageDebugEnabled) {
        [System.IO.File]::AppendAllText($StorageDebugPath, $record, [System.Text.UTF8Encoding]::new($false))
    }
}

function New-HpSession {
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'ILO admin credential')]
        [System.Management.Automation.PSCredential]$credential,

        [Parameter(Mandatory = $true, HelpMessage = 'ILO IP to connect to')]
        [string]$ip
    )

    # Convert SecureString to plain text (only in this context)
    $passwordPointer = [IntPtr]::Zero
    $plainPassword = $null
    try {
        if ([System.Net.ServicePointManager]::SecurityProtocol -ne [System.Net.SecurityProtocolType]::SystemDefault) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        }
        $passwordPointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
        $CredentialsJson = @{
            UserName = $credential.UserName
            Password = $plainPassword
        } | ConvertTo-Json -Depth 3

    $session = [PSCustomObject]@{
        session = $null
        version = 5
    }

    # Use a compiled callback because .NET may invoke certificate validation on a worker thread.
    if (-not ('ILORemoteCertificateValidation' -as [type])) {
        Add-Type -TypeDefinition @"
            using System.Net.Security;
            using System.Security.Cryptography.X509Certificates;
            public static class ILORemoteCertificateValidation {
                public static bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
                    return true;
                }
            }
"@ -ErrorAction Stop
    }
    $certificateCallback = [Delegate]::CreateDelegate(
        [System.Net.Security.RemoteCertificateValidationCallback],
        [ILORemoteCertificateValidation],
        'Validate'
    )
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $certificateCallback
        try {
            $entrypointResponse = Invoke-WebRequest -Uri "https://$ip/redfish/v1" -Method Get -UseBasicParsing -ErrorAction Stop -TimeoutSec 30
            $entrypoint = $entrypointResponse.Content | ConvertFrom-Json
            $SessionServiceURI = $entrypoint.SessionService.'@odata.id'
            if ([string]::IsNullOrWhiteSpace([string]$SessionServiceURI)) {
                throw 'The Redfish entry point does not provide a SessionService URI.'
            }

            $sessionUri = "https://$ip$($SessionServiceURI.TrimEnd('/'))/Sessions"
            $sessionVersion = 5
        }
        catch {
            $response = $_.Exception.Response
            $statusCode = $null
            if ($null -ne $response -and $null -ne $response.PSObject.Properties['StatusCode']) {
                $statusCode = [int]$response.StatusCode
            }
            if ($statusCode -notin @(404, 405)) {
                $tlsProtocols = [System.Net.ServicePointManager]::SecurityProtocol
                throw "Failed to discover the iLO Redfish session endpoint at https://$ip/redfish/v1. Enabled TLS protocols: $tlsProtocols. Details: $($_.Exception.ToString())"
            }

            $entrypoint = $null
            $sessionUri = "https://$ip/rest/v1/Sessions"
            $sessionVersion = 4
        }

        try {
            $sessionRequestUri = [Uri]$sessionUri
            $redirectCount = 0
            while ($true) {
                try {
                    $SessionJson = Invoke-WebRequest -Uri $sessionRequestUri.AbsoluteUri -TimeoutSec 30 `
                        -Method Post `
                        -Body $CredentialsJson `
                        -ContentType "application/json" `
                        -UseBasicParsing `
                        -ErrorAction Stop
                    break
                }
                catch {
                    $response = $_.Exception.Response
                    $statusCode = $null
                    if ($null -ne $response -and $null -ne $response.PSObject.Properties['StatusCode']) {
                        $statusCode = [int]$response.StatusCode
                    }
                    if ($statusCode -ne 308) {
                        throw
                    }

                    $location = $response.Headers['Location']
                    if ([string]::IsNullOrWhiteSpace([string]$location)) {
                        throw 'The iLO returned HTTP 308 without a Location header.'
                    }
                    if ($redirectCount -ge 3) {
                        throw 'The iLO session endpoint exceeded the maximum of three HTTP 308 redirects.'
                    }

                    $redirectUri = [Uri]::new($sessionRequestUri, $location)
                    if ($redirectUri.Scheme -ne 'https' -or
                        $redirectUri.Host -ne $sessionRequestUri.Host -or
                        $redirectUri.Port -ne $sessionRequestUri.Port) {
                        throw "The iLO session endpoint redirected to a different HTTPS origin: $redirectUri"
                    }

                    Write-Verbose "Following iLO session endpoint redirect to $redirectUri"
                    $sessionRequestUri = $redirectUri
                    $redirectCount++
                }
            }

            if ($SessionJson.StatusCode -ne 201) {
                throw "Failed to create session: Status Code $($SessionJson.StatusCode)"
            }

            $sessionId = ($SessionJson.Content | ConvertFrom-Json).Id
            if ([string]::IsNullOrWhiteSpace([string]$sessionId)) {
                throw 'The iLO session response did not contain a session ID.'
            }
            $sessionToken = $SessionJson.Headers['X-Auth-Token']
            if ([string]::IsNullOrWhiteSpace([string]$sessionToken)) {
                throw 'The iLO session response did not contain an authentication token.'
            }

            $sessionDeleteUri = $SessionJson.Headers['Location']
            if ([string]::IsNullOrWhiteSpace([string]$sessionDeleteUri)) {
                $sessionDeleteUri = "$($sessionRequestUri.AbsoluteUri.TrimEnd('/'))/$sessionId"
            }
            else {
                $sessionDeleteUri = ([Uri]::new($sessionRequestUri, [string]$sessionDeleteUri)).AbsoluteUri
            }
            $session.session = $SessionJson
            $session.version = $sessionVersion
            $script:HpSessions.Add([PSCustomObject]@{
                Server = $ip
                SessionId = $sessionId
                Token = $sessionToken
                SessionUri = $sessionDeleteUri
            })
            Add-Member -InputObject $session -type NoteProperty -Name entrypoint -Value $entrypoint
            Add-Member -InputObject $session -type NoteProperty -Name sessionUri -Value $sessionDeleteUri
            return $session
        }
        catch {
            Write-Host "Error creating session: $_" -ForegroundColor Red
            throw "Failed to establish a session with iLO at https://$ip. Enabled TLS protocols: $([System.Net.ServicePointManager]::SecurityProtocol). Details: $($_.Exception.ToString())"
        }
    }
    finally {
        if ($passwordPointer -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
        }
        $plainPassword = $null
    }
}

function Close-HpSession {
    param (
        [Parameter(Mandatory = $true)]
        [object]$session
    )

    $token = $session.auth['X-Auth-Token']
    $trackedSession = @($script:HpSessions | Where-Object { $_.Token -eq $token }) | Select-Object -First 1
    if ($null -eq $trackedSession) {
        return
    }

    Invoke-WebRequest -Uri $trackedSession.SessionUri -Method Delete -Headers $session.auth -UseBasicParsing -ErrorAction Stop | Out-Null
    $script:HpSessions.Remove($trackedSession) | Out-Null
}
function New-HpSessionV2 {
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'ILO admin credential' )]
        [System.Management.Automation.PSCredential]$credential,

        [Parameter(Mandatory = $true, HelpMessage = 'ILO ip to connect to')]
        [string]$server
    )
    Write-Progress -Activity "creation session"

    # Create a new session with iLO
    $sessionInfo = New-HpSession -ip $server -credential $credential
    if ($null -eq $sessionInfo ) {
        throw "Failed to establish a session with iLO."
    } 

    $AuthHeaders = @{
        "X-Auth-Token" = $sessionInfo.session.headers["X-Auth-Token"]
        "Content-Type" = "application/json"
    }
    Write-Progress -Activity "Determine the base URI based on the iLO version"
    # Determine the base URI based on the iLO version
    if ($sessionInfo.version -eq 4) {
        $version = 4
        $baseUri = "/rest/v1"
    }
    else {
        $version = 5
        $baseUri = "/redfish/v1"
    }


 
	$sessionreturn = New-Object -TypeName PSObject 

	Add-Member -InputObject $sessionreturn -type NoteProperty -name auth -value $AuthHeaders
	Add-Member -InputObject $sessionreturn -type NoteProperty -name baseUri -value $baseUri
	Add-Member -InputObject $sessionreturn -type NoteProperty -name credential -value $credential
	Add-Member -InputObject $sessionreturn -type NoteProperty -name server -value $server
	Add-Member -InputObject $sessionreturn -type NoteProperty -name version -value $version
	Add-Member -InputObject $sessionreturn -type NoteProperty -name sessionInfo -value $sessionInfo
	Add-Member -InputObject $sessionreturn -type NoteProperty -name Content -value $sessionInfo.Content
	Add-Member -InputObject $sessionreturn -type NoteProperty -name entrypoint -value $sessionInfo.entrypoint
	Add-Member -InputObject $sessionreturn -type NoteProperty -name sessionUri -value $sessionInfo.sessionUri
	return $sessionreturn
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

        if ($null -ne $script:CurrentHpSession -and $script:CurrentHpSession.server -eq $server) {
            $session = $script:CurrentHpSession
        }
       
        Start-Sleep -Milliseconds 250

        switch ($PSCmdlet.ParameterSetName) {


            'ServerEndpoint' {

                try {
                    $URI = "https://$($server)$($endpoint)"
                    Write-Progress -Activity "Get-RedfishData ServerEndpoint : $URI   " -Id 4
                    $response = Invoke-WebRequest -Uri $URI -Method Get -Headers $session.auth -UseBasicParsing -ErrorAction Stop -TimeoutSec 30
                    $return = $response.Content | ConvertFrom-Json
                }
                catch {

                    if ($retrynum -le $retrycount ) {
                        $retrynum ++
                        Write-Error "retry login"
                        Start-Sleep -Milliseconds 250
                        try {
                            Close-HpSession -session $session
                        }
                        catch {
                            Write-Warning "Could not close the expired iLO session: $($_.Exception.Message)"
                        }
                        Start-Sleep -Milliseconds 250
                        $session = New-HpSessionV2 -server $server -credential $session.credential
                        $script:CurrentHpSession = $session
                        return (Get-RedfishData $endpoint -server $server -session $session -retrynum $retrynum)

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
                    $response = Get-RedfishData $endpoint -server $server -session $session -retrynum $retrynum
                    $responses += $response
                }
                $return = $responses
            }
        }
        Write-StorageDebugSnapshot -Label "RedfishData: $URI" -Data $return

        return  $return
    }
}

function Get-RedfishCollectionResources {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [string]$CollectionUri,

        [Parameter(Mandatory = $true)]
        [object]$Session
    )

    if ([string]::IsNullOrWhiteSpace($CollectionUri)) {
        return @()
    }

    if ([Uri]::IsWellFormedUriString($CollectionUri, [UriKind]::Absolute)) {
        $collectionUriObject = [Uri]$CollectionUri
        if ($collectionUriObject.Scheme -ne 'https' -or $collectionUriObject.Host -ne $Server) {
            throw "Redfish collection URI must use HTTPS and the requested iLO host: $CollectionUri"
        }
        $CollectionUri = $collectionUriObject.PathAndQuery
    }

    $collection = Get-RedfishData -server $Server -endpoint $CollectionUri -session $Session
    Write-StorageDebugSnapshot -Label "Collection response: $CollectionUri" -Data $collection
    $memberEntries = @($collection.Members | Where-Object { $null -ne $_ })
    if ($memberEntries.Count -eq 0) {
        $memberEntries = @($collection.links.Member | Where-Object { $null -ne $_ })
    }
    if ($memberEntries.Count -eq 0) {
        $memberEntries = @($collection.links.Members | Where-Object { $null -ne $_ })
    }

    $memberUris = @(
        $memberEntries |
            ForEach-Object {
                $memberUri = $_.'@odata.id'
                if ([string]::IsNullOrWhiteSpace([string]$memberUri)) {
                    $memberUri = $_.href
                }
                if ([string]::IsNullOrWhiteSpace([string]$memberUri)) {
                    $memberUri = $_.Links.Self.href
                }
                if (-not [string]::IsNullOrWhiteSpace([string]$memberUri)) {
                    if ([Uri]::IsWellFormedUriString([string]$memberUri, [UriKind]::Absolute)) {
                        $memberUriObject = [Uri]$memberUri
                        if ($memberUriObject.Scheme -ne 'https' -or $memberUriObject.Host -ne $Server) {
                            throw "Redfish member URI must use HTTPS and the requested iLO host: $memberUri"
                        }
                        $memberUriObject.PathAndQuery
                    }
                    else {
                        [string]$memberUri
                    }
                }
            } |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    )
    Write-StorageDebugSnapshot -Label "Member URIs: $CollectionUri" -Data $memberUris
    if ($memberUris.Count -eq 0) {
        $resourceMembers = @($memberEntries | Where-Object {
            $null -ne $_ -and
            [string]::IsNullOrWhiteSpace([string]$_.'@odata.id') -and
            [string]::IsNullOrWhiteSpace([string]$_.href) -and
            $null -ne $_.PSObject.Properties['Status']
        })
        if ($resourceMembers.Count -gt 0) {
            Write-Verbose "iLO collection '$CollectionUri' returned embedded member resources."
            return $resourceMembers
        }

        Write-Verbose "No member links returned by iLO collection '$CollectionUri'. Collection fields: $($collection.PSObject.Properties.Name -join ', ')"
        return @()
    }

    Write-Verbose "iLO collection '$CollectionUri' returned $($memberUris.Count) member links."
    $resources = @(Get-RedfishData -server $Server -endpoints $memberUris -session $Session)
    Write-StorageDebugSnapshot -Label "Resolved resources: $CollectionUri" -Data $resources
    return $resources
}

try {
$session = New-HpSessionV2 -server $server -credential $credential
$script:CurrentHpSession = $session
switch ($session.version) {
    4 {
        # Retrieve data from various endpoints
        Write-Debug "ILO version 4"
        $ComputerSystems = Get-RedfishData  "/redfish/v1/Systems/1/" -server $server   -session $session
        $ManagedBy = Get-RedfishData  -server $server -endpoint $ComputerSystems.Links.ManagedBy."href"   -session $session
        $Chassis = Get-RedfishData  -server $server -endpoint $ComputerSystems.Links.Chassis."href"   -session $session

        $PowerMetrics_ = Get-RedfishData -server $server -endpoint $Chassis.Power."@odata.id"   -session $session
        $status = [PSCustomObject]@{
            Health = if ($PowerMetrics_.Redundancy.MinNumNeeded -ge $PowerMetrics_.Redundancy.RedundancySet.Count) { "OK" }else { "Error" }
        }
        $PowerMetrics_.Redundancy | Add-Member -NotePropertyName Status -NotePropertyValue $status
         
        
        
         
               

        $NetworkInterfaces = Get-RedfishData  -server $server -endpoints $ComputerSystems.Oem.Hp.links.NetworkAdapters."href"   -session $session
        $NetworkInterfacesMembers = Get-RedfishData  -server $server -endpoints $NetworkInterfaces.Members.'@odata.id'   -session $session

        $NetworkPortsMembers = $NetworkInterfacesMembers.PhysicalPorts


        $ProcessorSummary = Get-RedfishData  -server $server -endpoints $ComputerSystems.Links.Processors."href"   -session $session 
        $ProcessorSummary = Get-RedfishData  -server $server -endpoints $ProcessorSummary.Members.'@odata.id'   -session $session

        $Memories = Get-RedfishData -server $server -endpoints $ComputerSystems.Oem.Hp.links.Memory."href"   -session $session
        $Memories = Get-RedfishData -server $server -endpoints $Memories.Members.'@odata.id'   -session $session

        foreach ($Memory in $Memories) {
            if ($Memory.DIMMStatus -eq "GoodInUse") {
                $status = [PSCustomObject]@{
                    Health = "OK"
                }
                $Memory | Add-Member -NotePropertyName Status -NotePropertyValue $status
            }
            else {
                $status = [PSCustomObject]@{
                    Health = $Memory.DIMMStatus
                }
                $Memory | Add-Member -NotePropertyName Status -NotePropertyValue $status
            }
        }


        $Storages = Get-RedfishData  -server $server -endpoints $ComputerSystems.Oem.Hp.links.SmartStorage."href"   -session $session
        $Storagesall = Get-RedfishData  -server $server -endpoints $Storages.links.ArrayControllers.href   -session $session
        $Storagesall = Get-RedfishData  -server $server -endpoints $Storagesall.Members.'@odata.id'   -session $session
        foreach ($Storage in  $Storagesall) {
            $StorageDrives = Get-RedfishData  -server $server -endpoints $Storagesall.links.PhysicalDrives.href   -session $session

            $Storage | Add-Member -NotePropertyName Drives -NotePropertyValue ( Get-RedfishData  -server $server -endpoints $StorageDrives.Members.'@odata.id'   -session $session)
               
        }
        

        $Thermal = Get-RedfishData  -server $server -endpoint $Chassis.Thermal."@odata.id"   -session $session

         
    }
    5 {
        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5"

        # Retrieve data from various endpoints
        Write-Debug "ILO version 5"
        
        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - ComputerSystems"
        $entrypoint = $session.entrypoint  
        $entrypointOB = Get-RedfishData  -server $server -endpoint $entrypoint.systems.'@odata.id' -session $session 
        $ComputerSystems = Get-RedfishData  -server $server -endpoint $entrypointOB.Members.'@odata.id' -session $session 
         
        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - ManagedBy"

        $ManagedBy = Get-RedfishData  -server $server -endpoint $ComputerSystems.Links.ManagedBy."@odata.id"   -session $session
        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - Chassis"

        $Chassis = Get-RedfishData  -server $server -endpoint $ComputerSystems.Links.Chassis."@odata.id"   -session $session
        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - PowerMetrics_"

        $PowerMetrics_ = Get-RedfishData -server $server -endpoint $Chassis.Power."@odata.id"   -session $session
                   
           
               
        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - NetworkInterfaces"

        
        $NetworkInterfaces = Get-RedfishData  -server $server -endpoints $ComputerSystems.Oem.Hpe.links.NetworkAdapters.'@odata.id'   -session $session
        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - NetworkInterfacesMembers"
        $NetworkInterfacesMembers = Get-RedfishData  -server $server -endpoints $NetworkInterfaces.Members.'@odata.id'   -session $session

        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - NetworkPortsMembers"
        $NetworkPortsMembers = $NetworkInterfacesMembers.PhysicalPorts 

        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - ProcessorSummary"
        $ProcessorSummary = Get-RedfishData  -server $server -endpoints $ComputerSystems.Processors.'@odata.id'    -session $session
        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - ProcessorSummary 2"
        $ProcessorSummary = Get-RedfishData  -server $server -endpoints $ProcessorSummary.Members.'@odata.id'   -session $session

        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - Memories"
        $Memoriesdata = Get-RedfishData -server $server -endpoints $ComputerSystems.Memory.'@odata.id'   -session $session
        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - Memories 2"
        $Memories = Get-RedfishData -server $server -endpoints $Memoriesdata.Members.'@odata.id'   -session $session

       


        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - Storages"
        Write-StorageDebugSnapshot -Label 'ComputerSystems.Storage link' -Data $ComputerSystems.Storage
        Write-StorageDebugSnapshot -Label 'ComputerSystems OEM SmartStorage links' -Data @{
            Hpe = $ComputerSystems.Oem.Hpe.links.SmartStorage
            Hp = $ComputerSystems.Oem.Hp.links.SmartStorage
        }
        $Storagesall = @(Get-RedfishCollectionResources -Server $server -CollectionUri $ComputerSystems.Storage.'@odata.id' -Session $session)
        Write-StorageDebugSnapshot -Label 'Standard Redfish storage resources' -Data $Storagesall
        if ($Storagesall.Count -eq 0) {
            $smartStorageUri = $ComputerSystems.Oem.Hpe.Links.SmartStorage.'@odata.id'
            if ([string]::IsNullOrWhiteSpace([string]$smartStorageUri)) {
                $smartStorageUri = $ComputerSystems.Oem.Hpe.links.SmartStorage.href
            }
            if ([string]::IsNullOrWhiteSpace([string]$smartStorageUri)) {
                $smartStorageUri = $ComputerSystems.Oem.Hp.links.SmartStorage.href
            }
            if ([string]::IsNullOrWhiteSpace([string]$smartStorageUri)) {
                $smartStorageUri = $ComputerSystems.Oem.Hp.Links.SmartStorage.'@odata.id'
            }

            if (-not [string]::IsNullOrWhiteSpace([string]$smartStorageUri)) {
                Write-StorageDebugSnapshot -Label 'Selected HPE SmartStorage URI' -Data $smartStorageUri
                $smartStorage = Get-RedfishData -server $server -endpoint $smartStorageUri -session $session
                Write-StorageDebugSnapshot -Label 'HPE SmartStorage response' -Data $smartStorage
                $arrayControllersUri = $smartStorage.Links.ArrayControllers.'@odata.id'
                if ([string]::IsNullOrWhiteSpace([string]$arrayControllersUri)) {
                    $arrayControllersUri = $smartStorage.links.ArrayControllers.href
                }
                $Storagesall = @(Get-RedfishCollectionResources -Server $server -CollectionUri $arrayControllersUri -Session $session)
                Write-StorageDebugSnapshot -Label 'HPE ArrayController resources' -Data $Storagesall
            }
        }
        

        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - Thermal"
        $Thermal = Get-RedfishData  -server $server -endpoint $Chassis.Thermal."@odata.id"   -session $session

        Write-Progress -Activity "Retrieve data from various endpoints : ILO version 5 - Managers"
        $Managers = $ManagedBy  
         

    }
}
Write-Progress -Activity " Check for OEM data under different keys"

# Check for OEM data under different keys
$omehp = $ComputerSystems.Oem.Hpe
$ManagedByoemhp = $ManagedBy.Oem.Hpe
if ($null -eq $omehp ) {
    $omehp = $ComputerSystems.Oem.Hp
    $ManagedByoemhp = $ManagedBy.Oem.Hp
}
Write-Progress -Activity "Build the report body"

# Build the report body
$Body = "`n"
$Body += "- General Health status : $($ComputerSystems.Status.Health)`n`n"

$Body += "| Information               |                                          |`n"
$Body += "|---------------------------|------------------------------------------|`n"
$Body += "| Server Name               | $($ComputerSystems.HostName)             |`n"
$Body += "| Product Name              | $($ComputerSystems.Model)                |`n"
$Body += "| Server Serial Number      | $($ComputerSystems.SerialNumber)         |`n"
$Body += "| Product ID                | $($ComputerSystems.SKU)                  |`n"
$Body += "| System ROM                | $($omehp.Bios.Current.VersionString)     |`n"
$Body += "| System ROM Date           | $($omehp.Bios.Current.Date)              |`n"
$Body += "| System ROM Family         | $($omehp.Bios.Current.Family)            |`n"
$Body += "| Backup ROM                | $($omehp.Bios.Backup.VersionString)      |`n"
$Body += "| Backup ROM Date           | $($omehp.Bios.Backup.Date)               |`n"
$Body += "| Backup ROM Family         | $($omehp.Bios.Backup.Family)             |`n"
$Body += "| License Type              | $($ilolicenseservice.License)            |`n"
$Body += "| iLO Firmware Version      | $($ManagedByoemhp.Firmware.Current.VersionString) ($($ManagedByoemhp.Firmware.Current.Date))     |`n"
$Body += "| IPv4 Address              | $($server)                               |`n"
$Body += "| iLO Hostname              | $($ethernetinterfaces.FQDN)              |`n"

$Body += "`n"

 

$PowerMetrics = @{}

foreach ($PowerMetric_ in $PowerMetrics_) {
    $PowerMetrics[$PowerMetric_."@odata.id"] = $PowerMetric_
}
$PowerMetrics = $PowerMetrics.Values 


$fans = $Thermal.Fans
$fansstatus = ""
foreach ($fan in  $fans) {
    if (($fan.Status.Health -eq "OK") -or ($fan.Status.State -eq "Absent" )) {
          
    }
    else {
        $fansstatus += "$($fan.FanName) $($fan.Status.Health) :x: - "
    }
}
if ($fansstatus -eq "") { $fansstatus = "All fans OK  :white_check_mark:" }

$PowerStatusHealth = "N/A"
if ( $null -ne $PowerMetrics.Redundancy ) {
    if ($PowerMetrics.Redundancy.Status.Health -eq "OK") {
        $PowerStatusHealth = "$($PowerMetrics.Redundancy.Status.Health) :white_check_mark:"
    }
    else {
        $PowerStatusHealth = "$($PowerMetrics.Redundancy.Status.Health) :x:"
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

$MemoriesStatus = ""
foreach ($Memory in  $Memories) {
    if ($null -ne $Memory.Status.Health) {
        if ($Memory.Status.Health -eq "OK") {
           
        }
        else {

            $MemoriesStatus += "$($Memory.ID) $($Memory.Status.Health) :x: - "
        }
    }
    # else { $MemoriesStatus = $null }

}
if ($MemoriesStatus -eq "") { $MemoriesStatus = "All Memories OK  :white_check_mark:" }

$StoragesStatus = ""
$StoragesForReport = @()
foreach ($Storage in  $Storagesall) {
    if ($session.version -eq 4) {
        if (@($Storage.Drives).Count -gt 0) {
            $StoragesForReport += $Storage
        }
    }
    else {
        $StoragesForReport += $Storage
    }

    $storageHealth = $Storage.Status.HealthRollup
    if ([string]::IsNullOrWhiteSpace([string]$storageHealth)) {
        $storageHealth = $Storage.Status.Health
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$storageHealth) -and $storageHealth -ne "OK") {
        $StoragesStatus += "$($Storage.Name) $storageHealth :x: - "
    }
}
if ($Storagesall.Count -eq 0) {
    $StoragesStatus = "No storage resources returned by standard Redfish or HPE SmartStorage."
    Write-Warning "No storage resources were found for iLO $server. Check the Systems Storage and HPE SmartStorage links."
}
elseif ($StoragesStatus -eq "") {
    $StoragesStatus = "All Storage OK  :white_check_mark:"
}

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

# Check health status of subsystems
$Body += "| Subsystems and Devices    | Status                                                                                           |`n"
$Body += "|---------------------------|-----------------------------------------------------------------------------------------------|`n"


$Body += "| Power Supply Redundancy   | $($PowerStatusHealth) |`n"
foreach ($PowerSupplies in $PowerMetrics.PowerSupplies) {
    $Body += "| Power Supplie   $($PowerSupplies.MemberId)         | $($PowerSupplies.Status.Health) |`n"
}
$Body += "| Fans                      | $($fansstatus) |`n"
$Body += "| Temperatures              | $($TemperaturesStatus) |`n"
if ($null -ne $NetworkPortStatus) {
    $Body += "| Network Interfaces        | $($NetworkPortStatus) |`n"
}
$Body += "| Storage Controllers       | $($StoragesStatus) |`n"
$Body += "| Memory                    | $($MemoriesStatus) |`n"
$Body += "| Processors                | $($ProcessorsStatus) |`n"


# Function to retrieve   controller information
function Get-ControllerInfo {
    param ( 
        $session,
        $Storages
         
    )
	$server= $session.server

    $ControllersInfo = @()
    $DrivesInfo = @()
    $VolumesInfo = @()
    foreach ($Storage in $Storages) {  
        Write-StorageDebugSnapshot -Label 'Storage resource passed to Get-ControllerInfo' -Data $Storage
        $InternalPortCount = 0
        switch ($session.version) {
            4 {
                # Retrieve data from various endpoints
                Write-Debug "ILO version 4"
                
                $drivesLink = Get-RedfishData -server $server -endpoints $Storage.links.PhysicalDrives.href   -session $session
                $drives = Get-RedfishData -server $server -endpoints $drivesLink.Members.'@odata.id'   -session $session
                $VolumesLink = Get-RedfishData -server $server -endpoints $Storage.links.LogicalDrives.href   -session $session
                $Volumes = Get-RedfishData -server $server -endpoints $VolumesLink.Members.'@odata.id'   -session $session
                $StorageEnclosuresLink = Get-RedfishData -server $server -endpoints $Storage.links.StorageEnclosures.href   -session $session
                $StorageEnclosures = Get-RedfishData -server $server -endpoints $StorageEnclosuresLink.Members.'@odata.id'   -session $session
               
                foreach ($StorageEnclosure in $StorageEnclosures) { 
                    $InternalPortCount += $StorageEnclosure.DriveBayCount
                }
                $Controllers = @()
                $Controllers += $Storage
 
            }
            5 {
                Write-Debug "ILO version 5"
                $driveCollectionUri = $Storage.Drives.'@odata.id'
                if ([string]::IsNullOrWhiteSpace([string]$driveCollectionUri)) {
                    $driveCollectionUri = $Storage.Links.DiskDrives.'@odata.id'
                }
                if ([string]::IsNullOrWhiteSpace([string]$driveCollectionUri)) {
                    $driveCollectionUri = $Storage.Links.PhysicalDrives.'@odata.id'
                }
                if ([string]::IsNullOrWhiteSpace([string]$driveCollectionUri)) {
                    $driveCollectionUri = $Storage.links.PhysicalDrives.href
                }
                Write-StorageDebugSnapshot -Label "Drive collection URI for storage '$($Storage.Id)'" -Data $driveCollectionUri
                $drives = @(Get-RedfishCollectionResources -Server $server -CollectionUri $driveCollectionUri -Session $session)
                Write-StorageDebugSnapshot -Label "Drive resources for storage '$($Storage.Id)'" -Data $drives

                $volumeCollectionUri = $Storage.Volumes.'@odata.id'
                if ([string]::IsNullOrWhiteSpace([string]$volumeCollectionUri)) {
                    $volumeCollectionUri = $Storage.Links.LogicalDrives.'@odata.id'
                }
                if ([string]::IsNullOrWhiteSpace([string]$volumeCollectionUri)) {
                    $volumeCollectionUri = $Storage.links.LogicalDrives.href
                }
                Write-StorageDebugSnapshot -Label "Volume collection URI for storage '$($Storage.Id)'" -Data $volumeCollectionUri
                $Volumes = @(Get-RedfishCollectionResources -Server $server -CollectionUri $volumeCollectionUri -Session $session)
                Write-StorageDebugSnapshot -Label "Volume resources for storage '$($Storage.Id)'" -Data $Volumes

                $controllerCollectionUri = $Storage.Controllers.'@odata.id'
                if ([string]::IsNullOrWhiteSpace([string]$controllerCollectionUri)) {
                    $controllerCollectionUri = $Storage.StorageControllers.'@odata.id'
                }
                if (-not [string]::IsNullOrWhiteSpace([string]$controllerCollectionUri)) {
                    $Controllers = @(Get-RedfishCollectionResources -Server $server -CollectionUri $controllerCollectionUri -Session $session)
                }
                elseif ($null -ne $Storage.StorageControllers) {
                    $Controllers = @($Storage.StorageControllers)
                }
                else {
                    $Controllers = @($Storage)
                }
                Write-StorageDebugSnapshot -Label "Controller resources for storage '$($Storage.Id)'" -Data $Controllers

                foreach ($Controller in $Controllers) {
                    $portsCollectionUri = $Controller.Ports.'@odata.id'
                    if ([string]::IsNullOrWhiteSpace([string]$portsCollectionUri)) {
                        $portsCollectionUri = $Controller.links.Ports.href
                    }
                    $ports = @(Get-RedfishCollectionResources -Server $server -CollectionUri $portsCollectionUri -Session $session)
                    foreach ($Port in $ports) {
                        $InternalPortCount += $Port.Width
                    }
                }
                 
            }
        }

        
        
        
            
        foreach ($Controller in $Controllers) { 
            $StatusHealth = if ($Controller.Status.Health -eq "OK") {
                "$( $Controller.Status.Health ) :white_check_mark:"
            }
            else {
                "$($Controller.Status.Health) :x:"
            }
            switch ($session.version) {
                4 {
                    # Retrieve data from various endpoints
                    Write-Debug "ILO version 4"
                    $FirmwareVersion = $Controller.FirmwareVersion.Current.VersionString
                }
                5 {
                    Write-Debug "ILO version 5"
                    $FirmwareVersion = $Controller.FirmwareVersion
                    if ($FirmwareVersion -isnot [string]) {
                        $FirmwareVersion = $Controller.FirmwareVersion.Current.VersionString
                    }
                }
            }

            $controllerId = $Controller.Id
            if ($null -eq $controllerId) {
                $controllerId = $Controller.Index
            }
            $controllerModel = $Controller.Model
            if ([string]::IsNullOrWhiteSpace([string]$controllerModel)) {
                $controllerModel = $Controller.ControllerModel
            }
            $ControllerInfo = [PSCustomObject]@{ ID = $controllerId  
                PartNumber                          = $Controller.SerialNumber
                Status                              = $StatusHealth 
                Model                               = $controllerModel
                Vendor                              = "HPe"
                FirmwareVersion                     = $FirmwareVersion
                SlotDisk                            = $InternalPortCount
            } 
            $ControllersInfo += $ControllerInfo
        } 
         
        foreach ($drive in $drives) {  
            $DriveStatusHealth = if ($drive.Status.Health -eq "OK") {
                "$($drive.Status.Health) :white_check_mark:"
            }
            else {
                "$($drive.Status.Health) :x:"
            }
            switch ($session.version) {
                4 {
                    # Retrieve data from various endpoints
                    Write-Debug "ILO version 4"
                    $driveLocation = $drive.Location
                    $drive.PhysicalLocation
                    $driveCapacityGB = $drive.CapacityGB
                }
                5 {
                    Write-Debug "ILO version 5"
                    $driveLocation = $drive.PhysicalLocation.PartLocation.LocationOrdinalValue
                    if ([string]::IsNullOrWhiteSpace([string]$driveLocation)) {
                        $driveLocation = $drive.Location
                    }
                    if ($null -ne $drive.CapacityBytes) {
                        $driveCapacityGB = [math]::Round($drive.CapacityBytes / 1Gb, 2)
                    }
                    else {
                        $driveCapacityGB = $drive.CapacityGB
                    }

                }
            }
            $DriveInfo = [PSCustomObject]@{ DiskSlot = $driveLocation  
                SerialNumber                         = $drive.SerialNumber
                DiskHealth                           = $DriveStatusHealth 
                DiskModel                            = $drive.Model
                DiskVendor                           = $drive.Manufacturer
                MediaType                            = $drive.MediaType 
                HotspareType                         = $drive.HotspareType 
                DiskCapacityGB                       = $driveCapacityGB
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
            switch ($session.version) {
                4 {
                    # Retrieve data from various endpoints
                    Write-Debug "ILO version 4"
                    $VolumeLogicalDriveName = $Volume.LogicalDriveName
                    $VolumeRaid = $Volume.Raid
                    $VolumeCapacityGiB = [math]::Round($Volume.CapacityMiB / 1024 , 2)
                }
                5 {
                    Write-Debug "ILO version 5"
                    $VolumeLogicalDriveName = $Volume.DisplayName
                    if ([string]::IsNullOrWhiteSpace([string]$VolumeLogicalDriveName)) {
                        $VolumeLogicalDriveName = $Volume.LogicalDriveName
                    }
                    $VolumeRaid = $Volume.RAIDType
                    if ($null -eq $VolumeRaid) {
                        $VolumeRaid = $Volume.Raid
                    }
                    if ($null -ne $Volume.CapacityBytes) {
                        $VolumeCapacityGiB = [math]::Round($Volume.CapacityBytes / 1Gb, 2)
                    }
                    elseif ($null -ne $Volume.CapacityMiB) {
                        $VolumeCapacityGiB = [math]::Round($Volume.CapacityMiB / 1024, 2)
                    }
                    else {
                        $VolumeCapacityGiB = $Volume.CapacityGiB
                    }
                }
            }
            $VolumeInfo = [PSCustomObject]@{
                    
                Name        = $VolumeLogicalDriveName
                  
                DiskHealth  = $VolumeStatusHealth 
                Raid        = $VolumeRaid
                CapacityGiB = $VolumeCapacityGiB
            }

               
                


            $VolumesInfo += $VolumeInfo
        }


    } 
    $result = New-Object -TypeName PSObject 
   
      Add-Member -InputObject $result -type NoteProperty -name ControllersInfo -value $ControllersInfo
      Add-Member -InputObject $result -type NoteProperty -name DrivesInfo -value $DrivesInfo
      Add-Member -InputObject $result -type NoteProperty -name VolumesInfo -value $VolumesInfo
	 
      $result
	   
	  
}

$returnInfo = (Get-ControllerInfo  -Storages $StoragesForReport -session $session) 
$controlerInfo = $returnInfo.ControllersInfo
$diskInfo = $returnInfo.DrivesInfo
$volumeInfo = $returnInfo.VolumesInfo
Write-StorageDebugSnapshot -Label 'Final report drive rows' -Data $diskInfo
Write-StorageDebugSnapshot -Label 'Final report volume rows' -Data $volumeInfo


# Report Formatting
$Body += "`n#### Check Controlers Status  `n" 
# controler  Information Table
if ($null -ne $controlerInfo) {
    $Body += "| controler ID | PartNumber | Brand | Model | Health | FirmwareVersion |`n"
    $Body += "|-----------|-------|-------|---------------|--------|--------|`n"
    foreach ($controler in $controlerInfo) {
        if ($controler.ID ) {
            $Body += "| $($controler.ID) | $($controler.PartNumber) | $($controler.Vendor) | $($controler.Model) | $($controler.Status) | $($controler.FirmwareVersion) |`n"
        }
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
        if ($disk.DiskModel) {
            $Body += "| $($disk.DiskSlot) | $($disk.DiskVendor) | $($disk.DiskModel) | $($disk.SerialNumber) | $($disk.MediaType) | $($disk.DiskCapacityGB) |$($disk.DiskHealth) |`n"
        }
    }
}
else {
    $Body += "No physical disk data available.`n"
}
$Body += "`n#### Check Volumes  Status  `n" 

# Volume Information Table
$Body += "| Name | Volume Raid type | Capacity (GB) | Health |`n"
$Body += "|-----------|-------------|---------------|--------|`n"
foreach ($volume in $volumeInfo) {

    if ($volume.Name ) {
        $Body += "| $($volume.Name) | $($volume.Raid) | $($volume.CapacityGiB) | $($Volume.DiskHealth) |`n"
    }
}
    


# Output the report
return $Body
}
finally {
    foreach ($trackedSession in @($script:HpSessions)) {
        try {
            $headers = @{ 'X-Auth-Token' = $trackedSession.Token }
            Invoke-WebRequest -Uri $trackedSession.SessionUri -Method Delete -Headers $headers -UseBasicParsing -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Warning "Could not close iLO session for $($trackedSession.Server): $($_.Exception.Message)"
        }
    }
    $script:HpSessions.Clear()
    $script:CurrentHpSession = $null
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $script:OriginalServerCertificateValidationCallback
    $script:OriginalServerCertificateValidationCallback = $null
    Write-Progress -Activity 'iLO session setup' -Id 0 -Completed
    Write-Progress -Activity 'Redfish endpoint collection' -Id 2 -Completed
    Write-Progress -Activity 'Redfish endpoint iteration' -Id 3 -Completed
    Write-Progress -Activity 'Redfish endpoint request' -Id 4 -Completed
}
