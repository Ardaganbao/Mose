param (
    [Parameter(Mandatory = $true, HelpMessage = 'VSA admin credential')]
    [System.Net.NetworkCredential]$Credential,

    [Parameter(Mandatory = $true, HelpMessage = 'VSA IP to connect to')]
    [string]$Server
)
function New-HTTPSessionJson {
    param (
        [Parameter(Mandatory = $true)]
        [System.Net.NetworkCredential]$Credential,

        [Parameter(Mandatory = $true, HelpMessage = 'URL to connect to')]
        [string]$URL,

        [switch]$IgnoreCert
    )

    if ($IgnoreCert) {
        # Ignore certificate errors
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
       
    }

    # Prepare JSON request body
    $bodyObj = @{
        "targets" = @{
            "id"   = "ff"
            "hash" = "ff"
        }
    }
    $bodyJson = $bodyObj | ConvertTo-Json

    $psCredential = New-Object System.Management.Automation.PSCredential($Credential.UserName, $Credential.SecurePassword)

    try {
        $response = Invoke-WebRequest -Uri $URL -Credential $psCredential -Method "Post" -UseBasicParsing -ContentType "application/x-www-form-urlencoded; charset=UTF-8" -Body $bodyJson -ErrorAction Stop
    } catch {
        Write-Error "Failed to make the web request: $_"
        return $null
    }

    return [PSCustomObject]@{ session = $response }
}


function Get-TargetState {
    param (
        [string]$State
    )

    switch ($State) {
        "online" { return "online :white_check_mark:" }
        "conflicted" { return "conflicted :x:" }
        "missing" { return "missing :x:" }
        "destroying" { return "destroying :x:" }
        "storage_failed" { return "storage_failed :x:" }
        default { return "offline :x:" }
    }
}

function ConvertTo-MarkdownCell {
    param (
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return ([string]$Value).Replace('|', '\|') -replace '\r?\n', '<br>'
}

function ConvertTo-MarkdownTable {
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$Property
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $headers = foreach ($name in $Property) {
        ConvertTo-MarkdownCell -Value $name
    }
    $lines.Add("| $($headers -join ' | ') |")
    $lines.Add("| $(($Property | ForEach-Object { '---' }) -join ' | ') |")

    foreach ($item in $InputObject) {
        $values = foreach ($name in $Property) {
            $propertyValue = $item.PSObject.Properties[$name]
            if ($null -eq $propertyValue) {
                ''
            }
            else {
                ConvertTo-MarkdownCell -Value $propertyValue.Value
            }
        }
        $lines.Add("| $($values -join ' | ') |")
    }

    return [string]::Join([Environment]::NewLine, $lines.ToArray())
}

function ConvertTo-MarkdownList {
    param (
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$Property
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('| Property | Value |')
    $lines.Add('| --- | --- |')

    foreach ($name in $Property) {
        $propertyValue = $InputObject.PSObject.Properties[$name]
        $value = ''
        if ($null -ne $propertyValue) {
            $value = ConvertTo-MarkdownCell -Value $propertyValue.Value
        }
        $lines.Add("| $(ConvertTo-MarkdownCell -Value $name) | $value |")
    }

    return [string]::Join([Environment]::NewLine, $lines.ToArray())
}
 

# Define URLs and paths
$URLTarget = "https://$Server/target/json/update/all/"
$session = New-HTTPSessionJson -URL $URLTarget -Credential $Credential -IgnoreCert


$resultOBJ = (ConvertFrom-Json $session.session.content)
$targetsfromAPI = $resultOBJ.targets
$targets = New-Object System.Collections.ArrayList

Foreach ($targetfromAPI in $targetsfromAPI.added) { 
    $State = "offline :x:"
    if ( $targetfromAPI.online) {
        $State = "online :white_check_mark:"
    }
    if ( $targetfromAPI.conflicted) {
        $State = "conflicted :x:"
    }
    if ( $targetfromAPI.missing) {
        $State = "missing :x:"
    }
    if ( $targetfromAPI.destroying) {
        $State = "destroying :x:"
    } 
    if ( $targetfromAPI.storage_failed) {
        $State = "storage_failed :x:"
    }
    $StateNSH = "offline  :x:"
    if ($targetfromAPI.nsh.online) {
        $StateNSH = "online  :white_check_mark:"
    }

    $nsh = [PSCustomObject]@{
        Name  = $targetfromAPI.nsh.name
        State = $StateNSH
    }
    $nsh | add-member scriptmethod tostring { '{0} ({1})' -f $this.Name, $this.State } -force 

    $si = New-Object System.Collections.ArrayList
    Foreach ($nodefromAPI in  $targetfromAPI.lu.plexes) { 
        $statenode = 'offline :x:'
        if ( $nodefromAPI.state.resynchronizing) {
            $Statenode = "resynchronizing :large_blue_circle:"
        }
        if ( $nodefromAPI.state.not_responding) {
            $Statenode = "not responding :x:"
        }
        if ( $nodefromAPI.state.storage_failed) {
            $Statenode = "storage failed :x:"
        }
        if ( $nodefromAPI.state.cache_failed) {
            $Statenode = "cache failed :x:"
        }
        if ( $nodefromAPI.state.online) {
            $Statenode = "online :white_check_mark: :large_orange_diamond:"
        }
        if ( $nodefromAPI.state.synchronized) {
            $Statenode = "synchronized :white_check_mark: "
        }
        $pso = [PSCustomObject]@{
            Name  = $nodefromAPI.node.name
            State = $statenode 
        }
        $pso | add-member scriptmethod tostring { '{0} ({1})' -f $this.Name, $this.State } -force 

        $si.add($pso)> $null 

    }


    $targets.Add([PSCustomObject]@{
            "Name"                = $targetfromAPI.volume.name
            "EUI-64"              = $targetfromAPI.volume.eui64  
            "Enabled"             = $targetfromAPI.enabled
            "State"               = $State
            "Size (Tb)"           = [math]::round($targetfromAPI.volume.size / 1Tb  , 2) 
            "Sessions"            = $targetfromAPI.sessions.Count
            "Storage Information" = $si -join "`r`n"  
            "Witness"             = $nsh.tostring()

        }  ) > $null 
} 
 
$URLtarget = "https://$($server)/"
$session = New-HTTPSessionJson -URL $URLtarget -credential $Credential -ignoreCert
$PathToLicencesFile =  New-TemporaryFile 
 $session.session.content  | Out-File -FilePath $PathToLicencesFile

 
$Body = "## Check Stormagic`r`n"
$Body += "### System`r`n"


$system = "" 
Foreach ($data in  (Select-String -Path $PathToLicencesFile '.*var data =(.*);?$' -AllMatches).Matches) {
$group = $data.Groups[1].Value
 

if($group -like "*system*"){
    $obj = $group | ConvertFrom-Json # -Depth 100
    
        $system = $obj.system
         
    
    }
} 

$licences = "" 
Foreach ($data in  (Select-String -Path $PathToLicencesFile '.*var license =(.*);$' -AllMatches).Matches) {
    $obj = $data.Groups[1].Value | ConvertFrom-Json  #-Depth 100 
    if ($obj.customer) {
        $Body += "#### Licences Owner`r`n"
        $Body += ConvertTo-MarkdownTable -InputObject @($obj.customer) -Property @('name', 'email', 'company', 'address')
        $licences = $obj;
    }
}
  




$Body += "`r`n#### Licences Info`r`n"

if ($licences.license_eval) {
    $statusLicence = "Evaluation :exclamation:"
}
if ($licences.license_eval -and $licences.eval_expired) {
    $statusLicence = "Evaluation expired :x:"
}
if ($licences.license_violated) {
    $statusLicence = "License Violated :x:"
}
if ($licences.valid) {
    $statusLicence = "License Valid :white_check_mark:"
}

$statusSupport = $licences.maintenance
$statusSupport | Add-Member -MemberType ScriptMethod -Name ToString -Value { 
    $stringtext = "" 
    if ($this.gracePeriod -gt 0) {
        $stringtext += "Grace Period $($this.gracePeriod) :exclamation:`r`n"
    }
    if ($this.supportExpired) {
        $stringtext += " Expired :x:`r`n"
    }
    else {
         
        $UnixEpoch = [datetime]"1970-01-01T00:00:00Z"

        # Convert the Unix timestamp to a DateTime object
        $EndDate = $UnixEpoch.AddSeconds($licences.maintenance.supportExpiry).ToUniversalTime()


        $StartDate = Get-Date
        $days = (New-TimeSpan -Start $StartDate -End $EndDate).Days
        $warning = ":white_check_mark:"
        if ($days -lt 61) {
            $warning = ":exclamation:"
        }
        if ($days -lt 31) {
            $warning = ":x:"
        }
        $stringtext += "$($licences.maintenance.supportType) - Expires  $($EndDate.ToString()) ( $($days) days ) {0}" -f $warning
    
    }
   
    $stringtext
} -force 
$issubscription = $true
Foreach ($data in  (Select-String -Path $PathToLicencesFile '.*var subscription = (.*);$' -AllMatches).Matches) {
    $obj = $data.Groups[1].Value | ConvertFrom-Json # -Depth 100
    if ($obj) {
        $issubscription = "Subcription"
        
    }
    else {
        $issubscription = "Perpetual"
    }
} 
$licence = [PSCustomObject]@{
    "License Key"    = $licences.license
    "Status"         = $statusLicence
    "Edition"        = "$($licences.edition)  ($( $issubscription))"
    "Support Status" = $statusSupport.ToString() 
} 

$Body += ConvertTo-MarkdownList -InputObject $licence -Property @('License Key', 'Status', 'Edition', 'Support Status')

$Body += "`r`n#### System Info`r`n" 
$UnixEpoch = [datetime]"1970-01-01T00:00:00Z"

# Convert the Unix timestamp to a DateTime object
$start = $UnixEpoch.AddSeconds($system.start_time).ToUniversalTime()

$system|Add-Member  -NotePropertyName "start time" -NotePropertyValue  $start
$Body += ConvertTo-MarkdownList -InputObject $system -Property @('hostname', 'start time', 'sysID', 'version', 'serial', 'recovery', 'status')
# #### System
# | Start Time          | 2023-08-08 11:46:47           |
# |---------------------|-------------------------------|
# | Status              | Normal                        |
# | Version             | 6.2.U5P6.51590                |
# | Edition             | Standard                      |
# | System Discovery ID | <discovery id>                |
# | Serial Number       | <serial number>               |
$Body += "`r`n#### Targets`r`n"
$Body += ConvertTo-MarkdownTable -InputObject @($targets) -Property @('Name', 'EUI-64', 'Enabled', 'State', 'Size (Tb)', 'Sessions', 'Storage Information', 'Witness')

return $Body
