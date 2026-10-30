<#
    Commvault Cloud and On-Premises – Monthly Health Report Generator
    --------------------------------------------------------------
    Features:
      - Uses SecretStore for per-client tokens ("<ClientName>_Token")
      - Uses the Commvault access token with Bearer authentication
      - Connects to Commvault Cloud or an on-premises Command Center
      - Uses Cloud ring authentication or the on-premises Authtoken header
      - Renews a rejected Cloud access token once with the stored refresh token (POST /V4/AccessToken/Renew)
      - -RenewTokenOnly renews the stored Cloud token and exits (scheduled by Renew-CommvaultToken.ps1)
      - Fixes SecureString → plaintext
      - Reads license usage from the License Summary report datasets:
            /cr/reportsplusengine/datasets/<report id>:<dataset id>/data   (IDs as used by cvpysdk)
      - Fetches paged backup and restore job history for the last 30 days by default
      - Summarizes job status per day (last 16 days) and per month (last 12 months) by default
      - Builds protected-item inventory from Client/Subclient APIs
      - Reads the SLA period from POST /GetSLAConfiguration and marks each item Met or Missed
        from its last completed backup (-DefaultSlaDays when Commvault returns no period)
      - Fills in missing reasons for unsuccessful jobs from GET /Events?jobId=<id>
      - Generates Markdown report file
      - Supports per-client execution

    Requirements:
      Install-Module Microsoft.PowerShell.SecretManagement -Scope CurrentUser
      Install-Module Microsoft.PowerShell.SecretStore      -Scope CurrentUser

    Secret format:
      Set-Secret -Name "<ClientName>_Token" -Secret @{
          Type = "Cloud"
          AccessToken = ConvertTo-SecureString "<access-token>" -AsPlainText -Force
          RefreshToken = ConvertTo-SecureString "<refresh-token>" -AsPlainText -Force
          Ring  = "m108"
          TokenEndpoint = "<optional: overrides the default /V4/AccessToken/Renew URL>"
      }

    On-premises secret format:
      Set-Secret -Name "<ClientName>_Token" -Secret @{
          Type = "OnPrem"
          AccessToken = ConvertTo-SecureString "<access-token>" -AsPlainText -Force
          Server = "https://commvault.example.com"
      }
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ClientName,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Cloud', 'OnPrem')]
    [string]$Mode,

    [string]$CommvaultServer,

    [string]$SecretSuffix = "_Token",

    [ValidateRange(1, 365)]
    [int]$JobLookbackDays = 30,

    [ValidateRange(0, 2147483647)]
    [int]$JobLookbackSeconds = 0,

    # Calendar months (including the current one) in the monthly job status table; 0 disables it.
    [ValidateRange(0, 24)]
    [int]$JobTrendMonths = 12,

    # Days (including today) in the daily job status table; 0 disables it.
    [ValidateRange(0, 62)]
    [int]$JobDailyDays = 16,

    # SLA period used when Commvault does not return one from its SLA configuration.
    [ValidateRange(1, 365)]
    [int]$DefaultSlaDays = 1,

    [string]$SecretVaultName = 'SecretStore1',

    [string]$OutputFolder = "$HOME\Documents\MetallicReports",

    # Renew the stored Cloud token and exit without building a report.
    [switch]$RenewTokenOnly
)
#--------------------------------------------------------
# Helper: Convert SecureString to plaintext
#--------------------------------------------------------
function ConvertFrom-SecureStringToPlainText {
    param($Secure)

    if ($Secure -isnot [System.Security.SecureString]) { return $Secure }

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}

function Get-FirstObjectValue {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    foreach ($name in $Names) {
        $property = $InputObject.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value -and
            -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return $property.Value
        }
    }
    return $null
}

function Get-CommvaultApiEntities {
    param(
        [Parameter(Mandatory = $true)]$Response,
        [Parameter(Mandatory = $true)][string[]]$CollectionNames,
        [Parameter(Mandatory = $true)][string[]]$WrapperNames
    )

    foreach ($collectionName in $CollectionNames) {
        $collectionProperty = $Response.PSObject.Properties[$collectionName]
        if ($null -eq $collectionProperty -or $null -eq $collectionProperty.Value) {
            continue
        }

        $entities = @()
        foreach ($entry in @($collectionProperty.Value)) {
            if ($null -eq $entry) { continue }
            # Unwrap nested wrappers, e.g. /Client returns clientProperties[].client.clientEntity.
            $entity = $entry
            do {
                $unwrapped = $false
                foreach ($wrapperName in $WrapperNames) {
                    $wrapperProperty = $entity.PSObject.Properties[$wrapperName]
                    if ($null -ne $wrapperProperty -and $null -ne $wrapperProperty.Value) {
                        $entity = $wrapperProperty.Value
                        $unwrapped = $true
                        break
                    }
                }
            } while ($unwrapped)
            $entities += $entity
        }
        return $entities
    }

    return @()
}

function ConvertTo-MarkdownCell {
    param($Value)

    if ($null -eq $Value) { return '' }
    return ([string]$Value -replace '\|', '\|' -replace '[\r\n]+', ' ').Trim()
}

function ConvertTo-MarkdownTable {
    param([object[]]$Rows)

    $columns = @()
    foreach ($row in $Rows) {
        foreach ($name in $row.PSObject.Properties.Name) {
            if ($columns -notcontains $name) { $columns += $name }
        }
    }
    $lines = @(
        '| ' + (($columns | ForEach-Object { ConvertTo-MarkdownCell -Value $_ }) -join ' | ') + ' |'
        '|' + (($columns | ForEach-Object { '---' }) -join '|') + '|'
    )
    foreach ($row in $Rows) {
        $lines += '| ' + (($columns | ForEach-Object { ConvertTo-MarkdownCell -Value $row.$_ }) -join ' | ') + ' |'
    }
    return $lines -join "`r`n"
}

# Report dataset data comes back as column definitions plus one value array per record.
function ConvertFrom-CommvaultDataset {
    param($Response)

    $columns = @($Response.columns)
    foreach ($record in @($Response.records)) {
        if ($record -isnot [array]) {
            $record | Select-Object -Property * -ExcludeProperty 'sys_rowid'
            continue
        }
        $row = [ordered]@{}
        for ($index = 0; $index -lt $columns.Count; $index++) {
            $name = Get-FirstObjectValue -InputObject $columns[$index] -Names @('displayName', 'name', 'dataField')
            if (-not $name -or $name -eq 'sys_rowid') { continue }
            $row[[string]$name] = $record[$index]
        }
        [PSCustomObject]$row
    }
}

# SLA period in days and exclusion for one entity returned by POST /GetSLAConfiguration.
function Get-SlaSetting {
    param($Entity)

    $days = $null
    foreach ($source in @($Entity, $Entity.inheritedSLA)) {
        $value = 0
        if ($null -ne $source -and [int]::TryParse([string]$source.slaDays, [ref]$value) -and $value -gt 0) {
            $days = $value
            break
        }
    }
    return [PSCustomObject]@{
        Days     = $days
        Excluded = $Entity.excludeFromSLA -eq $true -or ($null -ne $Entity.inheritedSLA -and $Entity.inheritedSLA.excludeFromSLA -eq $true)
        Reason   = [string]$Entity.excludedReason
    }
}

function ConvertFrom-CommvaultTimestamp {
    param($Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    $number = 0L
    if ([long]::TryParse([string]$Value, [ref]$number)) {
        try {
            return [DateTimeOffset]::FromUnixTimeSeconds($number).LocalDateTime
        }
        catch {
            return $null
        }
    }

    $date = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [ref]$date)) {
        return $date
    }
    return $null
}

function ConvertTo-ReadableBytes {
    param($Bytes)

    $number = 0.0
    if (-not [double]::TryParse([string]$Bytes, [ref]$number)) { return 'Unavailable' }
    if ($number -ge 1TB) { return '{0:N2} TB' -f ($number / 1TB) }
    if ($number -ge 1GB) { return '{0:N2} GB' -f ($number / 1GB) }
    if ($number -ge 1MB) { return '{0:N2} MB' -f ($number / 1MB) }
    return '{0:N2} KB' -f ($number / 1KB)
}

function ConvertTo-ReadableDuration {
    param($Seconds)

    $number = 0.0
    if (-not [double]::TryParse([string]$Seconds, [ref]$number) -or $number -lt 0) {
        return 'Unavailable'
    }
    return [timespan]::FromSeconds($number).ToString('d\.hh\:mm\:ss')
}

function Get-JobOutcome {
    param([string]$Status)

    if ($Status -match '^(Completed|Success)$') { return 'Completed' }
    if ($Status -match '^Completed w/|^Completed with|Warning|Partial') { return 'Completed with Errors or Warnings' }
    if ($Status -match '^Committed') { return 'Committed' }
    if ($Status -match '^Killed') { return 'Killed' }
    if ($Status -match '^(Failed|Error|Terminated)') { return 'Failed' }
    return 'Other'
}

function Get-JobPageRecords {
    param($Response)

    if ($Response.jobs) { return @($Response.jobs) }
    if ($Response.jobList) { return @($Response.jobList) }
    return @()
}

function Measure-JobValue {
    param(
        [object[]]$Jobs,
        [Parameter(Mandatory = $true)][string]$Property
    )

    $sum = 0.0
    $count = 0
    foreach ($job in $Jobs) {
        $value = 0.0
        if ([double]::TryParse([string]$job.$Property, [ref]$value)) {
            $sum += $value
            $count++
        }
    }
    return [PSCustomObject]@{ Sum = $sum; Count = $count }
}

# Job status counts per period: a CommVaultJob chart block followed by the full table with totals.
function New-JobStatusTable {
    param(
        [object[]]$Jobs,
        [Parameter(Mandatory = $true)][datetime[]]$Periods,
        [Parameter(Mandatory = $true)][string]$PeriodKeyFormat,
        [Parameter(Mandatory = $true)][string]$HeaderFormat
    )

    $statusRows = @('Completed', 'Completed with Errors or Warnings', 'Failed', 'Killed', 'Committed')
    $invariant = [cultureinfo]::InvariantCulture
    $english = [cultureinfo]::GetCultureInfo('en-US')
    $counts = @{}
    foreach ($job in $Jobs) {
        if (-not $job.StartTime) { continue }
        $key = '{0}|{1}' -f $job.StartTime.ToString($PeriodKeyFormat, $invariant), $job.Outcome
        $counts[$key] = 1 + [int]$counts[$key]
    }

    $periodKeys = @($Periods | ForEach-Object { $_.ToString($PeriodKeyFormat, $invariant) })
    $statusTable = @(
        '| Job Status | ' + (($Periods | ForEach-Object { $_.ToString($HeaderFormat, $english) }) -join ' | ') + ' |'
        '|---|' + (($Periods | ForEach-Object { '---:' }) -join '|') + '|'
    )
    foreach ($status in $statusRows) {
        $cells = foreach ($periodKey in $periodKeys) { [int]$counts["$periodKey|$status"] }
        $statusTable += "| $status | $($cells -join ' | ') |"
    }

    $totalCells = @()
    $rateCells = @()
    foreach ($periodKey in $periodKeys) {
        $periodTotal = 0
        foreach ($status in $statusRows) { $periodTotal += [int]$counts["$periodKey|$status"] }
        $periodSuccessful = [int]$counts["$periodKey|Completed"] + [int]$counts["$periodKey|Completed with Errors or Warnings"]
        $totalCells += $periodTotal
        $rateCells += if ($periodTotal -gt 0) {
            [math]::Round(100 * $periodSuccessful / $periodTotal, 1).ToString($invariant)
        }
        else {
            '-'
        }
    }

    $lines = @('```CommVaultJob') + $statusTable + @('```', '') + $statusTable + @(
        "| Total | $($totalCells -join ' | ') |"
        "| Success Rate (%) | $($rateCells -join ' | ') |"
    )
    return $lines -join "`r`n"
}

# Progress like IDRAC.ps1: Id 1 shows the report step, Id 2 the Commvault API request being sent.
function Write-CommvaultReportProgress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Status,
        [Parameter(Mandatory = $true)]
        [int]$PercentComplete
    )

    $percent = [math]::Max(0, [math]::Min(100, $PercentComplete))
    Write-Progress -Activity $script:ProgressActivity -Status $Status -PercentComplete $percent -Id 1
}

function Complete-CommvaultReportProgress {
    Write-Progress -Activity 'Commvault API request' -Id 2 -Completed
    Write-Progress -Activity $script:ProgressActivity -Id 1 -Completed
}

#--------------------------------------------------------
# Load SecretModules
#--------------------------------------------------------
function Import-SecretModules {
    try {
        Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
        Import-Module Microsoft.PowerShell.SecretStore      -ErrorAction Stop
    }
    catch {
        throw "SecretManagement or SecretStore module missing."
    }
}

#--------------------------------------------------------
# Get secret containing access/refresh tokens and the ring ID
#--------------------------------------------------------
function Get-CommvaultSecret {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientName,
        [string]$Suffix = "_Token",
        [string]$VaultName = 'MetallicVault',
        [Parameter(Mandatory = $true)]
        [ValidateSet('Cloud', 'OnPrem')]
        [string]$Mode,
        [string]$ServerOverride
    )
    $name = "$ClientName$Suffix"

    $secret = Get-Secret -Name $name -Vault $VaultName -ErrorAction Stop
    if (-not $secret) {
        throw "Secret '$name' not found."
    }

    $getSecretValue = {
        param([string]$PropertyName)
        if ($secret -is [System.Collections.IDictionary]) {
            return $secret[$PropertyName]
        }
        $property = $secret.PSObject.Properties[$PropertyName]
        if ($null -ne $property) {
            return $property.Value
        }
        return $null
    }

    $accessToken = ConvertFrom-SecureStringToPlainText (& $getSecretValue 'AccessToken')
    $refreshToken = ConvertFrom-SecureStringToPlainText (& $getSecretValue 'RefreshToken')
    $ring = ConvertFrom-SecureStringToPlainText (& $getSecretValue 'Ring')
    $tokenEndpoint = ConvertFrom-SecureStringToPlainText (& $getSecretValue 'TokenEndpoint')
    $clientId = ConvertFrom-SecureStringToPlainText (& $getSecretValue 'ClientId')
    $clientSecret = ConvertFrom-SecureStringToPlainText (& $getSecretValue 'ClientSecret')
    $server = ConvertFrom-SecureStringToPlainText (& $getSecretValue 'Server')

    if (-not $accessToken) { throw "Secret '$name' is missing 'AccessToken'." }
    if ($Mode -eq 'Cloud' -and -not $ring) { throw "Cloud secret '$name' is missing 'Ring'." }
    if ($Mode -eq 'OnPrem' -and -not ($server -or $ServerOverride)) {
        throw "On-prem secret '$name' is missing 'Server'. Store the Command Center URL in the secret or supply -CommvaultServer."
    }

    return [PSCustomObject]@{
        AccessToken   = $accessToken
        RefreshToken  = $refreshToken
        Ring          = $ring
        TokenEndpoint = $tokenEndpoint
        ClientId      = $clientId
        ClientSecret  = $clientSecret
        Server        = $server
        VaultName     = $VaultName
        Name          = $name
        Mode          = $Mode
    }
}

#--------------------------------------------------------
# Build Metallic REST headers
#--------------------------------------------------------
function New-MetallicHeaders {
    param([Parameter(Mandatory = $true)]$SecretObject)

    return @{
        "Authorization" = "Bearer $($SecretObject.Token)"
        "ring-id"       = $SecretObject.Ring
        "Accept"        = "application/json"
        "Content-Type"  = "application/json"
    }
}

#--------------------------------------------------------
# Universal REST wrapper
#--------------------------------------------------------
function ConvertTo-SecureSecretValue {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }
    return ConvertTo-SecureString -String $Value -AsPlainText -Force
}

function Update-MetallicAccessToken {
    $secretName = $script:SecretObject.Name
    $resetHint = "Generate a new access and refresh token in Commvault, run: Remove-Secret -Name '$secretName' -Vault '$($script:SecretObject.VaultName)', then run the report again to enter them."
    if ([string]::IsNullOrWhiteSpace($script:SecretObject.RefreshToken)) {
        throw "The Commvault access token was rejected and secret '$secretName' has no RefreshToken. $resetHint"
    }

    # Commvault renews tokens through its own API (POST /V4/AccessToken/Renew); a stored TokenEndpoint overrides the URL.
    $renewUri = if ([string]::IsNullOrWhiteSpace($script:SecretObject.TokenEndpoint)) {
        "$($script:BaseUri.TrimEnd('/'))/V4/AccessToken/Renew"
    }
    else {
        $script:SecretObject.TokenEndpoint
    }
    # Commvault requires the expired access token as the Bearer token on the renew call.
    $renewHeaders = @{
        Accept        = 'application/json'
        Authorization = "Bearer $($script:SecretObject.AccessToken)"
    }
    if ($script:SecretObject.Ring) {
        $renewHeaders['ring-id'] = $script:SecretObject.Ring
    }
    $renewBody = @{
        accessToken  = $script:SecretObject.AccessToken
        refreshToken = $script:SecretObject.RefreshToken
    } | ConvertTo-Json

    Write-Progress -Activity "Renew access token : $renewUri" -Id 2
    $ProgressPreference = 'SilentlyContinue'
    try {
        $tokenResponse = Invoke-RestMethod `
            -Method POST `
            -Uri $renewUri `
            -Headers $renewHeaders `
            -ContentType 'application/json' `
            -Body $renewBody `
            -ErrorAction Stop
    }
    catch {
        throw "The Commvault access token expired and renewing it at '$renewUri' failed: $($_.Exception.Message) $resetHint"
    }

    $newAccessToken = Get-FirstObjectValue -InputObject $tokenResponse -Names @('accessToken', 'access_token', 'AccessToken')
    if ([string]::IsNullOrWhiteSpace([string]$newAccessToken)) {
        throw "Commvault token renewal returned no access token. $resetHint"
    }
    $newRefreshToken = Get-FirstObjectValue -InputObject $tokenResponse -Names @('refreshToken', 'refresh_token', 'RefreshToken')
    if ([string]::IsNullOrWhiteSpace([string]$newRefreshToken)) {
        $newRefreshToken = $script:SecretObject.RefreshToken
    }
    $updatedSecret = @{
        Type         = 'Cloud'
        AccessToken  = ConvertTo-SecureSecretValue -Value ([string]$newAccessToken)
        RefreshToken = ConvertTo-SecureSecretValue -Value ([string]$newRefreshToken)
        Ring         = $script:SecretObject.Ring
    }
    if ($script:SecretObject.TokenEndpoint) {
        $updatedSecret.TokenEndpoint = $script:SecretObject.TokenEndpoint
    }
    if ($script:SecretObject.ClientId) {
        $updatedSecret.ClientId = $script:SecretObject.ClientId
    }
    if ($script:SecretObject.ClientSecret) {
        $updatedSecret.ClientSecret = ConvertTo-SecureSecretValue -Value $script:SecretObject.ClientSecret
    }

    Set-Secret -Name $script:SecretObject.Name -Vault $script:SecretObject.VaultName -Secret $updatedSecret -ErrorAction Stop
    $script:SecretObject.AccessToken = [string]$newAccessToken
    $script:SecretObject.RefreshToken = [string]$newRefreshToken
    $script:GlobalHeaders = New-CommvaultHeaders -SecretObject $script:SecretObject -Mode Cloud
    Write-Host "Renewed the Commvault access token and saved it to secret '$secretName'." -ForegroundColor Cyan
}
function New-CommvaultHeaders {

    param(
        [Parameter(Mandatory)]
        $SecretObject,

        [Parameter(Mandatory)]
        [ValidateSet('Cloud','OnPrem')]
        [string]$Mode
    )

    if ($Mode -eq 'Cloud') {

        return @{
            Authorization  = "Bearer $($SecretObject.AccessToken)"
            "ring-id"      = $SecretObject.Ring
            Accept         = "application/json"
            "Content-Type" = "application/json"
        }
    }

    return @{
        Authtoken      = $SecretObject.AccessToken
        Accept         = "application/json"
        "Content-Type" = "application/json"
    }
}
# Builds the Invoke-RestMethod parameters for a Commvault API call; also used for the parallel job pages.
function New-MetallicApiRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST', 'PUT', 'DELETE')] [string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [hashtable]$Query = $null,
        [hashtable]$AdditionalHeaders = $null,
        [object]$Body = $null
    )

    $uri = [System.UriBuilder]::new($script:BaseUri)
    $basePath = $uri.Path.TrimEnd('/')
    $requestPath = $Path.TrimStart('/')
    $uri.Path = if ($basePath) { "$basePath/$requestPath" } else { "/$requestPath" }

    if ($Query) {
        $queryParts = foreach ($key in $Query.Keys) {
            '{0}={1}' -f [uri]::EscapeDataString([string]$key), [uri]::EscapeDataString([string]$Query[$key])
        }
        $uri.Query = $queryParts -join '&'
    }

    $headers = @{}
    foreach ($key in $script:GlobalHeaders.Keys) {
        $headers[$key] = $script:GlobalHeaders[$key]
    }
    if ($AdditionalHeaders) {
        foreach ($key in $AdditionalHeaders.Keys) {
            $headers[$key] = $AdditionalHeaders[$key]
        }
    }

    $requestParameters = @{
        Method      = $Method
        Uri         = $uri.Uri.AbsoluteUri
        Headers     = $headers
        ErrorAction = 'Stop'
    }
    if ($Body) {
        $requestParameters.Body = $Body | ConvertTo-Json -Depth 12
    }
    return $requestParameters
}

function Invoke-MetallicApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST', 'PUT', 'DELETE')] [string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [hashtable]$Query = $null,
        [hashtable]$AdditionalHeaders = $null,
        [object]$Body = $null
    )

    $requestParameters = New-MetallicApiRequest -Method $Method -Path $Path -Query $Query -AdditionalHeaders $AdditionalHeaders -Body $Body
    Write-Progress -Activity "Invoke-MetallicApi $Method : $($requestParameters.Uri)" -Id 2
    # Windows PowerShell 5.1 slows large downloads by drawing its own download progress bar;
    # hiding it for this function only keeps the report progress bars visible.
    $ProgressPreference = 'SilentlyContinue'
    try {
        return Invoke-RestMethod @requestParameters
    }
    catch {
        $statusCode = Get-HttpStatusCode -Exception $_.Exception
        # An on-premises token can't be renewed here: it has to be replaced.
        if ($statusCode -eq 401 -and $script:CommvaultMode -eq 'OnPrem') {
            throw "Commvault refused the access token in secret '$($script:SecretObject.Name)' (401 Unauthorized) at $($requestParameters.Uri). If it expired or was revoked, create a new access token in Command Center, then run .\Start.ps1 -Configure, remove this Commvault on-premises (R) and add it again with the new token."
        }
        if ($statusCode -ne 401 -or $script:CommvaultMode -ne 'Cloud') {
            throw
        }

        Update-MetallicAccessToken
        $requestParameters = New-MetallicApiRequest -Method $Method -Path $Path -Query $Query -AdditionalHeaders $AdditionalHeaders -Body $Body
        return Invoke-RestMethod @requestParameters
    }
}

# The HTTP status code of a failed Invoke-RestMethod call, or $null when there was no answer.
function Get-HttpStatusCode {
    param($Exception)

    if ($Exception.Response -and $Exception.Response.StatusCode) {
        return [int]$Exception.Response.StatusCode
    }
    if ($Exception.StatusCode) {
        return [int]$Exception.StatusCode
    }
    return $null
}

# Sends several Commvault API calls at once, for calls that spend most of their time waiting on
# the Commvault side. $Requests are Invoke-MetallicApi parameters (Method, Path, Query...). Returns,
# in the same order, the Response of each call or the exception (Error) it failed with, and the
# Seconds it took. A rejected Cloud token is renewed once and the calls it rejected are sent again.
# $OnProgress gets the number of answered calls and the time spent.
function Invoke-MetallicApiParallel {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][hashtable[]]$Requests,
        [ValidateRange(1, 16)][int]$ThrottleLimit = 6,
        [scriptblock]$OnProgress
    )

    if ($Requests.Count -eq 0) {
        return @()
    }
    $results = @(foreach ($request in $Requests) { [PSCustomObject]@{ Response = $null; Error = $null; Seconds = $null } })
    $toSend = @(0..($Requests.Count - 1))
    $renewed = $false
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    # .NET allows only 2 connections per host by default.
    $servicePoint = [System.Net.ServicePointManager]::FindServicePoint([uri]$script:BaseUri)
    $servicePoint.ConnectionLimit = [math]::Max($servicePoint.ConnectionLimit, $ThrottleLimit)
    $pool = [runspacefactory]::CreateRunspacePool(1, [math]::Min($ThrottleLimit, $Requests.Count))
    $pool.Open()
    try {
        while ($toSend.Count -gt 0) {
            $calls = @(foreach ($index in $toSend) {
                $parameters = $Requests[$index]
                $request = New-MetallicApiRequest @parameters
                $worker = [powershell]::Create().AddScript({
                        param($Request)
                        $ProgressPreference = 'SilentlyContinue'
                        $watch = [System.Diagnostics.Stopwatch]::StartNew()
                        try {
                            $response = Invoke-RestMethod @Request
                            [PSCustomObject]@{ Response = $response; Error = $null; Seconds = $watch.Elapsed.TotalSeconds }
                        }
                        catch {
                            [PSCustomObject]@{ Response = $null; Error = $_.Exception; Seconds = $watch.Elapsed.TotalSeconds }
                        }
                    }).AddArgument($request)
                $worker.RunspacePool = $pool
                [PSCustomObject]@{ Index = $index; Worker = $worker; Handle = $worker.BeginInvoke() }
            })
            Write-Progress -Activity "Invoke-MetallicApi: $($calls.Count) calls at once, e.g. $($request.Method) : $($request.Uri)" -Id 2

            $answeredBefore = $Requests.Count - $calls.Count
            do {
                $answered = @($calls | Where-Object { $_.Handle.IsCompleted }).Count
                if ($OnProgress) {
                    & $OnProgress ($answeredBefore + $answered) $timer.Elapsed
                }
                if ($answered -lt $calls.Count) {
                    Start-Sleep -Milliseconds 250
                }
            } while ($answered -lt $calls.Count)

            $rejected = @()
            foreach ($call in $calls) {
                $output = @($call.Worker.EndInvoke($call.Handle))
                $call.Worker.Dispose()
                if ($output.Count -eq 0) {
                    $results[$call.Index].Error = [System.Exception]::new("No answer from $($Requests[$call.Index].Path)")
                    continue
                }
                $results[$call.Index] = $output[-1]
                if ($output[-1].Error -and (Get-HttpStatusCode -Exception $output[-1].Error) -eq 401) {
                    $rejected += $call.Index
                }
            }

            # Every call gets the same 401 when the token expired: renew it once, then send them again.
            $toSend = @()
            if ($rejected.Count -gt 0 -and $script:CommvaultMode -eq 'Cloud' -and -not $renewed) {
                Update-MetallicAccessToken
                $renewed = $true
                $toSend = $rejected
            }
        }
    }
    finally {
        $pool.Close()
        $pool.Dispose()
    }
    return $results
}

#--------------------------------------------------------
# MAIN EXECUTION
#--------------------------------------------------------
$script:ProgressActivity = "Generating Commvault $Mode report ($ClientName)"
# Clear the progress bar if the script stops on an error; break passes the error on to the caller.
trap {
    Complete-CommvaultReportProgress
    break
}

Write-CommvaultReportProgress -Status "Reading token from secret '$ClientName$SecretSuffix'" -PercentComplete 0
Import-SecretModules

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

# Resolve credentials for the selected Commvault deployment.
$secretObj = Get-CommvaultSecret -ClientName $ClientName -Suffix $SecretSuffix -VaultName $SecretVaultName -Mode $Mode -ServerOverride $CommvaultServer
$GlobalHeaders = @{}
$script:SecretObject = $secretObj
$script:GlobalHeaders = $GlobalHeaders
$script:CommvaultMode = $Mode
$script:GlobalHeaders = New-CommvaultHeaders -SecretObject $secretObj -Mode $Mode

if ($Mode -eq 'Cloud') {
    $script:BaseUri = 'https://api.metallic.io'
}
else {
    $serverUri = if (-not [string]::IsNullOrWhiteSpace($CommvaultServer)) { $CommvaultServer } else { $secretObj.Server }
    if ($serverUri -notmatch '^https?://') {
        $serverUri = "https://$serverUri"
    }

    $parsedServerUri = $null
    if (-not [uri]::TryCreate($serverUri, [System.UriKind]::Absolute, [ref]$parsedServerUri) -or
        $parsedServerUri.Scheme -notin @('http', 'https')) {
        throw "Invalid Commvault Command Center URL: '$serverUri'."
    }

    $serverBuilder = [System.UriBuilder]::new($parsedServerUri)
    $serverPath = $serverBuilder.Path.TrimEnd('/')
    if ($serverPath -notmatch '(?i)/commandcenter/api$') {
        if ($serverPath -match '(?i)/commandcenter$') {
            $serverBuilder.Path = "$serverPath/api"
        }
        else {
            $serverBuilder.Path = "$serverPath/commandcenter/api"
        }
    }
    $script:BaseUri = $serverBuilder.Uri.AbsoluteUri.TrimEnd('/')
}
$script:GlobalHeaders.Authorization = "Bearer $($secretObj.AccessToken)"

$script:GlobalHeaders = New-CommvaultHeaders -SecretObject $secretObj -Mode $Mode
$connectionLabel = if ($Mode -eq 'Cloud') { "ring-id '$($secretObj.Ring)'" } else { "server '$script:BaseUri'" }
Write-Host "Using Commvault $Mode secret '$($secretObj.Name)' with $connectionLabel" -ForegroundColor Cyan

# Commvault drops a token chain that is not renewed within 14 days of the access token expiring,
# so this mode is run on a schedule to keep the stored token alive between monthly reports.
if ($RenewTokenOnly) {
    if ($Mode -ne 'Cloud') {
        throw '-RenewTokenOnly applies only to Commvault Cloud tokens.'
    }
    Write-CommvaultReportProgress -Status 'Renewing the Commvault access token' -PercentComplete 50
    Update-MetallicAccessToken
    Complete-CommvaultReportProgress
    Write-Host 'Token renewed.' -ForegroundColor Green
    return
}

#--------------------------------------------------------
# 1) LICENSE AND SUBSCRIPTION USAGE (License Summary report datasets)
#--------------------------------------------------------
# The dataset list API only returns a few global datasets, so the License Summary report datasets
# are read by their fixed IDs (the same IDs Commvault's Python SDK, cvpysdk, uses).
$licenseDatasets = [ordered]@{
    'Commvault Cloud (Metallic)' = 'd7faef75-cf66-40a2-98ce-a2d0cc2a144b:cc2e77ec-9315-4446-cd7e-44ef80a8860e'
    'Capacity'                   = 'd7faef75-cf66-40a2-98ce-a2d0cc2a144b:feabb5ca-b6b7-4572-b0cb-39352c7e1b67'
    'Users'                      = 'd7faef75-cf66-40a2-98ce-a2d0cc2a144b:44cd7de8-ecb2-4ec8-8b2b-162491172eef'
    'Virtualization'             = 'd7faef75-cf66-40a2-98ce-a2d0cc2a144b:0aac5b36-10a4-4970-838a-c41fa2365583'
    'Operating instances'        = 'd7faef75-cf66-40a2-98ce-a2d0cc2a144b:cd38c52a-e099-4252-d36f-3e2c54540f6f'
    'Other'                      = 'd7faef75-cf66-40a2-98ce-a2d0cc2a144b:2654b01f-9bb0-481e-b273-4b4fddc585b1'
}
# The time of each part of the report, shown at the end to see where the time goes.
$apiTimes = [ordered]@{}
$apiTimer = [System.Diagnostics.Stopwatch]::StartNew()

$licenseSections = @()
$licenseNotes = @()
# Commvault runs each dataset's query when it is asked for, so they are all asked for at once.
$licenseNames = @($licenseDatasets.Keys)
$licenseRequests = @(foreach ($licenseName in $licenseNames) {
    @{ Method = 'GET'; Path = "/cr/reportsplusengine/datasets/$($licenseDatasets[$licenseName])/data" }
})
$licenseResults = @(Invoke-MetallicApiParallel -Requests $licenseRequests -ThrottleLimit $licenseRequests.Count -OnProgress {
    param($Answered, $Elapsed)
    Write-CommvaultReportProgress -Status "License usage: $Answered of $($licenseNames.Count) datasets received ($($Elapsed.ToString('m\:ss')))" -PercentComplete (5 + 10 * $Answered / $licenseNames.Count)
})
for ($licenseIndex = 0; $licenseIndex -lt $licenseNames.Count; $licenseIndex++) {
    $licenseName = $licenseNames[$licenseIndex]
    $licenseResult = $licenseResults[$licenseIndex]
    try {
        if ($licenseResult.Error) {
            throw $licenseResult.Error
        }
        $licenseRows = @(ConvertFrom-CommvaultDataset -Response $licenseResult.Response)
        if ($licenseRows.Count -gt 0) {
            $licenseSections += "### $licenseName licenses`r`n`r`n$(ConvertTo-MarkdownTable -Rows $licenseRows)"
        }
    }
    catch {
        $licenseNotes += "- ${licenseName}: $($_.Exception.Message)"
    }
}
$licenseText = if ($licenseSections.Count -gt 0) {
    $licenseSections -join "`r`n`r`n"
}
else {
    'The License Summary datasets returned no license rows.'
}
if ($licenseNotes.Count -gt 0) {
    $licenseText += "`r`n`r`nLicense datasets that could not be read:`r`n`r`n" + ($licenseNotes -join "`r`n")
}
# Sent together, so answers at regular steps (10, 20, 30 s...) mean Commvault runs them one at a time.
$licenseSeconds = @($licenseResults | Where-Object { $null -ne $_.Seconds } | ForEach-Object { [math]::Round($_.Seconds) } | Sort-Object)
$apiTimes['licenses'] = "$($apiTimer.Elapsed.ToString('m\:ss')) (answers after $($licenseSeconds -join ', ') s)"
$apiTimer.Restart()

#--------------------------------------------------------
# 2) BACKUP AND RESTORE JOB HISTORY (paged, rolling period)
#--------------------------------------------------------
$jobLookbackSeconds = if ($JobLookbackSeconds -gt 0) {
    $JobLookbackSeconds
}
else {
    $JobLookbackDays * 86400
}
$jobLookbackLabel = '{0} days' -f [math]::Round($jobLookbackSeconds / 86400, 2).ToString([cultureinfo]::InvariantCulture)

# Fetch enough history for the lookback period and the daily and monthly tables.
$now = Get-Date
$jobFetchSeconds = $jobLookbackSeconds
$trendMonths = @()
if ($JobTrendMonths -gt 0) {
    $trendStart = [datetime]::new($now.Year, $now.Month, 1).AddMonths( - ($JobTrendMonths - 1))
    $trendMonths = @(0..($JobTrendMonths - 1) | ForEach-Object { $trendStart.AddMonths($_) })
    $jobFetchSeconds = [math]::Max($jobFetchSeconds, [int][math]::Ceiling(($now - $trendStart).TotalSeconds))
}
$dailyDays = @()
if ($JobDailyDays -gt 0) {
    $dailyStart = $now.Date.AddDays( - ($JobDailyDays - 1))
    $dailyDays = @(0..($JobDailyDays - 1) | ForEach-Object { $dailyStart.AddDays($_) })
    $jobFetchSeconds = [math]::Max($jobFetchSeconds, [int][math]::Ceiling(($now - $dailyStart).TotalSeconds))
}

# Large pages keep the number of calls low when fetching a year of jobs.
$pageSize = 500
# Every /Job call re-runs the query over the whole period on the Commvault side, so most of the
# time is spent waiting on the server; the pages after the first are fetched this many at a time.
$maxParallelPages = 4
$jobQuery = @{
    completedJobLookupTime = $jobFetchSeconds
    jobCategory            = "All"
    jobFilter              = "backup,restore"
}
$allJobRecords = [System.Collections.Generic.List[object]]::new()
$jobFetchTimer = [System.Diagnostics.Stopwatch]::StartNew()
$writeJobProgress = {
    $elapsed = $jobFetchTimer.Elapsed.ToString('m\:ss')
    if ($totalRecords -gt 0) {
        Write-CommvaultReportProgress -Status "Jobs: $($allJobRecords.Count) of $totalRecords fetched ($elapsed)" -PercentComplete (20 + 35 * $allJobRecords.Count / $totalRecords)
    }
    else {
        Write-CommvaultReportProgress -Status "Jobs: $($allJobRecords.Count) fetched ($elapsed)" -PercentComplete 20
    }
}
Write-CommvaultReportProgress -Status ('Fetching backup and restore jobs (last {0:N0} days)' -f ($jobFetchSeconds / 86400)) -PercentComplete 20

# The first page returns the total job count, and renews an expired token before the parallel calls.
$jobResponse = Invoke-MetallicApi -Method GET -Path "/Job" -Query $jobQuery -AdditionalHeaders @{ limit = [string]$pageSize; offset = '0' }
$pageRecords = @(Get-JobPageRecords -Response $jobResponse)
foreach ($pageRecord in $pageRecords) { $allJobRecords.Add($pageRecord) }
$totalRecords = if ($null -ne $jobResponse.totalRecordsWithoutPaging) { [int]$jobResponse.totalRecordsWithoutPaging } else { $null }
& $writeJobProgress

if ($null -ne $totalRecords -and $pageRecords.Count -gt 0 -and $pageRecords.Count -lt $totalRecords) {
    # Step by the first page's size in case the API caps pages below $pageSize.
    $pageStep = $pageRecords.Count
    # .NET allows only 2 connections per host by default.
    [System.Net.ServicePointManager]::FindServicePoint([uri]$script:BaseUri).ConnectionLimit = $maxParallelPages
    $pagePool = [runspacefactory]::CreateRunspacePool(1, $maxParallelPages)
    $pagePool.Open()
    try {
        $pendingPages = for ($pageOffset = $pageStep; $pageOffset -lt $totalRecords; $pageOffset += $pageStep) {
            $pageRequest = New-MetallicApiRequest -Method GET -Path "/Job" -Query $jobQuery -AdditionalHeaders @{ limit = [string]$pageStep; offset = [string]$pageOffset }
            $pageWorker = [powershell]::Create().AddScript({
                    param($Request)
                    $ProgressPreference = 'SilentlyContinue'
                    Invoke-RestMethod @Request
                }).AddArgument($pageRequest)
            $pageWorker.RunspacePool = $pagePool
            [PSCustomObject]@{ Offset = $pageOffset; Worker = $pageWorker; Handle = $pageWorker.BeginInvoke() }
        }
        Write-Progress -Activity "Invoke-MetallicApi GET : $($pageRequest.Uri) ($($pendingPages.Count) pages, $maxParallelPages at a time)" -Id 2

        foreach ($pendingPage in $pendingPages) {
            $pageResult = @($pendingPage.Worker.EndInvoke($pendingPage.Handle))
            $pageFailed = $pendingPage.Worker.HadErrors -or $pageResult.Count -eq 0
            $pendingPage.Worker.Dispose()
            $jobResponse = if ($pageFailed) {
                # A failed request returns nothing; retry the page on its own, which also renews an expired token.
                Invoke-MetallicApi -Method GET -Path "/Job" -Query $jobQuery -AdditionalHeaders @{ limit = [string]$pageStep; offset = [string]$pendingPage.Offset }
            }
            else {
                $pageResult[0]
            }
            foreach ($pageRecord in @(Get-JobPageRecords -Response $jobResponse)) { $allJobRecords.Add($pageRecord) }
            & $writeJobProgress
        }
    }
    finally {
        $pagePool.Close()
        $pagePool.Dispose()
    }
}
elseif ($null -eq $totalRecords) {
    # Without a total count, page one at a time until a page comes back short.
    $offset = $pageRecords.Count
    while ($pageRecords.Count -eq $pageSize) {
        $jobResponse = Invoke-MetallicApi -Method GET -Path "/Job" -Query $jobQuery -AdditionalHeaders @{ limit = [string]$pageSize; offset = [string]$offset }
        $pageRecords = @(Get-JobPageRecords -Response $jobResponse)
        foreach ($pageRecord in $pageRecords) { $allJobRecords.Add($pageRecord) }
        $offset += $pageRecords.Count
        & $writeJobProgress
    }
}

$apiTimes['jobs'] = "$($apiTimer.Elapsed.ToString('m\:ss')) ($($allJobRecords.Count) jobs)"

Write-CommvaultReportProgress -Status "Summarizing $($allJobRecords.Count) jobs" -PercentComplete 55
$seenJobIds = [System.Collections.Generic.HashSet[string]]::new()
$commcellId = $null
$allJobRows = @(foreach ($record in $allJobRecords) {
    $summary = if ($record.jobSummary) { $record.jobSummary } else { $record }
    $jobId = Get-FirstObjectValue -InputObject $summary -Names @('jobId', 'id')
    # Jobs that finish during the fetch shift the pages, so a job can be returned twice.
    if ($jobId -and -not $seenJobIds.Add([string]$jobId)) { continue }
    if ($null -eq $commcellId) { $commcellId = Get-FirstObjectValue -InputObject $summary -Names @('commcellId') }
    $subclient = $summary.subclient
    $plan = $summary.plan
    $client = Get-FirstObjectValue -InputObject $summary -Names @('clientName')
    if (-not $client -and $subclient) {
        $client = Get-FirstObjectValue -InputObject $subclient -Names @('clientName')
    }
    if (-not $client) { $client = 'Unknown' }

    $itemName = Get-FirstObjectValue -InputObject $summary -Names @('subclientName')
    if (-not $itemName -and $subclient) {
        $itemName = Get-FirstObjectValue -InputObject $subclient -Names @('subclientName', 'backupsetName', 'instanceName')
    }
    if (-not $itemName) { $itemName = Get-FirstObjectValue -InputObject $summary -Names @('backupSetName', 'instanceName') }
    $jobBackupSet = if ($subclient) { Get-FirstObjectValue -InputObject $subclient -Names @('backupsetName') } else { $null }
    if ($jobBackupSet -and $itemName -and $itemName -ne 'default') {
        $itemName = "$jobBackupSet / $itemName"
    }
    if (-not $itemName) { $itemName = 'Unknown protected item' }

    $application = Get-FirstObjectValue -InputObject $summary -Names @('appTypeName', 'applicationName')
    if (-not $application -and $subclient) {
        $application = Get-FirstObjectValue -InputObject $subclient -Names @('appName')
    }
    if (-not $application) { $application = 'Unknown' }
    $planName = if ($plan) { Get-FirstObjectValue -InputObject $plan -Names @('planName', 'name') } else { $null }
    if (-not $planName) { $planName = Get-FirstObjectValue -InputObject $summary -Names @('planName', 'slaName') }
    if (-not $planName) { $planName = 'Not returned by API' }

    $startValue = Get-FirstObjectValue -InputObject $summary -Names @('jobStartTime', 'startTime', 'lastUpdateTime')
    $startTime = ConvertFrom-CommvaultTimestamp -Value $startValue
    $status = Get-FirstObjectValue -InputObject $summary -Names @('status', 'localizedStatus')
    if (-not $status) { $status = 'Unknown' }

    [PSCustomObject]@{
        JobId           = $jobId
        Client          = [string]$client
        Item            = [string]$itemName
        Application     = [string]$application
        Plan            = [string]$planName
        Operation       = [string](Get-FirstObjectValue -InputObject $summary -Names @('localizedOperationName', 'jobType'))
        Level           = [string](Get-FirstObjectValue -InputObject $summary -Names @('localizedBackupLevelName', 'backupLevelName'))
        Status          = [string]$status
        Outcome         = Get-JobOutcome -Status ([string]$status)
        StartTime       = $startTime
        DurationSeconds = Get-FirstObjectValue -InputObject $summary -Names @('jobElapsedTime', 'duration')
        DataBytes       = Get-FirstObjectValue -InputObject $summary -Names @('sizeOfApplication')
        Reason          = [string](Get-FirstObjectValue -InputObject $summary -Names @('pendingReason', 'failureReason', 'jobFailureReason'))
    }
})

# The trend table uses all fetched jobs; every other section uses only the lookback period.
$lookbackStart = (Get-Date).AddSeconds(-$jobLookbackSeconds)
$jobRows = @($allJobRows |
    Where-Object { -not $_.StartTime -or $_.StartTime -ge $lookbackStart } |
    Sort-Object -Property StartTime -Descending)
$success = @($jobRows | Where-Object { $_.Outcome -eq 'Completed' }).Count
$warning = @($jobRows | Where-Object { $_.Outcome -eq 'Completed with Errors or Warnings' }).Count
$failed = @($jobRows | Where-Object { $_.Outcome -in @('Failed', 'Killed') }).Count
$committed = @($jobRows | Where-Object { $_.Outcome -eq 'Committed' }).Count
$otherJobs = $jobRows.Count - $success - $warning - $failed - $committed
$BackupHealthStatus = "Jobs: $($jobRows.Count), Successful: $success, Completed with errors/warnings: $warning, Failed/killed: $failed"
if ($committed -gt 0) { $BackupHealthStatus += ", Committed: $committed" }
if ($otherJobs -gt 0) { $BackupHealthStatus += ", Other (running, pending, ...): $otherJobs" }
$BackupHealthLabel = if ($failed -gt 0 -or $warning -gt 0) { 'Review failed or warning jobs.' } elseif ($jobRows.Count -gt 0) { 'No failed or warning jobs reported.' } else { 'No jobs were returned for this period.' }
$totalDataProtected = ConvertTo-ReadableBytes ([long](Measure-JobValue -Jobs $jobRows -Property DataBytes).Sum)

$protectedItemsByKey = @{}
foreach ($group in ($jobRows | Group-Object -Property { '{0}|{1}|{2}' -f $_.Client, $_.Application, $_.Item })) {
    $itemJobs = @($group.Group | Sort-Object -Property StartTime -Descending)
    $latest = $itemJobs | Select-Object -First 1
    $protectedItemsByKey[$group.Name] = [PSCustomObject]@{
        Client            = $latest.Client
        Application       = $latest.Application
        Item              = $latest.Item
        Plan              = $latest.Plan
        LatestStatus      = $latest.Status
        LatestRun         = $latest.StartTime
        LastSuccessfulRun = $null
        SlaTarget         = $null
        SlaStatus         = $null
    }
}

$inventoryCollectionNotes = @()
$inventoryClientIds = @{}
$clientOffset = 0
$clientPageSize = 100
$clientTotalRecords = $null
$inventoryClients = @()
$apiTimer.Restart()
Write-CommvaultReportProgress -Status 'Collecting protected-item inventory (clients and subclients)' -PercentComplete 60
try {
    do {
        $clientResponse = Invoke-MetallicApi -Method GET -Path "/Client" -AdditionalHeaders @{
            limit  = [string]$clientPageSize
            offset = [string]$clientOffset
        }
        $clientPage = @(Get-CommvaultApiEntities -Response $clientResponse `
                -CollectionNames @('clientProperties', 'clients', 'clientList') `
                -WrapperNames @('client', 'clientEntity'))
        if ($null -eq $clientTotalRecords -and $null -ne $clientResponse.totalRecordsWithoutPaging) {
            $clientTotalRecords = [int]$clientResponse.totalRecordsWithoutPaging
        }
        if ($clientPage.Count -eq 0) {
            if ($clientOffset -eq 0) {
                $inventoryCollectionNotes += 'The Client API returned no recognizable client records.'
            }
            break
        }

        foreach ($clientEntity in $clientPage) {
            $clientId = Get-FirstObjectValue -InputObject $clientEntity -Names @('clientId', 'id')
            $inventoryClientName = Get-FirstObjectValue -InputObject $clientEntity -Names @('clientName', 'displayName', 'hostName')
            if (-not $clientId -or -not $inventoryClientName) {
                continue
            }
            $inventoryClientIds[[string]$inventoryClientName] = $clientId
            $inventoryClients += [PSCustomObject]@{ Id = $clientId; Name = $inventoryClientName }
        }

        $clientOffset += $clientPage.Count
    } while ($clientPage.Count -eq $clientPageSize -and
        ($null -eq $clientTotalRecords -or $clientOffset -lt $clientTotalRecords))

    # One call per client, each waiting on Commvault: the first subclient page of every client is asked for at once.
    $subclientPageSize = 100
    $subclientRequests = @(foreach ($inventoryClient in $inventoryClients) {
        @{
            Method            = 'GET'
            Path              = '/Subclient'
            Query             = @{ clientId = [string]$inventoryClient.Id }
            AdditionalHeaders = @{ limit = [string]$subclientPageSize; offset = '0' }
        }
    })
    $subclientResults = @(Invoke-MetallicApiParallel -Requests $subclientRequests -OnProgress {
        param($Answered, $Elapsed)
        Write-CommvaultReportProgress -Status "Inventory: subclients of $Answered of $($inventoryClients.Count) clients received ($($Elapsed.ToString('m\:ss')))" -PercentComplete (60 + 25 * $Answered / $inventoryClients.Count)
    })

    for ($clientIndex = 0; $clientIndex -lt $inventoryClients.Count; $clientIndex++) {
        $clientId = $inventoryClients[$clientIndex].Id
        $inventoryClientName = $inventoryClients[$clientIndex].Name
        $subclientResponse = $subclientResults[$clientIndex].Response
        $subclientError = $subclientResults[$clientIndex].Error
        $subclientOffset = 0
        $subclientTotalRecords = $null
        do {
            # A client with more subclients than one page: the next pages one at a time.
            if ($subclientOffset -gt 0) {
                try {
                    $subclientResponse = Invoke-MetallicApi -Method GET -Path "/Subclient" -Query @{
                        clientId = [string]$clientId
                    } -AdditionalHeaders @{
                        limit  = [string]$subclientPageSize
                        offset = [string]$subclientOffset
                    }
                }
                catch {
                    $subclientError = $_.Exception
                }
            }
            if ($subclientError) {
                $inventoryCollectionNotes += "Protected-item inventory failed for '$inventoryClientName': $($subclientError.Message)"
                break
            }

            $subclientPage = @(Get-CommvaultApiEntities -Response $subclientResponse `
                    -CollectionNames @('subClientProperties', 'subclientProperties', 'subclients', 'subClientList') `
                    -WrapperNames @('subClientEntity', 'subclientEntity', 'subclient', 'subClient'))
            if ($null -eq $subclientTotalRecords -and $null -ne $subclientResponse.totalRecordsWithoutPaging) {
                $subclientTotalRecords = [int]$subclientResponse.totalRecordsWithoutPaging
            }

            foreach ($subclientEntity in $subclientPage) {
                $subclientName = Get-FirstObjectValue -InputObject $subclientEntity -Names @('subclientName', 'name')
                if (-not $subclientName) { continue }
                $inventoryClient = Get-FirstObjectValue -InputObject $subclientEntity -Names @('clientName')
                if (-not $inventoryClient) { $inventoryClient = $inventoryClientName }
                $application = Get-FirstObjectValue -InputObject $subclientEntity -Names @('appName', 'applicationName', 'appTypeName')
                if (-not $application) { $application = 'Unknown' }
                $backupSetName = Get-FirstObjectValue -InputObject $subclientEntity -Names @('backupsetName')
                $protectedName = if ($backupSetName -and $subclientName -ne 'default') { "$backupSetName / $subclientName" } else { $subclientName }
                $inventoryPlan = Get-FirstObjectValue -InputObject $subclientEntity -Names @('planName', 'slaName')
                if (-not $inventoryPlan -and $subclientEntity.plan) {
                    $inventoryPlan = Get-FirstObjectValue -InputObject $subclientEntity.plan -Names @('planName', 'name')
                }
                $itemKey = '{0}|{1}|{2}' -f $inventoryClient, $application, $protectedName

                if (-not $protectedItemsByKey.ContainsKey($itemKey)) {
                    $protectedItemsByKey[$itemKey] = [PSCustomObject]@{
                        Client            = [string]$inventoryClient
                        Application       = [string]$application
                        Item              = [string]$protectedName
                        Plan              = if ($inventoryPlan) { [string]$inventoryPlan } else { 'Not returned by API' }
                        LatestStatus      = 'No job in lookback'
                        LatestRun         = $null
                        LastSuccessfulRun = $null
                        SlaTarget         = $null
                        SlaStatus         = $null
                    }
                }
                elseif ($inventoryPlan -and $protectedItemsByKey[$itemKey].Plan -eq 'Not returned by API') {
                    $protectedItemsByKey[$itemKey].Plan = [string]$inventoryPlan
                }
            }

            $subclientOffset += $subclientPage.Count
        } while ($subclientPage.Count -eq $subclientPageSize -and
            ($null -eq $subclientTotalRecords -or $subclientOffset -lt $subclientTotalRecords))
    }
}
catch {
    $inventoryCollectionNotes += "Protected-item inventory collection failed: $($_.Exception.Message)"
    Write-Warning $inventoryCollectionNotes[-1]
}
$apiTimes['inventory'] = "$($apiTimer.Elapsed.ToString('m\:ss')) ($($inventoryClients.Count) clients)"
$apiTimer.Restart()

#--------------------------------------------------------
# SLA: configured period from Commvault, compliance from the last completed backup
#--------------------------------------------------------
Write-CommvaultReportProgress -Status 'Reading the SLA configuration' -PercentComplete 86
$slaRequestKeys = @()
$slaRequestEntities = @()
if ($commcellId) {
    $slaRequestKeys += ''
    $slaRequestEntities += @{ entity = @{ commCellId = [int]$commcellId; _type_ = 1 } }
}
foreach ($inventoryClientName in $inventoryClientIds.Keys) {
    $slaRequestKeys += $inventoryClientName
    $slaRequestEntities += @{ entity = @{ clientId = [int]$inventoryClientIds[$inventoryClientName]; _type_ = 3 } }
}
$slaByClient = @{}
$commcellSla = $null
$slaNote = $null
# Ask for the CommCell and all clients at once; if client entities are refused, retry with the CommCell only.
$slaAttempts = @()
if ($slaRequestEntities.Count -gt 0) { $slaAttempts += $slaRequestEntities.Count }
if ($commcellId -and $slaRequestEntities.Count -gt 1) { $slaAttempts += 1 }
foreach ($slaAttempt in $slaAttempts) {
    try {
        $slaResponse = Invoke-MetallicApi -Method POST -Path '/GetSLAConfiguration' -Body @{ entities = @($slaRequestEntities | Select-Object -First $slaAttempt) }
        $slaEntities = @($slaResponse.entities)
        for ($index = 0; $index -lt [math]::Min($slaAttempt, $slaEntities.Count); $index++) {
            $slaSetting = Get-SlaSetting -Entity $slaEntities[$index]
            if ($slaRequestKeys[$index] -eq '') { $commcellSla = $slaSetting } else { $slaByClient[$slaRequestKeys[$index]] = $slaSetting }
        }
        $slaNote = $null
        break
    }
    catch {
        $slaNote = "The SLA configuration could not be read: $($_.Exception.Message)"
    }
}
$apiTimes['SLA'] = $apiTimer.Elapsed.ToString('m\:ss')

# Last backup per protected item over the whole fetched period; completed with errors still protected data.
$lastBackupByKey = @{}
foreach ($job in $allJobRows) {
    if ($job.Outcome -notin @('Completed', 'Completed with Errors or Warnings') -or $job.Operation -match 'Restore' -or -not $job.StartTime) {
        continue
    }
    $itemKey = '{0}|{1}|{2}' -f $job.Client, $job.Application, $job.Item
    if (-not $lastBackupByKey.ContainsKey($itemKey) -or $job.StartTime -gt $lastBackupByKey[$itemKey]) {
        $lastBackupByKey[$itemKey] = $job.StartTime
    }
}

$fetchedDays = [math]::Floor($jobFetchSeconds / 86400)
$slaDefaultUsed = $false
foreach ($itemKey in @($protectedItemsByKey.Keys)) {
    $protectedItem = $protectedItemsByKey[$itemKey]
    $slaSetting = $slaByClient[$protectedItem.Client]
    $slaDays = if ($slaSetting -and $slaSetting.Days) { $slaSetting.Days } elseif ($commcellSla -and $commcellSla.Days) { $commcellSla.Days } else { $null }
    if (-not $slaDays) {
        $slaDays = $DefaultSlaDays
        $slaDefaultUsed = $true
    }
    $lastBackup = $lastBackupByKey[$itemKey]
    $protectedItem.LastSuccessfulRun = $lastBackup
    $protectedItem.SlaTarget = if ($slaDays -eq 1) { '1 day' } else { "$slaDays days" }
    $protectedItem.SlaStatus = if (($slaSetting -and $slaSetting.Excluded) -or (-not $slaSetting -and $commcellSla -and $commcellSla.Excluded)) {
        $excludedReason = if ($slaSetting -and $slaSetting.Reason) { $slaSetting.Reason } elseif ($commcellSla) { $commcellSla.Reason } else { '' }
        if ($excludedReason) { "Excluded ($excludedReason)" } else { 'Excluded' }
    }
    elseif (-not $lastBackup) {
        "Missed (no completed backup in the last $fetchedDays days)"
    }
    elseif (($now - $lastBackup).TotalDays -le $slaDays) {
        'Met'
    }
    else {
        'Missed (last backup {0:N1} days ago)' -f ($now - $lastBackup).TotalDays
    }
}

$protectedItems = @($protectedItemsByKey.Values | Sort-Object -Property Client, Application, Item)
$slaMet = @($protectedItems | Where-Object { $_.SlaStatus -eq 'Met' }).Count
$slaMissed = @($protectedItems | Where-Object { $_.SlaStatus -like 'Missed*' }).Count
$slaExcluded = @($protectedItems | Where-Object { $_.SlaStatus -like 'Excluded*' }).Count
$slaPeriods = @($protectedItems.SlaTarget | Sort-Object -Unique)
$slaSource = if ($slaDefaultUsed) {
    "the Commvault SLA configuration was not available for every item, so $DefaultSlaDays day(s) is used where it was missing"
}
else {
    'from the Commvault SLA configuration'
}
$slaSummary = "SLA period: $($slaPeriods -join ', ') ($slaSource). $slaMet of $($protectedItems.Count) protected items met the SLA"
if ($slaMissed -gt 0) { $slaSummary += ", $slaMissed missed" }
if ($slaExcluded -gt 0) { $slaSummary += ", $slaExcluded excluded" }
$slaSummary += '.'
if ($slaNote) { $slaSummary += " $slaNote" }

#--------------------------------------------------------
# Reasons for jobs that did not complete successfully: the job events when the job has no reason text
#--------------------------------------------------------
$maxAttentionJobs = 25
$attentionJobs = @($jobRows | Where-Object { $_.Outcome -ne 'Completed' })
$eventJobs = @($attentionJobs | Select-Object -First $maxAttentionJobs | Where-Object { -not $_.Reason -and $_.JobId })
$apiTimer.Restart()
# One call per job: they are all asked for at once.
$eventRequests = @(foreach ($eventJob in $eventJobs) {
    @{ Method = 'GET'; Path = '/Events'; Query = @{ jobId = [string]$eventJob.JobId } }
})
try {
    $eventResults = @(Invoke-MetallicApiParallel -Requests $eventRequests -OnProgress {
        param($Answered, $Elapsed)
        Write-CommvaultReportProgress -Status "Job events: $Answered of $($eventJobs.Count) jobs received ($($Elapsed.ToString('m\:ss')))" -PercentComplete (88 + 6 * $Answered / $eventJobs.Count)
    })
}
catch {
    Write-Warning "Job events could not be read: $($_.Exception.Message)"
    $eventResults = @()
}
for ($eventIndex = 0; $eventIndex -lt $eventResults.Count; $eventIndex++) {
    $eventJob = $eventJobs[$eventIndex]
    try {
        if ($eventResults[$eventIndex].Error) {
            throw $eventResults[$eventIndex].Error
        }
        $eventResponse = $eventResults[$eventIndex].Response
        # Keep only the most severe events, so informational ones such as "Job started" are left out.
        $jobEvents = @(@($eventResponse.commservEvents) | Where-Object { $_.description } | ForEach-Object {
                $severity = 0
                [void][int]::TryParse([string]$_.severity, [ref]$severity)
                [PSCustomObject]@{ Severity = $severity; Text = ($_.description -replace '<[^>]+>', ' ' -replace '\s+', ' ').Trim() }
            })
        $topSeverity = ($jobEvents | Measure-Object -Property Severity -Maximum).Maximum
        $eventDescriptions = @($jobEvents |
            Where-Object { $_.Severity -eq $topSeverity } |
            Select-Object -ExpandProperty Text -Unique |
            Select-Object -First 2)
        if ($eventDescriptions.Count -gt 0) {
            $eventJob.Reason = $eventDescriptions -join ' / '
        }
    }
    catch {
        Write-Warning "Events for job $($eventJob.JobId) could not be read: $($_.Exception.Message)"
    }
}
$apiTimes['job events'] = "$($apiTimer.Elapsed.ToString('m\:ss')) ($($eventJobs.Count) jobs)"

#--------------------------------------------------------
# 3) MARKDOWN OUTPUT
#--------------------------------------------------------
Write-CommvaultReportProgress -Status 'Building the Markdown report' -PercentComplete 95
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
# A ':' in the client name would write to an NTFS alternate data stream instead of a .md file.
$fileClientName = $ClientName -replace '[\\/:*?"<>|]', '_'
$mdPath = Join-Path $OutputFolder "CommvaultReport_${fileClientName}_$ts.md"

$protectedItemLines = @($protectedItems | ForEach-Object {
        $latestRun = if ($_.LatestRun) { $_.LatestRun.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Unavailable' }
        $lastSuccess = if ($_.LastSuccessfulRun) { $_.LastSuccessfulRun.ToString('yyyy-MM-dd HH:mm:ss') } else { "None in the last $fetchedDays days" }
        '| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} |' -f `
        (ConvertTo-MarkdownCell $_.Client),
        (ConvertTo-MarkdownCell $_.Application),
        (ConvertTo-MarkdownCell $_.Item),
        (ConvertTo-MarkdownCell $_.Plan),
        (ConvertTo-MarkdownCell $_.SlaTarget),
        (ConvertTo-MarkdownCell $_.SlaStatus),
        (ConvertTo-MarkdownCell $latestRun),
        (ConvertTo-MarkdownCell $_.LatestStatus),
        (ConvertTo-MarkdownCell $lastSuccess)
    })
if ($protectedItemLines.Count -eq 0) {
    $protectedItemLines = @('| No protected items were returned by the inventory and job APIs. | | | | | | | | |')
}

$jobSummaryLines = @($jobRows |
    Group-Object -Property { '{0}|{1}|{2}' -f $_.Client, $_.Application, $_.Item } |
    Sort-Object -Property Name |
    ForEach-Object {
        $itemJobs = @($_.Group)
        $itemSuccess = @($itemJobs | Where-Object { $_.Outcome -eq 'Completed' }).Count
        $itemWarning = @($itemJobs | Where-Object { $_.Outcome -eq 'Completed with Errors or Warnings' }).Count
        $itemFailed = @($itemJobs | Where-Object { $_.Outcome -in @('Failed', 'Killed') }).Count
        $itemBytes = Measure-JobValue -Jobs $itemJobs -Property DataBytes
        $itemDuration = Measure-JobValue -Jobs $itemJobs -Property DurationSeconds
        $averageDuration = if ($itemDuration.Count -gt 0) {
            ConvertTo-ReadableDuration ([long][math]::Round($itemDuration.Sum / $itemDuration.Count))
        }
        else {
            'Unavailable'
        }
        '| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} |' -f `
        (ConvertTo-MarkdownCell $itemJobs[0].Client),
        (ConvertTo-MarkdownCell $itemJobs[0].Item),
        (ConvertTo-MarkdownCell $itemJobs[0].Application),
        $itemJobs.Count,
        $itemSuccess,
        $itemWarning,
        $itemFailed,
        ('{0:N1} %' -f (100 * $itemSuccess / $itemJobs.Count)),
        (ConvertTo-ReadableBytes ([long]$itemBytes.Sum)),
        $averageDuration
    })
if ($jobSummaryLines.Count -eq 0) {
    $jobSummaryLines = @('| No jobs were returned for this period. | | | | | | | | | |')
}

$attentionLines = @($attentionJobs | Select-Object -First $maxAttentionJobs | ForEach-Object {
        $start = if ($_.StartTime) { $_.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Unavailable' }
        $reason = ($_.Reason -replace '<[^>]+>', ' ' -replace '\s+', ' ').Trim()
        if ($reason.Length -gt 200) { $reason = $reason.Substring(0, 197) + '...' }
        '| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} |' -f `
        (ConvertTo-MarkdownCell $_.JobId),
        (ConvertTo-MarkdownCell $_.Client),
        (ConvertTo-MarkdownCell $_.Item),
        (ConvertTo-MarkdownCell $_.Operation),
        (ConvertTo-MarkdownCell $start),
        (ConvertTo-MarkdownCell $_.Status),
        (ConvertTo-MarkdownCell (ConvertTo-ReadableDuration $_.DurationSeconds)),
        (ConvertTo-MarkdownCell $reason)
    })
if ($attentionLines.Count -eq 0) {
    $attentionLines = @('| All jobs in this period completed successfully. | | | | | | | |')
}

$jobDailySection = if ($dailyDays.Count -gt 0) {
    @"
### Last $JobDailyDays Days Summary

Jobs are counted on the day they started; today is partial.

$(New-JobStatusTable -Jobs $allJobRows -Periods $dailyDays -PeriodKeyFormat 'yyyy-MM-dd' -HeaderFormat 'ddd MMM d')
"@
}
else {
    ''
}

$jobTrendSection = if ($trendMonths.Count -gt 0) {
    $monthFormat = if ($JobTrendMonths -gt 12) { 'MMM yy' } else { 'MMM' }
    @"
### Last $JobTrendMonths Months Backup Statistics

Jobs are counted in the month they started; the current month is partial. Success rate counts completed jobs, including those with errors or warnings. A month with no jobs shows '-', which can also mean the API keeps less job history than the period shown.

$(New-JobStatusTable -Jobs $allJobRows -Periods $trendMonths -PeriodKeyFormat 'yyyy-MM' -HeaderFormat $monthFormat)
"@
}
else {
    ''
}

$attentionNote = if ($attentionJobs.Count -gt $maxAttentionJobs) {
    "Showing the $maxAttentionJobs most recent of $($attentionJobs.Count) jobs that did not complete successfully."
}
else {
    "$($attentionJobs.Count) job(s) did not complete successfully."
}

$inventoryNotesText = if ($inventoryCollectionNotes.Count -gt 0) {
    $inventoryCollectionNotes -join "`r`n"
}
else {
    'Protected-item inventory collection completed.'
}

$md = @"
# Commvault $Mode Health Report - $ClientName - $((Get-Date).ToString('dd MMM yyyy', [cultureinfo]::GetCultureInfo('en-US')))

## License and Subscription Usage

$licenseText

---

## Protected Item Health and SLA

$slaSummary

An item meets the SLA when its last completed backup (with or without errors) is within the SLA period. The protected items combine the configured subclients from the Client/Subclient APIs with the items that ran jobs.

| Client | Workload | Protected item | Plan | SLA period | SLA status | Latest run | Latest status | Last completed backup |
|---|---|---|---|---|---|---|---|---|
$($protectedItemLines -join "`r`n")

Inventory status: $inventoryNotesText

---

## Job History

$jobDailySection

$jobTrendSection

### Last $jobLookbackLabel Overview

- $BackupHealthLabel
- $BackupHealthStatus
- Data protected: $totalDataProtected
- SLA: $slaMet of $($protectedItems.Count) protected items met the SLA

#### Summary per Protected Item

| Client | Protected item | Workload | Jobs | Successful | Errors / warnings | Failed | Success rate | Data protected | Avg duration |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
$($jobSummaryLines -join "`r`n")

#### Jobs Not Completed Successfully

$attentionNote

| Job ID | Client | Protected item | Operation | Start time | Status | Duration | Reason |
|---:|---|---|---|---|---|---:|---|
$($attentionLines -join "`r`n")

---

Report generated: $(Get-Date)
"@

$md | Set-Content -LiteralPath $mdPath -Encoding UTF8 -ErrorAction Stop

Complete-CommvaultReportProgress
Write-Host "Commvault API time: $(@($apiTimes.Keys | ForEach-Object { "$_ $($apiTimes[$_])" }) -join ', ')" -ForegroundColor DarkGray
Write-Host "Report created at: $mdPath" -ForegroundColor Yellow