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

    # The backup trend/daily charts show data-protection backups only. Restores are always left out, and
    # a job whose Application or protected item matches this regex (the daily CommServe DR / system
    # backups) is left out too, so the charts are not padded with one system job per day. Set to '' to
    # keep every backup. If a system job still shows, set this to match its Application value.
    [string]$BackupChartExcludePattern = 'DR\s*Backup|Disaster Recovery|CommServ',

    # SLA period used when Commvault does not return one from its SLA configuration.
    [ValidateRange(1, 365)]
    [int]$DefaultSlaDays = 1,

    [string]$SecretVaultName = 'SecretStore1',

    [string]$OutputFolder = "$HOME\Documents\MetallicReports",

    # Renew the stored Cloud token and exit without building a report.
    [switch]$RenewTokenOnly,

    # Discover the Commvault SLA report/dataset IDs (reusing the login) and exit, writing the findings
    # to <OutputFolder>\sla-discovery.json. Used once to wire Commvault's own SLA into the report.
    [switch]$DiscoverSla
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
    $text = ([string]$Value -replace '\|', '\|' -replace '[\r\n]+', ' ').Trim()
    # Commvault renders an unset date as the Unix epoch (Jan 1 1970, or Dec 31 1969 in some zones);
    # show nothing rather than a meaningless 1970 date.
    if ($text -match '^(Jan 0?1,? 1970|0?1 Jan 1970|1970-01-01|Dec 31,? 1969|31 Dec 1969|1969-12-31)') { return '' }
    # Round long decimals (e.g. license usage 0.55875587463378 -> 0.56); leave integers and ids alone.
    if ($text -match '^-?\d+\.\d{3,}$') {
        $decimal = 0.0
        if ([double]::TryParse($text, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$decimal)) {
            $text = ('{0:0.##}' -f $decimal)
        }
    }
    return $text
}

function ConvertTo-MarkdownTable {
    param([object[]]$Rows)

    $columns = @()
    foreach ($row in $Rows) {
        foreach ($name in $row.PSObject.Properties.Name) {
            if ($columns -notcontains $name) { $columns += $name }
        }
    }
    # Drop only columns the API did not fill in at all: empty in every row (e.g. dates Commvault left
    # at the epoch, now blanked). A column is kept when at least one row has a value - including a zero,
    # because a usage/capacity figure of 0 is real data (do NOT drop zero columns, which hid the usage).
    $columns = @($columns | Where-Object {
            $col = $_
            @($Rows | Where-Object { (ConvertTo-MarkdownCell -Value $_.$col) -ne '' }).Count -gt 0
        })
    if ($columns.Count -eq 0) { return '' }
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
            $record | Select-Object -Property * -ExcludeProperty 'sys_rowid', '$row_number$', 'LicUsageType', 'InputMsg'
            continue
        }
        $row = [ordered]@{}
        for ($index = 0; $index -lt $columns.Count; $index++) {
            $name = Get-FirstObjectValue -InputObject $columns[$index] -Names @('displayName', 'name', 'dataField')
            # Skip Commvault's internal row id, report template placeholders like $row_number$, and the
            # numeric LicUsageType code (its readable name is already shown in the Dial column).
            if (-not $name -or $name -eq 'sys_rowid' -or $name -eq 'LicUsageType' -or $name -eq 'InputMsg' -or $name -match '^\$.*\$$') { continue }
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

function Format-CommvaultSubscriptionDate {
    param($Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return '' }
    $num = 0L
    if ([long]::TryParse([string]$Value, [ref]$num)) {
        if ($num -le 0) { return '' }
        try {
            # Reports-plus-engine returns dates as an epoch; large values are milliseconds, else seconds.
            $dt = if ($num -gt 100000000000) {
                [DateTimeOffset]::FromUnixTimeMilliseconds($num).LocalDateTime
            }
            else {
                [DateTimeOffset]::FromUnixTimeSeconds($num).LocalDateTime
            }
            return $dt.ToString('dd MMM yyyy', [cultureinfo]::GetCultureInfo('en-US'))
        }
        catch { return '' }
    }
    $date = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [ref]$date)) {
        return $date.ToString('dd MMM yyyy', [cultureinfo]::GetCultureInfo('en-US'))
    }
    return [string]$Value
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

# In a background job (Report.ps1), a call SecretManagement passes on to the vault stops the rest
# of the job's progress, Write-Host lines and warnings from reaching the report: there it is made in
# a runspace of its own. SecretStore stays unlocked for the whole process; should the call fail
# there, it is made here.
function Invoke-SecretCommand {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Get-Secret', 'Set-Secret')][string]$Name,
        [Parameter(Mandatory = $true)][hashtable]$Parameters
    )

    if ($Host.Name -eq 'ServerRemoteHost') {
        $vaultCall = [powershell]::Create()
        try {
            [void]$vaultCall.AddCommand('Import-Module').AddParameter('Name', 'Microsoft.PowerShell.SecretManagement').AddStatement()
            [void]$vaultCall.AddCommand($Name).AddParameters($Parameters)
            $result = $vaultCall.Invoke()
            if (-not $vaultCall.HadErrors) {
                return $result
            }
            Write-Verbose "$Name in a runspace of its own failed: $($vaultCall.Streams.Error[0])"
        }
        catch {
            Write-Verbose "$Name in a runspace of its own failed: $($_.Exception.Message)"
        }
        finally {
            $vaultCall.Dispose()
        }
    }
    & $Name @Parameters
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

    $secret = Invoke-SecretCommand -Name Get-Secret -Parameters @{ Name = $name; Vault = $VaultName; ErrorAction = 'Stop' }
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
    # On-premises can log in with a username and password each run (a fresh token, so nothing to
    # renew), instead of a static access token that Commvault expires.
    $username = ConvertFrom-SecureStringToPlainText (& $getSecretValue 'Username')
    $password = ConvertFrom-SecureStringToPlainText (& $getSecretValue 'Password')

    if ($Mode -eq 'Cloud') {
        if (-not $accessToken) { throw "Secret '$name' is missing 'AccessToken'." }
        if (-not $ring) { throw "Cloud secret '$name' is missing 'Ring'." }
    }
    else {
        if (-not ($server -or $ServerOverride)) {
            throw "On-prem secret '$name' is missing 'Server'. Store the Command Center URL in the secret or supply -CommvaultServer."
        }
        if (-not $accessToken -and -not ($username -and $password)) {
            throw "On-prem secret '$name' has neither a username/password nor an access token. Run .\Start.ps1 -Configure, remove this Commvault on-premises (R) and add it again."
        }
    }

    return [PSCustomObject]@{
        AccessToken   = $accessToken
        RefreshToken  = $refreshToken
        Ring          = $ring
        TokenEndpoint = $tokenEndpoint
        ClientId      = $clientId
        ClientSecret  = $clientSecret
        Server        = $server
        Username      = $username
        Password      = $password
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
    $resetHint = "Create a new access and refresh token in Commvault, then run .\Start.ps1 -Configure, remove this Commvault Cloud (R) and add it again with the new tokens (answer n to reusing '$secretName')."
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
        # Windows PowerShell keeps Commvault's answer, which says why, in ErrorDetails.
        $reason = ''
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $answer = [string]$_.ErrorDetails.Message
            try {
                $message = Get-FirstObjectValue -InputObject ($answer | ConvertFrom-Json) -Names @('errorMessage', 'errMessage', 'message', 'error_description', 'error')
                if ($message) { $answer = [string]$message }
            }
            catch {
                # Not JSON: the text as it came.
            }
            # Never show the tokens, should Commvault send them back.
            foreach ($token in @($script:SecretObject.AccessToken, $script:SecretObject.RefreshToken) | Where-Object { $_ }) {
                $answer = $answer -replace [regex]::Escape($token), '<token>'
            }
            $answer = ($answer -replace '\s+', ' ').Trim()
            if ($answer.Length -gt 300) { $answer = $answer.Substring(0, 300) + '...' }
            if ($answer) { $reason = " Commvault says: $answer." }
        }
        # Each refresh token works once: a copy of these tokens renewed elsewhere (another computer,
        # an older script) leaves this one unusable.
        throw "The Commvault access token expired and renewing it at '$renewUri' failed: $($_.Exception.Message)$reason This happens when the tokens were revoked, or renewed from another computer or script that has a copy of them. $resetHint"
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

    Invoke-SecretCommand -Name Set-Secret -Parameters @{ Name = $script:SecretObject.Name; Vault = $script:SecretObject.VaultName; Secret = $updatedSecret; ErrorAction = 'Stop' } | Out-Null
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

# On-premises: log in with the stored username and password (POST /Login) to get a fresh Authtoken,
# so there is no static token to expire. Sets the token on the secret object and rebuilds the headers.
function Connect-CommvaultOnPrem {
    $loginUri = "$($script:BaseUri.TrimEnd('/'))/Login"
    # Commvault expects the password base64-encoded; a domain account is given as domain\user.
    $passwordB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]$script:SecretObject.Password))
    $loginBody = @{ username = [string]$script:SecretObject.Username; password = $passwordB64 } | ConvertTo-Json

    $loginParameters = @{
        Method      = 'POST'
        Uri         = $loginUri
        Headers     = @{ Accept = 'application/json' }
        ContentType = 'application/json'
        Body        = $loginBody
        ErrorAction = 'Stop'
    }
    if ($script:SkipCertCheck -and (Get-Command Invoke-RestMethod).Parameters.ContainsKey('SkipCertificateCheck')) {
        $loginParameters['SkipCertificateCheck'] = $true
    }

    Write-Progress -Activity "Commvault login : $loginUri" -Id 2
    $ProgressPreference = 'SilentlyContinue'
    try {
        $loginResponse = Invoke-RestMethod @loginParameters
    }
    catch {
        $reason = ''
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $answer = [string]$_.ErrorDetails.Message
            try {
                $message = Get-FirstObjectValue -InputObject ($answer | ConvertFrom-Json) -Names @('errorMessage', 'errMessage', 'message', 'error_description', 'error')
                if ($message) { $answer = [string]$message }
            }
            catch { }
            $answer = ($answer -replace '\s+', ' ').Trim()
            if ($answer) { $reason = " Commvault says: $answer." }
        }
        throw "Could not log in to Commvault at $loginUri as '$($script:SecretObject.Username)': $($_.Exception.Message)$reason Check the username, password and that the account may sign in to the Command Center."
    }

    # A failed login can come back as HTTP 200 with an error code and no token.
    $token = Get-FirstObjectValue -InputObject $loginResponse -Names @('token')
    if ([string]::IsNullOrWhiteSpace([string]$token)) {
        $errMessage = Get-FirstObjectValue -InputObject $loginResponse -Names @('errorMessage', 'errMessage', 'error')
        throw "Commvault login at $loginUri returned no token$(if ($errMessage) { ": $errMessage" } else { ' (check the username and password)' })."
    }

    $script:SecretObject.AccessToken = [string]$token
    $script:GlobalHeaders = New-CommvaultHeaders -SecretObject $script:SecretObject -Mode 'OnPrem'
}

# Builds the Invoke-RestMethod parameters for a Commvault API call; also used for the parallel job pages.
function New-MetallicApiRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST', 'PUT', 'DELETE')] [string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [hashtable]$Query = $null,
        [hashtable]$AdditionalHeaders = $null,
        [object]$Body = $null,
        [switch]$DisableKeepAlive,
        [int]$TimeoutSec = 0,
        [switch]$EncodeDatasetColon
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
    # PowerShell 7 ignores the ServicePointManager callback; it needs -SkipCertificateCheck instead.
    if ($script:SkipCertCheck -and (Get-Command Invoke-RestMethod).Parameters.ContainsKey('SkipCertificateCheck')) {
        $requestParameters['SkipCertificateCheck'] = $true
    }
    if ($Body) {
        $requestParameters.Body = $Body | ConvertTo-Json -Depth 12
    }
    # Force a brand-new connection instead of a pooled one. .NET 4.x (Windows PowerShell 5.1) throws
    # "Could not create SSL/TLS secure channel" when it reuses a connection the Metallic gateway has
    # already closed, so the reports-plus-engine calls use this to avoid stale-connection failures.
    if ($DisableKeepAlive) { $requestParameters['DisableKeepAlive'] = $true }
    # Cap the wait: a request a firewall silently drops otherwise hangs for the 100 s default.
    if ($TimeoutSec -gt 0) { $requestParameters['TimeoutSec'] = $TimeoutSec }
    # Send the report:dataset id's ':' as %3A. Firewalls/IPS often block a ':' in a URL path (NTFS
    # alternate-data-stream rule), which resets the connection ("Could not create SSL/TLS secure
    # channel"). Done on the final string because UriBuilder.Path would re-escape the '%'.
    if ($EncodeDatasetColon) {
        $requestParameters.Uri = $requestParameters.Uri -replace '(/datasets/[0-9a-fA-F-]{36}):([0-9a-fA-F-]{36})', '$1%3A$2'
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
        [object]$Body = $null,
        [switch]$DisableKeepAlive,
        [int]$TimeoutSec = 0,
        [switch]$EncodeDatasetColon
    )

    # Connection options, passed again whenever the request is rebuilt after a token renewal.
    $connectionOptions = @{ DisableKeepAlive = $DisableKeepAlive; TimeoutSec = $TimeoutSec; EncodeDatasetColon = $EncodeDatasetColon }
    $requestParameters = New-MetallicApiRequest -Method $Method -Path $Path -Query $Query -AdditionalHeaders $AdditionalHeaders -Body $Body @connectionOptions
    Write-Progress -Activity "Invoke-MetallicApi $Method : $($requestParameters.Uri)" -Id 2
    # Windows PowerShell 5.1 slows large downloads by drawing its own download progress bar;
    # hiding it for this function only keeps the report progress bars visible.
    $ProgressPreference = 'SilentlyContinue'
    try {
        return Invoke-RestMethod @requestParameters
    }
    catch {
        $statusCode = Get-HttpStatusCode -Exception $_.Exception
        # On-premises: with a stored username/password, log in again for a fresh token and retry;
        # otherwise the static token has to be replaced by hand.
        if ($statusCode -eq 401 -and $script:CommvaultMode -eq 'OnPrem') {
            if ($script:SecretObject.Username -and $script:SecretObject.Password) {
                Connect-CommvaultOnPrem
                $requestParameters = New-MetallicApiRequest -Method $Method -Path $Path -Query $Query -AdditionalHeaders $AdditionalHeaders -Body $Body @connectionOptions
                return Invoke-RestMethod @requestParameters
            }
            throw "Commvault refused the access token in secret '$($script:SecretObject.Name)' (401 Unauthorized) at $($requestParameters.Uri). If it expired or was revoked, run .\Start.ps1 -Configure, remove this Commvault on-premises (R) and add it again - it now stores a username and password and logs in for a fresh token each run."
        }
        if ($statusCode -ne 401 -or $script:CommvaultMode -ne 'Cloud') {
            throw
        }

        Update-MetallicAccessToken
        $requestParameters = New-MetallicApiRequest -Method $Method -Path $Path -Query $Query -AdditionalHeaders $AdditionalHeaders -Body $Body @connectionOptions
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

# The time of each part of the report, from here, shown at the end to see where the time goes.
$apiTimes = [ordered]@{}
$apiTimer = [System.Diagnostics.Stopwatch]::StartNew()

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
$script:SkipCertCheck = $false
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

    # The CommServe often presents a self-signed or internal-CA certificate that Windows does not
    # trust, which fails the TLS handshake ("Could not establish trust relationship for the SSL/TLS
    # secure channel"). Accept the certificate for this on-premises connection, the way the Veeam
    # REST collector does; Cloud (api.metallic.io) keeps normal certificate validation.
    $script:SkipCertCheck = $true
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    if ($PSVersionTable.PSEdition -ne 'Core') {
        # A scriptblock callback runs on a .NET worker thread that has no PowerShell runspace and throws
        # ("There is no Runspace available"); a compiled delegate works there, as the Veeam collector does.
        if (-not ('CommvaultApiCertificateValidation' -as [type])) {
            Add-Type -TypeDefinition @"
                using System;
                using System.Net;
                using System.Net.Security;
                using System.Security.Cryptography.X509Certificates;
                public static class CommvaultApiCertificateValidation {
                    public static string ExpectedHost { get; set; }
                    public static bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
                        if (errors == SslPolicyErrors.None) { return true; }
                        var request = sender as HttpWebRequest;
                        return request != null && String.Equals(request.RequestUri.Host, ExpectedHost, StringComparison.OrdinalIgnoreCase);
                    }
                }
"@ -ErrorAction Stop
        }
        [CommvaultApiCertificateValidation]::ExpectedHost = ([uri]$script:BaseUri).Host
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [Delegate]::CreateDelegate(
            [System.Net.Security.RemoteCertificateValidationCallback],
            [CommvaultApiCertificateValidation],
            'Validate'
        )
    }
}
$script:GlobalHeaders.Authorization = "Bearer $($secretObj.AccessToken)"

$script:GlobalHeaders = New-CommvaultHeaders -SecretObject $secretObj -Mode $Mode

# On-premises with a stored username/password logs in now for a fresh token, so there is no static
# token to expire between runs (Cloud keeps its access/refresh token chain instead).
if ($Mode -eq 'OnPrem' -and $secretObj.Username -and $secretObj.Password) {
    Connect-CommvaultOnPrem
}

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

# Discover the Commvault SLA report and its dataset GUID (so the report can read Commvault's own SLA,
# matching Command Center), then exit. Dumps the raw reports-engine responses to a file to read back.
if ($DiscoverSla) {
    Write-Host "`n=== SLA dataset discovery ===" -ForegroundColor Cyan

    # Run standalone, this session's TLS/cert state is not the fresh one the report normally runs in
    # (a background job), so the on-prem TLS handshake can fail ("Could not create SSL/TLS secure
    # channel"). Force TLS 1.2 cleanly and re-assert the compiled certificate callback before calling.
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    if ($Mode -eq 'OnPrem' -and $PSVersionTable.PSEdition -ne 'Core' -and ('CommvaultApiCertificateValidation' -as [type])) {
        [CommvaultApiCertificateValidation]::ExpectedHost = ([uri]$script:BaseUri).Host
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [Delegate]::CreateDelegate(
            [System.Net.Security.RemoteCertificateValidationCallback], [CommvaultApiCertificateValidation], 'Validate')
    }

    $discovery = [ordered]@{ generated = (Get-Date).ToString('o'); baseUri = $script:BaseUri; attempts = @() }
    function Invoke-SlaDiscovery {
        param([string]$Path)
        $entry = [ordered]@{ path = $Path; ok = $false; error = $null; errorType = $null; innerError = $null; response = $null }
        try {
            Write-Host "GET $Path" -ForegroundColor DarkGray
            $entry.response = Invoke-MetallicApi -Method GET -Path $Path
            $entry.ok = $true
        }
        catch {
            $entry.error = $_.Exception.Message
            $entry.errorType = $_.Exception.GetType().FullName
            if ($_.Exception.InnerException) { $entry.innerError = $_.Exception.InnerException.Message }
            Write-Host "  failed: $($entry.error)" -ForegroundColor Yellow
        }
        $discovery.attempts += $entry
        return $entry
    }

    # The reports-engine list of installed reports. A couple of spellings are tried in case the path differs.
    $listEntry = $null
    foreach ($listPath in @('/cr/reportsplusengine/reports', '/cr/reportsplusengine/reports/')) {
        $listEntry = Invoke-SlaDiscovery -Path $listPath
        if ($listEntry.ok -and $listEntry.response) { break }
    }

    # Pull report name/guid pairs out of the response whatever its exact shape, and keep the SLA ones.
    $slaReports = @()
    if ($listEntry -and $listEntry.ok -and $listEntry.response) {
        $listJson = $listEntry.response | ConvertTo-Json -Depth 30 -Compress
        $guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        $patterns = @(
            ('"name"\s*:\s*"([^"]*[Ss][Ll][Aa][^"]*)"[^{}]*?"guid"\s*:\s*"(' + $guidPattern + ')"'),
            ('"guid"\s*:\s*"(' + $guidPattern + ')"[^{}]*?"name"\s*:\s*"([^"]*[Ss][Ll][Aa][^"]*)"')
        )
        $nameFirst = $true
        foreach ($pat in $patterns) {
            foreach ($match in [regex]::Matches($listJson, $pat)) {
                if ($nameFirst) { $reportName = $match.Groups[1].Value; $reportGuid = $match.Groups[2].Value }
                else { $reportGuid = $match.Groups[1].Value; $reportName = $match.Groups[2].Value }
                $slaReports += [pscustomobject]@{ Name = $reportName; Guid = $reportGuid }
            }
            $nameFirst = $false
        }
        $slaReports = @($slaReports | Sort-Object Guid -Unique)
    }

    # For each SLA report, fetch its definition (which lists the dataset GUIDs the report draws from).
    foreach ($slaReport in $slaReports) {
        Write-Host "SLA report: $($slaReport.Name)  [$($slaReport.Guid)]" -ForegroundColor Green
        Invoke-SlaDiscovery -Path "/cr/reportsplusengine/reports/$($slaReport.Guid)" | Out-Null
    }

    if (-not (Test-Path -LiteralPath $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }
    $discoveryFile = Join-Path $OutputFolder 'sla-discovery.json'
    $discovery | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $discoveryFile -Encoding UTF8
    Write-Host "`nSaved discovery to: $discoveryFile" -ForegroundColor Cyan
    if ($slaReports.Count -gt 0) {
        Write-Host "Found $($slaReports.Count) SLA report(s) - the file has their definitions and dataset IDs." -ForegroundColor Green
    }
    else {
        Write-Host "No report name matched 'SLA' in the list - the file still has the full reports list to work from." -ForegroundColor Yellow
    }
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
$apiTimes['token'] = $apiTimer.Elapsed.ToString('m\:ss')

$licenseSections = @()
$licenseNotes = @()
$licenseForbidden = @()
$licenseResults = @()
$licenseNames = @()
# On Commvault Cloud the License Summary datasets are CommCell-administrator reports: a tenant gets
# nothing from them (403 / no rows) and the one-at-a-time retry of their connection failures costs
# many minutes. Cloud licence usage comes from the Subscription Usage by Tenant dataset below instead,
# so the License Summary fetch runs on-premises only.
if ($Mode -ne 'Cloud') {
    Write-CommvaultReportProgress -Status "License usage: asking for $($licenseDatasets.Count) datasets at once" -PercentComplete 5
    # Commvault runs each dataset's query when it is asked for, so they are all asked for at once.
    $licenseNames = @($licenseDatasets.Keys)
$licenseRequests = @(foreach ($licenseName in $licenseNames) {
    @{ Method = 'GET'; Path = "/cr/reportsplusengine/datasets/$($licenseDatasets[$licenseName])/data" }
})
$licenseResults = @(Invoke-MetallicApiParallel -Requests $licenseRequests -ThrottleLimit $licenseRequests.Count -OnProgress {
    param($Answered, $Elapsed)
    Write-CommvaultReportProgress -Status "License usage: $Answered of $($licenseNames.Count) datasets received ($($Elapsed.ToString('m\:ss')))" -PercentComplete (5 + 10 * $Answered / $licenseNames.Count)
})
# Sent at once, the calls can all fail before Commvault answers (seen: "Could not create SSL/TLS
# secure channel"): those are asked for again, one at a time.
for ($licenseIndex = 0; $licenseIndex -lt $licenseNames.Count; $licenseIndex++) {
    $licenseResult = $licenseResults[$licenseIndex]
    if (-not $licenseResult.Error -or $null -ne (Get-HttpStatusCode -Exception $licenseResult.Error)) {
        continue
    }
    Write-CommvaultReportProgress -Status "License usage: asking again for $($licenseNames[$licenseIndex]), one at a time ($($apiTimer.Elapsed.ToString('m\:ss')))" -PercentComplete 15
    $licenseRequest = $licenseRequests[$licenseIndex]
    $licenseWatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $licenseResult.Response = Invoke-MetallicApi @licenseRequest
        $licenseResult.Error = $null
    }
    catch {
        $licenseResult.Error = $_.Exception
    }
    $licenseResult.Seconds = $licenseWatch.Elapsed.TotalSeconds
}
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
        # Refused to the account: said once for all of them, rather than in Windows' language for each.
        if ((Get-HttpStatusCode -Exception $_.Exception) -eq 403) {
            $licenseForbidden += $licenseName
        }
        else {
            $licenseNotes += "- ${licenseName}: $($_.Exception.Message)"
        }
    }
}
if ($licenseForbidden.Count -gt 0) {
    $licenseNotes = @("- $($licenseForbidden -join ', '): Commvault refused them to this account (HTTP 403 Forbidden): the License Summary report is for CommCell administrators.") + $licenseNotes
}
}

# Subscription Usage by Tenant (Commvault Cloud / Metallic). The License Summary datasets above return
# no rows on Cloud (the tenant does not own the CommCell), but "Subscription Usage by Tenant" IS a
# tenant report, so the tenant token reads its dataset directly - this is the licence consumption
# (entitled quantity, peak usage, peak %) the manual Subscriptions export used to carry. Best-effort:
# if it returns rows they replace the manual-export placeholder; if it is refused/empty it falls back
# to that placeholder. Dataset id (report:dataset) is Commvault's shipped Subscription Usage report.
if ($Mode -eq 'Cloud') {
    try {
        Write-CommvaultReportProgress -Status 'License usage: reading Subscription Usage by Tenant' -PercentComplete 16
        # sys_rowid is kept because some datasets require it; every field is aliased so the parsed
        # column names are deterministic (ConvertFrom-CommvaultDataset drops sys_rowid itself).
        $subFields = '[sys_rowid],[baseOfferingDisplayName] AS [Offering],[subscriptionType] AS [Subscription],[unitOfMeasure] AS [Unit],[quantity] AS [Entitled],[peakUsage] AS [PeakUsage],[peakUsagePct] AS [PeakPct],[isActive] AS [Active],[startDate] AS [StartDate],[endDate] AS [EndDate]'
        # From some networks the call is reset before Commvault answers ("Could not create SSL/TLS secure
        # channel") while every other api.metallic.io call works: a firewall/IPS between this machine and
        # Commvault Cloud blocks the ':' in the report:dataset path and/or the bracketed fields query
        # (looks like SQL). So up to three shapes are tried - each on a fresh connection, capped at 25 s
        # so a dropped request cannot hang the report - and the first one Commvault actually answers wins:
        #   1. as Command Center sends it   2. ':' sent as %3A   3. %3A and no fields query (default columns)
        # A real HTTP answer (200/401/403...) is final and handled below; only a connection failure moves on.
        $subPath = '/cr/reportsplusengine/datasets/e2a304c9-fc1c-4ced-a5eb-d393e500fbca:bcdb3658-e0a4-46cb-8d22-d8a732f9289c/data'
        $subFullQuery = @{ fields = $subFields; orderby = '[baseOfferingDisplayName] Asc'; timeZoneOffset = '-60' }
        $subShapes = @(
            @{ EncodeDatasetColon = $false; Query = $subFullQuery }
            @{ EncodeDatasetColon = $true;  Query = $subFullQuery }
            @{ EncodeDatasetColon = $true;  Query = @{ timeZoneOffset = '-60' } }
        )
        $subResponse = $null
        for ($subIndex = 0; $subIndex -lt $subShapes.Count; $subIndex++) {
            $shape = $subShapes[$subIndex]
            try {
                $subResponse = Invoke-MetallicApi -Method GET -Path $subPath -Query $shape.Query -DisableKeepAlive -TimeoutSec 25 -EncodeDatasetColon:$shape.EncodeDatasetColon
                break
            }
            catch {
                if ((Get-HttpStatusCode -Exception $_.Exception) -or $subIndex -ge $subShapes.Count - 1) { throw }
            }
        }
        $subRowsRaw = @(ConvertFrom-CommvaultDataset -Response $subResponse)
        if ($subRowsRaw.Count -gt 0) {
            # Our aliases (Offering, Entitled...) come back with the fields query; without it (shape 3) the
            # dataset's own column names do - so each value is read from a list of candidate names.
            $pick = {
                param($Row, [string[]]$Names)
                Get-FirstObjectValue -InputObject $Row -Names $Names
            }
            $subRows = @(foreach ($r in $subRowsRaw) {
                    $activeRaw = & $pick $r @('Active', 'isActive', 'Is Active', 'Status')
                    $active = switch -Regex ("$activeRaw") {
                        '^(1|true|yes)$' { 'Yes'; break }
                        '^(0|false|no)$' { 'No'; break }
                        default { "$activeRaw" }
                    }
                    $pct = "$(& $pick $r @('PeakPct', 'peakUsagePct', 'Peak Usage Pct', 'Peak Usage %', 'Peak Usage (%)', 'Peak %'))"
                    if ($pct -match '^-?\d+(\.\d+)?$') { $pct = '{0:0.#} %' -f [double]$pct }
                    [PSCustomObject][ordered]@{
                        'Offering'     = & $pick $r @('Offering', 'baseOfferingDisplayName', 'Base Offering', 'Base Offering Display Name', 'Offering Name')
                        'Subscription' = & $pick $r @('Subscription', 'subscriptionType', 'Subscription Type')
                        'Unit'         = & $pick $r @('Unit', 'unitOfMeasure', 'Unit Of Measure', 'Unit of Measure')
                        'Entitled'     = & $pick $r @('Entitled', 'quantity', 'Quantity')
                        'Peak usage'   = & $pick $r @('PeakUsage', 'peakUsage', 'Peak Usage')
                        'Peak %'       = $pct
                        'Active'       = $active
                        'Start'        = Format-CommvaultSubscriptionDate (& $pick $r @('StartDate', 'startDate', 'Start Date'))
                        'End'          = Format-CommvaultSubscriptionDate (& $pick $r @('EndDate', 'endDate', 'End Date'))
                    }
                })
            # If none of the candidate names matched (unexpected column names), show the dataset as it
            # came back rather than an empty table.
            $mapped = @($subRows | Where-Object { $_.Offering }).Count -gt 0
            $subTable = if ($mapped) { ConvertTo-MarkdownTable -Rows $subRows } else { ConvertTo-MarkdownTable -Rows $subRowsRaw }
            # Real subscription usage goes at the top of the licence section; a non-empty licenseSections
            # also skips the manual-export placeholder below.
            $licenseSections = @("### Subscription usage by tenant`r`n`r`n$subTable") + $licenseSections
        }
        else {
            $licenseNotes += '- Subscription Usage by Tenant: the dataset returned no rows.'
        }
    }
    catch {
        $subCode = Get-HttpStatusCode -Exception $_.Exception
        if ($subCode -eq 403) {
            $licenseNotes += '- Subscription Usage by Tenant: Commvault refused it to this account (HTTP 403 Forbidden).'
        }
        elseif (-not $subCode) {
            $licenseNotes += "- Subscription Usage by Tenant: the connection was reset before Commvault answered ($($_.Exception.Message)). Other Commvault Cloud calls work, so a firewall/proxy on this network is likely blocking Commvault's reports API path."
        }
        else {
            $licenseNotes += "- Subscription Usage by Tenant: HTTP $subCode - $($_.Exception.Message)"
        }
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
if ($licenseSections.Count -eq 0 -and $Mode -eq 'Cloud') {
    # Commvault Cloud runs the CommCell, so even a tenant's administrator gets no license rows:
    # Report.ps1 puts the Subscriptions page exported from Commvault Cloud in place of this text.
    $licenseText = "<!-- MOSE:CommvaultSubscriptions -->`r`n$licenseText`r`n<!-- /MOSE:CommvaultSubscriptions -->"
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
    if (-not $planName) { $planName = '' }

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
                        Plan              = if ($inventoryPlan) { [string]$inventoryPlan } else { '' }
                        LatestStatus      = 'No job in lookback'
                        LatestRun         = $null
                        LastSuccessfulRun = $null
                        SlaTarget         = $null
                        SlaStatus         = $null
                    }
                }
                elseif ($inventoryPlan -and -not $protectedItemsByKey[$itemKey].Plan) {
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
    # Exclude an item only when its own client's SLA setting says so. The CommCell-level excludeFromSLA
    # flag is not a per-item exclusion: using it as a fallback excluded every item (0 met) whenever the
    # per-client SLA lookup came back empty, which is wrong when backups are completing.
    $protectedItem.SlaStatus = if ($slaSetting -and $slaSetting.Excluded) {
        if ($slaSetting.Reason) { "Excluded ($($slaSetting.Reason))" } else { 'Excluded' }
    }
    elseif (-not $lastBackup) {
        # No backup at all in the whole lookback: likely a default/system subclient that is not actually
        # protected (no plan, never run). Shown as its own category, not counted as a missed SLA, so one
        # real figure is not drowned out by placeholders -- but still listed, to verify.
        "No backup in the last $fetchedDays days"
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
$slaNoHistory = @($protectedItems | Where-Object { $_.SlaStatus -like 'No backup*' }).Count
$slaWithHistory = $slaMet + $slaMissed
$slaPeriods = @($protectedItems.SlaTarget | Sort-Object -Unique)
$slaSource = if ($slaDefaultUsed) {
    "the Commvault SLA configuration was not available for every item, so $DefaultSlaDays day(s) is used where it was missing"
}
else {
    'from the Commvault SLA configuration'
}
$slaSummary = "SLA period: $($slaPeriods -join ', ') ($slaSource). $slaMet of $slaWithHistory protected items with backup history met the SLA"
if ($slaMissed -gt 0) { $slaSummary += ", $slaMissed missed" }
if ($slaExcluded -gt 0) { $slaSummary += ", $slaExcluded excluded" }
if ($slaNoHistory -gt 0) { $slaSummary += ". $slaNoHistory item(s) have no backup in the last $fetchedDays days (often default/system subclients) - verify whether they are meant to be protected" }
$slaSummary += '.'
if ($slaNote) { $slaSummary += " $slaNote" }

# Commvault's OWN SLA figure, from the same dataset the Command Center SLA tile uses (getslacounts).
# This is the authoritative Met/Missed count the dashboard shows; the per-item analysis above is MOSE's
# own and can differ (Commvault's SLA engine has its own exclusions and strike logic). Best effort: on
# any failure the report still has the analysis above.
$commvaultSlaBlock = ''
try {
    Write-CommvaultReportProgress -Status "Reading Commvault's own SLA (Command Center)" -PercentComplete 87
    $slaCountsResponse = Invoke-MetallicApi -Method GET -Path '/cr/reportsplusengine/datasets/getslacounts/data' -Query @{
        cache                       = 'true'
        'parameter.i_dashboardtype' = 'commcell'
        datasource                  = '2'
    }
    $slaCountRows = @(ConvertFrom-CommvaultDataset -Response $slaCountsResponse)
    $cvStatusCount = [ordered]@{}
    $cvMissedClients = @()
    foreach ($slaRow in $slaCountRows) {
        $cvStatus = [string](Get-FirstObjectValue -InputObject $slaRow -Names @('SLAStatus', 'SLA Status', 'Status'))
        if (-not $cvStatus) { continue }
        $cvCount = 0
        [void][int]::TryParse([string](Get-FirstObjectValue -InputObject $slaRow -Names @('CurrentCount', 'Current Count', 'Count')), [ref]$cvCount)
        $cvStatusCount[$cvStatus] = $cvCount + [int]$cvStatusCount[$cvStatus]
        if ($cvStatus -eq 'Missed SLA' -and $cvCount -gt 0) {
            $cvClient = [string](Get-FirstObjectValue -InputObject $slaRow -Names @('Data Source', 'DataSource', 'clientName', 'Client'))
            if ($cvClient) { $cvMissedClients += "$cvClient ($cvCount)" }
        }
    }
    $cvMet = [int]$cvStatusCount['Met SLA']
    $cvMissed = [int]$cvStatusCount['Missed SLA']
    $cvTotal = $cvMet + $cvMissed
    if ($slaCountRows.Count -gt 0 -and ($cvStatusCount.Keys.Count -gt 0)) {
        $cvPct = if ($cvTotal -gt 0) { [math]::Round(100 * $cvMet / $cvTotal, 1) } else { 0 }
        $cvPending = @($cvStatusCount.Keys | Where-Object { $_ -notin @('Met SLA', 'Missed SLA') -and [int]$cvStatusCount[$_] -gt 0 } |
            ForEach-Object { "$($_): $([int]$cvStatusCount[$_])" })
        $commvaultSlaBlock = "**Commvault SLA (Command Center): $cvMet of $cvTotal met ($cvPct%), $cvMissed missed.**"
        if ($cvPending.Count -gt 0) { $commvaultSlaBlock += ' ' + ($cvPending -join '; ') + '.' }
        if ($cvMissedClients.Count -gt 0) { $commvaultSlaBlock += " Missed: $($cvMissedClients -join ', ')." }
        # Command Center is authoritative above, so drop MOSE's own met/missed count (it reads as a
        # competing figure). Keep only the context the dashboard tile does not give: the SLA period and
        # any items with no backup at all, which are worth verifying.
        $moseContext = "SLA period: $($slaPeriods -join ', ') ($slaSource)."
        $moseExtras = @()
        if ($slaExcluded -gt 0) { $moseExtras += "$slaExcluded excluded from SLA" }
        if ($slaNoHistory -gt 0) { $moseExtras += "$slaNoHistory with no backup in the last $fetchedDays days (often default/system subclients) - verify whether they are meant to be protected" }
        $slaSummary = "MOSE per-item view (context only; the Command Center figure above is authoritative) - $moseContext"
        if ($moseExtras.Count -gt 0) { $slaSummary += ' ' + ($moseExtras -join '; ') + '.' }
        if ($slaNote) { $slaSummary += " $slaNote" }
    }
    $apiTimes['sla-counts'] = $apiTimer.Elapsed.ToString('m\:ss')
}
catch {
    Write-Warning "Could not read Commvault's own SLA (getslacounts): $($_.Exception.Message)"
}

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

# Only items with backup history: the never-run default/system subclients (counted separately as "no
# backup in the lookback", which is why the Command Center SLA count is lower) are left out so the
# table reflects what is actually protected. Columns trimmed to the useful ones.
$protectedItemLines = @($protectedItems | Where-Object { $_.SlaStatus -notlike 'No backup*' } | ForEach-Object {
        $lastSuccess = if ($_.LastSuccessfulRun) { $_.LastSuccessfulRun.ToString('yyyy-MM-dd HH:mm:ss') } else { "None in the last $fetchedDays days" }
        '| {0} | {1} | {2} | {3} | {4} | {5} |' -f `
        (ConvertTo-MarkdownCell $_.Client),
        (ConvertTo-MarkdownCell $_.Application),
        (ConvertTo-MarkdownCell $_.Item),
        (ConvertTo-MarkdownCell $_.Plan),
        (ConvertTo-MarkdownCell $_.SlaStatus),
        (ConvertTo-MarkdownCell $lastSuccess)
    })
if ($protectedItemLines.Count -eq 0) {
    $protectedItemLines = @('| All protected items with backup history met the SLA. | | | | | |')
}

# SLA graph (drawn by the WordPress plugin): items that met and missed the SLA, in total and, with
# several workloads, per workload. Excluded items are not counted.
$slaGraph = ''
$slaCounted = @($protectedItems | Where-Object { $_.SlaStatus -eq 'Met' -or $_.SlaStatus -like 'Missed*' })
if ($slaCounted.Count -gt 0) {
    $slaGraphRows = @("| All protected items | $slaMet | $slaMissed |")
    $slaWorkloads = @($slaCounted | Group-Object -Property Application | Sort-Object -Property Name)
    if ($slaWorkloads.Count -gt 1) {
        foreach ($workload in $slaWorkloads) {
            $workloadMet = @($workload.Group | Where-Object { $_.SlaStatus -eq 'Met' }).Count
            $workloadName = if ($workload.Name) { $workload.Name } else { 'Other' }
            $slaGraphRows += '| {0} | {1} | {2} |' -f (ConvertTo-MarkdownCell $workloadName), $workloadMet, ($workload.Count - $workloadMet)
        }
    }
    $slaGraph = (@('```SLA', '| Protected items within the SLA | Met | Missed |', '|---|---|---|') + $slaGraphRows + @('```')) -join "`r`n"
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

# The trend and daily charts show data-protection backups only: restores are not backups, and the daily
# CommServe DR / system backups are excluded ($BackupChartExcludePattern) so a month is not padded with
# one system job per day. Every other section still uses the full job set ($allJobRows).
$backupChartJobs = @($allJobRows | Where-Object {
    $_.Operation -notmatch 'Restore' -and
    (-not $BackupChartExcludePattern -or
        -not ("$($_.Application)" -match $BackupChartExcludePattern -or "$($_.Item)" -match $BackupChartExcludePattern))
})

# Trim leading months so the chart covers only the period that actually has data. After Commvault ages
# out older job history, a month keeps at most the residual daily system/DR backup (~one job per day),
# which looks exactly like the number of days in the month. So drop a leading month whose backup count
# is at or below the number of days in it (<= ~1/day = residual, not real workload), and start the chart
# at the first month with real activity. If no month exceeds that, leave the table as is (don't blank it).
if ($trendMonths.Count -gt 0 -and $backupChartJobs.Count -gt 0) {
    $invariantMonth = [cultureinfo]::InvariantCulture
    $monthBackupCount = @{}
    foreach ($chartJob in $backupChartJobs) {
        if ($chartJob.StartTime) {
            $monthKey = $chartJob.StartTime.ToString('yyyy-MM', $invariantMonth)
            $monthBackupCount[$monthKey] = 1 + [int]$monthBackupCount[$monthKey]
        }
    }
    $firstMonth = -1
    for ($monthIndex = 0; $monthIndex -lt $trendMonths.Count; $monthIndex++) {
        $trendMonth = $trendMonths[$monthIndex]
        $monthKey = $trendMonth.ToString('yyyy-MM', $invariantMonth)
        $daysInMonth = [datetime]::DaysInMonth($trendMonth.Year, $trendMonth.Month)
        if ([int]$monthBackupCount[$monthKey] -gt $daysInMonth) { $firstMonth = $monthIndex; break }
    }
    if ($firstMonth -gt 0) {
        $trendMonths = @($trendMonths[$firstMonth..($trendMonths.Count - 1)])
    }
}

$jobDailySection = if ($dailyDays.Count -gt 0) {
    @"
### Last $JobDailyDays Days Summary

Jobs are counted on the day they started; today is partial. Restores are excluded.

$(New-JobStatusTable -Jobs $backupChartJobs -Periods $dailyDays -PeriodKeyFormat 'yyyy-MM-dd' -HeaderFormat 'ddd MMM d')
"@
}
else {
    ''
}

$jobTrendSection = if ($trendMonths.Count -gt 0) {
    $monthFormat = if ($trendMonths.Count -gt 12) { 'MMM yy' } else { 'MMM' }
    @"
### Last $($trendMonths.Count) Months Backup Statistics

Jobs are counted in the month they started; the current month is partial. Restores are excluded. Success rate counts completed jobs, including those with errors or warnings. The chart reaches back only as far as Commvault still keeps backup job history: after older months age out, only the daily system/DR backup remains (about one job per day), so leading months with at most one backup per day are not shown and the chart starts at the first month with real workload.

$(New-JobStatusTable -Jobs $backupChartJobs -Periods $trendMonths -PeriodKeyFormat 'yyyy-MM' -HeaderFormat $monthFormat)
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

#--------------------------------------------------------
# STORAGE AND MEDIA AGENTS (on-premises only)
#--------------------------------------------------------
# Media agent health, storage pool capacity and free space, and free (spare) tape media. On-premises
# only - Commvault Cloud runs the storage itself. Best-effort: every call is guarded, so anything
# that cannot be read becomes a note instead of stopping the report. Field names and units differ
# between CommServe versions, so each value is read from a list of candidate names; if a column
# comes back blank or a size looks off, the raw endpoint output tells which name/unit to use.
$storageSection = ''
if ($Mode -eq 'OnPrem') {
    $storageBlocks = @()
    $storageNotes = @()

    # Media agents: name, online/offline, version.
    try {
        Write-CommvaultReportProgress -Status 'Storage: reading media agents' -PercentComplete 86
        $maResponse = Invoke-MetallicApi -Method GET -Path '/MediaAgent'
        # The /MediaAgent list carries only name + id (in entityInfo); status/version need the per-agent
        # detail call /MediaAgent/{id}. Keep the item whole (no unwrap) so we can read its id.
        $mediaAgents = @()
        foreach ($cn in @('mediaAgentList', 'mediaAgents', 'response')) {
            $prop = $maResponse.PSObject.Properties[$cn]
            if ($null -ne $prop -and $null -ne $prop.Value) { $mediaAgents = @($prop.Value); break }
        }
        if ($mediaAgents.Count -gt 0) {
            $maLines = foreach ($ma in $mediaAgents) {
                $entity = if ($ma.PSObject.Properties['entityInfo']) { $ma.entityInfo } else { $ma }
                $name = Get-FirstObjectValue -InputObject $entity -Names @('name', 'mediaAgentName', 'displayName', 'clientName')
                $maId = Get-FirstObjectValue -InputObject $entity -Names @('id', 'mediaAgentId', 'clientId')
                $statusRaw = $null; $version = $null
                if ($maId) {
                    try {
                        $maDetail = Invoke-MetallicApi -Method GET -Path "/MediaAgent/$maId"
                        $src = $maDetail
                        foreach ($cn in @('mediaAgentList', 'mediaAgents', 'response')) {
                            $p = $maDetail.PSObject.Properties[$cn]
                            if ($null -ne $p -and $null -ne $p.Value) {
                                $first = @($p.Value)[0]
                                if ($null -ne $first) { $src = $first }
                                break
                            }
                        }
                        foreach ($w in @('mediaAgent', 'mediaAgentInfo', 'mediaAgentProperties')) {
                            if ($src.PSObject.Properties[$w] -and $null -ne $src.$w) { $src = $src.$w }
                        }
                        $statusRaw = Get-FirstObjectValue -InputObject $src -Names @('status', 'isOnline', 'onlineStatus', 'health', 'mediaAgentStatus')
                        $version = Get-FirstObjectValue -InputObject $src -Names @('version', 'mediaAgentVersion', 'csVersion')
                        $offline = Get-FirstObjectValue -InputObject $src -Names @('offlineReason')
                        if ($null -ne $offline -and "$offline" -ne '0') { $statusRaw = 'Offline' }
                    }
                    catch { }
                }
                $status = switch -Regex ("$statusRaw") {
                    '^(1|true|online|ready|up)$' { 'Online'; break }
                    '^(0|false|offline|down)$' { 'Offline'; break }
                    default { if ("$statusRaw") { "$statusRaw" } else { '-' } }
                }
                "| $(ConvertTo-MarkdownCell $name) | $status | $(ConvertTo-MarkdownCell $version) |"
            }
            $storageBlocks += "### Media agents`r`n`r`n| Media agent | Status | Version |`r`n|---|---|---|`r`n$($maLines -join "`r`n")"
        }
        else {
            $storageNotes += "- /MediaAgent: no media agent was returned (or the field names differ on this CommServe)."
        }
    }
    catch {
        $maCode = Get-HttpStatusCode -Exception $_.Exception
        $storageNotes += "- /MediaAgent: $(if ($maCode) { "HTTP $maCode - " })$($_.Exception.Message)"
    }

    # Storage pools: capacity, free space, used %. The /StoragePool items carry capacity/free/status at
    # the TOP level and the pool name only in a nested storagePoolEntity, so do NOT unwrap the item
    # (unwrapping to the entity drops every size, which is what showed "Unavailable"). Sizes are in MB.
    try {
        Write-CommvaultReportProgress -Status 'Storage: reading storage pools' -PercentComplete 88
        $spResponse = Invoke-MetallicApi -Method GET -Path '/StoragePool'
        $pools = @()
        foreach ($cn in @('storagePoolList', 'storagePools', 'response')) {
            $prop = $spResponse.PSObject.Properties[$cn]
            if ($null -ne $prop -and $null -ne $prop.Value) { $pools = @($prop.Value); break }
        }
        if ($pools.Count -gt 0) {
            $poolLines = foreach ($pool in $pools) {
                $name = Get-FirstObjectValue -InputObject $pool -Names @('storagePoolName', 'name', 'displayName')
                if (-not $name -and $pool.PSObject.Properties['storagePoolEntity']) {
                    $name = Get-FirstObjectValue -InputObject $pool.storagePoolEntity -Names @('storagePoolName', 'name')
                }
                if (-not $name -and $pool.PSObject.Properties['storagePool']) {
                    $name = Get-FirstObjectValue -InputObject $pool.storagePool -Names @('clientGroupName', 'name')
                }
                $status = Get-FirstObjectValue -InputObject $pool -Names @('status', 'statusString')
                # Sizes are returned in MB - convert to bytes for ConvertTo-ReadableBytes.
                $totalMb = Get-FirstObjectValue -InputObject $pool -Names @('totalCapacity', 'totalCapacityMB', 'capacityMB')
                $freeMb = Get-FirstObjectValue -InputObject $pool -Names @('totalFreeSpace', 'totalUsableFreeSpace', 'freeSpace')
                $totalBytes = $null; $freeBytes = $null; $tmp = 0.0
                if ([double]::TryParse("$totalMb", [ref]$tmp) -and $tmp -gt 0) { $totalBytes = $tmp * 1MB }
                if ([double]::TryParse("$freeMb", [ref]$tmp)) { $freeBytes = $tmp * 1MB }
                $used = ''
                if ($null -ne $totalBytes -and $totalBytes -gt 0 -and $null -ne $freeBytes) {
                    $used = '{0:N0} %' -f ((($totalBytes - $freeBytes) / $totalBytes) * 100)
                }
                $capCell = if ($null -ne $totalBytes) { ConvertTo-ReadableBytes $totalBytes } else { 'Unavailable' }
                $freeCell = if ($null -ne $freeBytes) { ConvertTo-ReadableBytes $freeBytes } else { 'Unavailable' }
                "| $(ConvertTo-MarkdownCell $name) | $(ConvertTo-MarkdownCell $status) | $capCell | $freeCell | $used |"
            }
            $storageBlocks += "### Storage pools`r`n`r`n| Storage pool | Status | Capacity | Free | Used |`r`n|---|---|---:|---:|---:|`r`n$($poolLines -join "`r`n")"
        }
        else {
            $storageNotes += "- /StoragePool: no storage pool was returned (or the field names differ on this CommServe)."
        }
    }
    catch {
        $spCode = Get-HttpStatusCode -Exception $_.Exception
        $storageNotes += "- /StoragePool: $(if ($spCode) { "HTTP $spCode - " })$($_.Exception.Message)"
    }

    # Tape libraries: free (spare / scratch) media. Not every CommServe returns spare counts at this
    # detail level; when it does not, a note says so rather than inventing a number.
    try {
        Write-CommvaultReportProgress -Status 'Storage: reading tape libraries' -PercentComplete 90
        # The plain /Library list returns name + id only (the libraryType=2 filter returns HTTP 500 on this
        # CommServe), so list all libraries and get spare-media counts from the per-library detail call.
        $libResponse = Invoke-MetallicApi -Method GET -Path '/Library'
        $libraries = @()
        foreach ($cn in @('response', 'libraryList', 'libraries')) {
            $prop = $libResponse.PSObject.Properties[$cn]
            if ($null -ne $prop -and $null -ne $prop.Value) { $libraries = @($prop.Value); break }
        }
        $tapeLines = foreach ($lib in $libraries) {
            $entity = if ($lib.PSObject.Properties['entityInfo']) { $lib.entityInfo } else { $lib }
            $name = Get-FirstObjectValue -InputObject $entity -Names @('name', 'libraryName', 'displayName', 'alias')
            $libId = Get-FirstObjectValue -InputObject $entity -Names @('id', 'libraryId')
            if (-not $name) { continue }
            $spare = $null; $total = $null; $isTape = ($name -match '(?i)tape|_TL\d|VTL')
            if ($libId) {
                try {
                    $libDetail = Invoke-MetallicApi -Method GET -Path "/Library/$libId" -Query @{ propertyLevel = '30' }
                    $src = $libDetail
                    foreach ($cn in @('libraryList', 'libraries', 'response')) {
                        $p = $libDetail.PSObject.Properties[$cn]
                        if ($null -ne $p -and $null -ne $p.Value) { $first = @($p.Value)[0]; if ($null -ne $first) { $src = $first }; break }
                    }
                    foreach ($w in @('library', 'libraryInfo', 'magLibSummary', 'detectedMedia')) {
                        if ($src.PSObject.Properties[$w] -and $null -ne $src.$w) { $src = $src.$w }
                    }
                    $libType = Get-FirstObjectValue -InputObject $src -Names @('libraryType', 'model', 'mediaAgentType')
                    if ("$libType" -match '(?i)tape' -or "$libType" -eq '2') { $isTape = $true }
                    $spare = Get-FirstObjectValue -InputObject $src -Names @('spareMediaCount', 'scratchMediaCount', 'numberOfSpareMedia', 'spareMedia', 'freeMedia', 'availableMedia')
                    $total = Get-FirstObjectValue -InputObject $src -Names @('totalMediaCount', 'numberOfMedia', 'mediaCount', 'totalMedia')
                    if ($null -ne $spare -or $null -ne $total) { $isTape = $true }
                }
                catch { }
            }
            if (-not $isTape) { continue }
            "| $(ConvertTo-MarkdownCell $name) | $(if ($null -ne $spare) { ConvertTo-MarkdownCell $spare } else { 'n/a' }) | $(if ($null -ne $total) { ConvertTo-MarkdownCell $total } else { 'n/a' }) |"
        }
        $tapeLines = @($tapeLines | Where-Object { $_ })
        if ($tapeLines.Count -gt 0) {
            $storageBlocks += "### Tape libraries`r`n`r`n| Tape library | Free (spare) media | Total media |`r`n|---|---:|---:|`r`n$($tapeLines -join "`r`n")"
        }
        else {
            $storageNotes += "- /Library: no tape library with a spare-media count was returned (there may be no tape library, or the spare count needs the tape-specific endpoint on this CommServe version)."
        }
    }
    catch {
        $libCode = Get-HttpStatusCode -Exception $_.Exception
        $storageNotes += "- /Library: $(if ($libCode) { "HTTP $libCode - " })$($_.Exception.Message)"
    }

    if ($storageBlocks.Count -gt 0 -or $storageNotes.Count -gt 0) {
        $storageBody = if ($storageBlocks.Count -gt 0) { $storageBlocks -join "`r`n`r`n" } else { 'No storage or media agent data could be read.' }
        if ($storageNotes.Count -gt 0) {
            $storageBody += "`r`n`r`nStorage data that could not be read (tell me the raw endpoint output and I will adjust the field names/units):`r`n`r`n" + ($storageNotes -join "`r`n")
        }
        $storageSection = "`r`n## Storage and media agents`r`n`r`n$storageBody`r`n"
    }
    $apiTimes['storage'] = $apiTimer.Elapsed.ToString('m\:ss')
}

$md = @"
# Commvault $Mode Health Report - $ClientName - $((Get-Date).ToString('dd MMM yyyy', [cultureinfo]::GetCultureInfo('en-US')))

## License and Subscription Usage

$licenseText
$storageSection
## Protected Item Health and SLA

$(if ($commvaultSlaBlock) { "$commvaultSlaBlock`r`n" })
$slaSummary

$slaGraph

An item meets the SLA when its last completed backup (with or without errors) is within the SLA period. Items with no backup job at all in the lookback (the never-run default or system subclients that Commvault does not count in its own SLA either) are reported in the summary above and not listed here.

| Client | Workload | Protected item | Plan | SLA status | Last completed backup |
|---|---|---|---|---|---|
$($protectedItemLines -join "`r`n")

Inventory status: $inventoryNotesText

## Job History

$jobDailySection

$jobTrendSection

### Last $jobLookbackLabel Overview

- $BackupHealthLabel
- $BackupHealthStatus
- Data protected: $totalDataProtected
- SLA: $slaMet of $slaWithHistory protected items with backup history met the SLA$(if ($slaNoHistory -gt 0) { " ($slaNoHistory with no backup in the lookback - verify)" })

#### Summary per Protected Item

| Client | Protected item | Workload | Jobs | Successful | Errors / warnings | Failed | Success rate | Data protected | Avg duration |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
$($jobSummaryLines -join "`r`n")

#### Jobs Not Completed Successfully

$attentionNote

| Job ID | Client | Protected item | Operation | Start time | Status | Duration | Reason |
|---:|---|---|---|---|---|---:|---|
$($attentionLines -join "`r`n")
"@

$md | Set-Content -LiteralPath $mdPath -Encoding UTF8 -ErrorAction Stop

Complete-CommvaultReportProgress
Write-Host "Commvault API time: $(@($apiTimes.Keys | ForEach-Object { "$_ $($apiTimes[$_])" }) -join ', ')" -ForegroundColor DarkGray
Write-Host "Report created at: $mdPath" -ForegroundColor Yellow