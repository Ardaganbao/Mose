[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'Veeam Backup & Replication server: IP address or host name.')]
    [string]$Server,

    [Parameter(Mandatory = $true, HelpMessage = 'Veeam account (DOMAIN\user) with a Veeam role, such as Veeam Backup Viewer.')]
    [pscredential]$Credential,

    [Parameter(HelpMessage = 'Port of the Veeam Backup & Replication REST API.')]
    [ValidateRange(1, 65535)]
    [int]$Port = 9419,

    [Parameter(HelpMessage = 'SHA-1 thumbprint of the Veeam server certificate to trust. Use only after checking it on the Veeam server.')]
    [string]$CertificateThumbprint,

    [Parameter(HelpMessage = 'Accept any certificate of the Veeam server. This disables the identity check and allows interception.')]
    [switch]$AcceptAnyCertificate,

    [Parameter(HelpMessage = 'File where every API answer is written (Report.ps1 -DebugLog), to adapt the report to another Veeam version.')]
    [string]$ApiDumpPath
)

# Veeam Backup & Replication report over its REST API (Veeam 11 or later, HTTPS port 9419). Unlike
# VeeamReport.ps1, it needs no Veeam console, no PowerShell remoting and no administrator rights on
# the Veeam server: only a Veeam account with a role. Same sections as VeeamReport.ps1, with the
# repositories' free space added.

$ErrorActionPreference = 'Stop'
$progressActivity = "Veeam report: $Server"
# The newest first: each Veeam version accepts its own and older ones.
$apiVersions = @('1.3-rev1', '1.3-rev0', '1.2-rev1', '1.2-rev0', '1.1-rev2', '1.1-rev1', '1.1-rev0', '1.0-rev2', '1.0-rev1')
$apiBase = "https://$($Server):$Port"
$script:ApiVersion = $null
$script:AccessToken = $null
$script:RefreshToken = $null

if ([int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

# Compiled, because .NET may check certificates on a thread where no script can run. Remembers the
# certificate it saw, so that an untrusted one can be shown with its thumbprint.
if (-not ('VeeamApiCertificateValidationV1' -as [type])) {
    Add-Type -TypeDefinition @"
        using System;
        using System.Net;
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public static class VeeamApiCertificateValidationV1 {
            public static string ExpectedHost { get; set; }
            public static string ExpectedThumbprint { get; set; }
            public static bool AcceptAnyCertificate { get; set; }
            public static string LastThumbprint { get; set; }
            public static string LastSubject { get; set; }
            public static string LastErrors { get; set; }
            public static bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
                var cert = certificate as X509Certificate2 ?? new X509Certificate2(certificate);
                LastThumbprint = cert.GetCertHashString();
                LastSubject = cert.Subject;
                LastErrors = errors.ToString();
                if (errors == SslPolicyErrors.None) {
                    return true;
                }
                var request = sender as HttpWebRequest;
                if (request == null || !String.Equals(request.RequestUri.Host, ExpectedHost, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }
                if (!String.IsNullOrEmpty(ExpectedThumbprint)) {
                    return String.Equals(LastThumbprint, ExpectedThumbprint, StringComparison.OrdinalIgnoreCase);
                }
                return AcceptAnyCertificate;
            }
        }
"@ -ErrorAction Stop
}
[VeeamApiCertificateValidationV1]::ExpectedHost = $Server
[VeeamApiCertificateValidationV1]::ExpectedThumbprint = ($CertificateThumbprint -replace '[\s:]', '')
[VeeamApiCertificateValidationV1]::AcceptAnyCertificate = [bool]$AcceptAnyCertificate
[VeeamApiCertificateValidationV1]::LastThumbprint = $null

function Write-VeeamReportProgress {
    param(
        [string]$Status,
        [int]$PercentComplete
    )

    Write-Progress -Id 10 -Activity $progressActivity -Status $Status -PercentComplete ([math]::Max(0, [math]::Min(100, $PercentComplete)))
}

# The first of these properties that has a value; the API's field names differ between versions.
function Get-VeeamValue {
    param(
        $InputObject,
        [string[]]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }
    foreach ($propertyName in $Name) {
        $property = $InputObject.PSObject.Properties[$propertyName]
        if ($property -and $null -ne $property.Value -and "$($property.Value)" -ne '') {
            return $property.Value
        }
    }
    return $null
}

# The items of a page of results ({ data: [...], pagination: {...} }).
function Get-VeeamData {
    param(
        $Page
    )

    if ($null -ne $Page -and $Page.PSObject.Properties['data'] -and $null -ne $Page.data) {
        $Page.data
    }
}

function Write-ApiDump {
    param(
        [string]$Label,
        $Data
    )

    if ($ApiDumpPath) {
        $text = "=== $Label`r`n$(ConvertTo-Json -InputObject $Data -Depth 20)`r`n"
        [System.IO.File]::AppendAllText($ApiDumpPath, $text, [System.Text.UTF8Encoding]::new($false))
    }
}

function Get-HttpStatusCode {
    param(
        [System.Exception]$Exception
    )

    if ($Exception -is [System.Net.WebException] -and $Exception.Response) {
        return [int]$Exception.Response.StatusCode
    }
    return $null
}

# An error for Report.ps1: a certificate this computer does not trust, with its thumbprint, or a
# refused login, which it offers to fix.
function New-VeeamApiException {
    param(
        [string]$Message,
        [System.Exception]$InnerException,
        [switch]$LoginRefused
    )

    $exception = [System.Exception]::new($Message, $InnerException)
    $exception.Data['LoginRefused'] = [bool]$LoginRefused
    if ($InnerException -is [System.Net.WebException] -and -not $InnerException.Response -and
        [VeeamApiCertificateValidationV1]::LastThumbprint -and [VeeamApiCertificateValidationV1]::LastErrors -ne 'None') {
        $exception.Data['UntrustedCertificate'] = [VeeamApiCertificateValidationV1]::LastThumbprint
        $exception.Data['CertificateSubject'] = [VeeamApiCertificateValidationV1]::LastSubject
    }
    return $exception
}

# Why a call got no answer at all: the certificate, or the network.
function Get-NoAnswerText {
    param(
        [System.Exception]$Exception
    )

    $thumbprint = [VeeamApiCertificateValidationV1]::LastThumbprint
    if ($thumbprint -and [VeeamApiCertificateValidationV1]::LastErrors -ne 'None') {
        return "This computer does not trust the certificate of $Server ($([VeeamApiCertificateValidationV1]::LastErrors), $([VeeamApiCertificateValidationV1]::LastSubject), SHA-1 thumbprint $thumbprint). Check this thumbprint on the Veeam server, then trust it for this server (the report offers it), or install the certificate as trusted on this computer."
    }
    $cause = $Exception.Message
    for ($inner = $Exception.InnerException; $inner; $inner = $inner.InnerException) {
        $cause += " ($($inner.Message.Trim()))"
    }
    return "The Veeam REST API at $apiBase did not answer: $cause. It needs Veeam Backup & Replication 11 or later, its REST API service running, and port $Port open from this computer."
}

function Invoke-VeeamToken {
    param(
        [hashtable]$Body,
        [string]$Version
    )

    $headers = @{ 'x-api-version' = $Version; Accept = 'application/json' }
    Invoke-RestMethod -Method Post -Uri "$apiBase/api/oauth2/token" -Headers $headers -Body $Body `
        -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -TimeoutSec 60
}

# Signs in with the newest API version this server accepts.
function Connect-VeeamApi {
    $password = $Credential.GetNetworkCredential().Password
    $refused = @()
    foreach ($version in $apiVersions) {
        try {
            $token = Invoke-VeeamToken -Version $version -Body @{ grant_type = 'password'; username = $Credential.UserName; password = $password }
        }
        catch {
            $status = Get-HttpStatusCode $_.Exception
            $answer = if ($_.ErrorDetails) { "$($_.ErrorDetails.Message)" } else { '' }
            if ($null -eq $status) {
                throw (New-VeeamApiException -Message (Get-NoAnswerText $_.Exception) -InnerException $_.Exception)
            }
            # A version this server does not know: the next, older one.
            if ($status -in 400, 404, 406, 415 -and $answer -match '(?i)version') {
                $refused += $version
                continue
            }
            if ($status -in 400, 401, 403) {
                throw (New-VeeamApiException -LoginRefused -InnerException $_.Exception -Message "Veeam on $Server refused the login $($Credential.UserName) (HTTP $status): $answer It needs the user name with its domain (DOMAIN\user), its password, and a Veeam role for this account (Users and Roles in the Veeam console, e.g. Veeam Backup Viewer).")
            }
            throw (New-VeeamApiException -InnerException $_.Exception -Message "Signing in to the Veeam REST API at $apiBase failed (HTTP $status): $answer")
        }
        $script:ApiVersion = $version
        $script:AccessToken = $token.access_token
        $script:RefreshToken = Get-VeeamValue $token 'refresh_token'
        return
    }
    throw "The Veeam REST API at $apiBase accepts none of the API versions $($refused -join ', '): this needs Veeam Backup & Replication 11 or later."
}

# The access token lasts 15 minutes; a longer report gets a new one with the refresh token.
function Update-VeeamToken {
    $token = Invoke-VeeamToken -Version $script:ApiVersion -Body @{ grant_type = 'refresh_token'; refresh_token = $script:RefreshToken }
    $script:AccessToken = $token.access_token
    $script:RefreshToken = Get-VeeamValue $token 'refresh_token'
}

function Invoke-VeeamApi {
    param(
        [string]$Path,
        [hashtable]$Query = @{}
    )

    $uri = $apiBase + $Path
    if ($Query.Count -gt 0) {
        $uri += '?' + (@($Query.GetEnumerator() | Sort-Object -Property Key | ForEach-Object {
                    "$([uri]::EscapeDataString([string]$_.Key))=$([uri]::EscapeDataString([string]$_.Value))"
                }) -join '&')
    }
    for ($attempt = 1; ; $attempt++) {
        $headers = @{ Authorization = "Bearer $script:AccessToken"; 'x-api-version' = $script:ApiVersion; Accept = 'application/json' }
        try {
            $answer = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -UseBasicParsing -TimeoutSec 120
            Write-ApiDump -Label "GET $($uri.Substring($apiBase.Length))" -Data $answer
            return $answer
        }
        catch {
            $status = Get-HttpStatusCode $_.Exception
            if ($status -eq 401 -and $attempt -eq 1 -and $script:RefreshToken) {
                Update-VeeamToken
                continue
            }
            if ($null -eq $status) {
                throw (New-VeeamApiException -Message (Get-NoAnswerText $_.Exception) -InnerException $_.Exception)
            }
            $answer = if ($_.ErrorDetails) { "$($_.ErrorDetails.Message)" } else { '' }
            Write-ApiDump -Label "GET $($uri.Substring($apiBase.Length)) -> HTTP $status" -Data $answer
            $exception = [System.Exception]::new("The Veeam REST API answered HTTP $status to $($uri.Substring($apiBase.Length)): $answer", $_.Exception)
            $exception.Data['HttpStatus'] = $status
            throw $exception
        }
    }
}

# Every item of a list, page after page.
function Get-VeeamApiItems {
    param(
        [string]$Path,
        [hashtable]$Query = @{},
        [int]$MaxItems = 0
    )

    $limit = 200
    $skip = 0
    while ($true) {
        $pageQuery = @{ skip = $skip; limit = $limit }
        foreach ($key in $Query.Keys) {
            $pageQuery[$key] = $Query[$key]
        }
        $page = Invoke-VeeamApi -Path $Path -Query $pageQuery
        $items = @(Get-VeeamData $page)
        $items
        $skip += $items.Count
        # The server may return fewer items than asked per page: its total says when all came.
        $total = Get-VeeamValue (Get-VeeamValue $page 'pagination') 'total'
        if ($items.Count -eq 0 -or ($null -ne $total -and $skip -ge [int]$total) -or ($null -eq $total -and $items.Count -lt $limit) -or
            ($MaxItems -gt 0 -and $skip -ge $MaxItems)) {
            break
        }
    }
}

function Convert-Bytes {
    param(
        $Bytes
    )

    if ($null -eq $Bytes -or "$Bytes" -eq '') {
        return 'n/a'
    }
    $value = [double]$Bytes
    if ($value -ge 1TB) {
        return '{0:N2} TB' -f ($value / 1TB)
    }
    if ($value -ge 1GB) {
        return '{0:N2} GB' -f ($value / 1GB)
    }
    return '{0:N2} MB' -f ($value / 1MB)
}

# Dates come as ISO 8601 text (Windows PowerShell) or as dates (PowerShell 7).
function ConvertTo-LocalTime {
    param(
        $Value
    )

    if ($null -eq $Value -or "$Value" -eq '') {
        return $null
    }
    if ($Value -is [datetime]) {
        return $Value.ToLocalTime()
    }
    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
        return $parsed.LocalDateTime
    }
    return $null
}

function Format-Time {
    param(
        $Value,
        [string]$Format = 'HH:mm:ss'
    )

    $time = ConvertTo-LocalTime $Value
    if ($time) {
        return $time.ToString($Format)
    }
    return 'n/a'
}

# A duration given as "hh:mm:ss" or seconds, else the time between start and end.
function Format-Duration {
    param(
        $Value,
        $Start,
        $End
    )

    $span = [timespan]::Zero
    if ($null -ne $Value -and "$Value" -ne '') {
        if ($Value -is [timespan]) {
            $span = $Value
        }
        elseif ("$Value" -match '^\d+(\.\d+)?$') {
            $span = [timespan]::FromSeconds([double]$Value)
        }
        elseif (-not [timespan]::TryParse("$Value", [ref]$span)) {
            return "$Value"
        }
        return '{0:00}:{1:mm\:ss}' -f [math]::Floor($span.TotalHours), $span
    }
    $startTime = ConvertTo-LocalTime $Start
    $endTime = ConvertTo-LocalTime $End
    if ($startTime -and $endTime -and $endTime -ge $startTime) {
        $span = $endTime - $startTime
        return '{0:00}:{1:mm\:ss}' -f [math]::Floor($span.TotalHours), $span
    }
    return 'n/a'
}

# Success, Warning, Failed or None, from a session or task: { result: { result: "Success" } }.
function Get-VeeamResult {
    param(
        $Item
    )

    $result = Get-VeeamValue $Item 'result'
    if ($result -and $result.PSObject.Properties['result']) {
        return "$($result.result)"
    }
    if ($result) {
        return "$result"
    }
    return "$(Get-VeeamValue $Item 'state')"
}

# The job sessions of the last 31 days, read once. They give the last session of a job when the
# API doesn't give it by its ID (a backup copy job), and the SureBackup sessions, whose jobs some
# Veeam versions don't list.
$script:RecentSessions = $null
function Get-RecentSessions {
    if ($null -eq $script:RecentSessions) {
        $since = (Get-Date).ToUniversalTime().AddDays(-31).ToString('yyyy-MM-ddTHH:mm:ssZ')
        try {
            $script:RecentSessions = @(Get-VeeamApiItems -Path '/api/v1/sessions' -Query @{ createdAfterFilter = $since } -MaxItems 5000)
        }
        catch {
            Write-Warning "The Veeam sessions of the last 31 days are not available: $($_.Exception.Message)"
            $script:RecentSessions = @()
        }
    }
    $script:RecentSessions
}

# Every backup, read once: the restore points of a backup copy job's VMs.
$script:AllBackups = $null
function Get-AllBackups {
    if ($null -eq $script:AllBackups) {
        $script:AllBackups = @(Get-VeeamApiItems -Path '/api/v1/backups' -MaxItems 5000)
    }
    $script:AllBackups
}

# The newest session of each worker of a backup copy job: Veeam 12 and later run a backup copy job
# as one worker job per source job, whose sessions are named "<copy job>\<source job> (<copy type>)".
function Get-CopyWorkerSessions {
    param(
        $JobState
    )

    $prefix = "$($JobState.name)\"
    $workerSessions = @(Get-RecentSessions | Where-Object { "$($_.name)".StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase) })
    $workers = $workerSessions | Group-Object -Property {
        $workerId = Get-VeeamValue $_ 'jobId'
        if ($workerId) { $workerId } else { "$($_.name)" -replace ' \([^)]*\)$', '' }
    }
    foreach ($worker in $workers) {
        Get-NewestSession $worker.Group
    }
}

function Get-NewestSession {
    param(
        [object[]]$Sessions
    )

    @($Sessions | Sort-Object -Property { ConvertTo-LocalTime (Get-VeeamValue $_ 'creationTime') } -Descending) | Select-Object -First 1
}

# The last session of a job: by its ID in the job state, else the newest of the job among the
# recent sessions, else the newest with the job's name.
function Get-LastJobSession {
    param(
        $JobState
    )

    $sessionId = Get-VeeamValue $JobState 'sessionId', 'lastSessionId'
    if ($sessionId) {
        try {
            return Invoke-VeeamApi -Path "/api/v1/sessions/$sessionId"
        }
        catch {
            # Not given by its ID (seen for a backup copy job): looked for below.
            if ($_.Exception.Data['HttpStatus'] -ne 404) {
                throw
            }
        }
    }
    $jobId = Get-VeeamValue $JobState 'id'
    $name = "$($JobState.name)"
    $sessions = @(Get-RecentSessions | Where-Object { $jobId -and (Get-VeeamValue $_ 'jobId') -eq $jobId })
    if ($sessions.Count -eq 0) {
        $sessions = @(Get-RecentSessions | Where-Object { "$($_.name)" -eq $name })
    }
    if ($sessions.Count -eq 0) {
        $sessions = @(Get-VeeamData (Invoke-VeeamApi -Path '/api/v1/sessions' -Query @{ nameFilter = "*$name*"; limit = 50 }) | Where-Object {
                $sessionJobId = Get-VeeamValue $_ 'jobId'
                ($jobId -and $sessionJobId -eq $jobId) -or (-not $sessionJobId -and "$($_.name)" -eq $name)
            })
    }
    return (Get-NewestSession $sessions)
}

# The VMs of a session; none when the API doesn't give them for this session.
function Get-TaskSessions {
    param(
        $Session
    )

    try {
        @(Get-VeeamApiItems -Path "/api/v1/sessions/$($Session.id)/taskSessions" | Sort-Object -Property name)
    }
    catch {
        if ($_.Exception.Data['HttpStatus'] -ne 404) {
            throw
        }
        Write-Warning "The VMs of the Veeam session '$($Session.name)' are not available (HTTP 404)."
    }
}

function Get-TaskSize {
    param(
        $Task,
        [string[]]$Name
    )

    $progress = Get-VeeamValue $Task 'progress'
    $value = Get-VeeamValue $progress $Name
    if ($null -eq $value) {
        $value = Get-VeeamValue $Task $Name
    }
    return $value
}

function Get-TaskSizeSum {
    param(
        [object[]]$Tasks,
        [string[]]$Name
    )

    $values = @($Tasks | ForEach-Object { Get-TaskSize $_ $Name } | Where-Object { $null -ne $_ })
    if ($values.Count -eq 0) {
        return $null
    }
    return ($values | Measure-Object -Sum).Sum
}

$totalSizeNames = @('totalSize', 'processedSize', 'processedUsedSize')
$readSizeNames = @('readSize', 'processedReadSize')
$transferredSizeNames = @('transferredSize', 'transferedSize')

# The job table and its VM details, as VeeamReport.ps1 writes them.
function Format-BackupJob {
    param(
        $JobState
    )

    $text = "`n#### $($JobState.name)`n"
    $session = Get-LastJobSession $JobState
    if ($null -eq $session) {
        return $text + "No backup session found.`n"
    }
    $tasks = @(Get-TaskSessions $session)
    $results = @($tasks | ForEach-Object { Get-VeeamResult $_ })
    $succeeded = @($results | Where-Object { $_ -match '(?i)success' }).Count
    $warnings = @($results | Where-Object { $_ -match '(?i)warning' }).Count
    $failed = @($results | Where-Object { $_ -match '(?i)fail|error' }).Count
    $processed = $succeeded + $warnings + $failed
    $start = Get-VeeamValue $session 'creationTime'
    $end = Get-VeeamValue $session 'endTime'
    $repository = Get-VeeamValue $JobState 'repositoryName'
    $nextRun = Get-VeeamValue $JobState 'nextRun'
    $nextRunText = if ($nextRun) { Format-Time $nextRun 'yyyy-MM-dd HH:mm' } else { 'Not scheduled' }

    $text += "|$(Format-Time $start 'yyyy-MM-dd HH:mm:ss')||||||$(Get-VeeamResult $session)|$processed of $($tasks.Count) VMs processed |`n"
    $text += "|---|---|---|-----|---|----|----|----|`n"
    $text += "|Success|$succeeded| Start time |$(Format-Time $start)| Total size |$(Convert-Bytes (Get-TaskSizeSum $tasks $totalSizeNames)) |Repository |$(if ($repository) { $repository } else { 'n/a' })|`n"
    $text += "|Warning|$warnings| End time   |$(Format-Time $end)| Data read  |$(Convert-Bytes (Get-TaskSizeSum $tasks $readSizeNames)) |Next run |$nextRunText|`n"
    $text += "|Error|$failed| Duration     |$(Format-Duration $null $start $end)| Transferred  |$(Convert-Bytes (Get-TaskSizeSum $tasks $transferredSizeNames)) |Job status |$(Get-VeeamValue $JobState 'status')|`n"
    $text += "`n##### Details`n"
    if ($tasks.Count -eq 0) {
        return $text + "No VM details were returned for this session.`n"
    }
    $text += "| Name | Status | Start time | End time | Size | Read | Transferred | Duration |`n"
    $text += "|------|--------|------------|----------|------|------|-------------|----------|`n"
    foreach ($task in $tasks) {
        $taskStart = Get-VeeamValue $task 'creationTime'
        $taskEnd = Get-VeeamValue $task 'endTime'
        $duration = Format-Duration (Get-TaskSize $task 'duration') $taskStart $taskEnd
        $text += "| $($task.name) | $(Get-VeeamResult $task) | $(Format-Time $taskStart) | $(Format-Time $taskEnd) | $(Convert-Bytes (Get-TaskSize $task $totalSizeNames)) | $(Convert-Bytes (Get-TaskSize $task $readSizeNames)) | $(Convert-Bytes (Get-TaskSize $task $transferredSizeNames)) | $duration |`n"
    }
    return $text
}

# A backup copy job: the last session of each of its workers (one per source job, or the job's own
# session), and per VM the last copy, its result and its restore points.
function Format-BackupCopyJob {
    param(
        $JobState
    )

    $text = "`n#### $($JobState.name)`n"
    $sessions = @(Get-CopyWorkerSessions $JobState | Sort-Object -Property name)
    if ($sessions.Count -eq 0) {
        $session = Get-LastJobSession $JobState
        if ($null -ne $session) {
            $sessions = @($session)
        }
    }
    if ($sessions.Count -eq 0) {
        return $text + "$($JobState.name) has no backup session available :warning:`n"
    }

    # The worst result of the workers is the job's.
    $results = @($sessions | ForEach-Object { Get-VeeamResult $_ })
    $result = if ($results -match '(?i)fail|error') { 'Failed' } elseif ($results -match '(?i)warning') { 'Warning' } elseif ($results -match '(?i)success') { 'Success' } else { $results[0] }
    $status = if ($result -match '(?i)success') { ':white_check_mark:' } else { ':x:' }
    $starts = @($sessions | ForEach-Object { ConvertTo-LocalTime (Get-VeeamValue $_ 'creationTime') } | Where-Object { $_ } | Sort-Object)
    $ends = @($sessions | ForEach-Object { ConvertTo-LocalTime (Get-VeeamValue $_ 'endTime') } | Where-Object { $_ } | Sort-Object)
    $start = if ($starts.Count -gt 0) { $starts[0] } else { $null }
    $end = if ($ends.Count -gt 0) { $ends[-1] } else { $null }
    $tasks = @(foreach ($session in $sessions) { Get-TaskSessions $session })
    $text += "| Result |  |`n"
    $text += "|----|----|`n"
    $text += "| Status |  $result $status |`n"
    $text += "| Start | $(Format-Time $start 'yyyy-MM-dd HH:mm:ss') |`n"
    $text += "| End |  $(Format-Time $end 'yyyy-MM-dd HH:mm:ss') |`n"
    $text += "| Duration |  $(Format-Duration $null $start $end) |`n"
    $read = Get-TaskSizeSum $tasks $readSizeNames
    if ($read) {
        $text += "| Read |  $(Convert-Bytes $read) |`n"
    }
    $text += "| VM count |  $($tasks.Count) |`n"

    # A worker's session is named "<copy job>\<source job> (<copy type>)".
    $workerIds = @($sessions | ForEach-Object { Get-VeeamValue $_ 'jobId' } | Where-Object { $_ })
    if (@($sessions | Where-Object { "$($_.name)".StartsWith("$($JobState.name)\") }).Count -gt 0) {
        $text += "`n##### Source jobs`n"
        $text += "| Source job | Copy | Start | End | Duration | Result |`n"
        $text += "|------------|------|-------|-----|----------|--------|`n"
        foreach ($session in $sessions) {
            $source = "$($session.name)"
            $kind = ''
            if ($source -match '^(?:.*?\\)?(?<source>.+?)(?: \((?<kind>[^)]+)\))?$') {
                $source = $Matches['source']
                $kind = $Matches['kind']
            }
            $sessionStart = Get-VeeamValue $session 'creationTime'
            $sessionEnd = Get-VeeamValue $session 'endTime'
            $text += "| $source | $kind | $(Format-Time $sessionStart 'yyyy-MM-dd HH:mm:ss') | $(Format-Time $sessionEnd 'yyyy-MM-dd HH:mm:ss') | $(Format-Duration $null $sessionStart $sessionEnd) | $(Get-VeeamResult $session) |`n"
        }
    }

    # Restore points per VM, from the backups of the job or of its workers.
    $restorePoints = @{}
    try {
        $jobIds = @(@(Get-VeeamValue $JobState 'id') + $workerIds | Where-Object { $_ })
        $backups = @(Get-AllBackups)
        $ownBackups = @($backups | Where-Object { (Get-VeeamValue $_ 'jobId') -in $jobIds })
        if ($ownBackups.Count -eq 0) {
            $ownBackups = @($backups | Where-Object { "$($_.name)" -eq $JobState.name -or "$($_.name)".StartsWith("$($JobState.name)\") })
        }
        foreach ($backup in $ownBackups) {
            foreach ($object in @(Get-VeeamApiItems -Path "/api/v1/backups/$($backup.id)/objects")) {
                $count = Get-VeeamValue $object 'restorePointsCount'
                if ($null -ne $count) {
                    $restorePoints["$($object.name)"] = [int]$count + [int]$restorePoints["$($object.name)"]
                }
            }
        }
    }
    catch {
        Write-Warning "Restore points of backup copy job '$($JobState.name)' are not available: $($_.Exception.Message)"
    }

    $text += "`n##### Details`n"
    if ($tasks.Count -eq 0) {
        return $text + "No VM details were returned for this session.`n"
    }
    $text += "| Name | Last Copy   | copy health | Number of RP |`n"
    $text += "|------|---------|---------|---------|`n"
    foreach ($task in $tasks) {
        $taskResult = Get-VeeamResult $task
        $health = if ($taskResult -match '(?i)success') { ':white_check_mark: OK' } else { ":x: $taskResult" }
        $count = if ($restorePoints.ContainsKey("$($task.name)")) { $restorePoints["$($task.name)"] } else { 'n/a' }
        $text += "| $($task.name) | $(Format-Time (Get-VeeamValue $task 'endTime', 'creationTime') 'yyyy-MM-dd HH:mm:ss') | $health | $count |`n"
    }
    return $text
}

# A SureBackup job: its last session and the verification of each VM. Without the job (not listed
# by every Veeam version), only its session.
function Format-SureBackupSession {
    param(
        [string]$Name,
        $Session,
        $JobState
    )

    $text = "`n#### $Name`n"
    $session = $Session
    if ($null -eq $session) {
        return $text + "No SureBackup session found. Last result: $(Get-VeeamValue $JobState 'lastResult') ($(Get-VeeamValue $JobState 'status')).`n"
    }
    $start = Get-VeeamValue $session 'creationTime'
    $end = Get-VeeamValue $session 'endTime'
    $text += "`n| Last run | Result | State | Duration |`n"
    $text += "|---|---|---|---|`n"
    $text += "| $(Format-Time $start 'yyyy-MM-dd HH:mm:ss') | $(Get-VeeamResult $session) | $(Get-VeeamValue $session 'state') | $(Format-Duration $null $start $end) |`n"
    $tasks = @(Get-TaskSessions $session)
    if ($tasks.Count -eq 0) {
        return $text + "`nNo VM verification task details were returned for this session.`n"
    }
    $text += "`n##### VM verification details`n"
    $text += "| VM | Status |`n"
    $text += "|---|---|`n"
    foreach ($task in $tasks) {
        $text += "| $($task.name) | $(Get-VeeamResult $task) |`n"
    }
    return $text
}

# SureBackup sessions of the last 400 days, asked by their session type: Known says whether this
# Veeam has that type (an unknown one is refused with HTTP 400, or ignored).
function Find-SureBackupSessions {
    $since = (Get-Date).ToUniversalTime().AddDays(-400).ToString('yyyy-MM-ddTHH:mm:ssZ')
    foreach ($type in 'SureBackupJob', 'SureBackup') {
        try {
            $page = Invoke-VeeamApi -Path '/api/v1/sessions' -Query @{ typeFilter = $type; createdAfterFilter = $since; skip = 0; limit = 200 }
        }
        catch {
            if ($_.Exception.Data['HttpStatus'] -eq 400) {
                continue
            }
            throw
        }
        $items = @(Get-VeeamData $page)
        if (@($items | Where-Object { "$(Get-VeeamValue $_ 'sessionType')" -notmatch '(?i)sure' }).Count -gt 0) {
            # The filter was ignored: this Veeam has no such type.
            break
        }
        return [pscustomobject]@{ Known = $true; Sessions = $items }
    }
    return [pscustomobject]@{ Known = $false; Sessions = @() }
}

function Format-SureBackupJob {
    param(
        $JobState
    )

    Format-SureBackupSession -Name $JobState.name -Session (Get-LastJobSession $JobState) -JobState $JobState
}

function Format-Repositories {
    $text = "`n### Repositories`n"
    $repositories = @(Get-VeeamApiItems -Path '/api/v1/backupInfrastructure/repositories/states' | Sort-Object -Property name)
    if ($repositories.Count -eq 0) {
        return $text + "No repository was returned.`n"
    }
    $text += "| Name | Type | Host | Path | Capacity | Free | Used | Free space |`n"
    $text += "|------|------|------|------|----------|------|------|------------|`n"
    foreach ($repository in $repositories) {
        $capacity = Get-VeeamValue $repository 'capacityGB'
        $free = Get-VeeamValue $repository 'freeGB'
        $used = Get-VeeamValue $repository 'usedSpaceGB'
        $freeText = 'n/a'
        if ($capacity -and [double]$capacity -gt 0 -and $null -ne $free) {
            $percent = [math]::Round(100 * [double]$free / [double]$capacity)
            $mark = if ($percent -lt 10) { ':x:' } elseif ($percent -lt 20) { ':warning:' } else { ':white_check_mark:' }
            $freeText = "$percent % $mark"
        }
        $sizes = foreach ($value in $capacity, $free, $used) {
            if ($null -ne $value) { Convert-Bytes ([double]$value * 1GB) } else { 'n/a' }
        }
        $text += "| $($repository.name) | $(Get-VeeamValue $repository 'type') | $(Get-VeeamValue $repository 'hostName') | $(Get-VeeamValue $repository 'path') | $($sizes[0]) | $($sizes[1]) | $($sizes[2]) | $freeText |`n"
    }
    return $text
}

$originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [Delegate]::CreateDelegate(
    [System.Net.Security.RemoteCertificateValidationCallback],
    [VeeamApiCertificateValidationV1],
    'Validate'
)
try {
    Write-VeeamReportProgress -Status "Signing in to $apiBase" -PercentComplete 0
    Connect-VeeamApi

    $serverInfo = Invoke-VeeamApi -Path '/api/v1/serverInfo'
    $version = Get-VeeamValue $serverInfo 'buildVersion', 'version'
    $Body = "## Check Backup Veeam VM's:`n"
    $Body += "- Veeam version: $(if ($version) { $version } else { 'Unknown' }) (REST API $script:ApiVersion)`n"

    # The license as VeeamReport.ps1 shows it: when it, or its support, expires.
    try {
        $license = Invoke-VeeamApi -Path '/api/v1/license'
        $type = "$(Get-VeeamValue $license 'type')"
        $expires = if ($type -match '(?i)subscription|rental|evaluation|nfr') { Get-VeeamValue $license 'expirationDate' } else { Get-VeeamValue $license 'supportExpirationDate', 'expirationDate' }
        $what = if ($type -match '(?i)subscription|rental|evaluation|nfr') { 'license expires' } else { 'support expires' }
        $expirationDate = ConvertTo-LocalTime $expires
        if ($expirationDate) {
            $daysLeft = ($expirationDate.Date - (Get-Date).Date).Days
            $mark = if ($daysLeft -gt 45) { ':white_check_mark:' } elseif ($daysLeft -gt 15) { ':warning:' } else { ':no_entry:' }
            $Body += "- $mark Veeam $what in $daysLeft days ($($expirationDate.ToString('yyyy-MM-dd')))`n"
        }
        else {
            $Body += "- :warning: Veeam license: $type, $(Get-VeeamValue $license 'status'), no expiration date`n"
        }
    }
    catch {
        $Body += "- :warning: UNKNOWN: Cannot get Veeam License information ($($_.Exception.Message))`n"
    }

    Write-VeeamReportProgress -Status 'Collecting jobs' -PercentComplete 5
    $jobs = @(Get-VeeamApiItems -Path '/api/v1/jobs/states' | Sort-Object -Property name)
    $copyJobs = @($jobs | Where-Object { "$($_.type)" -match '(?i)copy' })
    $sureBackupJobs = @($jobs | Where-Object { "$($_.type)" -match '(?i)surebackup' })
    $backupJobs = @($jobs | Where-Object { "$($_.type)" -notmatch '(?i)copy|surebackup' })
    $count = [math]::Max(1, $jobs.Count)
    $done = 0

    $Body += "`n### Backup jobs`n"
    if ($backupJobs.Count -eq 0) {
        $Body += "No backup jobs are configured.`n"
    }
    foreach ($job in $backupJobs) {
        $done++
        Write-VeeamReportProgress -Status "Backup jobs: $($job.name)" -PercentComplete (5 + 85 * $done / $count)
        try {
            $Body += Format-BackupJob $job
        }
        catch {
            $Body += "`n#### $($job.name)`nCollection failed for this job: $($_.Exception.Message)`n"
        }
    }

    $Body += "`n### Check Backup Copy`n"
    if ($copyJobs.Count -eq 0) {
        $Body += "No Backup Copy jobs are configured.`n"
    }
    foreach ($job in $copyJobs) {
        $done++
        Write-VeeamReportProgress -Status "Backup Copy jobs: $($job.name)" -PercentComplete (5 + 85 * $done / $count)
        try {
            $Body += Format-BackupCopyJob $job
        }
        catch {
            $Body += "`n#### $($job.name)`nCollection failed for this job: $($_.Exception.Message)`n"
        }
    }

    $Body += "`n### SureBackup verification`n"
    if ($sureBackupJobs.Count -eq 0) {
        # Not listed with the jobs by every Veeam version: the newest SureBackup session of each job,
        # from the last 31 days, else asked for by type over 400 days.
        $sureBackupSessions = @(Get-RecentSessions | Where-Object { "$(Get-VeeamValue $_ 'sessionType')" -match '(?i)sure' })
        if ($sureBackupSessions.Count -eq 0) {
            Write-VeeamReportProgress -Status 'Looking for SureBackup sessions' -PercentComplete 90
            try {
                $found = Find-SureBackupSessions
            }
            catch {
                Write-Warning "SureBackup sessions could not be asked for: $($_.Exception.Message)"
                $found = [pscustomobject]@{ Known = $false; Sessions = @() }
            }
            $sureBackupSessions = [object[]]$found.Sessions
            if ($sureBackupSessions.Count -eq 0) {
                if ($found.Known) {
                    $Body += "No SureBackup job is listed, and no SureBackup session ran in the last 400 days.`n"
                }
                else {
                    $Body += ":warning: The REST API of this Veeam ($(if ($version) { $version } else { 'version unknown' })) gives no SureBackup jobs or sessions: check SureBackup in the Veeam console.`n"
                }
                $sessionTypes = @(Get-RecentSessions | ForEach-Object { "$(Get-VeeamValue $_ 'sessionType')" } | Sort-Object -Unique) -join ', '
                Write-Warning "No SureBackup session found (session types of the last 31 days: $sessionTypes)."
            }
        }
        foreach ($group in @($sureBackupSessions | Group-Object -Property { "$($_.name)" } | Sort-Object -Property Name)) {
            Write-VeeamReportProgress -Status "SureBackup sessions: $($group.Name)" -PercentComplete 90
            try {
                $Body += Format-SureBackupSession -Name $group.Name -Session (Get-NewestSession $group.Group)
            }
            catch {
                $Body += "`n#### $($group.Name)`nCollection failed for this SureBackup job: $($_.Exception.Message)`n"
            }
        }
    }
    foreach ($job in $sureBackupJobs) {
        $done++
        Write-VeeamReportProgress -Status "SureBackup jobs: $($job.name)" -PercentComplete (5 + 85 * $done / $count)
        try {
            $Body += Format-SureBackupJob $job
        }
        catch {
            $Body += "`n#### $($job.name)`nCollection failed for this job: $($_.Exception.Message)`n"
        }
    }

    Write-VeeamReportProgress -Status 'Collecting repositories' -PercentComplete 95
    try {
        $Body += Format-Repositories
    }
    catch {
        $Body += "`n### Repositories`nCollection failed: $($_.Exception.Message)`n"
    }
    $Body
}
finally {
    if ($script:AccessToken) {
        try {
            $headers = @{ Authorization = "Bearer $script:AccessToken"; 'x-api-version' = $script:ApiVersion }
            Invoke-RestMethod -Method Post -Uri "$apiBase/api/oauth2/logout" -Headers $headers -UseBasicParsing -TimeoutSec 30 | Out-Null
        }
        catch {
            Write-Verbose "Veeam REST API sign-out failed: $($_.Exception.Message)"
        }
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
    Write-Progress -Id 10 -Activity $progressActivity -Completed
}
