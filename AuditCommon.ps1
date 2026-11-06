# Helpers of the audit collectors (AuditNetwork.ps1, AuditDomain.ps1, AuditAD.ps1, AuditInventory.ps1,
# AuditM365.ps1), which dot-source this file. A collector writes Markdown lines for its section of the audit (### headings),
# findings (New-AuditFinding) and the data it read (New-AuditData), which Audit.ps1 saves as JSON.

if ([int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

# Compiled, because .NET may check a certificate on a thread where no script can run. The audit only
# reads what a device or website shows without logging in (its page title and certificate) and sends
# it nothing, so every certificate is accepted on these connections, and its errors are kept to report.
if (-not ('MoseAuditTlsV1' -as [type])) {
    Add-Type -TypeDefinition @"
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public class MoseAuditTlsV1 {
            public SslPolicyErrors Errors;
            public bool Accept(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
                Errors = errors;
                return true;
            }
        }
"@ -ErrorAction Stop
}

# High: fix now (an open door, a security setting missing). Medium: plan it. Low: worth knowing.
# Info: no problem, for the record.
function New-AuditFinding {
    param(
        [ValidateSet('High', 'Medium', 'Low', 'Info')]
        [string]$Severity,
        [string]$Area,
        [string]$Finding,
        [string]$Recommendation
    )

    [pscustomobject]@{ AuditFinding = $Severity; Area = $Area; Finding = $Finding; Recommendation = $Recommendation }
}

function New-AuditData {
    param(
        [string]$Name,
        $Value
    )

    [pscustomobject]@{ AuditData = $Name; Value = $Value }
}

# Table cells must not contain a | or a line break.
function Format-AuditCell {
    param(
        $Value
    )

    return ("$Value" -replace '\|', '/' -replace '\s*[\r\n]+\s*', ' ').Trim()
}

# A Markdown table from objects, with these columns (header = property name, or 'Header=Property').
function Format-AuditTable {
    param(
        [object[]]$Rows,
        [string[]]$Columns
    )

    $headers = @($Columns | ForEach-Object { ($_ -split '=', 2)[0] })
    $names = @($Columns | ForEach-Object { ($_ -split '=', 2)[-1] })
    $text = "| $($headers -join ' | ') |`n"
    $text += "|$((@($headers | ForEach-Object { '---' })) -join '|')|`n"
    foreach ($row in $Rows) {
        $cells = foreach ($name in $names) {
            $value = $row.$name
            if ($value -is [array]) { $value = $value -join ', ' }
            if ($value -is [datetime]) { $value = $value.ToString('yyyy-MM-dd') }
            Format-AuditCell $value
        }
        $text += "| $($cells -join ' | ') |`n"
    }
    return $text
}

# A file kept in the audit-cache folder next to the scripts, downloaded again after MaxAgeDays. An
# older copy is used when the download fails, else nothing.
function Get-AuditCacheFile {
    param(
        [string]$Name,
        [string]$Uri,
        [int]$MaxAgeDays = 30
    )

    $folder = Join-Path $PSScriptRoot 'audit-cache'
    $path = Join-Path $folder $Name
    $file = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if ($file -and $file.LastWriteTime -gt (Get-Date).AddDays(-$MaxAgeDays)) {
        return $path
    }
    $progress = $ProgressPreference
    try {
        $ProgressPreference = 'SilentlyContinue'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        Invoke-WebRequest -Uri $Uri -OutFile "$path.tmp" -UseBasicParsing -TimeoutSec 60
        Move-Item -LiteralPath "$path.tmp" -Destination $path -Force
        return $path
    }
    catch {
        Remove-Item -LiteralPath "$path.tmp" -Force -ErrorAction SilentlyContinue
        Write-Warning "$Name could not be downloaded from $($Uri): $($_.Exception.Message)"
        if ($file) {
            return $path
        }
        return $null
    }
    finally {
        $ProgressPreference = $progress
    }
}

# A program the audit downloads once, as a zip of a fixed version, into audit-cache\<Name>. The zip is
# checked against its SHA-256 before it is unpacked, and the program against its own before each use,
# so that a changed or damaged download never runs. $null when it can't be downloaded or doesn't match.
function Get-AuditTool {
    param(
        [string]$Name,
        [string]$Uri,
        [string]$ZipSha256,
        [string]$Program,
        [string]$ProgramSha256
    )

    $folder = Join-Path (Join-Path $PSScriptRoot 'audit-cache') $Name
    $path = Join-Path $folder $Program
    $zip = "$folder.zip"
    $progress = $ProgressPreference
    try {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            $ProgressPreference = 'SilentlyContinue'
            New-Item -ItemType Directory -Path (Split-Path $folder) -Force | Out-Null
            Invoke-WebRequest -Uri $Uri -OutFile $zip -UseBasicParsing -TimeoutSec 120
            $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
            if ($hash -ne $ZipSha256) {
                throw "the download's SHA-256 is $hash, not $ZipSha256"
            }
            Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $folder)
        }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($hash -ne $ProgramSha256) {
            Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
            throw "$Program's SHA-256 is $hash, not $ProgramSha256; it was removed"
        }
        return $path
    }
    catch {
        Write-Warning "$Name could not be used: $($_.Exception.Message)"
        return $null
    }
    finally {
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        $ProgressPreference = $progress
    }
}

# The open TCP ports of these addresses or names: address -> ports.
function Test-TcpPorts {
    param(
        [string[]]$Addresses,
        [int[]]$Ports,
        [int]$TimeoutMs = 1000,
        [string]$Status = 'Ports',
        [string]$Activity = 'Network audit',
        [int]$ProgressId = 20,
        [int]$Percent = 40
    )

    $open = @{}
    $pairs = @(foreach ($address in $Addresses) { foreach ($port in $Ports) { [pscustomobject]@{ Address = $address; Port = $port } } })
    for ($first = 0; $first -lt $pairs.Count; $first += 512) {
        $batch = @($pairs[$first..([math]::Min($first + 511, $pairs.Count - 1))] | ForEach-Object {
                $client = New-Object System.Net.Sockets.TcpClient
                [pscustomobject]@{ Pair = $_; Client = $client; Task = $client.ConnectAsync($_.Address, $_.Port) }
            })
        try {
            [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($batch.Task), $TimeoutMs)
        }
        catch {
            # Refused connections: closed ports.
        }
        foreach ($item in $batch) {
            if ($item.Task.Status -eq 'RanToCompletion' -and $item.Client.Connected) {
                if (-not $open.ContainsKey($item.Pair.Address)) {
                    $open[$item.Pair.Address] = New-Object System.Collections.Generic.List[int]
                }
                $open[$item.Pair.Address].Add($item.Pair.Port)
            }
            $item.Client.Close()
        }
        Write-Progress -Id $ProgressId -Activity $Activity -Status "$($Status): $([math]::Min($first + 512, $pairs.Count)) of $($pairs.Count)" -PercentComplete $Percent
    }
    return $open
}

# What a web page shows without logging in: its status, server, title and redirect, and for HTTPS its
# certificate. Follows up to 3 redirects on the same host. Plain HTTP/1.0 over a socket, so that no
# setting of this PowerShell process changes. $null when nothing answers on that port.
function Get-AuditWebInfo {
    param(
        [string]$HostName,
        [int]$Port = 443,
        [bool]$Tls = $true,
        [string]$Path = '/',
        [int]$TimeoutMs = 3000,
        [switch]$KeepBody
    )

    $result = [ordered]@{
        Url = $null; Status = $null; Server = $null; Title = $null; Location = $null
        CertificateSubject = $null; CertificateIssuer = $null; CertificateExpires = $null; CertificateSelfSigned = $null; CertificateErrors = $null
        Error = $null; Body = $null
    }
    for ($hop = 0; $hop -le 3; $hop++) {
        $scheme = if ($Tls) { 'https' } else { 'http' }
        $defaultPort = if ($Tls) { 443 } else { 80 }
        $result.Url = "$($scheme)://$HostName$(if ($Port -ne $defaultPort) { ":$Port" })$Path"
        $client = New-Object System.Net.Sockets.TcpClient
        $text = ''
        try {
            if (-not $client.ConnectAsync($HostName, $Port).Wait($TimeoutMs)) {
                throw 'no answer'
            }
            $io = $client.GetStream()
            $io.ReadTimeout = $TimeoutMs
            $io.WriteTimeout = $TimeoutMs
            if ($Tls) {
                $check = New-Object MoseAuditTlsV1
                $callback = [Delegate]::CreateDelegate([System.Net.Security.RemoteCertificateValidationCallback], $check, 'Accept')
                $ssl = New-Object System.Net.Security.SslStream($io, $false, $callback)
                $ssl.ReadTimeout = $TimeoutMs
                $ssl.WriteTimeout = $TimeoutMs
                try {
                    $ssl.AuthenticateAsClient($HostName, $null, [System.Security.Authentication.SslProtocols]'Tls, Tls11, Tls12', $false)
                }
                catch {
                    $result.Error = 'tls'
                    throw
                }
                if (-not $result.CertificateSubject -and $ssl.RemoteCertificate) {
                    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
                    $result.CertificateSubject = $certificate.Subject
                    $result.CertificateIssuer = $certificate.Issuer
                    $result.CertificateExpires = $certificate.NotAfter
                    $result.CertificateSelfSigned = $certificate.Subject -eq $certificate.Issuer
                    $result.CertificateErrors = "$($check.Errors)"
                }
                $io = $ssl
            }
            $request = [Text.Encoding]::ASCII.GetBytes("GET $Path HTTP/1.0`r`nHost: $HostName`r`nUser-Agent: Mozilla/5.0 (MOSE audit)`r`nAccept: text/html,*/*`r`nConnection: close`r`n`r`n")
            $io.Write($request, 0, $request.Length)
            $io.Flush()
            $buffer = New-Object byte[] 8192
            $received = New-Object System.IO.MemoryStream
            while ($received.Length -lt 131072) {
                try {
                    $count = $io.Read($buffer, 0, $buffer.Length)
                }
                catch {
                    # A device that keeps the connection open: what came is enough.
                    break
                }
                if ($count -le 0) {
                    break
                }
                $received.Write($buffer, 0, $count)
            }
            $text = [Text.Encoding]::UTF8.GetString($received.ToArray())
            $result.Error = $null
        }
        catch {
            if (-not $result.Error) {
                $result.Error = "$($_.Exception.Message)"
            }
        }
        finally {
            $client.Close()
        }
        if (-not $text) {
            break
        }

        $split = $text.IndexOf("`r`n`r`n")
        $head = if ($split -ge 0) { $text.Substring(0, $split) } else { $text }
        $body = if ($split -ge 0) { $text.Substring($split + 4) } else { '' }
        if ($head -match '^HTTP/\d\.\d\s+(\d{3})') {
            $result.Status = [int]$Matches[1]
        }
        if ($head -match '(?im)^Server:\s*(.+?)\s*$') {
            $result.Server = $Matches[1]
        }
        if ($body -match '(?is)<title[^>]*>(.*?)</title>') {
            $title = [System.Net.WebUtility]::HtmlDecode($Matches[1]) -replace '\s+', ' '
            if ($title.Trim()) {
                $result.Title = $title.Trim()
            }
        }
        if ($KeepBody) {
            $result.Body = $body
        }

        # A redirect, or a page that only sends the browser on (meta refresh, location in a script).
        $next = $null
        if ($result.Status -in 301, 302, 303, 307, 308 -and $head -match '(?im)^Location:\s*(.+?)\s*$') {
            $next = $Matches[1]
        }
        elseif (-not $result.Title -and $body -match '(?i)http-equiv=["'']?refresh["'']?[^>]*url=([^"''>\s]+)') {
            $next = $Matches[1]
        }
        elseif (-not $result.Title -and $body.Length -lt 2048 -and $body -match '(?i)(?:window\.|document\.)?location(?:\.href)?\s*=\s*["'']([^"'']+)["'']') {
            $next = $Matches[1]
        }
        if (-not $next) {
            break
        }
        $result.Location = $next
        if ($next -match '^(?<scheme>https?)://(?<host>[^/:]+)(?::(?<port>\d+))?(?<path>/.*)?$') {
            if ($Matches.host -ne $HostName) {
                break
            }
            $Tls = $Matches.scheme -eq 'https'
            $Port = if ($Matches.port) { [int]$Matches.port } elseif ($Tls) { 443 } else { 80 }
            $Path = if ($Matches.path) { $Matches.path } else { '/' }
        }
        elseif ($next.StartsWith('/')) {
            $Path = $next
        }
        else {
            $Path = '/' + $next.TrimStart('.', '/')
        }
    }
    if (-not $result.Status -and -not $result.CertificateSubject) {
        return $null
    }
    return [pscustomobject]$result
}

# When Microsoft stops the security updates of a Windows, from its name and version (Active Directory's
# "Windows 11 Pro" and "10.0 (26100)", or Entra ID's "Windows" and "10.0.26100.4349"): Status Ended,
# Ending (within a year, or 90 days for a Windows 11 version, which the next feature update replaces
# for free) or Supported, and End. Unknown for a Windows 11 version not in this list (an Insider or a
# newer build), $null for what is not Windows.
# Windows 11 ends per version: Home and Pro 24 months after it came out, Enterprise and Education 36.
# Add the new versions when Microsoft publishes their dates.
$windowsSupportEnds = @{
    # Windows 11: build = Home/Pro end, Enterprise/Education end.
    22000 = '2023-10-10', '2024-10-08'
    22621 = '2024-10-08', '2025-10-14'
    22631 = '2025-11-11', '2026-11-10'
    26100 = '2026-10-13', '2027-10-12'
    26200 = '2027-10-12', '2028-10-10'
}
function Get-WindowsSupportEnd {
    param(
        [string]$Name,
        [string]$Version
    )

    $build = if ("$Version" -match '(?:^10\.0\.|\()(\d{5})') { [int]$Matches[1] }
    $end = $null
    $warnDays = 365
    switch -Regex ($Name) {
        'Windows (XP|Vista|7|8)\b|Windows NT|Server (2000|2003|2008|2012)' { $end = [datetime]'2023-10-10'; break }
        'Server.*2016' { $end = [datetime]'2027-01-12'; break }
        'Server.*2019' { $end = [datetime]'2029-01-09'; break }
        'Server.*2022' { $end = [datetime]'2031-10-14'; break }
        'Server.*2025' { $end = [datetime]'2034-10-10'; break }
        'Windows 10.*(LTSC|LTSB)' {
            $end = switch ($build) { 14393 { [datetime]'2026-10-13' } 17763 { [datetime]'2029-01-09' } 19044 { [datetime]'2027-01-12' } }
            break
        }
        'Windows 10' { $end = [datetime]'2025-10-14'; break }
        'Windows 11.*LTSC' { $end = [datetime]'2029-10-09'; break }
        'Windows 11|^Windows$' {
            if ($Name -match '^Windows$' -and $build -lt 22000) {
                # Entra ID names Windows 10 and 11 alike: the build tells them apart.
                if ($build -ge 10240) { $end = [datetime]'2025-10-14' }
                break
            }
            $dates = $windowsSupportEnds[$build]
            if ($dates) {
                $end = [datetime]$dates[$(if ($Name -match 'Enterprise|Education') { 1 } else { 0 })]
                $warnDays = 90
            }
            elseif ($build -ge 22000) {
                return [pscustomobject]@{ Status = 'Unknown'; End = $null }
            }
            break
        }
        'Windows Server|Hyper-V Server' {
            $end = switch ($build) { 14393 { [datetime]'2027-01-12' } 17763 { [datetime]'2029-01-09' } 20348 { [datetime]'2031-10-14' } 26100 { [datetime]'2034-10-10' } }
            break
        }
    }
    if (-not $end) {
        return $null
    }
    $status = if ($end -lt (Get-Date)) { 'Ended' } elseif ($end -lt (Get-Date).AddDays($warnDays)) { 'Ending' } else { 'Supported' }
    return [pscustomobject]@{ Status = $status; End = $end }
}

# The support of a Windows as a cell: :x: ended on, :warning: ends on, :white_check_mark:, or :question:.
function Format-WindowsSupport {
    param(
        $Support
    )

    if (-not $Support) {
        return ''
    }
    switch ($Support.Status) {
        'Ended' { return ":x: ended $($Support.End.ToString('yyyy-MM-dd'))" }
        'Ending' { return ":warning: ends $($Support.End.ToString('yyyy-MM-dd'))" }
        'Unknown' { return ':question: version not in the list' }
        default { return ":white_check_mark: until $($Support.End.ToString('yyyy-MM-dd'))" }
    }
}

# The domains of a list that can be public: not .local, .lan and other internal names.
function Select-PublicDomain {
    param(
        [string[]]$Name
    )

    $Name | Where-Object { $_ -and $_ -match '^[a-z0-9-]+(\.[a-z0-9-]+)+$' -and $_ -notmatch '\.(local|lan|internal|intra|intranet|corp|home|private|localdomain|ad|onmicrosoft\.com)$' } |
        ForEach-Object { $_.ToLower() } | Select-Object -Unique
}

# The common name of a certificate subject or issuer: CN=device.local, O=Vendor -> device.local.
function Get-AuditCommonName {
    param(
        [string]$DistinguishedName
    )

    if ($DistinguishedName -match '(?:^|,\s*)CN=([^,]+)') {
        return $Matches[1].Trim()
    }
    if ($DistinguishedName -match '(?:^|,\s*)O=([^,]+)') {
        return $Matches[1].Trim()
    }
    return $DistinguishedName
}
