[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'The public domains of the client, e.g. example.be.')]
    [string[]]$Domain,

    [Parameter(HelpMessage = 'DNS server asked, so that the answers are the public ones and not those of the local network. The local DNS is used when it cannot be reached.')]
    [string]$DnsServer = '1.1.1.1'
)

# Audit of the client's Internet domains from public information only: who registers the domain and
# hosts its DNS, its e-mail (provider, SPF, DKIM, DMARC), its Microsoft 365 tenant, and its website
# (certificate, HTTPS, hosting, WordPress version).

$ErrorActionPreference = 'Stop'
# Start.ps1 runs in strict mode, where a property or regex group that is missing is an error; this
# script expects $null for it. Off for this script only.
Set-StrictMode -Off
. (Join-Path $PSScriptRoot 'AuditCommon.ps1')
$area = 'Domains and e-mail'
$script:DnsServer = $DnsServer

# The answers of the public DNS for a name; none when it has no such record.
function Resolve-PublicName {
    param(
        [string]$Name,
        [string]$Type
    )

    $parameters = @{ Name = $Name; Type = $Type; DnsOnly = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
    if ($script:DnsServer) {
        $parameters.Server = $script:DnsServer
    }
    try {
        return @(Resolve-DnsName @parameters | Where-Object { "$($_.Section)" -eq 'Answer' })
    }
    catch {
        $code = $_.Exception.NativeErrorCode
        # The name, or a record of that type, doesn't exist.
        if ($code -in 9003, 9501 -or $_.Exception.Message -match 'does not exist|No records') {
            return @()
        }
        if ($script:DnsServer) {
            # Port 53 to the Internet blocked: the DNS of this computer.
            Write-Warning "The DNS server $script:DnsServer did not answer ($($_.Exception.Message.Trim())): the DNS of this computer is used, whose answers may differ from the public ones."
            $script:DnsServer = $null
            return Resolve-PublicName -Name $Name -Type $Type
        }
        Write-Warning "DNS $Type $Name failed: $($_.Exception.Message.Trim())"
        return @()
    }
}

function Get-TxtRecords {
    param(
        [string]$Name
    )

    Resolve-PublicName -Name $Name -Type TXT | Where-Object { "$($_.Type)" -eq 'TXT' } | ForEach-Object { $_.Strings -join '' }
}

# Registrar and dates over RDAP, or WHOIS for the TLDs without RDAP (.be, .eu).
function Get-Registration {
    param(
        [string]$Name
    )

    try {
        $rdap = Invoke-RestMethod -Uri "https://rdap.org/domain/$Name" -UseBasicParsing -TimeoutSec 15
        $registrar = @($rdap.entities | Where-Object { $_.roles -contains 'registrar' } | Select-Object -First 1)
        $registrarName = if ($registrar) { @($registrar[0].vcardArray[1] | Where-Object { $_[0] -eq 'fn' } | ForEach-Object { $_[3] }) | Select-Object -First 1 }
        $events = @{}
        foreach ($rdapEvent in @($rdap.events)) {
            $events[$rdapEvent.eventAction] = ConvertTo-AuditDate $rdapEvent.eventDate
        }
        return [pscustomobject]@{ Registrar = $registrarName; Registered = $events['registration']; Expires = $events['expiration']; Source = 'RDAP' }
    }
    catch {
        Write-Verbose "RDAP of $Name failed: $($_.Exception.Message)"
    }
    $servers = @{ be = 'whois.dns.be'; eu = 'whois.eu' }
    $server = $servers[($Name -split '\.')[-1]]
    if (-not $server) {
        return $null
    }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        if (-not $client.ConnectAsync($server, 43).Wait(5000)) {
            throw "$server did not answer on port 43"
        }
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $query = [Text.Encoding]::ASCII.GetBytes("$Name`r`n")
        $stream.Write($query, 0, $query.Length)
        $text = (New-Object System.IO.StreamReader($stream)).ReadToEnd()
    }
    catch {
        Write-Verbose "WHOIS of $Name failed: $($_.Exception.Message)"
        return $null
    }
    finally {
        $client.Close()
    }
    $registrarName = if ($text -match '(?ms)^Registrar:\s*\r?\n\s*Name:\s*([^\r\n]+)') { $Matches[1].Trim() } elseif ($text -match '(?m)^Registrar:\s*(\S[^\r\n]*)') { $Matches[1].Trim() }
    $registered = if ($text -match '(?m)^Registered:\s*([^\r\n]+)') { ConvertTo-AuditDate ($Matches[1].Trim() -replace '^\w{3} ', '') }
    return [pscustomobject]@{ Registrar = $registrarName; Registered = $registered; Expires = $null; Source = 'WHOIS' }
}

function ConvertTo-AuditDate {
    param(
        $Value
    )

    $date = [datetime]::MinValue
    if ($Value -is [datetime]) {
        return $Value
    }
    if ([datetime]::TryParse("$Value", [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$date)) {
        return $date
    }
    return $null
}

# Who runs the mail of an MX host.
function Get-MailProvider {
    param(
        [string]$MailHost
    )

    switch -Regex ($MailHost) {
        'mail\.protection\.outlook\.com\.?$' { return 'Microsoft 365' }
        '(google|googlemail)\.com\.?$' { return 'Google Workspace' }
        'mimecast' { return 'Mimecast' }
        'pphosted|proofpoint' { return 'Proofpoint' }
        'barracudanetworks' { return 'Barracuda' }
        'messagelabs' { return 'Symantec / Broadcom' }
        'hornetsecurity|antispameurope' { return 'Hornetsecurity' }
        'trendmicro' { return 'Trend Micro' }
        'secureserver\.net' { return 'GoDaddy' }
        'ovh\.net' { return 'OVHcloud' }
        'one\.com' { return 'one.com' }
        'combell' { return 'Combell' }
        'register\.it' { return 'Register.it' }
    }
    return ($MailHost.TrimEnd('.') -split '\.' | Select-Object -Last 2) -join '.'
}

$wordPressLatest = $null
function Get-WordPressLatest {
    if ($null -eq $script:wordPressLatest) {
        try {
            $script:wordPressLatest = "$((Invoke-RestMethod -Uri 'https://api.wordpress.org/core/version-check/1.7/' -UseBasicParsing -TimeoutSec 15).offers[0].current)"
        }
        catch {
            $script:wordPressLatest = ''
        }
    }
    return $script:wordPressLatest
}

# The website of the domain: www first, else the domain itself, following redirects to the other one.
function Get-Website {
    param(
        [string]$Name
    )

    foreach ($start in "www.$Name", $Name) {
        if (@(Resolve-PublicName -Name $start -Type A | Where-Object { "$($_.Type)" -eq 'A' }).Count -eq 0) {
            continue
        }
        $hostName = $start
        $page = $null
        for ($hop = 0; $hop -lt 3; $hop++) {
            $page = Get-AuditWebInfo -HostName $hostName -Port 443 -Tls $true -TimeoutMs 8000 -KeepBody
            if (-not $page -or -not $page.Location -or $page.Location -notmatch '^https?://(?<host>[^/:]+)' -or $Matches.host -eq $hostName -or
                -not ($Matches.host -eq $Name -or $Matches.host.EndsWith(".$Name"))) {
                break
            }
            $hostName = $Matches.host
        }
        $plain = Get-AuditWebInfo -HostName $start -Port 80 -Tls $false -TimeoutMs 8000
        $addresses = @(Resolve-PublicName -Name $hostName -Type A | Where-Object { "$($_.Type)" -eq 'A' } | ForEach-Object { $_.IPAddress })
        $hosting = $null
        if ($addresses.Count -gt 0) {
            try {
                $hosting = (Invoke-RestMethod -Uri "https://ipinfo.io/$($addresses[0])/json" -UseBasicParsing -TimeoutSec 10).org
            }
            catch {
                Write-Verbose "The hosting of $($addresses[0]) is not known: $($_.Exception.Message)"
            }
        }
        $body = if ($page) { "$($page.Body)" } else { '' }
        $generator = if ($body -match '(?i)<meta[^>]+name=["'']generator["''][^>]+content=["'']([^"'']+)') { [System.Net.WebUtility]::HtmlDecode($Matches[1]) }
        $cms = if ($generator) { $generator } elseif ($body -match 'wp-content|wp-includes') { 'WordPress' } elseif ($body -match '(?i)wix\.com|_wixCIDX') { 'Wix' } elseif ($body -match '(?i)squarespace') { 'Squarespace' } elseif ($body -match '(?i)cdn\.shopify') { 'Shopify' }
        if ($page) {
            $page.Body = $null
        }
        return [pscustomobject]@{
            Host              = $hostName
            Addresses         = $addresses
            Hosting           = $hosting
            Https             = $page
            RedirectsToHttps  = [bool]($plain -and (($plain.Url -like 'https:*') -or ("$($plain.Location)" -like 'https:*')))
            PlainHttp         = [bool]($plain -and $plain.Status -eq 200 -and $plain.Url -like 'http:*')
            Cms               = $cms
        }
    }
    return $null
}

$results = @()
foreach ($name in @($Domain | ForEach-Object { $_.Trim().TrimEnd('.').ToLower() } | Where-Object { $_ } | Select-Object -Unique)) {
    Write-Progress -Id 40 -Activity 'Domain audit' -Status $name -PercentComplete (100 * $results.Count / @($Domain).Count)
    $nameServers = @(Resolve-PublicName -Name $name -Type NS | Where-Object { "$($_.Type)" -eq 'NS' } | ForEach-Object { $_.NameHost.TrimEnd('.') } | Sort-Object)
    "`n### $name"
    if ($nameServers.Count -eq 0 -and @(Resolve-PublicName -Name $name -Type SOA).Count -eq 0) {
        "$name does not exist in the public DNS."
        New-AuditFinding -Severity Medium -Area $area -Finding "The domain $name does not exist in the public DNS." -Recommendation 'Check its spelling, or whether its registration lapsed.'
        continue
    }
    $mx = @(Resolve-PublicName -Name $name -Type MX | Where-Object { "$($_.Type)" -eq 'MX' } | Sort-Object -Property Preference | ForEach-Object { [pscustomobject]@{ Preference = $_.Preference; Host = "$($_.NameExchange)".TrimEnd('.') } })
    # A "null MX" (RFC 7505), whose host is ".", says that the domain accepts no e-mail.
    $nullMx = @($mx | Where-Object { -not $_.Host }).Count -gt 0
    $mx = @($mx | Where-Object { $_.Host })
    $providers = @($mx | ForEach-Object { Get-MailProvider $_.Host } | Select-Object -Unique)
    $txt = @(Get-TxtRecords $name)
    $spf = @($txt | Where-Object { $_ -match '^v=spf1(\s|$)' })
    $dmarc = @(Get-TxtRecords "_dmarc.$name" | Where-Object { $_ -match '^v=DMARC1' })
    $dmarcPolicy = if ($dmarc.Count -and $dmarc[0] -match '(?i)\bp=(\w+)') { $Matches[1].ToLower() }
    # DKIM keys on the selectors of Microsoft 365 and the most common other senders.
    $dkim = @(foreach ($selector in 'selector1', 'selector2', 'google', 'default', 'k1', 's1', 's2', 'mail', 'dkim') {
            $answers = @(Resolve-PublicName -Name "$selector._domainkey.$name" -Type TXT)
            # An empty key (p=) is a revoked one.
            $key = @($answers | Where-Object { "$($_.Type)" -eq 'TXT' } | ForEach-Object { $_.Strings -join '' } | Where-Object { $_ -match '\bp=[A-Za-z0-9+/]' })
            $alias = @($answers | Where-Object { "$($_.Type)" -eq 'CNAME' } | ForEach-Object { $_.NameHost })
            if ($key.Count -or $alias.Count) {
                [pscustomobject]@{ Selector = $selector; HasKey = [bool]$key.Count; Alias = ($alias | Select-Object -First 1) }
            }
        })
    $autodiscover = @(Resolve-PublicName -Name "autodiscover.$name" -Type CNAME | Where-Object { "$($_.Type)" -eq 'CNAME' } | ForEach-Object { $_.NameHost }) | Select-Object -First 1
    $verifications = @(foreach ($pair in @(
                @('^MS=ms', 'Microsoft 365'), @('^google-site-verification', 'Google'), @('^facebook-domain-verification', 'Facebook / Meta'),
                @('^apple-domain-verification', 'Apple'), @('^atlassian-domain-verification', 'Atlassian'), @('^docusign', 'DocuSign'),
                @('^adobe-idp-site-verification', 'Adobe'), @('^zoho-verification', 'Zoho'), @('^(ahrefs|SEMrush)', 'SEO tool'),
                @('^teamviewer-sso-verification', 'TeamViewer'), @('^(mailchimp|mandrill)', 'Mailchimp'), @('^hubspot', 'HubSpot'))) {
            if ($txt -match $pair[0]) { $pair[1] }
        })

    # The Microsoft 365 tenant of the domain, if any, and how its users sign in.
    $tenant = $null
    try {
        $openId = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$name/.well-known/openid-configuration" -UseBasicParsing -TimeoutSec 15
        if ("$($openId.token_endpoint)" -match '/([0-9a-f-]{36})/') {
            $realm = Invoke-RestMethod -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=audit@$name&json=1" -UseBasicParsing -TimeoutSec 15
            $tenant = [pscustomobject]@{ Id = $Matches[1]; Region = $openId.tenant_region_scope; SignIn = $realm.NameSpaceType; Name = $realm.FederationBrandName; FederatedBy = $(if ($realm.AuthURL) { ([uri]$realm.AuthURL).Host }) }
        }
    }
    catch {
        # No tenant has this domain.
    }

    $registration = Get-Registration $name
    $website = Get-Website $name

    # The table of the domain.
    $spfText = if ($spf.Count -eq 0) { ':x: none' } elseif ($spf.Count -gt 1) { ":x: $($spf.Count) records (invalid): $($spf -join ' / ')" } else { $spf[0] }
    $dkimText = if ($dkim.Count -eq 0) { 'none found on the usual selectors' } else { (@($dkim | ForEach-Object { "$($_.Selector)$(if (-not $_.HasKey) { ' (alias without key)' })" })) -join ', ' }
    $https = if ($website) { $website.Https }
    $rows = @(
        [pscustomobject]@{ Item = 'Registrar'; Value = $(if ($registration) { "$(if ($registration.Registrar) { $registration.Registrar } else { 'n/a' })$(if ($registration.Registered) { ", registered $($registration.Registered.ToString('yyyy-MM-dd'))" })$(if ($registration.Expires) { ", expires $($registration.Expires.ToString('yyyy-MM-dd'))" })" } else { 'n/a' }) }
        [pscustomobject]@{ Item = 'Name servers'; Value = $nameServers }
        [pscustomobject]@{ Item = 'E-mail (MX)'; Value = $(if ($mx.Count) { "$(($mx | ForEach-Object { "$($_.Preference) $($_.Host)" }) -join ', ') ($($providers -join ', '))" } elseif ($nullMx) { 'none: null MX, the domain accepts no e-mail' } else { 'none: the domain receives no e-mail' }) }
        [pscustomobject]@{ Item = 'SPF'; Value = $spfText }
        [pscustomobject]@{ Item = 'DKIM'; Value = $dkimText }
        [pscustomobject]@{ Item = 'DMARC'; Value = $(if ($dmarc.Count) { $dmarc[0] } else { ':x: none' }) }
        [pscustomobject]@{ Item = 'Microsoft 365'; Value = $(if ($tenant) { "Tenant $($tenant.Id)$(if ($tenant.Name) { " ($($tenant.Name))" }), $(if ($tenant.SignIn -eq 'Federated') { "sign-in federated by $($tenant.FederatedBy)" } else { 'cloud sign-in' })" } else { 'no tenant has this domain' }) }
        [pscustomobject]@{ Item = 'Autodiscover'; Value = $(if ($autodiscover) { $autodiscover } else { 'none' }) }
        [pscustomobject]@{ Item = 'Other services (TXT)'; Value = $(if ($verifications.Count) { $verifications | Select-Object -Unique } else { 'none' }) }
    )
    if ($website) {
        $rows += [pscustomobject]@{ Item = 'Website'; Value = "$(if ($https -and $https.Url) { $https.Url } else { "http://$($website.Host)/" })$(if ($https -and $https.Title) { ": $($https.Title)" })$(if ($website.Cms) { ", $($website.Cms)" })" }
        $rows += [pscustomobject]@{ Item = 'Hosting'; Value = "$($website.Addresses -join ', ')$(if ($website.Hosting) { " ($($website.Hosting))" })$(if ($https -and $https.Server) { ", server $($https.Server)" })" }
        $rows += [pscustomobject]@{ Item = 'Certificate'; Value = $(if ($https -and $https.CertificateSubject) { "$(Get-AuditCommonName $https.CertificateSubject), by $(Get-AuditCommonName $https.CertificateIssuer), until $($https.CertificateExpires.ToString('yyyy-MM-dd'))$(if ($https.CertificateErrors -ne 'None') { " :x: $($https.CertificateErrors)" })" } else { ':x: no HTTPS' }) }
        $rows += [pscustomobject]@{ Item = 'HTTP to HTTPS'; Value = $(if ($website.RedirectsToHttps) { 'Redirected' } elseif ($website.PlainHttp) { ':warning: also served over plain HTTP' } else { 'n/a' }) }
    }
    else {
        $rows += [pscustomobject]@{ Item = 'Website'; Value = 'none (no address for www or the domain)' }
    }
    Format-AuditTable -Rows $rows -Columns ' =Item', ' =Value'

    # Findings.
    $sendsMail = ($mx.Count -gt 0 -or $tenant) -and -not $nullMx
    if ($sendsMail) {
        if ($spf.Count -eq 0) {
            New-AuditFinding -Severity High -Area $area -Finding "$name has no SPF record: anyone can send e-mail in its name, and its own mail is more often seen as spam." -Recommendation "Publish one listing the services that send its mail$(if ($providers -contains 'Microsoft 365') { ', e.g. v=spf1 include:spf.protection.outlook.com -all' })."
        }
        elseif ($spf.Count -gt 1) {
            New-AuditFinding -Severity High -Area $area -Finding "$name has $($spf.Count) SPF records, which makes SPF fail for all its mail." -Recommendation 'Merge them into one record.'
        }
        elseif ($spf[0] -match '(^|\s)[+]?all\b') {
            New-AuditFinding -Severity High -Area $area -Finding "The SPF record of $name ends with +all: it allows every server in the world to send its mail." -Recommendation 'End it with -all (or ~all while checking).'
        }
        elseif ($spf[0] -match '\?all\b' -or ($spf[0] -notmatch '[-~]all\b' -and $spf[0] -notmatch 'redirect=')) {
            New-AuditFinding -Severity Medium -Area $area -Finding "The SPF record of $name does not reject other senders ($($spf[0]))." -Recommendation 'End it with -all once every sending service is listed.'
        }
        if ($providers -contains 'Microsoft 365' -and $spf.Count -eq 1 -and $spf[0] -notmatch 'spf\.protection\.outlook\.com') {
            New-AuditFinding -Severity Medium -Area $area -Finding "$name receives its mail in Microsoft 365, but its SPF record does not include Microsoft 365." -Recommendation 'Add include:spf.protection.outlook.com.'
        }
        if ($dmarc.Count -eq 0) {
            New-AuditFinding -Severity High -Area $area -Finding "$name has no DMARC record: mail faking its address is delivered, and the owner never hears of it." -Recommendation "Publish _dmarc.$name with p=none and a rua address to collect reports, then move to p=quarantine or p=reject."
        }
        elseif ($dmarcPolicy -eq 'none') {
            New-AuditFinding -Severity Medium -Area $area -Finding "The DMARC policy of $name is p=none: mail faking its address is still delivered." -Recommendation 'Once the reports show only legitimate senders, move to p=quarantine, then p=reject.'
        }
        if ($dmarc.Count -and $dmarc[0] -notmatch '(?i)\brua=') {
            New-AuditFinding -Severity Low -Area $area -Finding "The DMARC record of $name sends no reports (no rua)." -Recommendation 'Add rua=mailto:... to see who sends mail in its name.'
        }
        if ($providers -contains 'Microsoft 365' -and @($dkim | Where-Object { $_.Selector -like 'selector*' -and $_.HasKey }).Count -eq 0) {
            New-AuditFinding -Severity Medium -Area $area -Finding "DKIM signing of $name is not set up in Microsoft 365 (no key on selector1 or selector2)." -Recommendation 'Publish the two CNAME records and turn DKIM on in Microsoft Defender (Email authentication settings).'
        }
        elseif ($dkim.Count -eq 0) {
            New-AuditFinding -Severity Low -Area $area -Finding "No DKIM key of $name was found on the usual selectors." -Recommendation 'Check with the mail provider that it signs the mail of the domain.'
        }
    }
    elseif ($spf.Count -eq 0 -or $dmarc.Count -eq 0) {
        New-AuditFinding -Severity Low -Area $area -Finding "$name receives no e-mail but does not say that it sends none: it can be used to fake e-mail." -Recommendation "Publish v=spf1 -all and _dmarc.$name 'v=DMARC1; p=reject'."
    }
    if ($nameServers.Count -eq 1) {
        New-AuditFinding -Severity Low -Area $area -Finding "$name has a single name server ($($nameServers[0]))." -Recommendation 'Use at least two name servers, on different networks.'
    }
    if ($registration -and $registration.Expires) {
        $days = ($registration.Expires - (Get-Date)).Days
        if ($days -lt 60) {
            New-AuditFinding -Severity $(if ($days -lt 30) { 'High' } else { 'Medium' }) -Area $area -Finding "The registration of $name expires on $($registration.Expires.ToString('yyyy-MM-dd'))." -Recommendation 'Renew it, or turn automatic renewal on with the registrar.'
        }
    }
    if ($website) {
        if (-not $https -or -not $https.CertificateSubject) {
            New-AuditFinding -Severity Medium -Area $area -Finding "The website of $name has no HTTPS." -Recommendation 'Add a certificate (e.g. free from the hosting provider) and redirect HTTP to HTTPS.'
        }
        elseif ($https.CertificateExpires -lt (Get-Date) -or $https.CertificateErrors -ne 'None') {
            New-AuditFinding -Severity High -Area $area -Finding "The certificate of $($https.Url) is not valid ($(if ($https.CertificateExpires -lt (Get-Date)) { "expired on $($https.CertificateExpires.ToString('yyyy-MM-dd'))" } else { $https.CertificateErrors })): visitors get a security warning." -Recommendation 'Renew or replace the certificate with the hosting provider.'
        }
        elseif ($https.CertificateExpires -lt (Get-Date).AddDays(14)) {
            New-AuditFinding -Severity Medium -Area $area -Finding "The certificate of $($https.Url) expires on $($https.CertificateExpires.ToString('yyyy-MM-dd'))." -Recommendation 'Check that it renews automatically.'
        }
        if ($website.PlainHttp -and -not $website.RedirectsToHttps) {
            New-AuditFinding -Severity Low -Area $area -Finding "The website of $name is also served over plain HTTP, without redirecting to HTTPS." -Recommendation 'Redirect HTTP to HTTPS.'
        }
        if ("$($website.Cms)" -match '^WordPress (\d+\.\d+(\.\d+)?)') {
            $latest = Get-WordPressLatest
            if ($latest -and [version]$Matches[1] -lt [version]$latest) {
                New-AuditFinding -Severity Medium -Area $area -Finding "The website of $name runs WordPress $($Matches[1]); the latest is $latest." -Recommendation 'Update WordPress, its theme and plugins, or ask who manages the website to.'
            }
        }
    }
    if ($tenant -and $tenant.SignIn -eq 'Federated') {
        New-AuditFinding -Severity Info -Area $area -Finding "Microsoft 365 sign-in of $name is federated by $($tenant.FederatedBy): if that server is down, nobody can sign in to Microsoft 365." -Recommendation 'Note it in the documentation; consider moving to cloud sign-in (password hash sync).'
    }

    $results += [pscustomobject]@{
        Domain       = $name
        NameServers  = $nameServers
        Registration = $registration
        Mx           = $mx
        MailProvider = $providers
        Spf          = $spf
        Dkim         = $dkim
        Dmarc        = $dmarc
        Tenant       = $tenant
        Autodiscover = $autodiscover
        Services     = @($verifications | Select-Object -Unique)
        Website      = $website
    }
}
Write-Progress -Id 40 -Activity 'Domain audit' -Completed

New-AuditData -Name 'Domains' -Value $results
