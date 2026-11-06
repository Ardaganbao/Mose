[CmdletBinding()]
param(
    # Import entries into Keeper, or export them from it. Asked when not given.
    [ValidateSet('Import', 'Export')]
    [string]$Action,

    # The address of the Keeper Connection Manager, e.g. https://bastion.example.com. Picked from the
    # known ones, or asked, when not given.
    [string]$Url,

    # Where it keeps its connections (mysql, postgresql...). The known one, or asked, when not given.
    [string]$DataSource,

    # The Guacamole-Token of a session signed in to it. Asked when not given; never saved.
    [securestring]$Token,

    # Don't open the export once it is written.
    [switch]$NoOpen
)

# Imports entries into Keeper, or exports them from it, over the Keeper API. Independent of the
# report: .\Start.ps1 -Keeper, or Keeper import/export in the Script Manager.
# Export: the RDP connections of a Keeper Connection Manager (the REST API of Apache Guacamole) with
# their drive settings, shown, written to KCM-RDP-Drive-Report_<yyyy-MM-dd_HHmmss>.csv next to the
# scripts and opened. It names the client's servers, so git ignores it like the report.
# The API is read with the token of a session signed in in the browser, which may need a second
# factor this script can't give. The session is not signed out: that would sign out the browser too.

$ErrorActionPreference = 'Stop'
# As Start.ps1 does: TLS 1.2 added to the versions allowed, unless Windows chooses them.
if ([int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
# For Get-MoseProperty: Start.ps1 runs this script in strict mode, where reading a property missing
# from an answer is an error, and Keeper leaves out the parameters a connection doesn't set.
. (Join-Path $PSScriptRoot 'helper.ps1')

# The Keeper Connection Managers used on this computer, offered at the next export: their address and
# data source, the last one used first. Client data, kept out of the repository (see .gitignore).
$KnownPath = Join-Path $PSScriptRoot 'keeper.local.json'

function Get-KnownKcm {
    if (-not (Test-Path -LiteralPath $KnownPath)) {
        return @()
    }
    # Inner parentheses: Windows PowerShell returns a JSON array as one object.
    return @((Get-Content -LiteralPath $KnownPath -Raw | ConvertFrom-Json))
}

function Save-KnownKcm {
    param(
        [object]$Kcm
    )

    $others = @(Get-KnownKcm | Where-Object { -not ($_.Url -eq $Kcm.Url -and $_.DataSource -eq $Kcm.DataSource) })
    $known = @([pscustomobject]@{ Url = $Kcm.Url; DataSource = $Kcm.DataSource }) + $others
    ConvertTo-Json -InputObject $known | Set-Content -LiteralPath $KnownPath -Encoding utf8
}

# The Keeper Connection Manager to read: -Url, one of the known ones, or a new one.
function Select-Kcm {
    $known = @(Get-KnownKcm)
    if (-not $Url -and $known.Count -gt 0) {
        Write-Host 'Keeper Connection Managers known on this computer' -ForegroundColor Cyan
        for ($i = 0; $i -lt $known.Count; $i++) {
            Write-Host ('  {0,2}. {1} ({2})' -f ($i + 1), $known[$i].Url, $known[$i].DataSource)
        }
        Write-Host ('  {0,2}. A new one' -f ($known.Count + 1))
        $answer = "$(Read-Host -Prompt 'Number (Enter for 1)')".Trim()
        $number = 1
        if ($answer -and -not [int]::TryParse($answer, [ref]$number)) {
            throw "Answer a number from 1 to $($known.Count + 1)."
        }
        if ($number -lt 1 -or $number -gt $known.Count + 1) {
            throw "Answer a number from 1 to $($known.Count + 1)."
        }
        if ($number -le $known.Count) {
            $picked = $known[$number - 1]
            $source = if ($DataSource) { $DataSource } else { $picked.DataSource }
            return [pscustomobject]@{ Url = $picked.Url; DataSource = $source }
        }
    }

    $address = $Url
    if (-not $address) {
        $address = "$(Read-Host -Prompt 'Address of the Keeper Connection Manager (https://...)')".Trim()
        if (-not $address) {
            throw 'No address was given.'
        }
    }
    $address = $address.TrimEnd('/')
    $source = $DataSource
    if (-not $source) {
        # Its last data source, so that -Url alone needs no question.
        $knownSource = @($known | Where-Object { $_.Url -eq $address } | ForEach-Object { $_.DataSource }) | Select-Object -First 1
        if ($Url -and $knownSource) {
            $source = $knownSource
        }
        else {
            $default = if ($knownSource) { $knownSource } else { 'mysql' }
            $source = "$(Read-Host -Prompt "Data source of its connections (Enter for $default)")".Trim()
            if (-not $source) {
                $source = $default
            }
        }
    }
    return [pscustomobject]@{ Url = $address; DataSource = $source }
}

function Export-KeeperConnections {
    $kcm = Select-Kcm
    $secureToken = $Token
    if (-not $secureToken) {
        Write-Host "Sign in to $($kcm.Url) in the browser, then copy the Guacamole-Token header of a request to /api (F12, Network)." -ForegroundColor DarkGray
        $secureToken = Read-Host -Prompt 'Token' -AsSecureString
    }
    $plainToken = (New-Object pscredential('token', $secureToken)).GetNetworkCredential().Password.Trim()
    if (-not $plainToken) {
        throw 'No token was given.'
    }
    $headers = @{ 'Guacamole-Token' = $plainToken }
    $api = "$($kcm.Url)/api/session/data/$($kcm.DataSource)"

    try {
        # One property per connection, named after its identifier.
        $connections = Invoke-RestMethod -Method GET -Uri "$api/connections" -Headers $headers
    }
    catch {
        throw "$($kcm.Url) refused the connections of data source $($kcm.DataSource): $($_.Exception.Message.TrimEnd('.')). A token stops working some time after the browser was last used: copy a new one."
    }
    # A sign-in page instead of the list: a string, whose only property is its Length, or an XML
    # document when the page happens to be valid XML. The list is a JSON object.
    if ($connections -isnot [System.Management.Automation.PSCustomObject]) {
        throw "$($kcm.Url) answered with a page instead of the connections: check the address, and copy a new token."
    }
    # Offered first at the next export, now that it answered.
    Save-KnownKcm $kcm

    $rows = @(foreach ($property in $connections.PSObject.Properties) {
            $summary = $property.Value
            if ("$(Get-MoseProperty $summary 'protocol')" -ne 'rdp') {
                continue
            }

            Write-Host "Reading $($summary.name) [$($summary.identifier)]..." -ForegroundColor DarkGray
            try {
                # Only the parameters, as flat properties: hostname, enable-drive...
                $parameters = Invoke-RestMethod -Method GET -Uri "$api/connections/$($summary.identifier)/parameters" -Headers $headers

                [pscustomobject]@{
                    Name            = $summary.name
                    ID              = $summary.identifier
                    ParentID        = Get-MoseProperty $summary 'parentIdentifier'
                    Hostname        = Get-MoseProperty $parameters 'hostname'
                    EnableDrive     = Get-MoseProperty $parameters 'enable-drive'
                    DriveName       = Get-MoseProperty $parameters 'drive-name'
                    DisableDownload = Get-MoseProperty $parameters 'disable-download'
                    DisableUpload   = Get-MoseProperty $parameters 'disable-upload'
                    DrivePath       = Get-MoseProperty $parameters 'drive-path'
                    AutoCreateDrive = Get-MoseProperty $parameters 'create-drive-path'
                }
            }
            catch {
                Write-Warning "Failed to read $($summary.name) [$($summary.identifier)]: $($_.Exception.Message)"
            }
        })

    if ($rows.Count -eq 0) {
        Write-Warning "$($kcm.Url) has no RDP connection in data source $($kcm.DataSource)."
        return
    }
    # The identifiers are numbers in text: 2 before 10.
    $rows = @($rows | Sort-Object Name, { "$($_.ID)".PadLeft(10, '0') })
    # Write-Host, so the Script Manager shows the table too.
    Write-Host ($rows | Format-Table -AutoSize -Wrap | Out-String).TrimEnd()
    # A name of its own each time: Excel locks the file it has open.
    $path = Join-Path $PSScriptRoot "KCM-RDP-Drive-Report_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').csv"
    $rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    Write-Host "$($rows.Count) RDP connection(s) written to $path" -ForegroundColor Green
    if (-not $NoOpen) {
        Invoke-Item -LiteralPath $path
    }
}

if (-not $Action) {
    $answer = "$(Read-Host -Prompt 'Import entries into Keeper or export them from it? (I/E)')".Trim()
    if ($answer -match '^i') {
        $Action = 'Import'
    }
    elseif ($answer -match '^e') {
        $Action = 'Export'
    }
    else {
        throw 'Answer I to import or E to export.'
    }
}

switch ($Action) {
    'Import' {
        Write-Warning 'The Keeper import is not written yet.'
    }
    'Export' {
        Export-KeeperConnections
    }
}
