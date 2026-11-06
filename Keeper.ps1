[CmdletBinding()]
param(
    # Import entries into Keeper, or export them from it. Asked when not given.
    [ValidateSet('Import', 'Export')]
    [string]$Action,

    # The address of the Keeper Connection Manager, e.g. https://bastion.example.com. Asked when not given.
    [string]$Url,

    # Its login. Asked when not given.
    [pscredential]$Credential,

    # Where it keeps its connections (postgresql, mysql...). By default the one the login gives.
    [string]$DataSource,

    # Don't open the export once it is written.
    [switch]$NoOpen
)

# Imports entries into Keeper, or exports them from it, over the Keeper API. Independent of the
# report: .\Start.ps1 -Keeper, or Keeper import/export in the Script Manager.
# Export: the RDP connections of a Keeper Connection Manager (the REST API of Apache Guacamole) with
# their drive settings, shown, written to KCM-RDP-Drive-Report_<yyyy-MM-dd_HHmmss>.csv next to the
# scripts and opened. It names the client's servers, so git ignores it like the report.

$ErrorActionPreference = 'Stop'
# As Start.ps1 does: TLS 1.2 added to the versions allowed, unless Windows chooses them.
if ([int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
# For Get-MoseProperty: Start.ps1 runs this script in strict mode, where reading a property missing
# from an answer is an error, and Keeper leaves out the parameters a connection doesn't set.
. (Join-Path $PSScriptRoot 'helper.ps1')

function Export-KeeperConnections {
    $address = $Url
    if (-not $address) {
        $address = "$(Read-Host -Prompt 'Address of the Keeper Connection Manager (https://...)')".Trim()
    }
    $address = $address.TrimEnd('/')
    $login = $Credential
    if (-not $login) {
        $login = Get-Credential -Message "Login for $address"
    }
    if (-not $login) {
        throw 'No login was given.'
    }

    try {
        $session = Invoke-RestMethod -Method POST -Uri "$address/api/tokens" -ContentType 'application/x-www-form-urlencoded' `
            -Body @{ username = $login.UserName; password = $login.GetNetworkCredential().Password }
    }
    catch {
        throw "$address refused the login of $($login.UserName): $($_.Exception.Message)"
    }
    $headers = @{ 'Guacamole-Token' = $session.authToken }
    $source = $DataSource
    if (-not $source) {
        $source = $session.dataSource
        $others = @(Get-MoseProperty $session 'availableDataSources' | Where-Object { $_ -and $_ -ne $source })
        if ($others.Count -gt 0) {
            Write-Host "Connections of data source $source (also: $($others -join ', '); pick one with -DataSource)." -ForegroundColor DarkGray
        }
    }

    try {
        # One property per connection, named after its identifier.
        $connections = Invoke-RestMethod -Method GET -Uri "$address/api/session/data/$source/connections" -Headers $headers

        $rows = @(foreach ($property in $connections.PSObject.Properties) {
                $summary = $property.Value
                if ("$(Get-MoseProperty $summary 'protocol')" -ne 'rdp') {
                    continue
                }

                Write-Host "Reading $($summary.name) [$($summary.identifier)]..." -ForegroundColor DarkGray
                try {
                    # Only the parameters, as flat properties: hostname, enable-drive...
                    $parameters = Invoke-RestMethod -Method GET -Uri "$address/api/session/data/$source/connections/$($summary.identifier)/parameters" -Headers $headers

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
    }
    finally {
        # Signed out, so the token can't be used any more.
        try {
            Invoke-RestMethod -Method DELETE -Uri "$address/api/tokens/$($session.authToken)" -Headers $headers | Out-Null
        }
        catch {
            Write-Verbose "Sign-out failed: $($_.Exception.Message)"
        }
    }

    if ($rows.Count -eq 0) {
        Write-Warning "$address has no RDP connection in data source $source."
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
