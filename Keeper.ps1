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

    # Import: the CSV of the drive settings to write, laid out like the export. Asked when not given.
    [string]$Path,

    # Import: only the rows of these connection IDs, e.g. 44, or 40-50,60 (* for all). Asked when not given.
    [string[]]$Id,

    # Don't open the export once it is written.
    [switch]$NoOpen,

    # The window instead of the questions: .\Start.ps1 -Keeper -Gui.
    [switch]$Gui
)

# Imports entries into Keeper, or exports them from it, over the Keeper API. Independent of the
# report: .\Start.ps1 -Keeper (questions in the console), .\Start.ps1 -Keeper -Gui or Keeper
# import/export in the Script Manager (a window), both running the same steps.
# Export: the RDP connections of a Keeper Connection Manager (the REST API of Apache Guacamole) with
# their drive settings, shown, written to KCM-RDP-Drive-Report_<yyyy-MM-dd_HHmmss>.csv next to the
# scripts and opened. It names the client's servers, so git ignores it like the report.
# Import: such a CSV, edited in Excel for example, written to the connections of its ID column, all of
# them or those picked by ID (44, or 40-50,60). The ID says which connection a row is; every other
# column is written to it: Name renames it, ParentID moves it to that folder, Hostname and the drive
# columns are its parameters. An empty Name, ParentID or Hostname is left as it is. The values that
# differ from Keeper are shown first, then written to all connections or to the first one only, after
# a backup of them in KCM-RDP-Backup_<yyyy-MM-dd_HHmmss>.json.
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

# The connections of a Keeper Connection Manager: one property per connection, named after its
# identifier. Read again for each step, so that a step sees what the one before wrote.
function Get-KcmConnectionList {
    param(
        [object]$Session
    )

    try {
        $connections = Invoke-RestMethod -Method GET -Uri "$($Session.Api)/connections" -Headers $Session.Headers
    }
    catch {
        throw "$($Session.Url) refused the connections of data source $($Session.DataSource): $($_.Exception.Message.TrimEnd('.')). A token stops working some time after the browser was last used: copy a new one."
    }
    # A sign-in page instead of the list: a string, whose only property is its Length, or an XML
    # document when the page happens to be valid XML. The list is a JSON object.
    if ($connections -isnot [System.Management.Automation.PSCustomObject]) {
        throw "$($Session.Url) answered with a page instead of the connections: check the address, and copy a new token."
    }
    return $connections
}

# Reads the connections with the token of a session signed in in the browser. The Keeper Connection
# Manager is then offered first next time, now that it answered.
function Connect-KcmApi {
    param(
        [string]$Address,
        [string]$Source,
        [string]$PlainToken
    )

    $Address = "$Address".Trim().TrimEnd('/')
    if (-not $Address) {
        throw 'No address was given.'
    }
    $Source = "$Source".Trim()
    if (-not $Source) {
        $Source = 'mysql'
    }
    $PlainToken = "$PlainToken".Trim()
    if (-not $PlainToken) {
        throw 'No token was given.'
    }
    $session = [pscustomobject]@{
        Url        = $Address
        DataSource = $Source
        Api        = "$Address/api/session/data/$Source"
        Headers    = @{ 'Guacamole-Token' = $PlainToken }
        Count      = 0
    }
    $session.Count = @((Get-KcmConnectionList $session).PSObject.Properties).Count
    Save-KnownKcm $session
    return $session
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

# Asks for the Keeper Connection Manager and the token, then connects.
function Connect-Kcm {
    $kcm = Select-Kcm
    $secureToken = $Token
    if (-not $secureToken) {
        Write-Host "Sign in to $($kcm.Url) in the browser, then copy the Guacamole-Token header of a request to /api (F12, Network)." -ForegroundColor DarkGray
        $secureToken = Read-Host -Prompt 'Token' -AsSecureString
    }
    $plainToken = (New-Object pscredential('token', $secureToken)).GetNetworkCredential().Password
    return Connect-KcmApi -Address $kcm.Url -Source $kcm.DataSource -PlainToken $plainToken
}

# The drive columns of the CSV and the connection parameters they are. A yes/no parameter is "true",
# or not set.
$DriveFields = [ordered]@{
    EnableDrive     = @{ Parameter = 'enable-drive'; YesNo = $true }
    DriveName       = @{ Parameter = 'drive-name'; YesNo = $false }
    DisableDownload = @{ Parameter = 'disable-download'; YesNo = $true }
    DisableUpload   = @{ Parameter = 'disable-upload'; YesNo = $true }
    DrivePath       = @{ Parameter = 'drive-path'; YesNo = $false }
    AutoCreateDrive = @{ Parameter = 'create-drive-path'; YesNo = $true }
}

# Import: the CSV columns besides the drive ones and where they go in Keeper, the connection itself
# (Field) or one of its parameters. Left as they are when empty: a connection can't be without them.
$OtherFields = [ordered]@{
    Name     = @{ Field = 'name' }
    ParentID = @{ Field = 'parentIdentifier' }
    Hostname = @{ Parameter = 'hostname' }
}

# The RDP connections with their drive settings, in the columns of the CSV, sorted by name and ID.
# -Progress: the window's status line, instead of a line in the console for each connection.
function Get-KcmRows {
    param(
        [object]$Session,
        [scriptblock]$Progress
    )

    $connections = Get-KcmConnectionList $Session
    $rows = @(foreach ($property in $connections.PSObject.Properties) {
            $summary = $property.Value
            if ("$(Get-MoseProperty $summary 'protocol')" -ne 'rdp') {
                continue
            }

            $text = "Reading $($summary.name) [$($summary.identifier)]..."
            if ($Progress) {
                & $Progress $text
            }
            else {
                Write-Host $text -ForegroundColor DarkGray
            }
            try {
                # Only the parameters, as flat properties: hostname, enable-drive...
                $parameters = Invoke-RestMethod -Method GET -Uri "$($Session.Api)/connections/$($summary.identifier)/parameters" -Headers $Session.Headers

                $row = [ordered]@{
                    Name     = $summary.name
                    ID       = $summary.identifier
                    ParentID = Get-MoseProperty $summary 'parentIdentifier'
                    Hostname = Get-MoseProperty $parameters 'hostname'
                }
                foreach ($column in $DriveFields.Keys) {
                    $row[$column] = Get-MoseProperty $parameters $DriveFields[$column].Parameter
                }
                [pscustomobject]$row
            }
            catch {
                Write-Warning "Failed to read $($summary.name) [$($summary.identifier)]: $($_.Exception.Message)"
            }
        })
    # The identifiers are numbers in text: 2 before 10.
    return @($rows | Sort-Object Name, { "$($_.ID)".PadLeft(10, '0') })
}

# Writes the export next to the scripts and returns its path. A name of its own each time: Excel
# locks the file it has open.
function Save-KcmExport {
    param(
        [object[]]$Rows
    )

    $path = Join-Path $PSScriptRoot "KCM-RDP-Drive-Report_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').csv"
    $Rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    return $path
}

function Export-KeeperConnections {
    $kcm = Connect-Kcm
    $rows = @(Get-KcmRows -Session $kcm)
    if ($rows.Count -eq 0) {
        Write-Warning "$($kcm.Url) has no RDP connection in data source $($kcm.DataSource)."
        return
    }
    # Write-Host, so the Script Manager shows the table too.
    Write-Host ($rows | Format-Table -AutoSize -Wrap | Out-String).TrimEnd()
    $path = Save-KcmExport -Rows $rows
    Write-Host "$($rows.Count) RDP connection(s) written to $path" -ForegroundColor Green
    if (-not $NoOpen) {
        Invoke-Item -LiteralPath $path
    }
}

# "true", or '' for not set. Excel writes TRUE and FALSE, or VRAI and FAUX, WAAR and ONWAAR.
function ConvertTo-KcmYesNo {
    param(
        [string]$Value,
        [string]$Where
    )

    if ($Value -match '^(true|vrai|waar|yes|oui|ja|1)$') {
        return 'true'
    }
    if ($Value -match '^(|false|faux|onwaar|no|non|nee|0)$') {
        return ''
    }
    throw "${Where}: '$Value' is neither true nor false."
}

# The rows of a CSV written by the export or saved by Excel: in UTF-8 or the Windows code page, with
# commas or semicolons (Excel's separator where the decimal mark is a comma).
function Read-DriveCsv {
    param(
        [string]$File
    )

    $bytes = [IO.File]::ReadAllBytes($File)
    try {
        $text = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes)
    }
    catch {
        $text = [Text.Encoding]::Default.GetString($bytes)
    }
    $text = $text.TrimStart([char]0xFEFF)
    $header = ($text -split '\r?\n', 2)[0]
    $delimiter = if ($header.Split(';').Count -gt $header.Split(',').Count) { ';' } else { ',' }
    return @($text | ConvertFrom-Csv -Delimiter $delimiter)
}

# IDs as ranges: 2-5, 8, 10-12. The IDs are numbers in Keeper's databases; any other is listed as is.
function Format-IdRanges {
    param(
        [string[]]$Ids
    )

    $numbers = @($Ids | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [long]$_ } | Sort-Object -Unique)
    $parts = New-Object System.Collections.Generic.List[string]
    $start = 0
    while ($start -lt $numbers.Count) {
        $end = $start
        while ($end + 1 -lt $numbers.Count -and $numbers[$end + 1] -eq $numbers[$end] + 1) {
            $end++
        }
        $parts.Add($(if ($end -gt $start) { "$($numbers[$start])-$($numbers[$end])" } else { "$($numbers[$start])" }))
        $start = $end + 1
    }
    foreach ($other in @($Ids | Where-Object { $_ -notmatch '^\d+$' })) {
        $parts.Add($other)
    }
    return $parts -join ', '
}

# The rows whose ID is in a selection like 44, or 40-50,60: a range takes the IDs from one number to
# the other. An ID or a range that no row has stops, in case of a typo.
function Select-DriveRows {
    param(
        [object[]]$Rows,
        [string]$Selection
    )

    $picked = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($part in @(($Selection -replace '\s*-\s*', '-') -split '[,;\s]+' | Where-Object { $_ })) {
        if ($part -match '^(\d+)-(\d+)$') {
            $low = [long]$Matches[1]
            $high = [long]$Matches[2]
            if ($low -gt $high) {
                $low, $high = $high, $low
            }
            $inRange = @($Rows | ForEach-Object { "$($_.ID)".Trim() } | Where-Object { $_ -match '^\d+$' -and [long]$_ -ge $low -and [long]$_ -le $high })
            if ($inRange.Count -eq 0) {
                throw "No row of the CSV has an ID from $low to $high."
            }
            $inRange | ForEach-Object { [void]$picked.Add($_) }
        }
        elseif (@($Rows | Where-Object { "$($_.ID)".Trim() -eq $part }).Count -gt 0) {
            [void]$picked.Add($part)
        }
        else {
            throw "No row of the CSV has ID $part."
        }
    }
    # In the CSV's order.
    return @($Rows | Where-Object { $picked.Contains("$($_.ID)".Trim()) })
}

# The CSVs laid out like the export (an ID column) next to the scripts, in the folder above and in
# PowerShell's folder, newest first.
function Find-ImportCsv {
    $folders = @($PSScriptRoot, (Split-Path -Parent $PSScriptRoot), (Get-Location).ProviderPath) | Where-Object { $_ } | Sort-Object -Unique
    $found = @(foreach ($folder in $folders) {
            # Not the ~$ file Excel keeps beside a workbook it has open.
            Get-ChildItem -LiteralPath $folder -Filter '*.csv' -File -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -notlike '~$*' -and "$(Get-Content -LiteralPath $_.FullName -TotalCount 1 -ErrorAction SilentlyContinue)" -match '(^|[,;])"?ID"?([,;]|$)'
            }
        }) | Sort-Object FullName -Unique | Sort-Object LastWriteTime -Descending
    return @($found)
}

# How a CSV is offered: its name, folder, rows and when it was saved; an export says it is one, since
# it only holds what Keeper had then.
function Format-CsvChoice {
    param(
        [System.IO.FileInfo]$File
    )

    $count = [math]::Max(0, @(Get-Content -LiteralPath $File.FullName).Count - 1)
    $note = if ($File.Name -like 'KCM-RDP-Drive-Report_*.csv') { '; an export: what Keeper had then' } else { '' }
    return '{0}  (in {1}, {2} rows, saved {3:yyyy-MM-dd HH:mm}{4})' -f $File.Name, (Split-Path -Leaf $File.DirectoryName), $count, $File.LastWriteTime, $note
}

# The CSV to import: one of those found, by number, or a path. No Enter default: the last export,
# which only says what Keeper had, was taken for the CSV to import.
function Select-ImportCsv {
    $found = @(Find-ImportCsv)
    $prompt = 'Path of the CSV to import'
    if ($found.Count -gt 0) {
        Write-Host 'CSVs found, newest first' -ForegroundColor Cyan
        for ($i = 0; $i -lt $found.Count; $i++) {
            Write-Host ('  {0,2}. {1}' -f ($i + 1), (Format-CsvChoice $found[$i]))
        }
        $prompt = 'Number of the CSV to import, or its path'
    }
    $answer = "$(Read-Host -Prompt $prompt)".Trim().Trim('"')
    if (-not $answer) {
        throw 'No CSV was given.'
    }
    $number = 0
    if ($found.Count -gt 0 -and [int]::TryParse($answer, [ref]$number)) {
        if ($number -lt 1 -or $number -gt $found.Count) {
            throw "Answer a number from 1 to $($found.Count), or a path."
        }
        return $found[$number - 1].FullName
    }
    return $answer
}

# A CSV to import, checked as a whole before Keeper is asked anything: its rows and the columns that
# are imported.
function Read-ImportCsv {
    param(
        [string]$File
    )

    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
        throw "There is no file $File."
    }
    # A relative path is from PowerShell's folder, which .NET, reading the file, doesn't know.
    $File = (Resolve-Path -LiteralPath $File).ProviderPath
    $rows = @(Read-DriveCsv $File)
    if ($rows.Count -eq 0) {
        throw "$File has no rows."
    }
    $columns = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name })
    if ($columns -notcontains 'ID') {
        throw "$File has no ID column, which says the connection of each row: start from an export."
    }
    $imported = @(@($OtherFields.Keys) + @($DriveFields.Keys) | Where-Object { $columns -contains $_ })
    if ($imported.Count -eq 0) {
        throw "$File has no column to import: $(@(@($OtherFields.Keys) + @($DriveFields.Keys)) -join ', ')."
    }
    $noId = @($rows | Where-Object { -not "$($_.ID)".Trim() })
    if ($noId.Count -gt 0) {
        throw "$($noId.Count) row(s) of $File have no ID: each row must say the connection it changes."
    }
    $twice = @($rows | Group-Object { "$($_.ID)".Trim() } | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    if ($twice.Count -gt 0) {
        throw "These IDs are on more than one row of ${File}: $($twice -join ', ')."
    }
    return [pscustomobject]@{ File = $File; Rows = $rows; Imported = $imported }
}

# Each row: its values for the connection itself (Fields) and for its parameters (Values), and the
# CSV column of each (ColumnOf), for the list of the changes.
function ConvertTo-ImportItems {
    param(
        [object[]]$Rows,
        [string[]]$Imported
    )

    $columnOf = @{}
    $items = @(foreach ($row in $Rows) {
            $fields = [ordered]@{}
            $values = [ordered]@{}
            foreach ($column in $Imported) {
                $value = "$($row.$column)".Trim()
                if ($OtherFields.Contains($column)) {
                    if (-not $value) {
                        continue
                    }
                    $target = $OtherFields[$column]
                    if ($target.Contains('Field')) {
                        $fields[$target.Field] = $value
                        $columnOf[$target.Field] = $column
                    }
                    else {
                        $values[$target.Parameter] = $value
                        $columnOf[$target.Parameter] = $column
                    }
                    continue
                }
                if ($DriveFields[$column].YesNo) {
                    $value = ConvertTo-KcmYesNo -Value $value -Where "ID $($row.ID), column $column"
                }
                $values[$DriveFields[$column].Parameter] = $value
                $columnOf[$DriveFields[$column].Parameter] = $column
            }
            [pscustomobject]@{ ID = "$($row.ID)".Trim(); Fields = $fields; Values = $values }
        })
    return [pscustomobject]@{ Items = $items; ColumnOf = $columnOf }
}

# What each row changes in Keeper, sorted by name: only the values that differ from it. The row of a
# connection it doesn't have, or that is not RDP, is skipped.
function Get-ImportPlans {
    param(
        [object]$Session,
        [object]$Import,
        [scriptblock]$Progress
    )

    $connections = Get-KcmConnectionList $Session
    $plans = New-Object System.Collections.Generic.List[object]
    $unchanged = 0
    $skipped = 0
    foreach ($item in $Import.Items) {
        $summary = Get-MoseProperty $connections $item.ID
        if (-not $summary) {
            Write-Warning "$($Session.Url) has no connection $($item.ID): its row is skipped."
            $skipped++
            continue
        }
        if ("$(Get-MoseProperty $summary 'protocol')" -ne 'rdp') {
            Write-Warning "$($summary.name) [$($item.ID)] is not an RDP connection: its row is skipped."
            $skipped++
            continue
        }
        if ($Progress) {
            & $Progress "Reading $($summary.name) [$($item.ID)]..."
        }
        $changes = New-Object System.Collections.Generic.List[object]
        foreach ($field in $item.Fields.Keys) {
            $old = "$(Get-MoseProperty $summary $field)"
            if ($old -cne $item.Fields[$field]) {
                $changes.Add([pscustomobject]@{ Column = $Import.ColumnOf[$field]; Key = $field; Field = $true; Before = $old; After = $item.Fields[$field] })
            }
        }
        try {
            $before = Invoke-RestMethod -Method GET -Uri "$($Session.Api)/connections/$($item.ID)/parameters" -Headers $Session.Headers
            # All its parameters, then the CSV's: a parameter left out of what is written is removed.
            $after = [ordered]@{}
            foreach ($parameter in $before.PSObject.Properties) {
                $after[$parameter.Name] = "$($parameter.Value)"
            }
            foreach ($parameter in $item.Values.Keys) {
                $old = "$(Get-MoseProperty $before $parameter)"
                $new = $item.Values[$parameter]
                if ($old -ceq $new) {
                    continue
                }
                if ($new) {
                    $after[$parameter] = $new
                }
                else {
                    $after.Remove($parameter)
                }
                $changes.Add([pscustomobject]@{ Column = $Import.ColumnOf[$parameter]; Key = $parameter; Field = $false; Before = $old; After = $new })
            }
            if ($changes.Count -eq 0) {
                $unchanged++
                continue
            }
            $connection = Invoke-RestMethod -Method GET -Uri "$($Session.Api)/connections/$($item.ID)" -Headers $Session.Headers
            $plans.Add([pscustomobject]@{ ID = $item.ID; Name = "$($summary.name)"; Connection = $connection; Before = $before; After = $after; Changes = $changes.ToArray() })
        }
        catch {
            Write-Warning "$($summary.name) [$($item.ID)] could not be read, so its row is skipped: $($_.Exception.Message)"
            $skipped++
        }
    }
    $sorted = @($plans | Sort-Object Name, { "$($_.ID)".PadLeft(10, '0') })
    return [pscustomobject]@{ Plans = $sorted; Unchanged = $unchanged; Skipped = $skipped }
}

# The changes as a list: the connection, the CSV column, what Keeper has now and what the CSV says.
function Get-ImportPreview {
    param(
        [object[]]$Plans
    )

    foreach ($plan in $Plans) {
        foreach ($change in $plan.Changes) {
            $old = if ($change.Before) { $change.Before } else { '(not set)' }
            $new = if ($change.After) { $change.After } else { '(not set)' }
            [pscustomobject]@{ Name = $plan.Name; ID = $plan.ID; Column = $change.Column; 'In Keeper now' = $old; 'From the CSV' = $new }
        }
    }
}

# Writes the connections planned, after a backup of them as Keeper has them now, and reads each one
# again to check it.
function Write-ImportPlans {
    param(
        [object]$Session,
        [object[]]$Plans,
        [scriptblock]$Progress
    )

    # With all their parameters, before anything is written. It may hold their passwords, so git
    # ignores it.
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $backupPath = Join-Path $PSScriptRoot "KCM-RDP-Backup_$stamp.json"
    # Never over an earlier backup.
    for ($number = 2; Test-Path -LiteralPath $backupPath; $number++) {
        $backupPath = Join-Path $PSScriptRoot "KCM-RDP-Backup_${stamp}_$number.json"
    }
    $backup = [pscustomobject]@{
        Url         = $Session.Url
        DataSource  = $Session.DataSource
        Saved       = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Connections = @($Plans | ForEach-Object { [pscustomobject]@{ Connection = $_.Connection; Parameters = $_.Before } })
    }
    ConvertTo-Json -InputObject $backup -Depth 10 | Set-Content -LiteralPath $backupPath -Encoding UTF8
    Write-Host "Backup of the $($Plans.Count) connection(s) as they are now: $backupPath" -ForegroundColor Green

    $failed = 0
    foreach ($plan in $Plans) {
        if ($Progress) {
            & $Progress "Writing $($plan.Name) [$($plan.ID)]..."
        }
        # The connection as Keeper gave it, with all its parameters: PUT replaces them all.
        $body = [ordered]@{}
        foreach ($property in $plan.Connection.PSObject.Properties) {
            if ($property.Name -notin 'activeConnections', 'lastActive') {
                $body[$property.Name] = $property.Value
            }
        }
        # Its new name and folder, if the CSV changes them.
        foreach ($change in @($plan.Changes | Where-Object { $_.Field })) {
            $body[$change.Key] = $change.After
        }
        $body['parameters'] = $plan.After
        $json = ConvertTo-Json -InputObject $body -Depth 10
        try {
            Invoke-RestMethod -Method PUT -Uri "$($Session.Api)/connections/$($plan.ID)" -Headers $Session.Headers `
                -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json)) | Out-Null
            # Read again: the values as asked, and no other parameter lost.
            $check = Invoke-RestMethod -Method GET -Uri "$($Session.Api)/connections/$($plan.ID)/parameters" -Headers $Session.Headers
            $wrong = @($plan.Changes | Where-Object { -not $_.Field -and "$(Get-MoseProperty $check $_.Key)" -cne $_.After } | ForEach-Object { $_.Column })
            $fieldChanges = @($plan.Changes | Where-Object { $_.Field })
            if ($fieldChanges.Count -gt 0) {
                $checkConnection = Invoke-RestMethod -Method GET -Uri "$($Session.Api)/connections/$($plan.ID)" -Headers $Session.Headers
                $wrong += @($fieldChanges | Where-Object { "$(Get-MoseProperty $checkConnection $_.Key)" -cne $_.After } | ForEach-Object { $_.Column })
            }
            $lost = @($plan.After.Keys | Where-Object { -not $check.PSObject.Properties[$_] })
            if ($wrong.Count -gt 0 -or $lost.Count -gt 0) {
                Write-Warning "$($plan.Name) [$($plan.ID)] was written, but Keeper now shows other values for: $(@($wrong + $lost | Sort-Object -Unique) -join ', '). Compare it with the backup."
                $failed++
            }
            else {
                Write-Host "Updated $($plan.Name) [$($plan.ID)]." -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "$($plan.Name) [$($plan.ID)] could not be written: $($_.Exception.Message)"
            $failed++
        }
    }
    return [pscustomobject]@{ Backup = $backupPath; Updated = $Plans.Count - $failed; Failed = $failed }
}

# The import with questions in the console.
function Import-KeeperConnections {
    $file = $Path
    if (-not $file) {
        $file = Select-ImportCsv
    }
    $csv = Read-ImportCsv -File $file
    $rows = $csv.Rows

    # Some rows only: the ID is the one thing that is unique, names repeat.
    $selection = "$($Id -join ',')".Trim()
    if (-not $Id) {
        Write-Host "IDs in the CSV: $(Format-IdRanges @($rows | ForEach-Object { "$($_.ID)".Trim() }))" -ForegroundColor DarkGray
        $selection = "$(Read-Host -Prompt "IDs to import (44, or 40-50,60; Enter for all $($rows.Count))")".Trim()
    }
    if ($selection -and $selection -ne '*') {
        $rows = @(Select-DriveRows -Rows $rows -Selection $selection)
        Write-Host "$($rows.Count) row(s) picked: IDs $(Format-IdRanges @($rows | ForEach-Object { "$($_.ID)".Trim() }))." -ForegroundColor DarkGray
    }
    $import = ConvertTo-ImportItems -Rows $rows -Imported $csv.Imported
    # The ID says which connection a row is; every other column of the CSV is written to it.
    Write-Host "$($rows.Count) row(s) of $($csv.File) to import. Columns imported: $($csv.Imported -join ', ')." -ForegroundColor DarkGray

    $kcm = Connect-Kcm
    $result = Get-ImportPlans -Session $kcm -Import $import
    $plans = @($result.Plans)
    $counts = "$($result.Unchanged) already as in the CSV, $($result.Skipped) skipped"
    if ($plans.Count -eq 0) {
        Write-Host "Nothing to change: $counts." -ForegroundColor Green
        if ($result.Unchanged -gt 0) {
            Write-Host "Keeper already has every value of these columns for the rows picked: $($csv.Imported -join ', ')." -ForegroundColor Yellow
        }
        return
    }
    Write-Host (Get-ImportPreview -Plans $plans | Format-Table -AutoSize -Wrap | Out-String).TrimEnd()
    Write-Host "All the columns are imported ($($csv.Imported -join ', ')); only the values that differ from Keeper are listed, the others are already the same." -ForegroundColor DarkGray
    Write-Host "$($plans.Count) connection(s) to change, $counts." -ForegroundColor Cyan

    # Nothing is written before this answer. A and F, the answers of earlier versions, still work.
    $first = $plans[0]
    if ($plans.Count -eq 1) {
        $answer = "$(Read-Host -Prompt "Nothing is written yet. Write the values above to $($first.Name) [$($first.ID)] in Keeper now? Y: yes, Enter: no")".Trim()
        # @() around the if: the value of an if is unrolled, one connection or none would be no list.
        $toWrite = @(if ($answer -match '^(y|o|j|a|f)') { $first })
    }
    else {
        Write-Host 'Nothing is written yet. Answer:'
        Write-Host "  Y      write the changes above to the $($plans.Count) connections"
        Write-Host "  1      write only $($first.Name) [$($first.ID)], to check it in Keeper first; import again afterwards for the others"
        Write-Host '  Enter  write nothing'
        $answer = "$(Read-Host -Prompt 'Your answer')".Trim()
        $toWrite = @(if ($answer -match '^(y|o|j|a)') { $plans } elseif ($answer -match '^(1|f)') { $first })
    }
    if ($toWrite.Count -eq 0) {
        Write-Host 'Nothing was written.'
        return
    }

    $written = Write-ImportPlans -Session $kcm -Plans $toWrite
    Write-Host "$($written.Updated) connection(s) updated, $($written.Failed) failed. Backup: $($written.Backup)" -ForegroundColor Cyan
    if ($toWrite.Count -lt $plans.Count) {
        Write-Host "Check $($first.Name) [$($first.ID)] in Keeper, then import the CSV again and answer Y: the connections already changed are left as they are." -ForegroundColor Yellow
    }
}

# Rows as a table the window's grids show. PowerShell lists a DataTable's rows instead of returning
# it, hence the comma.
function ConvertTo-KcmTable {
    param(
        [object[]]$Rows
    )

    $table = New-Object System.Data.DataTable
    if ($Rows.Count -gt 0) {
        foreach ($property in $Rows[0].PSObject.Properties) {
            [void]$table.Columns.Add($property.Name)
        }
        foreach ($row in $Rows) {
            $line = $table.NewRow()
            foreach ($property in $row.PSObject.Properties) {
                $line[$property.Name] = "$($property.Value)"
            }
            $table.Rows.Add($line)
        }
    }
    return , $table
}

# The window: the steps of the questions above as fields and buttons. Nothing is written before Write
# and its confirmation.
function Show-KeeperWindow {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    # What the window knows. A hashtable, so that the event handlers, which run in scopes of their
    # own, change it: the session, the known managers, the CSVs found, the CSV read, the changes
    # previewed, the last export.
    $ui = @{ Session = $null; Known = @(); CsvFiles = @(); Csv = $null; Plans = @(); Export = ''; Busy = $false; Loading = $false }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'MOSE Keeper import/export'
    $form.Size = New-Object System.Drawing.Size(940, 760)
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    # Controls are docked in reverse order of adding: the tabs fill what the others leave.
    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = 'Fill'
    $form.Controls.Add($tabs)

    $log = New-Object System.Windows.Forms.TextBox
    $log.Multiline = $true
    $log.ReadOnly = $true
    $log.ScrollBars = 'Vertical'
    $log.Dock = 'Bottom'
    $log.Height = 150
    $log.Font = New-Object System.Drawing.Font('Consolas', 9)
    $log.BackColor = [System.Drawing.SystemColors]::Window
    $form.Controls.Add($log)

    $status = New-Object System.Windows.Forms.Label
    $status.Dock = 'Bottom'
    $status.Height = 22
    $status.TextAlign = 'MiddleLeft'
    $form.Controls.Add($status)

    $box = New-Object System.Windows.Forms.GroupBox
    $box.Text = 'Keeper Connection Manager'
    $box.Dock = 'Top'
    $box.Height = 132
    $form.Controls.Add($box)

    function New-KcmLabel {
        param([object]$Parent, [string]$Text, [int]$X, [int]$Y, [int]$Width = 80)
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $Text
        $label.Location = New-Object System.Drawing.Point($X, $Y)
        $label.Size = New-Object System.Drawing.Size($Width, 20)
        $Parent.Controls.Add($label)
        return $label
    }

    function New-KcmButton {
        param([object]$Parent, [string]$Text, [int]$X, [int]$Y, [int]$Width = 160)
        $button = New-Object System.Windows.Forms.Button
        $button.Text = $Text
        $button.Location = New-Object System.Drawing.Point($X, $Y)
        $button.Size = New-Object System.Drawing.Size($Width, 26)
        $Parent.Controls.Add($button)
        return $button
    }

    function New-KcmGrid {
        $grid = New-Object System.Windows.Forms.DataGridView
        $grid.Dock = 'Fill'
        $grid.ReadOnly = $true
        $grid.AllowUserToAddRows = $false
        $grid.AllowUserToDeleteRows = $false
        $grid.RowHeadersVisible = $false
        $grid.SelectionMode = 'FullRowSelect'
        $grid.AutoSizeColumnsMode = 'AllCells'
        $grid.BackgroundColor = [System.Drawing.SystemColors]::Window
        return $grid
    }

    [void](New-KcmLabel $box 'Address' 12 26)
    $address = New-Object System.Windows.Forms.ComboBox
    $address.Location = New-Object System.Drawing.Point(96, 22)
    $address.Width = 480
    $box.Controls.Add($address)
    [void](New-KcmLabel $box 'Data source' 596 26)
    $source = New-Object System.Windows.Forms.TextBox
    $source.Location = New-Object System.Drawing.Point(680, 22)
    $source.Width = 110
    $box.Controls.Add($source)

    [void](New-KcmLabel $box 'Token' 12 58)
    $token = New-Object System.Windows.Forms.TextBox
    $token.Location = New-Object System.Drawing.Point(96, 54)
    $token.Width = 480
    $token.UseSystemPasswordChar = $true
    $box.Controls.Add($token)
    $connect = New-KcmButton $box 'Connect' 596 52 194
    [void](New-KcmLabel $box 'Sign in to the address in the browser, then copy the Guacamole-Token header of a request to /api (F12, Network). It is never saved.' 96 82 820)
    $connected = New-KcmLabel $box 'Not connected.' 12 104 900

    $exportPage = New-Object System.Windows.Forms.TabPage
    $exportPage.Text = 'Export'
    $tabs.TabPages.Add($exportPage)
    $exportGrid = New-KcmGrid
    $exportPage.Controls.Add($exportGrid)
    $exportBar = New-Object System.Windows.Forms.Panel
    $exportBar.Dock = 'Top'
    $exportBar.Height = 64
    $exportPage.Controls.Add($exportBar)
    $exportButton = New-KcmButton $exportBar 'Export the RDP connections' 8 8 220
    $openButton = New-KcmButton $exportBar 'Open the CSV' 236 8 140
    $exportInfo = New-KcmLabel $exportBar 'The RDP connections with their drive settings, written to a CSV next to the scripts.' 8 40 880
    $exportInfo.Anchor = 'Top, Left, Right'

    $importPage = New-Object System.Windows.Forms.TabPage
    $importPage.Text = 'Import'
    $tabs.TabPages.Add($importPage)
    $previewGrid = New-KcmGrid
    $importPage.Controls.Add($previewGrid)
    $writeBar = New-Object System.Windows.Forms.Panel
    $writeBar.Dock = 'Bottom'
    $writeBar.Height = 78
    $importPage.Controls.Add($writeBar)
    # Two lines, and as wide as the window: the long texts are not cut.
    $previewInfo = New-KcmLabel $writeBar '' 8 4 880
    $previewInfo.Height = 34
    $previewInfo.Anchor = 'Top, Left, Right'
    $writeAll = New-KcmButton $writeBar 'Write all' 8 42 160
    $writeFirst = New-KcmButton $writeBar 'Write the first only' 176 42 180
    $importBar = New-Object System.Windows.Forms.Panel
    $importBar.Dock = 'Top'
    $importBar.Height = 116
    $importPage.Controls.Add($importBar)
    [void](New-KcmLabel $importBar 'CSV' 8 12 50)
    $csvBox = New-Object System.Windows.Forms.ComboBox
    $csvBox.DropDownStyle = 'DropDownList'
    $csvBox.Location = New-Object System.Drawing.Point(60, 8)
    $csvBox.Width = 640
    $importBar.Controls.Add($csvBox)
    $browse = New-KcmButton $importBar 'Browse...' 710 7 100
    $csvInfo = New-KcmLabel $importBar 'Pick the CSV to import: yours, not an export, which only holds what Keeper had.' 60 38 820
    $csvInfo.Height = 34
    $csvInfo.Anchor = 'Top, Left, Right'
    [void](New-KcmLabel $importBar 'IDs' 8 86 50)
    $ids = New-Object System.Windows.Forms.TextBox
    $ids.Location = New-Object System.Drawing.Point(60, 82)
    $ids.Width = 200
    $importBar.Controls.Add($ids)
    [void](New-KcmLabel $importBar '44, or 40-50,60; empty for all the rows' 270 86 260)
    $preview = New-KcmButton $importBar 'Preview the changes' 560 80 180

    $addLog = {
        param([string]$Text)
        $log.AppendText("$Text`r`n")
    }
    $tell = {
        param([string]$Text, [string]$Icon = 'Information')
        [void][System.Windows.Forms.MessageBox]::Show($form, $Text, 'Keeper', 'OK', $Icon)
    }
    $confirm = {
        param([string]$Text)
        return [System.Windows.Forms.MessageBox]::Show($form, $Text, 'Keeper', 'YesNo', 'Question') -eq 'Yes'
    }
    # The status line during a long step; the clicks meanwhile are ignored (Busy).
    $progress = {
        param([string]$Text)
        $status.Text = $Text
        [System.Windows.Forms.Application]::DoEvents()
    }
    # Runs a step: its messages and warnings in the log, its error in the log and a message.
    $run = {
        param([scriptblock]$Step)
        if ($ui.Busy) {
            return
        }
        $ui.Busy = $true
        $form.UseWaitCursor = $true
        [System.Windows.Forms.Application]::DoEvents()
        try {
            # Through the pipeline, so that the messages before an error reach the log too.
            & $Step 3>&1 6>&1 | ForEach-Object {
                if ($_ -is [System.Management.Automation.WarningRecord]) {
                    & $addLog "WARNING: $($_.Message)"
                }
                elseif ($_ -is [System.Management.Automation.InformationRecord]) {
                    & $addLog "$($_.MessageData)"
                }
            }
        }
        catch {
            & $addLog "ERROR: $($_.Exception.Message)"
            & $tell $_.Exception.Message 'Error'
        }
        finally {
            $ui.Busy = $false
            $form.UseWaitCursor = $false
            $status.Text = ''
        }
    }
    $setButtons = {
        $exportButton.Enabled = [bool]$ui.Session
        $openButton.Enabled = [bool]$ui.Export
        $preview.Enabled = [bool]$ui.Session -and [bool]$ui.Csv
        $writeAll.Enabled = $ui.Plans.Count -gt 0
        $writeFirst.Enabled = $ui.Plans.Count -gt 1
    }
    # A change of the CSV, the IDs or the connection: the changes must be previewed again.
    $clearPlans = {
        $ui.Plans = @()
        $previewGrid.DataSource = $null
        $previewInfo.Text = 'Click Preview the changes: nothing is written before you click Write.'
        & $setButtons
    }
    $disconnect = {
        if ($ui.Loading -or -not $ui.Session) {
            return
        }
        $ui.Session = $null
        $connected.Text = 'Not connected: click Connect.'
        & $clearPlans
    }
    $loadCsvList = {
        $selected = if ($ui.Csv) { $ui.Csv.File } else { '' }
        $ui.Loading = $true
        try {
            $ui.CsvFiles = @(Find-ImportCsv)
            $csvBox.Items.Clear()
            foreach ($file in $ui.CsvFiles) {
                [void]$csvBox.Items.Add((Format-CsvChoice $file))
            }
            for ($i = 0; $i -lt $ui.CsvFiles.Count; $i++) {
                if ($ui.CsvFiles[$i].FullName -eq $selected) {
                    $csvBox.SelectedIndex = $i
                }
            }
        }
        finally {
            $ui.Loading = $false
        }
    }
    $doPreview = {
        & $clearPlans
        & $run {
            $rows = $ui.Csv.Rows
            $selection = $ids.Text.Trim()
            if ($selection -and $selection -ne '*') {
                $rows = @(Select-DriveRows -Rows $rows -Selection $selection)
            }
            $import = ConvertTo-ImportItems -Rows $rows -Imported $ui.Csv.Imported
            $result = Get-ImportPlans -Session $ui.Session -Import $import -Progress $progress
            $ui.Plans = @($result.Plans)
            $previewGrid.DataSource = ConvertTo-KcmTable @(Get-ImportPreview -Plans $ui.Plans)
            $counts = "$($result.Unchanged) already as in the CSV, $($result.Skipped) skipped (see the log)"
            if ($ui.Plans.Count -gt 0) {
                $previewInfo.Text = "$($ui.Plans.Count) connection(s) to change out of $($rows.Count) row(s), $counts. Only the values that differ from Keeper are listed. Nothing is written yet."
            }
            else {
                $previewInfo.Text = "Nothing to change in the $($rows.Count) row(s): $counts."
            }
            Write-Host $previewInfo.Text
        }
        & $setButtons
    }
    $write = {
        param([bool]$FirstOnly)
        $toWrite = @(if ($FirstOnly) { $ui.Plans[0] } else { $ui.Plans })
        $which = if ($toWrite.Count -eq 1) { "$($toWrite[0].Name) [$($toWrite[0].ID)]" } else { "the $($toWrite.Count) connections" }
        if (-not (& $confirm "Write the values listed to $which in $($ui.Session.Url)?`r`n`r`nA backup of them as they are now is saved first.")) {
            return
        }
        & $run {
            $written = Write-ImportPlans -Session $ui.Session -Plans $toWrite -Progress $progress
            $done = "$($written.Updated) connection(s) updated, $($written.Failed) failed. Backup: $($written.Backup)"
            Write-Host $done
            & $tell $done
        }
        # What is left to write, read again from Keeper.
        & $doPreview
    }

    $address.Add_SelectedIndexChanged({
            if ($address.SelectedIndex -ge 0 -and $address.SelectedIndex -lt $ui.Known.Count) {
                $source.Text = $ui.Known[$address.SelectedIndex].DataSource
            }
        })
    $address.Add_TextChanged({ & $disconnect })
    $source.Add_TextChanged({ & $disconnect })
    $token.Add_TextChanged({ & $disconnect })
    $connect.Add_Click({
            $ui.Session = $null
            & $clearPlans
            & $run {
                $ui.Session = Connect-KcmApi -Address $address.Text -Source $source.Text -PlainToken $token.Text
                $connected.Text = "Connected to $($ui.Session.Url), data source $($ui.Session.DataSource): $($ui.Session.Count) connection(s)."
                Write-Host $connected.Text
            }
            if (-not $ui.Session) {
                $connected.Text = 'Not connected.'
            }
            & $setButtons
        })
    $exportButton.Add_Click({
            & $run {
                $rows = @(Get-KcmRows -Session $ui.Session -Progress $progress)
                $exportGrid.DataSource = ConvertTo-KcmTable $rows
                if ($rows.Count -eq 0) {
                    Write-Warning "$($ui.Session.Url) has no RDP connection in data source $($ui.Session.DataSource)."
                    return
                }
                $ui.Export = Save-KcmExport -Rows $rows
                # The file name only here: the whole path is in the log.
                $exportInfo.Text = "$($rows.Count) RDP connection(s) written to $(Split-Path -Leaf $ui.Export), next to the scripts."
                Write-Host "$($rows.Count) RDP connection(s) written to $($ui.Export)"
                & $loadCsvList
            }
            & $setButtons
        })
    $openButton.Add_Click({
            if ($ui.Export) {
                Invoke-Item -LiteralPath $ui.Export
            }
        })
    $csvBox.Add_SelectedIndexChanged({
            if ($ui.Loading -or $csvBox.SelectedIndex -lt 0) {
                return
            }
            $ui.Csv = $null
            & $clearPlans
            & $run {
                $ui.Csv = Read-ImportCsv -File $ui.CsvFiles[$csvBox.SelectedIndex].FullName
                $csvInfo.Text = "$($ui.Csv.Rows.Count) rows, IDs $(Format-IdRanges @($ui.Csv.Rows | ForEach-Object { "$($_.ID)".Trim() })). Columns imported: $($ui.Csv.Imported -join ', ')."
            }
            if (-not $ui.Csv) {
                $csvInfo.Text = 'This CSV cannot be imported: see the log.'
            }
            & $setButtons
        })
    $browse.Add_Click({
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.Filter = 'CSV (*.csv)|*.csv|All files (*.*)|*.*'
            $dialog.InitialDirectory = Split-Path -Parent $PSScriptRoot
            if ($dialog.ShowDialog($form) -ne 'OK') {
                return
            }
            $file = Get-Item -LiteralPath $dialog.FileName
            $index = -1
            for ($i = 0; $i -lt $ui.CsvFiles.Count; $i++) {
                if ($ui.CsvFiles[$i].FullName -eq $file.FullName) {
                    $index = $i
                }
            }
            if ($index -lt 0) {
                $ui.CsvFiles = @($file) + @($ui.CsvFiles)
                $csvBox.Items.Insert(0, (Format-CsvChoice $file))
                $index = 0
            }
            $csvBox.SelectedIndex = $index
        })
    $ids.Add_TextChanged({ & $clearPlans })
    $preview.Add_Click({ & $doPreview })
    $writeAll.Add_Click({ & $write $false })
    $writeFirst.Add_Click({ & $write $true })

    $ui.Loading = $true
    $ui.Known = @(Get-KnownKcm)
    foreach ($kcm in $ui.Known) {
        [void]$address.Items.Add($kcm.Url)
    }
    if ($ui.Known.Count -gt 0) {
        $address.SelectedIndex = 0
    }
    $ui.Loading = $false
    & $loadCsvList
    & $clearPlans
    [void]$form.ShowDialog()
    $form.Dispose()
}

if ($Gui) {
    Show-KeeperWindow
    return
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
        Import-KeeperConnections
    }
    'Export' {
        Export-KeeperConnections
    }
}
