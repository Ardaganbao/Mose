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
    [switch]$NoOpen
)

# Imports entries into Keeper, or exports them from it, over the Keeper API. Independent of the
# report: .\Start.ps1 -Keeper, or Keeper import/export in the Script Manager.
# Export: the RDP connections of a Keeper Connection Manager (the REST API of Apache Guacamole) with
# their drive settings, shown, written to KCM-RDP-Drive-Report_<yyyy-MM-dd_HHmmss>.csv next to the
# scripts and opened. It names the client's servers, so git ignores it like the report.
# Import: the drive settings of such a CSV, edited in Excel for example, written to the connections of
# its ID column, all of them or those picked by ID (44, or 40-50,60). Only its drive columns are written; Name, ParentID and Hostname only say which
# connection a row is, and a row whose name is not the connection's is skipped. The changes are shown
# first, then written to all connections or to the first one only, after a backup of them in
# KCM-RDP-Backup_<yyyy-MM-dd_HHmmss>.json.
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

# Asks for the Keeper Connection Manager and the token, and reads its connections: one property per
# connection, named after its identifier.
function Connect-Kcm {
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
    # Offered first next time, now that it answered.
    Save-KnownKcm $kcm
    return [pscustomobject]@{ Url = $kcm.Url; DataSource = $kcm.DataSource; Api = $api; Headers = $headers; Connections = $connections }
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

function Export-KeeperConnections {
    $kcm = Connect-Kcm

    $rows = @(foreach ($property in $kcm.Connections.PSObject.Properties) {
            $summary = $property.Value
            if ("$(Get-MoseProperty $summary 'protocol')" -ne 'rdp') {
                continue
            }

            Write-Host "Reading $($summary.name) [$($summary.identifier)]..." -ForegroundColor DarkGray
            try {
                # Only the parameters, as flat properties: hostname, enable-drive...
                $parameters = Invoke-RestMethod -Method GET -Uri "$($kcm.Api)/connections/$($summary.identifier)/parameters" -Headers $kcm.Headers

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

# Writes the drive settings of a CSV laid out like the export to the connections of its ID column.
function Import-KeeperConnections {
    $file = $Path
    if (-not $file) {
        $latest = Get-ChildItem -Path (Join-Path $PSScriptRoot 'KCM-RDP-Drive-Report_*.csv') -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        # The last export, for an export edited and saved again in Excel.
        $prompt = if ($latest) { "Path of the CSV to import (Enter for the last export, $($latest.Name))" } else { 'Path of the CSV to import' }
        $file = "$(Read-Host -Prompt $prompt)".Trim().Trim('"')
        if (-not $file -and $latest) {
            $file = $latest.FullName
        }
    }
    if (-not $file) {
        throw 'No CSV was given.'
    }
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "There is no file $file."
    }
    # A relative path is from PowerShell's folder, which .NET, reading the file, doesn't know.
    $file = (Resolve-Path -LiteralPath $file).ProviderPath

    # The whole CSV is checked before Keeper is asked anything.
    $rows = @(Read-DriveCsv $file)
    if ($rows.Count -eq 0) {
        throw "$file has no rows."
    }
    $columns = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name })
    if ($columns -notcontains 'ID') {
        throw "$file has no ID column, which says the connection of each row: start from an export."
    }
    $changed = @($DriveFields.Keys | Where-Object { $columns -contains $_ })
    if ($changed.Count -eq 0) {
        throw "$file has none of the drive columns: $(@($DriveFields.Keys) -join ', ')."
    }
    $noId = @($rows | Where-Object { -not "$($_.ID)".Trim() })
    if ($noId.Count -gt 0) {
        throw "$($noId.Count) row(s) of $file have no ID: each row must say the connection it changes."
    }
    $twice = @($rows | Group-Object { "$($_.ID)".Trim() } | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    if ($twice.Count -gt 0) {
        throw "These IDs are on more than one row of ${file}: $($twice -join ', ')."
    }

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
    $wanted = @(foreach ($row in $rows) {
            $values = [ordered]@{}
            foreach ($column in $changed) {
                $value = "$($row.$column)".Trim()
                if ($DriveFields[$column].YesNo) {
                    $value = ConvertTo-KcmYesNo -Value $value -Where "ID $($row.ID), column $column"
                }
                $values[$DriveFields[$column].Parameter] = $value
            }
            [pscustomobject]@{ ID = "$($row.ID)".Trim(); Name = "$(Get-MoseProperty $row 'Name')".Trim(); Values = $values }
        })
    # Name, ParentID and Hostname only say which connection a row is.
    Write-Host "$($rows.Count) row(s) of $file to import. Columns written: $($changed -join ', ')." -ForegroundColor DarkGray

    $kcm = Connect-Kcm
    $plans = New-Object System.Collections.Generic.List[object]
    $unchanged = 0
    $skipped = 0
    foreach ($item in $wanted) {
        $summary = Get-MoseProperty $kcm.Connections $item.ID
        if (-not $summary) {
            Write-Warning "$($kcm.Url) has no connection $($item.ID): its row is skipped."
            $skipped++
            continue
        }
        if ($item.Name -and $item.Name -ne "$($summary.name)") {
            Write-Warning "Connection $($item.ID) is $($summary.name) in Keeper, not $($item.Name): its row is skipped, in case its ID is wrong."
            $skipped++
            continue
        }
        if ("$(Get-MoseProperty $summary 'protocol')" -ne 'rdp') {
            Write-Warning "$($summary.name) [$($item.ID)] is not an RDP connection: its row is skipped."
            $skipped++
            continue
        }
        try {
            $before = Invoke-RestMethod -Method GET -Uri "$($kcm.Api)/connections/$($item.ID)/parameters" -Headers $kcm.Headers
            # All its parameters, then the CSV's: a parameter left out of what is written is removed.
            $after = [ordered]@{}
            foreach ($parameter in $before.PSObject.Properties) {
                $after[$parameter.Name] = "$($parameter.Value)"
            }
            $changes = @(foreach ($parameter in $item.Values.Keys) {
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
                    [pscustomobject]@{ Parameter = $parameter; Before = $old; After = $new }
                })
            if ($changes.Count -eq 0) {
                $unchanged++
                continue
            }
            $connection = Invoke-RestMethod -Method GET -Uri "$($kcm.Api)/connections/$($item.ID)" -Headers $kcm.Headers
            $plans.Add([pscustomobject]@{ ID = $item.ID; Name = "$($summary.name)"; Connection = $connection; Before = $before; After = $after; Changes = $changes })
        }
        catch {
            Write-Warning "$($summary.name) [$($item.ID)] could not be read, so its row is skipped: $($_.Exception.Message)"
            $skipped++
        }
    }

    $counts = "$unchanged already as in the CSV, $skipped skipped"
    if ($plans.Count -eq 0) {
        Write-Host "Nothing to change: $counts." -ForegroundColor Green
        if ($unchanged -gt 0) {
            Write-Host "Keeper already has the drive settings of $file. To change them, edit its drive columns first, or give the path of the CSV you edited." -ForegroundColor Yellow
        }
        return
    }
    $plans = @($plans | Sort-Object Name, { "$($_.ID)".PadLeft(10, '0') })
    $preview = foreach ($plan in $plans) {
        foreach ($change in $plan.Changes) {
            $old = if ($change.Before) { $change.Before } else { '(not set)' }
            $new = if ($change.After) { $change.After } else { '(not set)' }
            [pscustomobject]@{ Name = $plan.Name; ID = $plan.ID; Parameter = $change.Parameter; Before = $old; After = $new }
        }
    }
    Write-Host ($preview | Format-Table -AutoSize -Wrap | Out-String).TrimEnd()
    Write-Host "$($plans.Count) connection(s) to change, $counts." -ForegroundColor Cyan

    # Nothing is written before this answer. A and F, the answers of earlier versions, still work.
    $first = $plans[0]
    if ($plans.Count -eq 1) {
        $answer = "$(Read-Host -Prompt "Nothing is written yet. Write the change above to $($first.Name) [$($first.ID)] in Keeper now? Y: yes, Enter: no")".Trim()
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

    # Each connection as Keeper has it now, with all its parameters, before anything is written. It
    # may hold their passwords, so git ignores it.
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $backupPath = Join-Path $PSScriptRoot "KCM-RDP-Backup_$stamp.json"
    # Never over an earlier backup.
    for ($number = 2; Test-Path -LiteralPath $backupPath; $number++) {
        $backupPath = Join-Path $PSScriptRoot "KCM-RDP-Backup_${stamp}_$number.json"
    }
    $backup = [pscustomobject]@{
        Url         = $kcm.Url
        DataSource  = $kcm.DataSource
        Saved       = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Connections = @($toWrite | ForEach-Object { [pscustomobject]@{ Connection = $_.Connection; Parameters = $_.Before } })
    }
    ConvertTo-Json -InputObject $backup -Depth 10 | Set-Content -LiteralPath $backupPath -Encoding UTF8
    Write-Host "Backup of the $($toWrite.Count) connection(s) as they are now: $backupPath" -ForegroundColor Green

    $failed = 0
    foreach ($plan in $toWrite) {
        # The connection as Keeper gave it, with all its parameters: PUT replaces them all.
        $body = [ordered]@{}
        foreach ($property in $plan.Connection.PSObject.Properties) {
            if ($property.Name -notin 'activeConnections', 'lastActive') {
                $body[$property.Name] = $property.Value
            }
        }
        $body['parameters'] = $plan.After
        $json = ConvertTo-Json -InputObject $body -Depth 10
        try {
            Invoke-RestMethod -Method PUT -Uri "$($kcm.Api)/connections/$($plan.ID)" -Headers $kcm.Headers `
                -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json)) | Out-Null
            # Read again: the drive settings as asked, and no other parameter lost.
            $check = Invoke-RestMethod -Method GET -Uri "$($kcm.Api)/connections/$($plan.ID)/parameters" -Headers $kcm.Headers
            $wrong = @($plan.Changes | Where-Object { "$(Get-MoseProperty $check $_.Parameter)" -cne $_.After } | ForEach-Object { $_.Parameter })
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

    Write-Host "$($toWrite.Count - $failed) connection(s) updated, $failed failed. Backup: $backupPath" -ForegroundColor Cyan
    if ($toWrite.Count -lt $plans.Count) {
        Write-Host "Check $($first.Name) [$($first.ID)] in Keeper, then import the CSV again and answer Y: the connections already changed are left as they are." -ForegroundColor Yellow
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
        Import-KeeperConnections
    }
    'Export' {
        Export-KeeperConnections
    }
}
