[CmdletBinding()]
param(
    # Set by Report.ps1, which has already unlocked the vault.
    [Parameter(DontShow)]
    [switch]$VaultUnlocked
)

# Asks for the client of this computer: its name, then the servers of each module and their
# credentials. Everything is saved in the SecretStore vault, never in the scripts.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'helper.ps1')

if (-not $VaultUnlocked) {
    Open-MoseVault
}

function Read-Answer {
    param(
        [string]$Prompt,
        [string]$Default = ''
    )

    if ($Default) {
        $Prompt = "$Prompt [$Default]"
    }
    $answer = "$(Read-Host -Prompt $Prompt)".Trim()
    if ($answer) {
        return $answer
    }
    return $Default
}

# Returns the name of the secret holding the login for one server, or $null when cancelled.
function Read-TargetCredential {
    param(
        [string]$Module,
        [string]$Server
    )

    # Servers of one kind often share a login, e.g. every iLO of a cluster.
    $previous = @($targets | Where-Object { $_.Module -eq $Module -and $_.Secret } | Select-Object -Last 1)
    if ($previous.Count -gt 0 -and (Read-YesNo "Same user and password as $($previous[0].Server)?")) {
        return $previous[0].Secret
    }

    $secretName = "MOSE:${Module}:$Server"
    if (Get-SecretInfo -Vault $MoseVaultName -Name $secretName -ErrorAction SilentlyContinue) {
        $saved = Get-Secret -Vault $MoseVaultName -Name $secretName
        if ($saved -is [pscredential] -and (Read-YesNo "Use the login already saved for $Server ($($saved.UserName))?")) {
            return $secretName
        }
    }

    $credential = Get-Credential -Message "$($MoseModules[$Module].Label) $Server"
    if (-not $credential) {
        return $null
    }
    Set-Secret -Vault $MoseVaultName -Name $secretName -Secret $credential
    return $secretName
}

# Returns the name of the secret holding the Commvault tokens, or $null when cancelled.
function Read-CommvaultSecret {
    param(
        [ValidateSet('Cloud', 'OnPrem')]
        [string]$Mode
    )

    # Tokens already in the vault (e.g. saved by an older report script) are reused,
    # which keeps a Cloud token chain and its weekly renewal going.
    $used = @($targets | ForEach-Object { $_.Secret })
    foreach ($name in @(Get-CommvaultSecretNames -Mode $Mode | Where-Object { $used -notcontains $_ })) {
        if (Read-YesNo "Use the Commvault $Mode tokens already saved in '$name'?") {
            return $name
        }
    }

    $count = @($targets | Where-Object { $_.Module -eq "Commvault$Mode" }).Count
    $secretName = "MOSE:Commvault${Mode}:$($count + 1)"

    if ($Mode -eq 'Cloud') {
        $accessToken = Read-Host -Prompt 'Commvault Cloud ACCESS token' -AsSecureString
        $refreshToken = Read-Host -Prompt 'Commvault Cloud REFRESH token' -AsSecureString
        $ring = Read-Answer 'Commvault Cloud ring ID (e.g. m108)'
        if ($accessToken.Length -eq 0 -or $refreshToken.Length -eq 0 -or -not $ring) {
            return $null
        }
        $secret = @{ Type = 'Cloud'; AccessToken = $accessToken; RefreshToken = $refreshToken; Ring = $ring }
    }
    else {
        $accessToken = Read-Host -Prompt 'Commvault on-premises ACCESS token' -AsSecureString
        $server = Read-Answer 'Commvault Command Center URL (e.g. https://commvault.example.com)'
        if ($accessToken.Length -eq 0 -or -not $server) {
            return $null
        }
        $secret = @{ Type = 'OnPrem'; AccessToken = $accessToken; Server = $server }
    }

    Set-Secret -Vault $MoseVaultName -Name $secretName -Secret $secret
    return $secretName
}

# Asks for one server of a module; returns $null when it is skipped.
function Read-Target {
    param(
        [string]$Module,
        [string]$Title
    )

    $label = $MoseModules[$Module].Label

    if ($Module -like 'Commvault*') {
        $secret = Read-CommvaultSecret -Mode ($Module -replace '^Commvault', '')
        if (-not $secret) {
            Write-Host "Skipped: the tokens were incomplete." -ForegroundColor Yellow
            return $null
        }
        return [pscustomobject]@{ Module = $Module; Server = ''; Secret = $secret }
    }

    $default = if ($Module -eq 'Veeam') { 'localhost' } else { '' }
    $server = Read-Answer "$Title - IP address or host name (Enter to skip)" $default
    if (-not $server) {
        return $null
    }
    if (@($targets | Where-Object { $_.Module -eq $Module -and $_.Server -eq $server }).Count -gt 0) {
        Write-Host "Skipped: $label $server is already configured." -ForegroundColor Yellow
        return $null
    }

    $target = [pscustomobject]@{ Module = $Module; Server = $server; Secret = '' }

    # Veeam and Hyper-V run as the current Windows user unless another account is given for PowerShell remoting,
    # which an IP address needs, as well as being in TrustedHosts.
    $remotingByIP = $Module -in 'Veeam', 'HyperV' -and (Test-MoseIPAddress $server)
    if ($remotingByIP) {
        Write-Host "$server is an IP address: PowerShell remoting needs a login for it, and the address in this computer's TrustedHosts. With the server's name instead, it needs neither." -ForegroundColor Yellow
    }
    # SQL Server: the account running the report, a SQL Server login, or another Windows account.
    $loginQuestion = if ($Module -eq 'SqlMaint') {
        "Use a SQL Server login, or another Windows account (DOMAIN\user), for ${server}? Else the account running the report"
    }
    else {
        "Use another Windows account for PowerShell remoting to ${server}?"
    }
    if ($Module -notin 'Veeam', 'HyperV', 'SqlMaint' -or $remotingByIP -or
        ($server -notin @('localhost', '.') -and (Read-YesNo $loginQuestion $false))) {
        $target.Secret = Read-TargetCredential -Module $Module -Server $server
        if (-not $target.Secret) {
            Write-Host "Skipped: no credential was entered for $label $server." -ForegroundColor Yellow
            return $null
        }
    }
    if ($remotingByIP) {
        [void](Confirm-MoseTrustedHost $server)
    }

    # Both usually have a certificate of their own; for the Veeam REST API, the report can also trust it on its first run.
    if ($Module -in 'NAS', 'VeeamApi') {
        $target | Add-Member -NotePropertyName CertificateThumbprint -NotePropertyValue (Read-Answer 'Trusted certificate SHA-1 thumbprint (Enter for the normal certificate check)')
        $target | Add-Member -NotePropertyName AcceptAnyCertificate -NotePropertyValue (Read-YesNo 'Accept any certificate? Insecure, only on a trusted network' $false)
    }
    elseif ($Module -in 'VMware', 'HyperV') {
        $target | Add-Member -NotePropertyName Site -NotePropertyValue (Read-Answer 'Site name shown in the report' 'main')
    }

    return $target
}

# True for a section of the layout that holds others (a group), false for a server or a table.
function Test-LayoutGroup {
    param(
        [object]$Section
    )

    return -not $Section.Target -and -not (Get-MoseProperty $Section 'Table')
}

# Layout entries of the report sections as the menu shows them: one entry per server, by its
# exact name, so a server added later goes at the end of the report, and one per table.
function ConvertTo-LayoutEntry {
    param(
        [object]$Section
    )

    if (Test-LayoutGroup $Section) {
        $group = [ordered]@{ Title = $Section.Title }
        if ($Section.Text) {
            $group.Text = $Section.Text
        }
        $group.Sections = @($Section.Children | ForEach-Object { ConvertTo-LayoutEntry $_ })
        if ($Section.Hide) {
            $group.Hide = $true
        }
        return [pscustomobject]$group
    }
    if ($Section.Table) {
        $entry = [ordered]@{ Table = $Section.Table }
    }
    else {
        $entry = [ordered]@{
            Module = $Section.Target.Module
            Server = [System.Management.Automation.WildcardPattern]::Escape((Get-MoseTargetName $Section.Target))
        }
    }
    if ($Section.Title) {
        $entry.Title = $Section.Title
    }
    if ($Section.Hide) {
        $entry.Hide = $true
    }
    return [pscustomobject]$entry
}

function ConvertTo-Layout {
    param(
        [System.Collections.Generic.List[object]]$Sections,
        [string]$Title,
        [string]$Unlisted
    )

    $result = [ordered]@{}
    if ($Title) {
        $result.Title = $Title
    }
    $result.Sections = @($Sections | ForEach-Object { ConvertTo-LayoutEntry $_ })
    if ($Unlisted) {
        $result.Unlisted = $Unlisted
    }
    return [pscustomobject]$result
}

# Numbers the sections in report order, those inside groups included. Hidden: hidden itself or
# inside a hidden section.
function Get-LayoutRows {
    param(
        [System.Collections.Generic.List[object]]$Sections,
        [int]$Depth = 0,
        [bool]$Hidden = $false
    )

    foreach ($section in $Sections) {
        $sectionHidden = $Hidden -or [bool]$section.Hide
        [pscustomobject]@{ Section = $section; Parent = $Sections; Depth = $Depth; Hidden = $sectionHidden }
        if (Test-LayoutGroup $section) {
            Get-LayoutRows -Sections $section.Children -Depth ($Depth + 1) -Hidden $sectionHidden
        }
    }
}

# Returns the row whose number is entered, or $null for Enter or a wrong number.
function Read-LayoutRow {
    param(
        [object[]]$Rows,
        [string]$Prompt
    )

    $answer = Read-Answer $Prompt
    $number = 0
    if (-not $answer) {
        return $null
    }
    if (-not [int]::TryParse($answer, [ref]$number) -or $number -lt 1 -or $number -gt $Rows.Count) {
        Write-Host "There is no number $answer." -ForegroundColor Yellow
        return $null
    }
    return $Rows[$number - 1]
}

# True when $Section is $Group or one of the sections inside it.
function Test-InGroup {
    param(
        [object]$Section,
        [object]$Group
    )

    if ([object]::ReferenceEquals($Section, $Group)) {
        return $true
    }
    foreach ($child in $Group.Children) {
        if (Test-InGroup -Section $Section -Group $child) {
            return $true
        }
    }
    return $false
}

# Opens $Content in Notepad and returns it as saved there.
function Edit-InNotepad {
    param(
        [string]$Content,
        [string]$Extension,
        [string]$What
    )

    # Deleted right after: the layout can name the client's servers.
    $path = Join-Path ([System.IO.Path]::GetTempPath()) "MOSE-layout-$([guid]::NewGuid().ToString('N'))$Extension"
    try {
        Set-Content -LiteralPath $path -Value $Content -Encoding UTF8
        Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$path`""
        # Notepad can open the file in an existing window and return at once, so the user says when.
        Read-Host -Prompt "Edit $What in Notepad, save it, then press Enter here" | Out-Null
        return "$(Get-Content -LiteralPath $path -Raw)".Trim()
    }
    finally {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

# Opens the layout in Notepad, for what the menu does not do: wildcards, groups in groups...
# Returns the edited layout, or throws when it is not valid JSON.
function Edit-LayoutJson {
    param(
        [object]$Layout
    )

    $json = Edit-InNotepad -Content (ConvertTo-Json -InputObject $Layout -Depth 20) -Extension '.json' -What 'the layout (see README, "Report layout")'
    try {
        return $json | ConvertFrom-Json
    }
    catch {
        throw "The layout is not valid JSON: $($_.Exception.Message)"
    }
}

# Text typed here, line by line, until a line with only a dot. Blank lines separate paragraphs.
function Read-TextLines {
    Write-Host "  Type the text (Markdown: **bold**, - list, | table |...). A line with only . ends it." -ForegroundColor DarkGray
    $lines = New-Object System.Collections.Generic.List[string]
    while ($true) {
        $line = "$(Read-Host -Prompt ' ')"
        if ($line.Trim() -eq '.') {
            break
        }
        $lines.Add($line)
    }
    return ($lines -join [Environment]::NewLine).Trim()
}

# Asks for several numbers at once, e.g. "2,3,4" or "2-4"; returns their rows.
function Read-LayoutRowList {
    param(
        [object[]]$Rows,
        [string]$Prompt
    )

    $answer = Read-Answer $Prompt
    foreach ($part in @($answer -split '[,; ]+' | Where-Object { $_ })) {
        $first = 0
        $last = 0
        if ($part -match '^(\d+)-(\d+)$') {
            $first = [int]$matches[1]
            $last = [int]$matches[2]
        }
        elseif ([int]::TryParse($part, [ref]$first)) {
            $last = $first
        }
        if ($first -lt 1 -or $last -gt $Rows.Count -or $first -gt $last) {
            Write-Host "There is no number $part." -ForegroundColor Yellow
            continue
        }
        $Rows[($first - 1)..($last - 1)]
    }
}

# Moves the rows to the end of $Section, skipping a section that would go inside itself.
function Add-ToLayoutSection {
    param(
        [object[]]$Members,
        [object]$Section
    )

    foreach ($member in $Members) {
        if (Test-InGroup -Section $Section -Group $member.Section) {
            Write-Host "A section cannot go inside itself." -ForegroundColor Yellow
            continue
        }
        [void]$member.Parent.Remove($member.Section)
        $Section.Children.Add($member.Section)
    }
}

# Menu to build the report sections (## headings) and attach the servers (###) to them.
# Changes $layout, saved with the rest of the configuration.
function Edit-ReportLayout {
    $date = Get-Date -Format 'yyyy-MM-dd'
    $sections = Get-MoseReportSections -Layout $script:layout -Targets $targets.ToArray()
    $title = "$(Get-MoseProperty $script:layout 'Title')"
    $unlisted = "$(Get-MoseProperty $script:layout 'Unlisted')"

    while ($true) {
        $rows = @(Get-LayoutRows -Sections $sections)
        $reportTitle = if ($title) { $title } else { $MoseDefaultReportTitle }
        Write-Host ""
        Write-Host "Report layout for $client" -ForegroundColor Cyan
        Write-Host "      # $(Format-MoseTitle $reportTitle @{ Client = $client; Date = $date })"
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $section = $rows[$i].Section
            $text = Get-MoseSectionTitle -Section $section -Client $client -Date $date
            $color = 'Gray'
            if (Test-LayoutGroup $section) {
                $color = 'Cyan'
                if ($section.Text) {
                    # The start of its text, to recognise it.
                    $firstLine = (($section.Text -split '\r?\n' | Where-Object { $_.Trim() }) | Select-Object -First 1).Trim()
                    if ($firstLine.Length -gt 40) {
                        $firstLine = $firstLine.Substring(0, 40) + '...'
                    }
                    $text += "  (text: $firstLine)"
                }
                elseif ($section.Children.Count -eq 0) {
                    $text += '  (empty, left out of the report)'
                }
            }
            elseif ($section.Table -and $section.Title) {
                # A renamed table is also named as the report makes it.
                $text += "  ($($MoseInventoryTables[$section.Table]) table)"
            }
            elseif ($section.Table) {
                $text += '  (table)'
            }
            elseif ($section.Title) {
                # A renamed server is also named as configured, to recognise it.
                $text += "  ($($MoseModules[$section.Target.Module].Label) $(Get-MoseTargetName $section.Target))"
            }
            if ($section.Hide) {
                $text += '  (hidden)'
            }
            # What a hidden section holds is hidden with it.
            if ($rows[$i].Hidden) {
                $color = 'DarkGray'
            }
            # The Markdown heading level each line gets in the report.
            $level = $rows[$i].Depth + 2
            $heading = if ($level -le 6) { '#' * $level } else { '**' }
            Write-Host ("  {0,2}. {1}{2,-4}{3}" -f ($i + 1), ('  ' * $rows[$i].Depth), $heading, $text) -ForegroundColor $color
        }
        Write-Host ""
        Write-Host "  N new section or subsection   A attach servers or tables to a section   M move   H hide/show"
        Write-Host "  T change the title of a server, table or section   W write the text of a section"
        Write-Host "  X remove a section (its servers and tables stay)   R report title   J edit as JSON   D default layout"
        Write-Host "  P preview the report with sample data   B back"
        $choice = Read-Answer 'Choice'

        if ($choice -match '^[Nn]$') {
            $sectionTitle = Read-Answer 'Section title (Enter to cancel). Placeholders: {Client} {Date}'
            if (-not $sectionTitle) {
                continue
            }
            $parent = Read-LayoutRow $rows 'Number of the section it goes in, as a subsection (Enter: a main ## section)'
            if ($parent -and -not (Test-LayoutGroup $parent.Section)) {
                Write-Host "Number $($rows.IndexOf($parent) + 1) is a server or a table, not a section." -ForegroundColor Yellow
                continue
            }
            $newSection = New-MoseSection -Title $sectionTitle
            if ($parent) {
                $parent.Section.Children.Add($newSection)
            }
            else {
                $sections.Add($newSection)
            }
            Add-ToLayoutSection -Section $newSection `
                -Members @(Read-LayoutRowList $rows 'Numbers of the servers, tables or sections to put in it, e.g. 2,3,4 or 2-4 (Enter for none)')
        }
        elseif ($choice -match '^[Aa]$') {
            $members = @(Read-LayoutRowList $rows 'Numbers of the servers, tables or sections to attach, e.g. 2,3,4 or 2-4')
            if ($members.Count -eq 0) {
                continue
            }
            $row = Read-LayoutRow $rows 'Number of the section to attach them to (Enter: the end of the report, as main sections, servers or tables)'
            if ($row -and -not (Test-LayoutGroup $row.Section)) {
                Write-Host "Number $($rows.IndexOf($row) + 1) is a server or a table, not a section." -ForegroundColor Yellow
                continue
            }
            if ($row) {
                Add-ToLayoutSection -Members $members -Section $row.Section
            }
            else {
                foreach ($member in $members) {
                    [void]$member.Parent.Remove($member.Section)
                    $sections.Add($member.Section)
                }
            }
        }
        elseif ($choice -match '^[Mm]$') {
            $row = Read-LayoutRow $rows 'Number of the section, server or table to move'
            if (-not $row) {
                continue
            }
            $before = Read-LayoutRow $rows 'Move it before which number (Enter: to the end of the report)'
            if ($before -and (Test-InGroup -Section $before.Section -Group $row.Section)) {
                Write-Host "A section cannot go inside itself." -ForegroundColor Yellow
                continue
            }
            [void]$row.Parent.Remove($row.Section)
            if ($before) {
                $before.Parent.Insert($before.Parent.IndexOf($before.Section), $row.Section)
            }
            else {
                $sections.Add($row.Section)
            }
        }
        elseif ($choice -match '^[Tt]$') {
            $row = Read-LayoutRow $rows 'Number of the server, table or section to give another title'
            if (-not $row) {
                continue
            }
            if (-not (Test-LayoutGroup $row.Section)) {
                $default = Get-MoseSectionTitle -Section (New-MoseSection -Target $row.Section.Target -Table $row.Section.Table) -Client $client -Date $date
                Write-Host "  Title now:      $(Get-MoseSectionTitle -Section $row.Section -Client $client -Date $date)"
                Write-Host "  Default title:  $default"
                if ($row.Section.Target) {
                    Write-Host "  Placeholders:   {Label} module, {Server} name or address, {Site}, {Client}, {Date}" -ForegroundColor DarkGray
                }
                else {
                    Write-Host "  Placeholders:   {Client}, {Date}" -ForegroundColor DarkGray
                }
                $answer = Read-Answer 'New title in the report (Enter keeps it, - for the default)'
                if ($answer -eq '-') {
                    $row.Section.Title = ''
                }
                elseif ($answer) {
                    $row.Section.Title = $answer
                }
            }
            else {
                $row.Section.Title = Read-Answer 'New section title. Placeholders: {Client} {Date}' $row.Section.Title
            }
        }
        elseif ($choice -match '^[Ww]$') {
            $row = Read-LayoutRow $rows 'Number of the section to write the text of'
            if (-not $row) {
                continue
            }
            if (-not (Test-LayoutGroup $row.Section)) {
                Write-Host "Number $($rows.IndexOf($row) + 1) is a server or a table: text goes in a section. Make one with N." -ForegroundColor Yellow
                continue
            }
            if ($row.Section.Text) {
                Write-Host "  Text now:" -ForegroundColor DarkGray
                $row.Section.Text -split '\r?\n' | ForEach-Object { Write-Host "  | $_" }
            }
            Write-Host "  Written under the section title, before its servers. Placeholders: {Client} {Date}" -ForegroundColor DarkGray
            $how = Read-Answer 'T to type it here, E to edit it in Notepad, - to remove it, Enter to keep it'
            if ($how -match '^[Tt]$') {
                $row.Section.Text = Read-TextLines
            }
            elseif ($how -match '^[Ee]$') {
                $row.Section.Text = Edit-InNotepad -Content $row.Section.Text -Extension '.md' -What "the text of $($row.Section.Title)"
            }
            elseif ($how -eq '-') {
                $row.Section.Text = ''
            }
            else {
                continue
            }
        }
        elseif ($choice -match '^[Hh]$') {
            $row = Read-LayoutRow $rows 'Number of the server, table or section to hide or show (a section with all it holds)'
            if (-not $row) {
                continue
            }
            $row.Section.Hide = -not $row.Section.Hide
        }
        elseif ($choice -match '^[Xx]$') {
            $row = Read-LayoutRow $rows 'Number of the section to remove (its servers and tables stay, in its place)'
            if (-not $row) {
                continue
            }
            if (-not (Test-LayoutGroup $row.Section)) {
                Write-Host "Number $($rows.IndexOf($row) + 1) is a server or a table, not a section. Use H to hide it." -ForegroundColor Yellow
                continue
            }
            $index = $row.Parent.IndexOf($row.Section)
            $row.Parent.RemoveAt($index)
            $row.Parent.InsertRange($index, $row.Section.Children)
        }
        elseif ($choice -match '^[Rr]$') {
            $answer = Read-Answer 'Report title, - for the default. Placeholders: {Client} {Date}' $reportTitle
            $title = if ($answer -eq '-' -or $answer -eq $MoseDefaultReportTitle) { '' } else { $answer }
        }
        elseif ($choice -match '^[Jj]$') {
            $current = if ($script:layout) { $script:layout } else { $MoseDefaultLayout }
            try {
                $edited = Edit-LayoutJson -Layout $current
            }
            catch {
                Write-Host "The layout was not changed. $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            }
            # Kept as written, wildcards included, until the menu changes it.
            $script:layout = $edited
            $sections = Get-MoseReportSections -Layout $edited -Targets $targets.ToArray()
            $title = "$(Get-MoseProperty $edited 'Title')"
            $unlisted = "$(Get-MoseProperty $edited 'Unlisted')"
            continue
        }
        elseif ($choice -match '^[Dd]$') {
            if (Read-YesNo "Go back to the default layout: $MoseInventoryTitle, Hardware, Virtualization and storage, Backup, Databases?" $false) {
                $script:layout = $null
                $sections = Get-MoseReportSections -Layout $null -Targets $targets.ToArray()
                $title = ''
                $unlisted = ''
            }
            continue
        }
        elseif ($choice -match '^[Pp]$') {
            # This layout, saved or not, with sample data instead of the servers' own.
            $preview = [pscustomobject]@{ Client = $client; Targets = $targets.ToArray(); Layout = $script:layout }
            & (Join-Path $PSScriptRoot 'Report.ps1') -DryRun -Config $preview | Out-Null
            continue
        }
        elseif ($choice -match '^[Bb]$') {
            return
        }
        else {
            continue
        }

        $script:layout = ConvertTo-Layout -Sections $sections -Title $title -Unlisted $unlisted
    }
}

# Every login and token in the vault but the configuration, with the servers of this configuration
# that use it.
function Get-SavedSecretList {
    foreach ($info in @(Get-SecretInfo -Vault $MoseVaultName | Where-Object { $_.Name -ne $MoseConfigSecretName } | Sort-Object -Property Name)) {
        $name = $info.Name
        $usedBy = @($targets | Where-Object { (Get-MoseProperty $_ 'Secret') -eq $name } |
            ForEach-Object { "$($MoseModules[$_.Module].Label) $(Get-MoseTargetName $_)" })
        [pscustomobject]@{ Name = $name; Type = "$($info.Type)"; UsedBy = $usedBy }
    }
}

# What a secret holds, without its password or tokens.
function Get-SavedSecretText {
    param(
        [object]$Secret
    )

    switch ($Secret.Type) {
        'PSCredential' {
            return "login $((Get-Secret -Vault $MoseVaultName -Name $Secret.Name).UserName)"
        }
        'Hashtable' {
            $value = Get-Secret -Vault $MoseVaultName -Name $Secret.Name -AsPlainText
            if ($value['Type'] -eq 'Cloud') {
                return "Commvault Cloud tokens, ring $($value['Ring'])"
            }
            if ($value['Type'] -eq 'OnPrem') {
                return "Commvault on-premises token, $($value['Server'])"
            }
            return 'table of values'
        }
        default {
            return $Secret.Type
        }
    }
}

# Asks for the new values of a login or of Commvault tokens; Enter keeps each current value.
function Edit-SavedSecret {
    param(
        [object]$Secret
    )

    if ($Secret.Type -eq 'PSCredential') {
        $current = Get-Secret -Vault $MoseVaultName -Name $Secret.Name
        $userName = Read-Answer 'User name (DOMAIN\user for a Windows account)' $current.UserName
        $password = Read-Host -Prompt 'Password (Enter keeps the current one)' -AsSecureString
        if ($password.Length -eq 0) {
            $password = $current.Password
        }
        Set-Secret -Vault $MoseVaultName -Name $Secret.Name -Secret ([pscredential]::new($userName, $password))
        Write-Host "Saved the login $userName in $($Secret.Name)." -ForegroundColor Green
        return
    }

    $value = $null
    if ($Secret.Type -eq 'Hashtable') {
        $value = @{}
        $stored = Get-Secret -Vault $MoseVaultName -Name $Secret.Name
        foreach ($key in @($stored.Keys)) {
            $value[$key] = $stored[$key]
        }
    }
    if (-not $value -or $value['Type'] -notin 'Cloud', 'OnPrem') {
        Write-Host "Only logins and Commvault tokens can be edited here; $($Secret.Name) can be removed." -ForegroundColor Yellow
        return
    }

    $mode = if ($value['Type'] -eq 'Cloud') { 'Cloud' } else { 'on-premises' }
    $accessToken = Read-Host -Prompt "Commvault $mode ACCESS token (Enter keeps the current one)" -AsSecureString
    if ($accessToken.Length -gt 0) {
        $value['AccessToken'] = $accessToken
    }
    if ($value['Type'] -eq 'Cloud') {
        # A new pair of tokens starts a new chain; the old refresh token stops working.
        $refreshToken = Read-Host -Prompt 'Commvault Cloud REFRESH token (Enter keeps the current one)' -AsSecureString
        if ($refreshToken.Length -gt 0) {
            $value['RefreshToken'] = $refreshToken
        }
        $value['Ring'] = Read-Answer 'Commvault Cloud ring ID (e.g. m108)' "$($value['Ring'])"
    }
    else {
        $value['Server'] = Read-Answer 'Commvault Command Center URL (e.g. https://commvault.example.com)' "$($value['Server'])"
    }
    Set-Secret -Vault $MoseVaultName -Name $Secret.Name -Secret $value
    Write-Host "Saved the Commvault $mode tokens in $($Secret.Name)." -ForegroundColor Green
}

# P in the menu: the saved logins and tokens, the servers that use each, and E to edit or D to
# remove one. Removing waits for S, like the other changes, so Q keeps everything.
function Edit-SavedSecrets {
    while ($true) {
        $secrets = @(Get-SavedSecretList)
        Write-Host ""
        Write-Host "Saved logins and tokens (vault $MoseVaultName)" -ForegroundColor Cyan
        if ($secrets.Count -eq 0) {
            Write-Host "  None."
            return
        }
        for ($i = 0; $i -lt $secrets.Count; $i++) {
            $secret = $secrets[$i]
            Write-Host ("  {0,2}. {1,-32} {2}" -f ($i + 1), $secret.Name, (Get-SavedSecretText $secret))
            if ($secretsToRemove -contains $secret.Name) {
                Write-Host '      removed when you save (S)' -ForegroundColor Yellow
            }
            elseif ($secret.UsedBy.Count -gt 0) {
                Write-Host "      used by $($secret.UsedBy -join ', ')" -ForegroundColor DarkGray
            }
            else {
                Write-Host '      not used by any server' -ForegroundColor Yellow
            }
        }
        Write-Host ""

        $number = 0
        if (-not [int]::TryParse((Read-Answer 'Number to edit or remove (Enter to go back)'), [ref]$number) -or
            $number -lt 1 -or $number -gt $secrets.Count) {
            return
        }
        $secret = $secrets[$number - 1]
        $action = Read-Answer "$($secret.Name): E to edit, D to remove (or keep, if marked), Enter for neither"
        if ($action -match '^[Ee]$') {
            Edit-SavedSecret $secret
        }
        elseif ($action -match '^[Dd]$') {
            if ($secretsToRemove -contains $secret.Name) {
                [void]$secretsToRemove.Remove($secret.Name)
                Write-Host "$($secret.Name) is kept." -ForegroundColor Green
            }
            elseif ($secret.UsedBy.Count -gt 0) {
                Write-Host "$($secret.Name) is used by $($secret.UsedBy -join ', '). Remove those servers first (R), or edit the login (E)." -ForegroundColor Yellow
            }
            else {
                if ($secret.Name -notlike 'MOSE:*') {
                    Write-Host "$($secret.Name) was not saved by MOSE: another script on this computer may still use it." -ForegroundColor Yellow
                }
                if (Read-YesNo "Remove $($secret.Name) from the vault when you save?" $false) {
                    $secretsToRemove.Add($secret.Name)
                }
            }
        }
    }
}

# V in the menu: a new vault password, changed at once rather than on S; everything in the vault
# stays. The weekly Commvault token renewal (Renew-CommvaultToken.ps1 -Register) keeps the password
# in a file next to the scripts, saved again with the new one.
function Set-MoseVaultPassword {
    Write-Host ""
    Write-Host "Password of the SecretStore vault '$MoseVaultName'" -ForegroundColor Cyan
    Write-Host "It changes at once, for every vault of $env:USERNAME on this computer. The saved logins, tokens and configuration stay."
    $current = Read-Host -Prompt 'Current password (Enter to cancel)' -AsSecureString
    if ($current.Length -eq 0) {
        return
    }
    $new = Read-Host -Prompt 'New password' -AsSecureString
    if ($new.Length -eq 0) {
        Write-Host "No new password: nothing changed." -ForegroundColor Yellow
        return
    }
    $again = Read-Host -Prompt 'New password again' -AsSecureString
    if ([System.Net.NetworkCredential]::new('', $new).Password -cne [System.Net.NetworkCredential]::new('', $again).Password) {
        Write-Host "The two new passwords differ: nothing changed." -ForegroundColor Yellow
        return
    }
    try {
        Set-SecretStorePassword -Password $current -NewPassword $new -ErrorAction Stop
    }
    catch {
        Write-Host "The vault password was not changed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    $script:MoseVaultPassword = $new
    Write-Host "Changed the vault password. The report and the configuration ask for the new one from now on." -ForegroundColor Green

    $renewalFile = Join-Path $PSScriptRoot 'SecretStore1.password.xml'
    if (Test-Path -LiteralPath $renewalFile -PathType Leaf) {
        try {
            $new | Export-Clixml -LiteralPath $renewalFile
            Write-Host "Saved it for the weekly Commvault token renewal too ($renewalFile)." -ForegroundColor Green
        }
        catch {
            Write-Host "The weekly Commvault token renewal still has the old password ($($_.Exception.Message)): run .\Renew-CommvaultToken.ps1 -Register." -ForegroundColor Yellow
        }
    }
}

# The fields of the lines entered under I, in the order they are asked. More: asked for a new line
# only when wanted; Date: yyyy-MM-dd.
$softwareFields = @(
    @{ Name = 'Name'; Prompt = 'Name (e.g. Microsoft Defender)' }
    @{ Name = 'Version'; Prompt = 'Version (Enter for none, or for the one the report reads)' }
    @{ Name = 'Purpose'; Prompt = 'Purpose (e.g. security and antivirus)' }
)
$machineFields = @(
    @{ Name = 'Name'; Prompt = 'Name as the report shows it (e.g. esxi01), or of a machine no module reads' }
    @{ Name = 'Serial'; Prompt = 'Serial number (Enter if the name is enough)' }
    @{ Name = 'WarrantyEnd'; Prompt = 'Warranty end date, yyyy-MM-dd (Enter for none)'; Date = $true }
    @{ Name = 'WarrantyNote'; Prompt = 'Warranty note (e.g. parts on site)' }
    @{ Name = 'Service'; Prompt = 'Service shown (e.g. NAS store for Veeam backup; Enter: as the report reads it)' }
    @{ Name = 'Brand'; Prompt = 'Brand'; More = $true }
    @{ Name = 'Model'; Prompt = 'Model'; More = $true }
    @{ Name = 'ProductId'; Prompt = 'Product ID'; More = $true }
    @{ Name = 'Bios'; Prompt = 'BIOS version'; More = $true }
)

# Asks the fields of a line under I. With $Line, Enter keeps a value and - empties it.
function Read-InventoryLine {
    param(
        [object[]]$Fields,
        [object]$Line
    )

    $values = [ordered]@{}
    $more = $null
    foreach ($field in $Fields) {
        $current = "$(Get-MoseProperty $Line $field.Name)"
        if ($field['More'] -and -not $Line) {
            if ($null -eq $more) {
                $more = Read-YesNo 'Also its brand, model, Product ID and BIOS, for a machine no module reads?' $false
            }
            if (-not $more) {
                $values[$field.Name] = ''
                continue
            }
        }
        $prompt = if ($Line) { "$($field.Prompt) (Enter keeps it, - to empty it)" } else { $field.Prompt }
        while ($true) {
            $value = Read-Answer $prompt $current
            if ($value -eq '-') {
                $value = ''
            }
            $date = [datetime]::MinValue
            if ($field['Date'] -and $value -and -not [datetime]::TryParseExact($value, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$date)) {
                Write-Host "Write the date as yyyy-MM-dd, e.g. 2027-11-30." -ForegroundColor Yellow
                continue
            }
            break
        }
        $values[$field.Name] = $value
    }
    return [pscustomobject]$values
}

# A list of lines under I: A adds one, its number changes or removes it.
function Edit-InventoryList {
    param(
        [System.Collections.Generic.List[object]]$Lines,
        [object[]]$Fields,
        [string]$Title,
        [string]$Help,
        [scriptblock]$Show
    )

    while ($true) {
        Write-Host ""
        Write-Host $Title -ForegroundColor Cyan
        Write-Host $Help -ForegroundColor DarkGray
        if ($Lines.Count -eq 0) {
            Write-Host "  None."
        }
        for ($i = 0; $i -lt $Lines.Count; $i++) {
            Write-Host ("  {0,2}. {1}" -f ($i + 1), (& $Show $Lines[$i]))
        }
        Write-Host ""

        $answer = Read-Answer 'A to add a line, a number to change or remove it, Enter to go back'
        $number = 0
        if (-not $answer) {
            return
        }
        if ($answer -match '^[Aa]$') {
            $line = Read-InventoryLine -Fields $Fields
            if ($line.Name -or (Get-MoseProperty $line 'Serial')) {
                $Lines.Add($line)
            }
        }
        elseif ([int]::TryParse($answer, [ref]$number) -and $number -ge 1 -and $number -le $Lines.Count) {
            $line = $Lines[$number - 1]
            $action = Read-Answer "$(Get-MoseProperty $line 'Name'): E to change it, D to remove it, Enter for neither"
            if ($action -match '^[Ee]$') {
                $Lines[$number - 1] = Read-InventoryLine -Fields $Fields -Line $line
            }
            elseif ($action -match '^[Dd]$') {
                $Lines.RemoveAt($number - 1)
            }
        }
    }
}

# I in the menu: what the inventory tables cannot read. The Software lines no module reads (e.g.
# Microsoft Defender), or the purpose of Veeam and msSQL; the warranty of the machines of the
# Physical System table, and the machines no module reads.
function Edit-Inventory {
    while ($true) {
        Write-Host ""
        Write-Host "Inventory tables ($MoseInventoryTitle)" -ForegroundColor Cyan
        Write-Host "   S. Software: lines no module reads, or the purpose of Veeam and msSQL ($($software.Count))"
        Write-Host "   M. Physical System: the warranty of the machines, and machines no module reads ($($machines.Count))"
        Write-Host ""
        $choice = Read-Answer 'S or M, Enter to go back'
        if (-not $choice) {
            return
        }
        if ($choice -match '^[Ss]$') {
            Edit-InventoryList -Lines $software -Fields $softwareFields -Title 'Lines of the Software table' `
                -Help 'The report reads Veeam and msSQL itself: a line with the same name gives their purpose, or a version to show instead.' `
                -Show { param($l) $version = Get-MoseProperty $l 'Version'; '{0,-24} {1,-16} {2}' -f (Get-MoseProperty $l 'Name'), $(if ($version) { $version } else { '-' }), (Get-MoseProperty $l 'Purpose') }
        }
        elseif ($choice -match '^[Mm]$') {
            Edit-InventoryList -Lines $machines -Fields $machineFields -Title 'Machines of the Physical System table' `
                -Help 'A line matches the machine of the same serial number, else of the same name: it gives its warranty, and what the report does not read.' `
                -Show { param($l) $end = Get-MoseProperty $l 'WarrantyEnd'; '{0,-20} {1,-16} warranty {2} {3}' -f (Get-MoseProperty $l 'Name'), (Get-MoseProperty $l 'Serial'), $(if ($end) { $end } else { '-' }), (Get-MoseProperty $l 'WarrantyNote') }
        }
    }
}

$config = Get-MoseConfig
$client = ''
$targets = New-Object System.Collections.Generic.List[object]
$software = New-Object System.Collections.Generic.List[object]
$machines = New-Object System.Collections.Generic.List[object]
$secretsToRemove = New-Object System.Collections.Generic.List[string]
$layout = $null
if ($config) {
    $client = $config.Client
    foreach ($target in @($config.Targets)) {
        $targets.Add($target)
    }
    foreach ($line in @(Get-MoseProperty $config 'Software' | Where-Object { $_ })) {
        $software.Add($line)
    }
    foreach ($line in @(Get-MoseProperty $config 'Machines' | Where-Object { $_ })) {
        $machines.Add($line)
    }
    $layout = Get-MoseProperty $config 'Layout'
}

Write-Host ""
Write-Host "MOSE client configuration" -ForegroundColor Cyan
Write-Host "Saved in the SecretStore vault '$MoseVaultName' of $env:USERNAME on this computer, never in the scripts."
Write-Host ""

# Asked once; C in the menu changes it.
while (-not $client) {
    $client = Read-Answer 'Client name (report title and file name)'
}

$moduleKeys = @($MoseModules.Keys)

while ($true) {
    Write-Host ""
    Write-Host "Modules for $client" -ForegroundColor Cyan
    for ($i = 0; $i -lt $moduleKeys.Count; $i++) {
        $names = @($targets | Where-Object { $_.Module -eq $moduleKeys[$i] } | ForEach-Object { Get-MoseTargetName $_ })
        $configured = if ($names.Count -gt 0) { $names -join ', ' } else { '-' }
        Write-Host ("  {0,2}. {1,-28} {2}" -f ($i + 1), $MoseModules[$moduleKeys[$i]].Label, $configured)
    }
    $layoutText = if ($layout) { 'custom' } else { 'default' }
    Write-Host "   P. Saved logins and tokens: edit or remove them, and the servers that use each"
    Write-Host "   I. Inventory: lines of the Software ($($software.Count)) and Physical System ($($machines.Count)) tables"
    Write-Host "   L. Report layout ($layoutText): the report sections and the servers in each"
    Write-Host "   C. Client name: $client"
    # Not when Report.ps1 started this: it keeps the password it was given, for the Commvault modules.
    if (-not $VaultUnlocked) {
        Write-Host "   V. Vault password: change it (at once, not on S)"
    }
    Write-Host ""

    $choice = Read-Answer 'Module number to add servers, R to remove one, P for the saved logins, I for the inventory, L for the report layout, C for the client name, V for the vault password, S to save, Q to quit without saving'
    $number = 0

    if ([int]::TryParse($choice, [ref]$number) -and $number -ge 1 -and $number -le $moduleKeys.Count) {
        $module = $moduleKeys[$number - 1]
        $label = $MoseModules[$module].Label
        $count = 0
        if (-not [int]::TryParse((Read-Answer "How many $label to add" '1'), [ref]$count) -or $count -lt 1) {
            continue
        }

        for ($n = 1; $n -le $count; $n++) {
            $target = Read-Target -Module $module -Title "$label $n of $count"
            if ($target) {
                $targets.Add($target)
                Write-Host "Added $label $(Get-MoseTargetName $target)" -ForegroundColor Green
            }
        }
    }
    elseif ($choice -match '^[Rr]$') {
        if ($targets.Count -eq 0) {
            Write-Host "Nothing to remove." -ForegroundColor Yellow
            continue
        }

        for ($i = 0; $i -lt $targets.Count; $i++) {
            Write-Host ("  {0}. {1} {2}" -f ($i + 1), $MoseModules[$targets[$i].Module].Label, (Get-MoseTargetName $targets[$i]))
        }
        # The saved login stays in the vault, so adding the server again can reuse it.
        if ([int]::TryParse((Read-Answer 'Number to remove (Enter for none)'), [ref]$number) -and
            $number -ge 1 -and $number -le $targets.Count) {
            $removed = $targets[$number - 1]
            $targets.RemoveAt($number - 1)
            Write-Host "Removed $($MoseModules[$removed.Module].Label) $(Get-MoseTargetName $removed)" -ForegroundColor Green
        }
    }
    elseif ($choice -match '^[Pp]$') {
        Edit-SavedSecrets
    }
    elseif ($choice -match '^[Ii]$') {
        Edit-Inventory
    }
    elseif ($choice -match '^[Ll]$') {
        Edit-ReportLayout
    }
    elseif ($choice -match '^[Cc]$') {
        $client = Read-Answer 'Client name (report title and file name)' $client
    }
    elseif ($choice -match '^[Vv]$') {
        if ($VaultUnlocked) {
            Write-Host "Change the vault password after this first configuration: .\Start.ps1 -Configure, then V." -ForegroundColor Yellow
            continue
        }
        Set-MoseVaultPassword
    }
    elseif ($choice -match '^[Ss]$') {
        Save-MoseConfig -Client $client -Targets $targets.ToArray() -Layout $layout -Software $software.ToArray() -Machines $machines.ToArray()
        Write-Host "Saved the configuration of $client ($($targets.Count) servers)." -ForegroundColor Green
        foreach ($name in $secretsToRemove) {
            # A server added since may have reused it.
            if (@($targets | Where-Object { (Get-MoseProperty $_ 'Secret') -eq $name }).Count -eq 0) {
                Remove-Secret -Vault $MoseVaultName -Name $name
                Write-Host "Removed $name from the vault." -ForegroundColor Green
            }
        }
        return
    }
    elseif ($choice -match '^[Qq]$') {
        Write-Host "Nothing was saved." -ForegroundColor Yellow
        return
    }
}
