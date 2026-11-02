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
    if ($Module -notin 'Veeam', 'HyperV' -or $remotingByIP -or
        ($server -notin @('localhost', '.') -and (Read-YesNo "Use another Windows account for PowerShell remoting to ${server}?" $false))) {
        $target.Secret = Read-TargetCredential -Module $Module -Server $server
        if (-not $target.Secret) {
            Write-Host "Skipped: no credential was entered for $label $server." -ForegroundColor Yellow
            return $null
        }
    }
    if ($remotingByIP) {
        [void](Confirm-MoseTrustedHost $server)
    }

    if ($Module -eq 'NAS') {
        $target | Add-Member -NotePropertyName CertificateThumbprint -NotePropertyValue (Read-Answer 'Trusted certificate SHA-1 thumbprint (Enter for the normal certificate check)')
        $target | Add-Member -NotePropertyName AcceptAnyCertificate -NotePropertyValue (Read-YesNo 'Accept any certificate? Insecure, only on a trusted network' $false)
    }
    elseif ($Module -in 'VMware', 'HyperV') {
        $target | Add-Member -NotePropertyName Site -NotePropertyValue (Read-Answer 'Site name shown in the report' 'main')
    }

    return $target
}

# Layout entries of the report sections as the menu shows them: one entry per server, by its
# exact name, so a server added later goes at the end of the report.
function ConvertTo-LayoutEntry {
    param(
        [object]$Section
    )

    if (-not $Section.Target) {
        $group = [ordered]@{ Title = $Section.Title }
        if ($Section.Text) {
            $group.Text = $Section.Text
        }
        $group.Sections = @($Section.Children | ForEach-Object { ConvertTo-LayoutEntry $_ })
        return [pscustomobject]$group
    }
    $entry = [ordered]@{
        Module = $Section.Target.Module
        Server = [System.Management.Automation.WildcardPattern]::Escape((Get-MoseTargetName $Section.Target))
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

# Numbers the sections in report order, those inside groups included.
function Get-LayoutRows {
    param(
        [System.Collections.Generic.List[object]]$Sections,
        [int]$Depth = 0
    )

    foreach ($section in $Sections) {
        [pscustomobject]@{ Section = $section; Parent = $Sections; Depth = $Depth }
        if (-not $section.Target) {
            Get-LayoutRows -Sections $section.Children -Depth ($Depth + 1)
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
            if (-not $section.Target) {
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
            elseif ($section.Hide) {
                $text += '  (hidden)'
                $color = 'DarkGray'
            }
            elseif ($section.Title) {
                # A renamed server is also named as configured, to recognise it.
                $text += "  ($($MoseModules[$section.Target.Module].Label) $(Get-MoseTargetName $section.Target))"
            }
            # The Markdown heading level each line gets in the report.
            $level = $rows[$i].Depth + 2
            $heading = if ($level -le 6) { '#' * $level } else { '**' }
            Write-Host ("  {0,2}. {1}{2,-4}{3}" -f ($i + 1), ('  ' * $rows[$i].Depth), $heading, $text) -ForegroundColor $color
        }
        Write-Host ""
        Write-Host "  N new section or subsection   A attach servers to a section   M move   H hide/show a server"
        Write-Host "  T change the title of a server or a section   W write the text of a section"
        Write-Host "  X remove a section (its servers stay)   R report title   J edit as JSON   D default layout"
        Write-Host "  P preview the report with sample data   B back"
        $choice = Read-Answer 'Choice'

        if ($choice -match '^[Nn]$') {
            $sectionTitle = Read-Answer 'Section title (Enter to cancel). Placeholders: {Client} {Date}'
            if (-not $sectionTitle) {
                continue
            }
            $parent = Read-LayoutRow $rows 'Number of the section it goes in, as a subsection (Enter: a main ## section)'
            if ($parent -and $parent.Section.Target) {
                Write-Host "Number $($rows.IndexOf($parent) + 1) is a server, not a section." -ForegroundColor Yellow
                continue
            }
            $newSection = [pscustomobject]@{ Title = $sectionTitle; Text = ''; Target = $null; Children = New-Object System.Collections.Generic.List[object]; Hide = $false }
            if ($parent) {
                $parent.Section.Children.Add($newSection)
            }
            else {
                $sections.Add($newSection)
            }
            Add-ToLayoutSection -Section $newSection `
                -Members @(Read-LayoutRowList $rows 'Numbers of the servers or sections to put in it, e.g. 2,3,4 or 2-4 (Enter for none)')
        }
        elseif ($choice -match '^[Aa]$') {
            $members = @(Read-LayoutRowList $rows 'Numbers of the servers or sections to attach, e.g. 2,3,4 or 2-4')
            if ($members.Count -eq 0) {
                continue
            }
            $row = Read-LayoutRow $rows 'Number of the section to attach them to (Enter: the end of the report, as main sections or servers)'
            if ($row -and $row.Section.Target) {
                Write-Host "Number $($rows.IndexOf($row) + 1) is a server, not a section." -ForegroundColor Yellow
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
            $row = Read-LayoutRow $rows 'Number of the section or server to move'
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
            $row = Read-LayoutRow $rows 'Number of the server or section to give another title'
            if (-not $row) {
                continue
            }
            if ($row.Section.Target) {
                $default = Get-MoseSectionTitle -Section ([pscustomobject]@{ Title = ''; Target = $row.Section.Target }) -Client $client -Date $date
                Write-Host "  Title now:      $(Get-MoseSectionTitle -Section $row.Section -Client $client -Date $date)"
                Write-Host "  Default title:  $default"
                Write-Host "  Placeholders:   {Label} module, {Server} name or address, {Site}, {Client}, {Date}" -ForegroundColor DarkGray
                $answer = Read-Answer 'New title of this server in the report (Enter keeps it, - for the default)'
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
            if ($row.Section.Target) {
                Write-Host "Number $($rows.IndexOf($row) + 1) is a server: text goes in a section. Make one with N." -ForegroundColor Yellow
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
            $row = Read-LayoutRow $rows 'Number of the server to hide or show'
            if (-not $row) {
                continue
            }
            if (-not $row.Section.Target) {
                Write-Host "Only a server can be hidden. A section is left out when all its servers are." -ForegroundColor Yellow
                continue
            }
            $row.Section.Hide = -not $row.Section.Hide
        }
        elseif ($choice -match '^[Xx]$') {
            $row = Read-LayoutRow $rows 'Number of the section to remove (its servers stay, in its place)'
            if (-not $row) {
                continue
            }
            if ($row.Section.Target) {
                Write-Host "Number $($rows.IndexOf($row) + 1) is a server, not a section. Use H to hide it." -ForegroundColor Yellow
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
            if (Read-YesNo 'Go back to the default layout: Hardware, Virtualization and storage, Backup?' $false) {
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

$config = Get-MoseConfig
$client = ''
$targets = New-Object System.Collections.Generic.List[object]
$secretsToRemove = New-Object System.Collections.Generic.List[string]
$layout = $null
if ($config) {
    $client = $config.Client
    foreach ($target in @($config.Targets)) {
        $targets.Add($target)
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
    Write-Host "   L. Report layout ($layoutText): the report sections and the servers in each"
    Write-Host "   C. Client name: $client"
    Write-Host ""

    $choice = Read-Answer 'Module number to add servers, R to remove one, P for the saved logins, L for the report layout, C for the client name, S to save, Q to quit without saving'
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
    elseif ($choice -match '^[Ll]$') {
        Edit-ReportLayout
    }
    elseif ($choice -match '^[Cc]$') {
        $client = Read-Answer 'Client name (report title and file name)' $client
    }
    elseif ($choice -match '^[Ss]$') {
        Save-MoseConfig -Client $client -Targets $targets.ToArray() -Layout $layout
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
