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

function Read-YesNo {
    param(
        [string]$Prompt,
        [bool]$Default = $true
    )

    $hint = if ($Default) { 'Y/n' } else { 'y/N' }
    $answer = "$(Read-Host -Prompt "$Prompt [$hint]")".Trim()
    if (-not $answer) {
        return $Default
    }
    return $answer -match '^(y|yes|o|oui)$'
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

    # Veeam runs as the current Windows user unless it is reached over PowerShell remoting.
    if ($Module -ne 'Veeam' -or
        ($server -notin @('localhost', '.') -and (Read-YesNo "Use another Windows account for PowerShell remoting to $server?" $false))) {
        $target.Secret = Read-TargetCredential -Module $Module -Server $server
        if (-not $target.Secret) {
            Write-Host "Skipped: no credential was entered for $label $server." -ForegroundColor Yellow
            return $null
        }
    }

    if ($Module -eq 'NAS') {
        $target | Add-Member -NotePropertyName CertificateThumbprint -NotePropertyValue (Read-Answer 'Trusted certificate SHA-1 thumbprint (Enter for the normal certificate check)')
        $target | Add-Member -NotePropertyName AcceptAnyCertificate -NotePropertyValue (Read-YesNo 'Accept any certificate? Insecure, only on a trusted network' $false)
    }
    elseif ($Module -eq 'VMware') {
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
        return [pscustomobject][ordered]@{ Title = $Section.Title; Sections = @($Section.Children | ForEach-Object { ConvertTo-LayoutEntry $_ }) }
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
        Write-Host "There is no section $answer." -ForegroundColor Yellow
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

# Opens the layout in Notepad, for what the menu does not do: wildcards, groups in groups...
# Returns the edited layout, or throws when it is not valid JSON.
function Edit-LayoutJson {
    param(
        [object]$Layout
    )

    # Deleted right after: the layout can name the client's servers.
    $path = Join-Path ([System.IO.Path]::GetTempPath()) "MOSE-layout-$([guid]::NewGuid().ToString('N')).json"
    try {
        ConvertTo-Json -InputObject $Layout -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8
        Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$path`""
        # Notepad can open the file in an existing window and return at once, so the user says when.
        Read-Host -Prompt 'Edit the layout in Notepad, save it, then press Enter here (see README, "Report layout")' | Out-Null
        try {
            return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        }
        catch {
            throw "The layout is not valid JSON: $($_.Exception.Message)"
        }
    }
    finally {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

# Menu to reorder, rename, group and hide the report sections. Changes $layout,
# saved with the rest of the configuration.
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
        Write-Host "  # $(Format-MoseTitle $reportTitle @{ Client = $client; Date = $date })"
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $section = $rows[$i].Section
            $text = Get-MoseSectionTitle -Section $section -Client $client -Date $date
            $color = 'Gray'
            if (-not $section.Target) {
                $text = "[$text]"
                $color = 'Cyan'
            }
            elseif ($section.Hide) {
                $text += '  (hidden)'
                $color = 'DarkGray'
            }
            elseif ($section.Title) {
                # A renamed server is also named as configured, to recognise it.
                $text += "  ($($MoseModules[$section.Target.Module].Label) $(Get-MoseTargetName $section.Target))"
            }
            Write-Host ("  {0,2}. {1}{2}" -f ($i + 1), ('    ' * $rows[$i].Depth), $text) -ForegroundColor $color
        }
        Write-Host ""
        Write-Host "  M move   T rename   H hide/show   G new group   X remove a group   R report title"
        Write-Host "  J edit as JSON   D default layout   B back"
        $choice = Read-Answer 'Choice'

        if ($choice -match '^[Mm]$') {
            $row = Read-LayoutRow $rows 'Number of the section to move'
            if (-not $row) {
                continue
            }
            $before = Read-LayoutRow $rows 'Move it before which number (Enter: to the end of a group or of the report)'
            if ($before) {
                if (Test-InGroup -Section $before.Section -Group $row.Section) {
                    Write-Host "A group cannot go inside itself." -ForegroundColor Yellow
                    continue
                }
                [void]$row.Parent.Remove($row.Section)
                $before.Parent.Insert($before.Parent.IndexOf($before.Section), $row.Section)
            }
            else {
                $group = Read-LayoutRow $rows 'To the end of which group number (Enter: the end of the report)'
                $destination = $sections
                if ($group) {
                    if ($group.Section.Target) {
                        Write-Host "Section $($rows.IndexOf($group) + 1) is a server, not a group." -ForegroundColor Yellow
                        continue
                    }
                    if (Test-InGroup -Section $group.Section -Group $row.Section) {
                        Write-Host "A group cannot go inside itself." -ForegroundColor Yellow
                        continue
                    }
                    $destination = $group.Section.Children
                }
                [void]$row.Parent.Remove($row.Section)
                $destination.Add($row.Section)
            }
        }
        elseif ($choice -match '^[Tt]$') {
            $row = Read-LayoutRow $rows 'Number of the section to rename'
            if (-not $row) {
                continue
            }
            if ($row.Section.Target) {
                $answer = Read-Answer 'New title, - for the default. Placeholders: {Label} {Server} {Site} {Client} {Date}' $row.Section.Title
                $row.Section.Title = if ($answer -eq '-') { '' } else { $answer }
            }
            else {
                $row.Section.Title = Read-Answer 'New group title. Placeholders: {Client} {Date}' $row.Section.Title
            }
        }
        elseif ($choice -match '^[Hh]$') {
            $row = Read-LayoutRow $rows 'Number of the server to hide or show'
            if (-not $row) {
                continue
            }
            if (-not $row.Section.Target) {
                Write-Host "Only a server can be hidden. A group is left out when all its servers are." -ForegroundColor Yellow
                continue
            }
            $row.Section.Hide = -not $row.Section.Hide
        }
        elseif ($choice -match '^[Gg]$') {
            $groupTitle = Read-Answer 'Group title (Enter to cancel). Placeholders: {Client} {Date}'
            if (-not $groupTitle) {
                continue
            }
            $group = [pscustomobject]@{ Title = $groupTitle; Target = $null; Children = New-Object System.Collections.Generic.List[object]; Hide = $false }
            $numbers = @((Read-Answer 'Numbers of the sections to put in it, separated by commas (Enter for none)') -split '[,; ]+' | Where-Object { $_ })
            $members = @($numbers | ForEach-Object {
                    $number = 0
                    if ([int]::TryParse($_, [ref]$number) -and $number -ge 1 -and $number -le $rows.Count) { $rows[$number - 1] }
                    else { Write-Host "There is no section $_." -ForegroundColor Yellow }
                })
            # The group takes the place of its first section.
            if ($members.Count -gt 0) {
                $members[0].Parent.Insert($members[0].Parent.IndexOf($members[0].Section), $group)
            }
            else {
                $sections.Add($group)
            }
            foreach ($member in $members) {
                if (-not (Test-InGroup -Section $group -Group $member.Section)) {
                    [void]$member.Parent.Remove($member.Section)
                    $group.Children.Add($member.Section)
                }
            }
        }
        elseif ($choice -match '^[Xx]$') {
            $row = Read-LayoutRow $rows 'Number of the group to remove (its sections stay)'
            if (-not $row) {
                continue
            }
            if ($row.Section.Target) {
                Write-Host "Section $($rows.IndexOf($row) + 1) is a server, not a group." -ForegroundColor Yellow
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
            $current = if ($script:layout) { $script:layout } else { ConvertTo-Layout -Sections $sections -Title $title -Unlisted $unlisted }
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
            if (Read-YesNo 'Go back to the default layout: one section per server, in module order?' $false) {
                $script:layout = $null
                $sections = Get-MoseReportSections -Layout $null -Targets $targets.ToArray()
                $title = ''
                $unlisted = ''
            }
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

$config = Get-MoseConfig
$client = ''
$targets = New-Object System.Collections.Generic.List[object]
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

do {
    $client = Read-Answer 'Client name (report title and file name)' $client
} until ($client)

$moduleKeys = @($MoseModules.Keys)

while ($true) {
    Write-Host ""
    Write-Host "Modules for $client" -ForegroundColor Cyan
    for ($i = 0; $i -lt $moduleKeys.Count; $i++) {
        $names = @($targets | Where-Object { $_.Module -eq $moduleKeys[$i] } | ForEach-Object { Get-MoseTargetName $_ })
        $configured = if ($names.Count -gt 0) { $names -join ', ' } else { '-' }
        Write-Host ("  {0}. {1,-28} {2}" -f ($i + 1), $MoseModules[$moduleKeys[$i]].Label, $configured)
    }
    $layoutText = if ($layout) { 'custom' } else { 'default' }
    Write-Host "  L. Report layout ($layoutText): order, titles and groups of the sections"
    Write-Host ""

    $choice = Read-Answer 'Module number to add servers, R to remove one, L for the report layout, S to save, Q to quit without saving'
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
    elseif ($choice -match '^[Ll]$') {
        Edit-ReportLayout
    }
    elseif ($choice -match '^[Ss]$') {
        Save-MoseConfig -Client $client -Targets $targets.ToArray() -Layout $layout
        Write-Host "Saved the configuration of $client ($($targets.Count) servers)." -ForegroundColor Green
        return
    }
    elseif ($choice -match '^[Qq]$') {
        Write-Host "Nothing was saved." -ForegroundColor Yellow
        return
    }
}
