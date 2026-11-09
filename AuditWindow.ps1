[CmdletBinding()]
param(
    # The answers already known, from the options given to Audit.ps1 -Gui (or Start.ps1 -Audit -Gui).
    [string]$Client,
    [string[]]$Domain,
    [string[]]$Subnet,
    [string[]]$AddSubnet,
    [string[]]$SnmpCommunity,
    [string[]]$Skip,
    [string]$ADServer,
    [pscredential]$ADCredential,
    [pscredential]$AdminCredential,
    [string]$Tenant,
    [string]$OutputPath = $PSScriptRoot,
    [switch]$ScanOtherNetworks,
    [switch]$Microsoft365,
    # Accepted with the others, but the window always runs the audit with its answers given.
    [switch]$NonInteractive,
    [switch]$NoOpen
)

# The IT audit in a window (Audit.ps1 -Gui): every answer the audit would ask for is entered first,
# then Audit.ps1 runs in the background with them (-NonInteractive), its messages and progress shown
# here, and its audit, diagram and folder opened from here. Nothing typed here is saved: the SNMP
# community and the passwords stay in this window and the audit's memory only.
#
# The second tab is the on-site checklist of an audit (the one just run, another of the folder, or one
# found elsewhere): each item ticked as done or skipped, with a note, saved in the audit's "To complete
# on site" section at each change, so that the audit says what is done. Hiding what is done or skipped
# is for this window only.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
# Windows PowerShell leaves $PSScriptRoot empty in a parameter's default when run with -File.
if (-not $OutputPath) {
    $OutputPath = $PSScriptRoot
}

$auditScript = Join-Path $PSScriptRoot 'Audit.ps1'
# What the window knows. A hashtable, so that the event handlers, which run in scopes of their own,
# change it: the audit running (its PowerShell, the stream items shown), when it started, its files.
$ui = @{ Shell = $null; Handle = $null; Shown = @{}; Started = $null; Markdown = $null; Diagram = $null; AuditFiles = @(); Checklist = $null; Loading = $false }

$computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$inDomain = [bool]($computer -and $computer.PartOfDomain)
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$ownNetworks = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter -and "$($_.NetAdapter.Status)" -eq 'Up' } | ForEach-Object {
        $adapter = $_
        @($_.IPv4Address | Where-Object { $_.IPAddress -notlike '169.254.*' }) | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength) ($($adapter.InterfaceAlias))" }
    })

$form = New-Object System.Windows.Forms.Form
$form.Text = 'MOSE IT audit'
$form.Size = New-Object System.Drawing.Size(960, [math]::Min(880, [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height - 20))
$form.MinimumSize = New-Object System.Drawing.Size(960, 640)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

function New-AuditLabel {
    param([object]$Parent, [string]$Text, [int]$X, [int]$Y, [int]$Width = 120)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point($X, $Y)
    $label.Size = New-Object System.Drawing.Size($Width, 20)
    $Parent.Controls.Add($label)
    return $label
}

function New-AuditTextBox {
    param([object]$Parent, [int]$X, [int]$Y, [int]$Width, [string]$Text = '', [switch]$Secret)
    $box = New-Object System.Windows.Forms.TextBox
    $box.Location = New-Object System.Drawing.Point($X, $Y)
    $box.Width = $Width
    $box.Text = $Text
    $box.UseSystemPasswordChar = [bool]$Secret
    $Parent.Controls.Add($box)
    return $box
}

function New-AuditCheckBox {
    param([object]$Parent, [string]$Text, [int]$X, [int]$Y, [int]$Width, [bool]$Checked = $true)
    $box = New-Object System.Windows.Forms.CheckBox
    $box.Text = $Text
    $box.Location = New-Object System.Drawing.Point($X, $Y)
    $box.Size = New-Object System.Drawing.Size($Width, 22)
    $box.Checked = $Checked
    $Parent.Controls.Add($box)
    return $box
}

function New-AuditButton {
    param([object]$Parent, [string]$Text, [int]$X, [int]$Width = 140)
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Location = New-Object System.Drawing.Point($X, 6)
    $button.Size = New-Object System.Drawing.Size($Width, 28)
    $Parent.Controls.Add($button)
    return $button
}

function New-AuditGroup {
    param([string]$Text, [int]$Height)
    $group = New-Object System.Windows.Forms.GroupBox
    $group.Text = $Text
    $group.Dock = 'Top'
    $group.Height = $Height
    $auditPage.Controls.Add($group)
    return $group
}

# The "To complete on site" section of an audit: its lines, where it starts, where its items start, where
# it ends, and its items, each done, skipped or neither, with its note. $null when there is no section.
function Read-AuditChecklist {
    param([string]$Path)

    $lines = [System.IO.File]::ReadAllLines($Path)
    $start = [array]::IndexOf($lines, '## To complete on site')
    if ($start -lt 0) {
        return $null
    }
    $end = $lines.Count
    for ($index = $start + 1; $index -lt $lines.Count; $index++) {
        if ($lines[$index].StartsWith('## ')) {
            $end = $index
            break
        }
    }
    $items = New-Object System.Collections.Generic.List[object]
    $first = $end
    for ($index = $start + 1; $index -lt $end; $index++) {
        if ($lines[$index] -match '^- \[(?<mark>[ xX])\] (?<text>.*)$') {
            $first = [math]::Min($first, $index)
            $text = $Matches.text
            $done = $Matches.mark -ne ' '
            $skipped = $text -match '^~~(?<inner>.*)~~ \(skipped\)$'
            if ($skipped) {
                $text = $Matches.inner
                $done = $false
            }
            $items.Add([pscustomobject]@{ Text = $text; Done = $done; Skipped = $skipped; Note = '' })
        }
        elseif ($items.Count -gt 0 -and $lines[$index] -match '^\s+- Note: (?<note>.*)$') {
            $items[$items.Count - 1].Note = $Matches.note
        }
    }
    return [pscustomobject]@{ Lines = $lines; Start = $start; First = $first; End = $end; Items = $items.ToArray() }
}

# Writes the items into the audit's section: a done item ticked, a skipped one struck through, a note
# on a line under its item. The rest of the audit stays as it is in the file now.
function Write-AuditChecklist {
    param([string]$Path, [object[]]$Items)

    $read = Read-AuditChecklist $Path
    if (-not $read) {
        throw "$(Split-Path -Leaf $Path) has no ""To complete on site"" section."
    }
    $lines = New-Object System.Collections.Generic.List[string]
    # The heading and its text, then the items, then a blank line before the next section.
    for ($index = 0; $index -lt $read.First; $index++) {
        $lines.Add($read.Lines[$index])
    }
    foreach ($item in $Items) {
        $text = if ($item.Skipped) { "~~$($item.Text)~~ (skipped)" } else { $item.Text }
        $lines.Add("- [$(if ($item.Done) { 'x' } else { ' ' })] $text")
        if ($item.Note) {
            $lines.Add("  - Note: $($item.Note)")
        }
    }
    if ($read.End -lt $read.Lines.Count) {
        $lines.Add('')
    }
    for ($index = $read.End; $index -lt $read.Lines.Count; $index++) {
        $lines.Add($read.Lines[$index])
    }
    # As Audit.ps1 writes it: UTF-8 with its mark, Windows line ends.
    [System.IO.File]::WriteAllText($Path, ($lines -join "`r`n") + "`r`n", (New-Object System.Text.UTF8Encoding($true)))
}

# Two tabs, the audit and the on-site checklist of an audit written, over the status line. Controls
# are docked in reverse order of adding: what fills is added first, and the last group added is the top
# one.
$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$form.Controls.Add($tabs)
$auditPage = New-Object System.Windows.Forms.TabPage
$auditPage.Text = 'Audit'
$tabs.TabPages.Add($auditPage)
$checkPage = New-Object System.Windows.Forms.TabPage
$checkPage.Text = 'On-site checklist'
$tabs.TabPages.Add($checkPage)

$status = New-Object System.Windows.Forms.Label
$status.Dock = 'Bottom'
$status.Height = 22
$status.TextAlign = 'MiddleLeft'
$status.Text = 'Enter the answers, then Run the audit.'
$form.Controls.Add($status)

$log = New-Object System.Windows.Forms.TextBox
$log.Multiline = $true
$log.ReadOnly = $true
$log.ScrollBars = 'Vertical'
$log.Dock = 'Fill'
$log.Font = New-Object System.Drawing.Font('Consolas', 9)
$log.BackColor = [System.Drawing.SystemColors]::Window
$auditPage.Controls.Add($log)

$bar = New-Object System.Windows.Forms.Panel
$bar.Dock = 'Top'
$bar.Height = 40
$auditPage.Controls.Add($bar)
$runButton = New-AuditButton $bar 'Run the audit' 8 160
$stopButton = New-AuditButton $bar 'Stop' 176 90
$openAudit = New-AuditButton $bar 'Open the audit' 300 140
$openDiagram = New-AuditButton $bar 'Open the diagram' 448 140
$openFolder = New-AuditButton $bar 'Open the folder' 596 140
$stopButton.Enabled = $false
$openAudit.Enabled = $false
$openDiagram.Enabled = $false

$cloud = New-AuditGroup 'Microsoft 365 and public domains' 82
$tenantLabel = New-AuditLabel $cloud 'Tenant (optional)' 12 24
$tenantBox = New-AuditTextBox $cloud 140 20 260 $Tenant
[void](New-AuditLabel $cloud 'Its domain; needed with a partner (CSP) account. Global Reader is enough.' 412 24 520)
$domainsLabel = New-AuditLabel $cloud 'Public domains' 12 52
$domainsBox = New-AuditTextBox $cloud 140 48 260 (@($Domain) -join ', ')
[void](New-AuditLabel $cloud 'Comma-separated; those of Active Directory and Microsoft 365 are added.' 412 52 520)

$accounts = New-AuditGroup 'Accounts (empty: the Windows user running the audit)' 136
[void](New-AuditLabel $accounts 'Domain controller' 12 24)
$serverBox = New-AuditTextBox $accounts 140 20 260 $ADServer
[void](New-AuditLabel $accounts 'Empty: the domain of this computer, or the first controller the scan finds.' 412 24 520)
[void](New-AuditLabel $accounts 'Domain account' 12 52)
$adUser = New-AuditTextBox $accounts 140 48 260 $(if ($ADCredential) { $ADCredential.UserName })
[void](New-AuditLabel $accounts 'Password' 412 52 70)
$adPassword = New-AuditTextBox $accounts 486 48 200 $(if ($ADCredential) { $ADCredential.GetNetworkCredential().Password }) -Secret
[void](New-AuditLabel $accounts 'DOMAIN\user, any user (Active Directory)' 698 52 240)
[void](New-AuditLabel $accounts 'Administrator' 12 80)
$adminUser = New-AuditTextBox $accounts 140 76 260 $(if ($AdminCredential) { $AdminCredential.UserName })
[void](New-AuditLabel $accounts 'Password' 412 80 70)
$adminPassword = New-AuditTextBox $accounts 486 76 200 $(if ($AdminCredential) { $AdminCredential.GetNetworkCredential().Password }) -Secret
[void](New-AuditLabel $accounts 'of the servers and computers' 698 80 240)
[void](New-AuditLabel $accounts $(if ($inDomain) { "This computer is in the domain $($computer.Domain): empty accounts read it as $currentUser." } else { "This computer is not in a domain: give a domain account and an administrator account, from the password manager." }) 12 108 920)

$net = New-AuditGroup 'Network' 158
[void](New-AuditLabel $net 'This computer' 12 24 140)
[void](New-AuditLabel $net $(if ($ownNetworks.Count) { $ownNetworks -join ', ' } else { 'none with a gateway' }) 156 24 776)
[void](New-AuditLabel $net 'Instead of them' 12 52 140)
$subnetBox = New-AuditTextBox $net 156 48 300 (@($Subnet) -join ', ')
[void](New-AuditLabel $net 'Also' 470 52 40)
$addSubnetBox = New-AuditTextBox $net 512 48 300 (@($AddSubnet) -join ', ')
[void](New-AuditLabel $net '192.0.2.0/24, 192.0.2.10-50 or an address; at most a /16 each.' 156 74 600)
$scanOthers = New-AuditCheckBox $net 'Then scan the other networks seen from here (routes, DNS servers, a router''s own networks), up to 1024 addresses each' 12 96 920 ([bool]$ScanOtherNetworks)
[void](New-AuditLabel $net 'SNMP community' 12 128 140)
$snmpBox = New-AuditTextBox $net 156 124 300 (@($SnmpCommunity) -join ', ') -Secret
[void](New-AuditLabel $net 'From the password manager; never written. Empty: only "public".' 470 128 460)

$parts = New-AuditGroup 'Parts of the audit' 52
$partNetwork = New-AuditCheckBox $parts 'Network' 12 22 90 ($Skip -notcontains 'Network')
$partSpeed = New-AuditCheckBox $parts 'Speed test' 106 22 100 ($Skip -notcontains 'SpeedTest')
$partAD = New-AuditCheckBox $parts 'Active Directory' 210 22 130 ($Skip -notcontains 'ActiveDirectory')
$partInventory = New-AuditCheckBox $parts 'Servers and computers' 344 22 170 ($Skip -notcontains 'Inventory')
$partM365 = New-AuditCheckBox $parts 'Microsoft 365' 518 22 120 ($Skip -notcontains 'Microsoft365')
$partDomains = New-AuditCheckBox $parts 'Domains and e-mail' 642 22 160 ($Skip -notcontains 'Domains')

$clientGroup = New-AuditGroup 'Client' 56
[void](New-AuditLabel $clientGroup 'Name' 12 24 60)
$clientBox = New-AuditTextBox $clientGroup 76 20 260 $Client
[void](New-AuditLabel $clientGroup 'Folder' 352 24 50)
$folderBox = New-AuditTextBox $clientGroup 404 20 420 $OutputPath
$browse = New-Object System.Windows.Forms.Button
$browse.Text = 'Browse...'
$browse.Location = New-Object System.Drawing.Point(832, 19)
$browse.Size = New-Object System.Drawing.Size(90, 24)
$clientGroup.Controls.Add($browse)

# The on-site checklist: an audit of the folder, its items to tick, skip and note.
$checkGrid = New-Object System.Windows.Forms.DataGridView
$checkGrid.Dock = 'Fill'
$checkGrid.AllowUserToAddRows = $false
$checkGrid.AllowUserToDeleteRows = $false
$checkGrid.AllowUserToResizeRows = $false
$checkGrid.RowHeadersVisible = $false
$checkGrid.SelectionMode = 'CellSelect'
$checkGrid.EditMode = 'EditOnEnter'
$checkGrid.AutoSizeRowsMode = 'AllCells'
$checkGrid.BackgroundColor = [System.Drawing.SystemColors]::Window
$doneColumn = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$doneColumn.HeaderText = 'Done'
$doneColumn.Width = 48
$skipColumn = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$skipColumn.HeaderText = 'Skip'
$skipColumn.Width = 48
$itemColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$itemColumn.HeaderText = 'To complete on site'
$itemColumn.ReadOnly = $true
$itemColumn.AutoSizeMode = 'Fill'
$itemColumn.DefaultCellStyle.WrapMode = 'True'
$noteColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$noteColumn.HeaderText = 'Note'
$noteColumn.Width = 300
$noteColumn.DefaultCellStyle.WrapMode = 'True'
$checkGrid.Columns.AddRange([System.Windows.Forms.DataGridViewColumn[]]@($doneColumn, $skipColumn, $itemColumn, $noteColumn))
$checkPage.Controls.Add($checkGrid)
$checkInfo = New-AuditLabel $checkPage 'Each change is saved in the audit at once: a done item ticked, a skipped one struck through, its note on a line under it. Hide only hides them here.' 0 0 900
$checkInfo.Dock = 'Bottom'
$checkInfo.Height = 24
$checkBar = New-Object System.Windows.Forms.Panel
$checkBar.Dock = 'Top'
$checkBar.Height = 64
$checkPage.Controls.Add($checkBar)
[void](New-AuditLabel $checkBar 'Audit' 8 12 50)
$auditList = New-Object System.Windows.Forms.ComboBox
$auditList.DropDownStyle = 'DropDownList'
$auditList.Location = New-Object System.Drawing.Point(60, 8)
$auditList.Width = 600
$checkBar.Controls.Add($auditList)
$browseAudit = New-AuditButton $checkBar 'Browse...' 670 100
$openChecklist = New-AuditButton $checkBar 'Open in Notepad' 778 140
$hideBox = New-AuditCheckBox $checkBar 'Hide what is done or skipped' 60 36 240 $false
$countLabel = New-AuditLabel $checkBar '' 310 38 600

$addLog = {
    param([string]$Text)
    $log.AppendText(("$Text" -replace '\r?\n', "`r`n") + "`r`n")
}
$tell = {
    param([string]$Text, [string]$Icon = 'Warning')
    [void][System.Windows.Forms.MessageBox]::Show($form, $Text, 'MOSE IT audit', 'OK', $Icon)
}
# What depends on a part is only there when the part runs.
$setEnabled = {
    $partSpeed.Enabled = $partNetwork.Checked
    $net.Enabled = $partNetwork.Checked
    $accounts.Enabled = $partAD.Checked -or $partInventory.Checked
    $tenantBox.Enabled = $partM365.Checked
    $tenantLabel.Enabled = $partM365.Checked
    $domainsBox.Enabled = $partDomains.Checked
    $domainsLabel.Enabled = $partDomains.Checked
}
foreach ($box in $partNetwork, $partAD, $partInventory, $partM365, $partDomains) {
    $box.Add_CheckedChanged($setEnabled)
}
& $setEnabled

$split = { param([string]$Text) @($Text -split '[,;\s]+' | Where-Object { $_ }) }
# The account of a user box and a hidden password box, or $null when the user is empty.
$credential = {
    param([System.Windows.Forms.TextBox]$UserBox, [System.Windows.Forms.TextBox]$HiddenBox, [string]$What)
    if (-not $UserBox.Text.Trim()) {
        return $null
    }
    if (-not $HiddenBox.TextLength) {
        throw "The $What has no password."
    }
    $secure = New-Object System.Security.SecureString
    foreach ($character in $HiddenBox.Text.ToCharArray()) {
        $secure.AppendChar($character)
    }
    return New-Object System.Management.Automation.PSCredential($UserBox.Text.Trim(), $secure)
}

# The answers as the audit's options. Throws what is missing or wrong, for the message box.
$getParameters = {
    $parameters = @{ NonInteractive = $true; NoOpen = $true }
    if (-not $clientBox.Text.Trim()) {
        throw 'Enter the name of the client: it is the title and the file name of the audit.'
    }
    $parameters.Client = $clientBox.Text.Trim()
    if (-not (Test-Path -LiteralPath $folderBox.Text.Trim() -PathType Container)) {
        throw "The folder $($folderBox.Text.Trim()) does not exist."
    }
    $parameters.OutputPath = $folderBox.Text.Trim()
    $skipped = @()
    if (-not $partNetwork.Checked) { $skipped += 'Network' }
    if (-not $partSpeed.Checked -or -not $partNetwork.Checked) { $skipped += 'SpeedTest' }
    if (-not $partAD.Checked) { $skipped += 'ActiveDirectory' }
    if (-not $partInventory.Checked) { $skipped += 'Inventory' }
    if (-not $partM365.Checked) { $skipped += 'Microsoft365' }
    if (-not $partDomains.Checked) { $skipped += 'Domains' }
    if ($skipped.Count -ge 6) {
        throw 'Every part is turned off: nothing to audit.'
    }
    if ($skipped.Count) {
        $parameters.Skip = $skipped
    }
    if ($partNetwork.Checked) {
        foreach ($field in @(@{ Box = $subnetBox; Name = 'Subnet' }, @{ Box = $addSubnetBox; Name = 'AddSubnet' })) {
            $networks = & $split $field.Box.Text
            $wrong = @($networks | Where-Object { $_ -notmatch '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2}|-\d{1,3}(\.\d{1,3}){3}|-\d{1,3})?$' })
            if ($wrong.Count) {
                throw "Not a network, range or address: $($wrong -join ', '). Write them as 192.0.2.0/24, 192.0.2.10-50 or 192.0.2.10."
            }
            if ($networks.Count) {
                $parameters[$field.Name] = $networks
            }
        }
        if ($scanOthers.Checked) {
            $parameters.ScanOtherNetworks = $true
        }
        if ($snmpBox.Text.Trim()) {
            $parameters.SnmpCommunity = @(& $split $snmpBox.Text)
        }
    }
    if ($partAD.Checked -or $partInventory.Checked) {
        if ($serverBox.Text.Trim()) {
            $parameters.ADServer = $serverBox.Text.Trim()
        }
        $account = & $credential $adUser $adPassword 'domain account'
        if ($account) {
            $parameters.ADCredential = $account
        }
        $account = & $credential $adminUser $adminPassword 'administrator account'
        if ($account) {
            $parameters.AdminCredential = $account
        }
    }
    if ($partM365.Checked) {
        $parameters.Microsoft365 = $true
        if ($tenantBox.Text.Trim()) {
            $parameters.Tenant = $tenantBox.Text.Trim()
        }
    }
    if ($partDomains.Checked -and $domainsBox.Text.Trim()) {
        $parameters.Domain = & $split $domainsBox.Text
    }
    return $parameters
}

# Shows what the audit wrote since the last tick: its messages (Write-Host), warnings and errors in the
# log, its progress in the status line.
$showStreams = {
    $shell = $ui.Shell
    foreach ($stream in 'Information', 'Warning', 'Error') {
        $items = $shell.Streams.$stream
        for ($index = [int]$ui.Shown[$stream]; $index -lt $items.Count; $index++) {
            $item = $items[$index]
            switch ($stream) {
                'Information' { & $addLog "$($item.MessageData)" }
                'Warning' { & $addLog "WARNING: $($item.Message)" }
                'Error' { & $addLog "ERROR: $($item.Exception.Message)" }
            }
        }
        $ui.Shown[$stream] = $items.Count
    }
    $progress = $shell.Streams.Progress
    if ($progress.Count -gt 0) {
        $record = $progress[$progress.Count - 1]
        $status.Text = if ("$($record.RecordType)" -eq 'Completed') { 'Running...' } else { "$($record.Activity): $($record.StatusDescription)" }
        $progress.Clear()
    }
}

$setRunning = {
    param([bool]$Running)
    $runButton.Enabled = -not $Running
    $stopButton.Enabled = $Running
    foreach ($group in $clientGroup, $parts, $net, $accounts, $cloud) {
        $group.Enabled = -not $Running
    }
    if (-not $Running) {
        & $setEnabled
    }
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 300
$timer.Add_Tick({
        if (-not $ui.Shell) {
            return
        }
        & $showStreams
        if (-not $ui.Handle.IsCompleted) {
            return
        }
        $timer.Stop()
        try {
            [void]$ui.Shell.EndInvoke($ui.Handle)
        }
        catch {
            & $addLog "ERROR: $($_.Exception.Message)"
        }
        & $showStreams
        $stopped = "$($ui.Shell.InvocationStateInfo.State)" -eq 'Stopped'
        $ui.Shell.Runspace.Dispose()
        $ui.Shell.Dispose()
        $ui.Shell = $null
        # The audit just written: the newest of its client in the folder.
        $ui.Markdown = Get-ChildItem -LiteralPath $folderBox.Text.Trim() -Filter '*_Audit_*.md' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $ui.Started } | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
        $ui.Diagram = if ($ui.Markdown) { Get-Item -LiteralPath ($ui.Markdown.FullName -replace '\.md$', '.drawio') -ErrorAction SilentlyContinue }
        $openAudit.Enabled = [bool]$ui.Markdown
        $openDiagram.Enabled = [bool]$ui.Diagram
        & $setRunning $false
        if ($ui.Markdown) {
            & $loadAudits $ui.Markdown.FullName
        }
        $status.Text = if ($stopped) { 'Stopped.' } elseif ($ui.Markdown) { "Done in $([math]::Round(((Get-Date) - $ui.Started).TotalMinutes, 1)) minutes: $($ui.Markdown.Name). Its on-site checklist is in the second tab." } else { 'The audit ended without writing its file: see above.' }
    })

$runButton.Add_Click({
        try {
            $parameters = & $getParameters
        }
        catch {
            & $tell $_.Exception.Message
            return
        }
        # Microsoft 365 is read with a module that its part would ask to install, which it can't from here.
        $installGraph = $false
        if ($parameters.Microsoft365 -and -not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
            $answer = [System.Windows.Forms.MessageBox]::Show($form, 'Microsoft 365 is read with the Microsoft Graph PowerShell module (Microsoft.Graph.Authentication), not installed here. Install it for this Windows user from the PowerShell Gallery?', 'MOSE IT audit', 'YesNo', 'Question')
            if ("$answer" -ne 'Yes') {
                $partM365.Checked = $false
                & $tell 'Microsoft 365 is turned off: run the audit again to read the other parts.' 'Information'
                return
            }
            $installGraph = $true
        }
        $log.Clear()
        & $addLog "Audit of $($parameters.Client), started $(Get-Date -Format 'yyyy-MM-dd HH:mm')."
        $ui.Started = (Get-Date).AddSeconds(-1)
        $ui.Shown = @{}
        $openAudit.Enabled = $false
        $openDiagram.Enabled = $false
        # Its own runspace, so that the window keeps answering; STA for the Microsoft 365 sign-in window.
        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.ApartmentState = 'STA'
        $runspace.Open()
        $shell = [powershell]::Create()
        $shell.Runspace = $runspace
        [void]$shell.AddScript({
                param([string]$Audit, [hashtable]$Parameters, [bool]$InstallGraph)
                if ($InstallGraph) {
                    Write-Host 'Installing Microsoft.Graph.Authentication for this Windows user...'
                    Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
                }
                & $Audit @Parameters
            }).AddArgument($auditScript).AddArgument($parameters).AddArgument($installGraph)
        $ui.Shell = $shell
        $ui.Handle = $shell.BeginInvoke()
        & $setRunning $true
        $status.Text = 'Running...'
        $timer.Start()
    })

$stopButton.Add_Click({
        if ($ui.Shell) {
            & $addLog 'Stopping...'
            [void]$ui.Shell.BeginStop($null, $null)
        }
    })

$openAudit.Add_Click({
        if ($ui.Markdown) {
            Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$($ui.Markdown.FullName)`""
        }
    })

$openDiagram.Add_Click({
        if ($ui.Diagram) {
            try {
                Invoke-Item -LiteralPath $ui.Diagram.FullName
            }
            catch {
                & $tell "No program opens .drawio files on this computer: install draw.io (diagrams.net), or the Draw.io Integration of VS Code, then open $($ui.Diagram.FullName)."
            }
        }
    })

$openFolder.Add_Click({
        if ($ui.Markdown) {
            Start-Process -FilePath 'explorer.exe' -ArgumentList "/select,`"$($ui.Markdown.FullName)`""
        }
        elseif (Test-Path -LiteralPath $folderBox.Text.Trim() -PathType Container) {
            Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$($folderBox.Text.Trim())`""
        }
    })

$browse.Add_Click({
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = 'Folder of the audit files'
        $dialog.SelectedPath = $folderBox.Text.Trim()
        if ("$($dialog.ShowDialog($form))" -eq 'OK') {
            $folderBox.Text = $dialog.SelectedPath
        }
    })

# The checklist's counts: done, skipped and left.
$countItems = {
    if (-not $ui.Checklist) {
        return
    }
    $rows = @($checkGrid.Rows)
    $done = @($rows | Where-Object { $_.Cells[0].Value -eq $true }).Count
    $skipped = @($rows | Where-Object { $_.Cells[1].Value -eq $true }).Count
    $countLabel.Text = "$done of $($rows.Count) done, $skipped skipped, $($rows.Count - $done - $skipped) left."
}

$applyHide = {
    [void]$checkGrid.EndEdit()
    $checkGrid.CurrentCell = $null
    foreach ($row in $checkGrid.Rows) {
        $row.Visible = -not ($hideBox.Checked -and ($row.Cells[0].Value -eq $true -or $row.Cells[1].Value -eq $true))
    }
}

# The items of the audit chosen, from its file.
$showChecklist = {
    $ui.Loading = $true
    $checkGrid.Rows.Clear()
    $ui.Checklist = $null
    $countLabel.Text = ''
    if ($auditList.SelectedIndex -ge 0) {
        $path = $ui.AuditFiles[$auditList.SelectedIndex]
        try {
            $read = Read-AuditChecklist $path
            if ($read) {
                $ui.Checklist = $path
                foreach ($item in $read.Items) {
                    [void]$checkGrid.Rows.Add($item.Done, $item.Skipped, $item.Text, $item.Note)
                }
            }
            else {
                $countLabel.Text = 'This audit has no "To complete on site" section.'
            }
        }
        catch {
            & $tell "The audit could not be read: $($_.Exception.Message)"
        }
    }
    $ui.Loading = $false
    & $applyHide
    & $countItems
}

# The audits of the folder, the newest first, and Select (an audit found elsewhere) in front.
$loadAudits = {
    param([string]$Select)
    $ui.Loading = $true
    $files = @(Get-ChildItem -LiteralPath $folderBox.Text.Trim() -Filter '*_Audit_*.md' -ErrorAction SilentlyContinue | Sort-Object -Property LastWriteTime -Descending | ForEach-Object { $_.FullName })
    if ($Select -and $files -notcontains $Select) {
        $files = @($Select) + $files
    }
    $ui.AuditFiles = $files
    $auditList.Items.Clear()
    foreach ($file in $files) {
        [void]$auditList.Items.Add("$(Split-Path -Leaf $file)   ($(Split-Path -Parent $file))")
    }
    if ($files.Count -gt 0) {
        $auditList.SelectedIndex = [math]::Max(0, [array]::IndexOf($files, $Select))
    }
    $ui.Loading = $false
    & $showChecklist
    if ($files.Count -eq 0) {
        $countLabel.Text = 'No audit in the folder of the Audit tab yet: run one, or Browse.'
    }
}

$saveChecklist = {
    if (-not $ui.Checklist) {
        return
    }
    $items = @(foreach ($row in $checkGrid.Rows) {
            [pscustomobject]@{
                Done    = $row.Cells[0].Value -eq $true
                Skipped = $row.Cells[1].Value -eq $true
                Text    = "$($row.Cells[2].Value)"
                Note    = ("$($row.Cells[3].Value)" -replace '\s*[\r\n]+\s*', ' ').Trim()
            }
        })
    try {
        Write-AuditChecklist -Path $ui.Checklist -Items $items
        $status.Text = "Saved in $(Split-Path -Leaf $ui.Checklist) at $(Get-Date -Format 'HH:mm:ss')."
    }
    catch {
        & $tell "The checklist could not be saved in the audit: $($_.Exception.Message)"
    }
}

# A tick is saved at once, not only when its cell is left.
$checkGrid.Add_CurrentCellDirtyStateChanged({
        if ($checkGrid.IsCurrentCellDirty -and $checkGrid.CurrentCell -is [System.Windows.Forms.DataGridViewCheckBoxCell]) {
            [void]$checkGrid.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
        }
    })

$checkGrid.Add_CellValueChanged({
        param($grid, $change)
        if ($ui.Loading -or $change.RowIndex -lt 0) {
            return
        }
        $row = $checkGrid.Rows[$change.RowIndex]
        # Done and skipped exclude each other.
        if ($change.ColumnIndex -le 1 -and $row.Cells[$change.ColumnIndex].Value -eq $true) {
            $ui.Loading = $true
            $row.Cells[1 - $change.ColumnIndex].Value = $false
            $ui.Loading = $false
        }
        & $saveChecklist
        & $countItems
        # After the grid has ended this change: hiding the current row now would be refused.
        if ($change.ColumnIndex -le 1 -and $hideBox.Checked) {
            [void]$form.BeginInvoke([System.Action]$applyHide)
        }
    })

$hideBox.Add_CheckedChanged({ & $applyHide })

$auditList.Add_SelectedIndexChanged({
        if (-not $ui.Loading) {
            & $showChecklist
        }
    })

$tabs.Add_SelectedIndexChanged({
        if ($tabs.SelectedTab -eq $checkPage) {
            & $loadAudits $ui.Checklist
        }
    })

$browseAudit.Add_Click({
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = 'An audit written by MOSE'
        $dialog.Filter = 'Audits (*_Audit_*.md)|*_Audit_*.md|Markdown (*.md)|*.md'
        $dialog.InitialDirectory = $folderBox.Text.Trim()
        if ("$($dialog.ShowDialog($form))" -eq 'OK') {
            & $loadAudits $dialog.FileName
        }
    })

$openChecklist.Add_Click({
        if ($ui.Checklist) {
            Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$($ui.Checklist)`""
        }
    })

$form.Add_FormClosing({
        param($window, $closing)
        if ($ui.Shell) {
            $answer = [System.Windows.Forms.MessageBox]::Show($form, 'The audit is still running. Stop it and close the window?', 'MOSE IT audit', 'YesNo', 'Question')
            if ("$answer" -ne 'Yes') {
                $closing.Cancel = $true
                return
            }
            $timer.Stop()
            # Not waited for: a computer that doesn't answer would keep the window open.
            [void]$ui.Shell.BeginStop($null, $null)
        }
    })

& $addLog 'The audit reads the network, Active Directory, the Windows servers and computers, Microsoft 365 and the public domains.'
& $addLog 'Agree on the network scan with the client first: a firewall or intrusion detection may report it.'
[void]$form.ShowDialog()
$timer.Stop()
$form.Dispose()
