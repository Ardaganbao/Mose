[CmdletBinding()]
param()

Set-StrictMode -Version Latest

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$ConfigPath = Join-Path $PSScriptRoot "updater.config.json"
# On/off state is per computer, so it is kept out of the repository (see .gitignore).
$StatePath = Join-Path $PSScriptRoot "scripts.local.json"
$PowerShellPath = (Get-Process -Id $PID).Path

$script:Queue = New-Object System.Collections.Queue
$script:Current = $null
$script:Log = ""
$script:Shown = ""
$script:Loading = $false

# A script runs unless it was unchecked on this computer.
function Get-TurnedOffScripts {
    if (-not (Test-Path $StatePath)) {
        return @()
    }

    return @((Get-Content -Path $StatePath -Raw | ConvertFrom-Json).PSObject.Properties |
        Where-Object { -not $_.Value } |
        ForEach-Object { $_.Name })
}

function Save-ScriptState {
    $state = [ordered]@{}
    foreach ($item in $list.Items) {
        $state[$item.Text] = $item.Checked
    }

    $state | ConvertTo-Json | Set-Content -Path $StatePath -Encoding utf8
}

function Import-ScriptList {
    $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    $turnedOff = Get-TurnedOffScripts

    $script:Loading = $true
    $list.Items.Clear()

    foreach ($name in $config.Scripts) {
        $item = New-Object System.Windows.Forms.ListViewItem($name)
        $item.SubItems.Add("") | Out-Null
        $item.SubItems.Add("") | Out-Null
        $item.Checked = $turnedOff -notcontains $name
        $list.Items.Add($item) | Out-Null
    }

    $script:Loading = $false
}

function Set-ItemStatus {
    param(
        [object]$Item,
        [string]$Status,
        [string]$LastRun
    )

    if (-not $Item) {
        return
    }

    $Item.SubItems[1].Text = $Status
    if ($LastRun) {
        $Item.SubItems[2].Text = $LastRun
    }
}

function Show-Output {
    param(
        [string]$Text
    )

    if ($Text -eq $script:Shown) {
        return
    }

    $script:Shown = $Text
    $output.Text = $Text
    $output.SelectionStart = $output.TextLength
    $output.ScrollToCaret()
}

function Read-JobOutput {
    param(
        [hashtable]$Job
    )

    # The script is still writing to the file, so open it with shared access.
    try {
        $stream = New-Object System.IO.FileStream($Job.OutFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $reader = New-Object System.IO.StreamReader($stream, $true)
        try {
            return $reader.ReadToEnd()
        }
        finally {
            $reader.Dispose()
        }
    }
    catch {
        return ""
    }
}

function Add-Job {
    param(
        [string]$Label,
        [string]$Path,
        [string]$Arguments = "",
        [object]$Item,
        [switch]$ReloadList,
        [switch]$Hidden
    )

    $script:Queue.Enqueue(@{ Label = $Label; Path = $Path; Arguments = $Arguments; Item = $Item; ReloadList = [bool]$ReloadList; Hidden = [bool]$Hidden })
    Set-ItemStatus -Item $Item -Status "Waiting..."
    Start-NextJob
}

function Start-NextJob {
    if ($script:Current -or $script:Queue.Count -eq 0) {
        return
    }

    $job = $script:Queue.Dequeue()

    if (-not (Test-Path $job.Path)) {
        $script:Log += "=== $($job.Label)`r`nFile not found: $($job.Path)`r`n`r`n"
        Set-ItemStatus -Item $job.Item -Status "File not found"
        Show-Output $script:Log
        Start-NextJob
        return
    }

    # Run in a new PowerShell process; *>&1 | Tee-Object shows every stream, including Write-Host,
    # in its window and copies it to the file shown here.
    $job.OutFile = [System.IO.Path]::GetTempFileName()
    $scriptPath = $job.Path -replace "'", "''"
    $outFile = $job.OutFile -replace "'", "''"
    $title = $job.Label -replace "'", "''"
    $command = @"
`$Host.UI.RawUI.WindowTitle = '$title'
`$code = 0
try { & '$scriptPath' $($job.Arguments) *>&1 | Tee-Object -FilePath '$outFile'; if (`$LASTEXITCODE) { `$code = `$LASTEXITCODE } }
catch { `$_ *>> '$outFile'; `$code = 1 }
exit `$code
"@

    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $PowerShellPath
    $info.Arguments = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand " + [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
    if ($job.Hidden) {
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
    }
    else {
        # Reports ask for the vault password and any credential not yet saved, so they get
        # their own window (ShellExecute) instead of sharing the console that started this one.
        $info.UseShellExecute = $true
    }

    $job.Started = Get-Date
    $job.Process = [System.Diagnostics.Process]::Start($info)
    $script:Current = $job
    $script:Log += "=== $($job.Label)  ($($job.Started.ToString('HH:mm:ss')))`r`n"
    Set-ItemStatus -Item $job.Item -Status "Running..."
}

# Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "MOSE Script Manager"
$form.Size = New-Object System.Drawing.Size(780, 540)
$form.StartPosition = "CenterScreen"
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Controls are docked in reverse order of adding: the output fills what the list and buttons leave.
$output = New-Object System.Windows.Forms.TextBox
$output.Multiline = $true
$output.ReadOnly = $true
$output.ScrollBars = "Vertical"
$output.Dock = "Fill"
$output.Font = New-Object System.Drawing.Font("Consolas", 9)
$output.BackColor = [System.Drawing.SystemColors]::Window
$form.Controls.Add($output)

$buttons = New-Object System.Windows.Forms.FlowLayoutPanel
$buttons.Dock = "Top"
$buttons.AutoSize = $true
$buttons.Padding = New-Object System.Windows.Forms.Padding(4)
$form.Controls.Add($buttons)

$list = New-Object System.Windows.Forms.ListView
$list.View = "Details"
$list.CheckBoxes = $true
$list.FullRowSelect = $true
$list.HideSelection = $false
$list.Dock = "Top"
$list.Height = 200
$list.Columns.Add("Script (checked = runs with Start.ps1)", 320) | Out-Null
$list.Columns.Add("Status", 200) | Out-Null
$list.Columns.Add("Last run", 180) | Out-Null
$form.Controls.Add($list)

function Add-Button {
    param(
        [string]$Text,
        [scriptblock]$OnClick
    )

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.AutoSize = $true
    $button.Add_Click($OnClick)
    $buttons.Controls.Add($button)
}

function Start-ScriptItem {
    param(
        [object]$Item
    )

    Add-Job -Label $Item.Text -Path (Join-Path $PSScriptRoot $Item.Text) -Item $Item
}

Add-Button "Run selected" {
    $selected = @($list.SelectedItems)
    if ($selected.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Select a script in the list first.", "Script Manager") | Out-Null
        return
    }
    $selected | ForEach-Object { Start-ScriptItem $_ }
}

Add-Button "Run all turned on" {
    @($list.CheckedItems) | ForEach-Object { Start-ScriptItem $_ }
}

# Opens in its own window, like the reports, to ask for the servers and credentials.
Add-Button "Configure client" {
    Add-Job -Label "Configure client" -Path (Join-Path $PSScriptRoot "Configure.ps1")
}

Add-Button "Check for updates" {
    Add-Job -Label "Check for updates" -Path (Join-Path $PSScriptRoot "Start.ps1") -Arguments "-UpdateOnly" -ReloadList -Hidden
}

Add-Button "Clear output" {
    $script:Log = ""
    Show-Output ""
}

$list.Add_ItemChecked({
    if (-not $script:Loading) {
        Save-ScriptState
    }
})

$list.Add_ItemActivate({
    @($list.SelectedItems) | ForEach-Object { Start-ScriptItem $_ }
})

# Polls the running script for new output and starts the next queued one when it ends.
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 500
$timer.Add_Tick({
    $job = $script:Current
    if (-not $job) {
        return
    }

    $text = Read-JobOutput $job

    if (-not $job.Process.HasExited) {
        Show-Output ($script:Log + $text)
        return
    }

    $exitCode = $job.Process.ExitCode
    $lastRun = $job.Started.ToString("yyyy-MM-dd HH:mm:ss")
    if ($exitCode -eq 0) {
        $script:Log += $text + "--- Finished`r`n`r`n"
        Set-ItemStatus -Item $job.Item -Status "Finished" -LastRun $lastRun
    }
    else {
        $script:Log += $text + "--- Failed (exit code $exitCode)`r`n`r`n"
        Set-ItemStatus -Item $job.Item -Status "Failed (exit code $exitCode)" -LastRun $lastRun
    }

    Remove-Item -Path $job.OutFile -Force -ErrorAction SilentlyContinue
    $script:Current = $null

    if ($job.ReloadList) {
        Import-ScriptList
    }

    Show-Output $script:Log
    Start-NextJob
})

Import-ScriptList
$timer.Start()
[void]$form.ShowDialog()
$timer.Stop()
$form.Dispose()
