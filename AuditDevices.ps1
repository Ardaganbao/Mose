# Read a discovered device in depth with the MOSE report module that already knows it. After the
# network scan a device typed as an iLO, iDRAC, Synology NAS, ESXi host... can be read further by
# iloreport.ps1, nas2.ps1, vmwarereport.ps1 and so on. The audit collects a login for it (kept in
# memory only, never written to the audit), runs the module in a PowerShell of its own so a missing
# prerequisite (PowerCLI, the Veeam module) or a crash loses only that device, and adds the module's
# report section to the audit. The parameter shapes mirror Report.ps1's own (Invoke-MoseModule), so
# the audit stays independent of the report (no vault, no helper.ps1).
#
# Audit.ps1 and AuditWindow.ps1 dot-source this; tests\Test-AuditDevices.ps1 checks it. It reads no
# vault. Set-StrictMode is left as the caller set it.

# Module key -> how to read it. Types: the device types (Get-DeviceType of AuditNetwork.ps1) the scan
# maps here. Manual: not found by the scan, only added by hand (the GUI, or a given address). Needs: a
# short note on a prerequisite, shown when it is missing.
$auditDeviceModules = [ordered]@{
    'iLO'    = @{ Label = 'HPE iLO'; Script = 'iloreport.ps1'; Types = @('Server management (iLO)'); Manual = $false; Needs = '' }
    'iDRAC'  = @{ Label = 'Dell iDRAC'; Script = 'IDRAC.ps1'; Types = @('Server management (iDRAC)'); Manual = $false; Needs = '' }
    'BMC'    = @{ Label = 'Lenovo BMC / XClarity'; Script = 'BMCreport.ps1'; Types = @('Server management (BMC)', 'Server management (XClarity)'); Manual = $false; Needs = '' }
    'NAS'    = @{ Label = 'Synology NAS'; Script = 'nas2.ps1'; Types = @('NAS (Synology)'); Manual = $false; Needs = '' }
    'VMware' = @{ Label = 'VMware ESXi / vCenter'; Script = 'vmwarereport.ps1'; Types = @('Hypervisor (VMware ESXi)', 'VMware vCenter'); Manual = $false; Needs = 'the VMware PowerCLI module (installed on first use)' }
    'Veeam'  = @{ Label = 'Veeam Backup & Replication'; Script = 'VeeamRestReport.ps1'; Types = @('Backup server (Veeam)'); Manual = $false; Needs = '' }
    'HyperV' = @{ Label = 'Microsoft Hyper-V host'; Script = 'hypervreport.ps1'; Types = @(); Manual = $true; Needs = 'PowerShell remoting to the host' }
    'SQL'    = @{ Label = 'SQL Server maintenance plans'; Script = 'sqlmaintenance.ps1'; Types = @(); Manual = $true; Needs = 'access to the SQL Server' }
}

# The module key that reads a device of this type, or $null when none does.
function Get-AuditDeviceModule {
    param(
        [string]$Type
    )

    foreach ($key in $auditDeviceModules.Keys) {
        if ($auditDeviceModules[$key].Types -contains $Type) {
            return $key
        }
    }
    return $null
}

# The named parameters to splat to a module, from one login (a PSCredential) and the client and site.
# Mirrors Report.ps1's Invoke-MoseModule: a credential for iLO/iDRAC/BMC/Veeam/Hyper-V/SQL, a user and
# a secure password for the NAS and VMware. The hashtable (with the credential or password inside) is
# what Invoke-AuditDeviceModule hands to the module.
function ConvertTo-AuditModuleParameters {
    param(
        [string]$Key,
        [string]$Server,
        [pscredential]$Credential,
        [string]$Client = 'Client',
        [string]$Site = 'main'
    )

    switch ($Key) {
        { $_ -in 'iLO', 'iDRAC', 'BMC' } {
            return @{ server = $Server; credential = $Credential }
        }
        'NAS' {
            return @{ server = $Server; user = $Credential.UserName; pass = $Credential.Password }
        }
        'VMware' {
            return @{ server = $Server; user = $Credential.UserName; pass = $Credential.Password; Client = $Client; Site = $Site }
        }
        'Veeam' {
            return @{ Server = $Server; Credential = $Credential }
        }
        'HyperV' {
            return @{ Server = $Server; Credential = $Credential; Site = $Site }
        }
        'SQL' {
            return @{ Server = $Server; Credential = $Credential }
        }
    }
    throw "No module is known for '$Key'."
}

# The devices to read in depth, from the scan and the logins given by hand. Each scanned device whose
# type a module reads becomes a target; each given login for an address the scan did not surface (a
# Hyper-V host, a vCenter by name, a SQL Server) is added too. One target per address, in that order.
# $Devices: the scan's device objects (Address, Name, Type). $DeviceLogin: @{ Key; Address; Credential }.
function Get-AuditDeviceTargets {
    param(
        [object[]]$Devices = @(),
        [object[]]$DeviceLogin = @()
    )

    $targets = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($device in @($Devices)) {
        $key = Get-AuditDeviceModule "$($device.Type)"
        $address = "$($device.Address)"
        if ($key -and $address -and -not $seen[$address]) {
            $targets.Add([pscustomobject]@{ Key = $key; Address = $address; Name = "$($device.Name)"; Label = $auditDeviceModules[$key].Label })
            $seen[$address] = $true
        }
    }
    foreach ($login in @($DeviceLogin)) {
        $key = "$($login.Key)"
        $address = "$($login.Address)"
        if ($address -and -not $seen[$address] -and $auditDeviceModules.Contains($key)) {
            $targets.Add([pscustomobject]@{ Key = $key; Address = $address; Name = ''; Label = $auditDeviceModules[$key].Label })
            $seen[$address] = $true
        }
    }
    # .ToArray(), not @($targets): Windows PowerShell throws on @() around a List[object].
    return $targets.ToArray()
}

# The login for a target among those given by hand: the one for its address, else the one for its module
# type with no address, else $null (the console then asks).
function Get-AuditDeviceLogin {
    param(
        [object]$Target,
        [object[]]$DeviceLogin = @()
    )

    $match = @($DeviceLogin | Where-Object { "$($_.Address)" -eq "$($Target.Address)" -and $_.Credential }) | Select-Object -First 1
    if (-not $match) {
        $match = @($DeviceLogin | Where-Object { "$($_.Key)" -eq "$($Target.Key)" -and -not "$($_.Address)" -and $_.Credential }) | Select-Object -First 1
    }
    if ($match) {
        return $match.Credential
    }
    return $null
}

# What a child PowerShell runs: it imports the module path and the splat (which carries the login, as
# an encrypted same-user CLIXML file), runs the module, and writes only its Markdown (the strings it
# returns; the inventory objects are left out). <<SCRIPT>> and <<PARAMS>> are replaced with the paths.
$auditModuleProcessCode = @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Read-Base64([string]$Text) { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Text)) }
$script = Read-Base64 '<<SCRIPT>>'
$splat = Import-Clixml (Read-Base64 '<<PARAMS>>')
$result = [pscustomobject]@{ Markdown = @(); Error = $null }
try {
    $result.Markdown = @(& $script @splat | Where-Object { $_ -is [string] })
}
catch {
    $result.Error = "$($_.Exception.Message)"
}
[Console]::Out.WriteLine('AUDIT MODULE RESULT: ' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([System.Management.Automation.PSSerializer]::Serialize($result, 10))))
[Console]::Out.Flush()
'@

# Runs the module for one device in a PowerShell of its own, so a module that needs a component that is
# not here, or that ends its process, only loses this device. Returns @{ Markdown = <lines>; Error =
# <why, or $null> }. The login is written to a temporary CLIXML file (encrypted for this Windows user),
# passed to the child, and deleted straight after.
function Invoke-AuditDeviceModule {
    param(
        [string]$Key,
        [string]$Server,
        [pscredential]$Credential,
        [string]$Client = 'Client',
        [string]$Site = 'main',
        [string]$ScriptRoot = $PSScriptRoot
    )

    $module = $auditDeviceModules[$Key]
    if (-not $module) {
        return [pscustomobject]@{ Markdown = @(); Error = "No module is known for '$Key'." }
    }
    $scriptPath = Join-Path $ScriptRoot $module.Script
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        return [pscustomobject]@{ Markdown = @(); Error = "The module $($module.Script) is not here: run .\Start.ps1 -Audit to download the audit scripts." }
    }

    $splat = ConvertTo-AuditModuleParameters -Key $Key -Server $Server -Credential $Credential -Client $Client -Site $Site
    $paramsFile = Join-Path ([System.IO.Path]::GetTempPath()) "mose-audit-dev-$([guid]::NewGuid().ToString('N')).xml"
    try {
        # CLIXML keeps the secure password and the credential encrypted for this Windows user only.
        $splat | Export-Clixml -LiteralPath $paramsFile -Depth 5
        $code = $auditModuleProcessCode.Replace('<<SCRIPT>>', [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($scriptPath))).Replace('<<PARAMS>>', [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($paramsFile)))
        # Not -EncodedCommand, after which PowerShell writes its messages to the console as XML.
        $bootstrap = "& ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{0}'))))" -f [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($code))
        $start = New-Object System.Diagnostics.ProcessStartInfo
        $start.FileName = (Get-Process -Id $PID).Path
        $start.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"$bootstrap`""
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $process = [System.Diagnostics.Process]::Start($start)
        $result = $null
        try {
            $line = $process.StandardOutput.ReadLineAsync()
            while ($true) {
                if (-not $line.Wait(300)) {
                    continue
                }
                if ($null -eq $line.Result) {
                    break
                }
                if ($line.Result.StartsWith('AUDIT MODULE RESULT: ')) {
                    $result = [System.Management.Automation.PSSerializer]::Deserialize([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($line.Result.Substring(21))))
                }
                else {
                    Write-Host $line.Result
                }
                $line = $process.StandardOutput.ReadLineAsync()
            }
            $process.WaitForExit()
        }
        finally {
            if (-not $process.HasExited) {
                $process.Kill()
            }
        }
        if (-not $result) {
            return [pscustomobject]@{ Markdown = @(); Error = "its PowerShell ended without finishing (exit code $($process.ExitCode))." }
        }
        return [pscustomobject]@{ Markdown = @($result.Markdown); Error = $result.Error }
    }
    finally {
        Remove-Item -LiteralPath $paramsFile -Force -ErrorAction SilentlyContinue
    }
}
