[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'Keep the test folder instead of deleting it.')]
    [switch]$Keep
)

# Tests of AuditDevices.ps1: the device-type -> module map, the parameter shapes it builds for each
# module, and the runner that reads a device in a PowerShell of its own. No real device is contacted:
# the modules are stand-ins in the test folder that only echo what they received. In Windows PowerShell,
# from the repository:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-AuditDevices.ps1

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
$repository = Split-Path -Parent $PSScriptRoot
$started = Get-Date
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:Passed = 0

function Test-Value {
    param([string]$Name, $Actual, $Expected)
    if ("$Actual" -ceq "$Expected") {
        $script:Passed++
        Write-Host "  ok    $Name" -ForegroundColor DarkGray
    }
    else {
        $script:Failures.Add($Name)
        Write-Host "  FAIL  $Name`n        got:      $Actual`n        expected: $Expected" -ForegroundColor Red
    }
}

function Test-That {
    param([string]$Name, [bool]$Condition, [string]$Detail)
    Test-Value -Name $Name -Actual $(if ($Condition) { 'yes' } else { "no$(if ($Detail) { ": $Detail" })" }) -Expected 'yes'
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n$Title" -ForegroundColor Cyan
}

. (Join-Path $repository 'AuditDevices.ps1')

# A folder of stand-in modules named as the real ones, so the runner finds them by the map.
$work = Join-Path ([System.IO.Path]::GetTempPath()) "mose-devices-test-$(Get-Random)"
New-Item -ItemType Directory -Path $work | Out-Null
# iloreport.ps1: echoes the credential, proving it arrived intact through the encrypted file.
Set-Content -LiteralPath (Join-Path $work 'iloreport.ps1') -Encoding ASCII -Value @'
param($credential, $server, $StorageDebugPath)
Write-Host "child host line for $server"
"### iLO $server"
"user=$($credential.UserName) passlen=$($credential.GetNetworkCredential().Password.Length)"
'@
# nas2.ps1: echoes the user and the secure password, proving the SecureString arrived.
Set-Content -LiteralPath (Join-Path $work 'nas2.ps1') -Encoding ASCII -Value @'
param($server, $user, $pass, $CertificateThumbprint, $AcceptAnyCertificate)
$plain = [System.Net.NetworkCredential]::new('', $pass).Password
"### NAS $server"
"user=$user passlen=$($plain.Length) secure=$($pass -is [securestring])"
'@
# vmwarereport.ps1: echoes its positional-style named parameters.
Set-Content -LiteralPath (Join-Path $work 'vmwarereport.ps1') -Encoding ASCII -Value @'
param($server, $user, $pass, $Client, $Site)
$plain = [System.Net.NetworkCredential]::new('', $pass).Password
"### VMware $server"
"user=$user passlen=$($plain.Length) client=$Client site=$Site"
'@
Set-Content -LiteralPath (Join-Path $work 'IDRAC.ps1') -Encoding ASCII -Value 'param($credential, $server); throw "iDRAC refused the login"'
Set-Content -LiteralPath (Join-Path $work 'BMCreport.ps1') -Encoding ASCII -Value 'param($credential, $server); [Environment]::Exit(-1)'

$standIn = 'p@ssw0rd-12'
$cred = New-Object System.Management.Automation.PSCredential('CONTOSO\svc', (ConvertTo-SecureString $standIn -AsPlainText -Force))

try {
    Write-Section 'The device type picks the right module'
    Test-Value 'an iLO' (Get-AuditDeviceModule 'Server management (iLO)') 'iLO'
    Test-Value 'an iDRAC' (Get-AuditDeviceModule 'Server management (iDRAC)') 'iDRAC'
    Test-Value 'a Lenovo BMC' (Get-AuditDeviceModule 'Server management (BMC)') 'BMC'
    Test-Value 'an XClarity is also the BMC module' (Get-AuditDeviceModule 'Server management (XClarity)') 'BMC'
    Test-Value 'a Synology NAS' (Get-AuditDeviceModule 'NAS (Synology)') 'NAS'
    Test-Value 'an ESXi host' (Get-AuditDeviceModule 'Hypervisor (VMware ESXi)') 'VMware'
    Test-Value 'a vCenter' (Get-AuditDeviceModule 'VMware vCenter') 'VMware'
    Test-Value 'a Veeam server' (Get-AuditDeviceModule 'Backup server (Veeam)') 'Veeam'
    Test-Value 'a printer has no module' "$(Get-AuditDeviceModule 'Printer')" ''
    Test-Value 'a QNAP NAS has no module yet' "$(Get-AuditDeviceModule 'NAS (QNAP)')" ''
    Test-That 'Hyper-V and SQL are manual (not found by the scan)' ($auditDeviceModules['HyperV'].Manual -and $auditDeviceModules['SQL'].Manual -and $auditDeviceModules['HyperV'].Types.Count -eq 0)

    Write-Section 'The parameters built for each module'
    $p = ConvertTo-AuditModuleParameters -Key 'iLO' -Server '192.0.2.5' -Credential $cred
    Test-Value 'iLO: server and credential' "$($p.server) $($p.credential.UserName)" '192.0.2.5 CONTOSO\svc'
    $p = ConvertTo-AuditModuleParameters -Key 'NAS' -Server '192.0.2.10' -Credential $cred
    Test-Value 'NAS: server, user, a secure password' "$($p.server) $($p.user) $($p.pass -is [securestring])" '192.0.2.10 CONTOSO\svc True'
    $p = ConvertTo-AuditModuleParameters -Key 'VMware' -Server '192.0.2.20' -Credential $cred -Client 'Contoso' -Site 'HQ'
    Test-Value 'VMware: user, secure password, client, site' "$($p.user) $($p.pass -is [securestring]) $($p.Client) $($p.Site)" 'CONTOSO\svc True Contoso HQ'
    $p = ConvertTo-AuditModuleParameters -Key 'Veeam' -Server 'veeam01' -Credential $cred
    Test-Value 'Veeam: server and credential' "$($p.Server) $($p.Credential.UserName)" 'veeam01 CONTOSO\svc'

    Write-Section 'Choosing which devices to read'
    $devs = @(
        [pscustomobject]@{ Address = '192.0.2.5'; Name = 'ILO5'; Type = 'Server management (iLO)' }
        [pscustomobject]@{ Address = '192.0.2.9'; Name = 'PR'; Type = 'Printer' }
        [pscustomobject]@{ Address = '192.0.2.10'; Name = 'NAS'; Type = 'NAS (Synology)' }
    )
    $logins = @(
        [pscustomobject]@{ Key = 'iLO'; Address = ''; Credential = $cred }         # every iLO found
        [pscustomobject]@{ Key = 'HyperV'; Address = 'HV01'; Credential = $cred }   # a host given by hand
    )
    $targets = @(Get-AuditDeviceTargets -Devices $devs -DeviceLogin $logins)
    Test-Value 'the scanned readable devices and the manual host; the printer is left out' (@($targets | ForEach-Object { "$($_.Key)@$($_.Address)" }) -join ', ') 'iLO@192.0.2.5, NAS@192.0.2.10, HyperV@HV01'
    Test-Value 'the iLO gets the login given for every iLO' "$((Get-AuditDeviceLogin -Target $targets[0] -DeviceLogin $logins).UserName)" 'CONTOSO\svc'
    Test-That 'the NAS has no login (none was given for it)' ($null -eq (Get-AuditDeviceLogin -Target $targets[1] -DeviceLogin $logins))
    Test-Value 'the manual host gets the login for its address' "$((Get-AuditDeviceLogin -Target $targets[2] -DeviceLogin $logins).UserName)" 'CONTOSO\svc'
    $logins2 = @(
        [pscustomobject]@{ Key = 'iLO'; Address = ''; Credential = (New-Object System.Management.Automation.PSCredential('by-type', (ConvertTo-SecureString $standIn -AsPlainText -Force))) }
        [pscustomobject]@{ Key = 'iLO'; Address = '192.0.2.5'; Credential = (New-Object System.Management.Automation.PSCredential('by-address', (ConvertTo-SecureString $standIn -AsPlainText -Force))) }
    )
    Test-Value 'a login for the address wins over one for the type' "$((Get-AuditDeviceLogin -Target $targets[0] -DeviceLogin $logins2).UserName)" 'by-address'
    Test-That 'no devices and no logins: no targets' (@(Get-AuditDeviceTargets).Count -eq 0)
    Test-Value 'a manual Hyper-V login is kept even without a scan' ((@(Get-AuditDeviceTargets -DeviceLogin @([pscustomobject]@{ Key = 'HyperV'; Address = 'HV02'; Credential = $cred })) | ForEach-Object { "$($_.Key)@$($_.Address)" }) -join ',') 'HyperV@HV02'

    Write-Section 'Reading a device in a PowerShell of its own'
    $r = Invoke-AuditDeviceModule -Key 'iLO' -Server '192.0.2.5' -Credential $cred -ScriptRoot $work
    Test-That 'iLO: the module ran and its Markdown came back' (($r.Markdown -join ' | ') -match '### iLO 192\.0\.2\.5') ($r.Markdown -join ' | ')
    Test-That 'the credential arrived intact (name and password length)' (($r.Markdown -join ' ') -match 'user=CONTOSO\\svc passlen=11') ($r.Markdown -join ' ')
    Test-That 'no error' (-not $r.Error) $r.Error
    $r = Invoke-AuditDeviceModule -Key 'NAS' -Server '192.0.2.10' -Credential $cred -ScriptRoot $work
    Test-That 'NAS: the secure password arrived as a SecureString' (($r.Markdown -join ' ') -match 'user=CONTOSO\\svc passlen=11 secure=True') ($r.Markdown -join ' ')
    $r = Invoke-AuditDeviceModule -Key 'VMware' -Server '192.0.2.20' -Credential $cred -Client 'Contoso' -Site 'HQ' -ScriptRoot $work
    Test-That 'VMware: client and site passed through' (($r.Markdown -join ' ') -match 'client=Contoso site=HQ') ($r.Markdown -join ' ')
    $r = Invoke-AuditDeviceModule -Key 'iDRAC' -Server '192.0.2.6' -Credential $cred -ScriptRoot $work
    Test-That 'a module that fails: its reason, no Markdown' ($r.Error -eq 'iDRAC refused the login' -and @($r.Markdown).Count -eq 0) "$($r.Error) / $(@($r.Markdown).Count)"
    $r = Invoke-AuditDeviceModule -Key 'BMC' -Server '192.0.2.7' -Credential $cred -ScriptRoot $work
    Test-That 'a module that ends its PowerShell: only that device is lost' ($r.Error -match 'ended without finishing \(exit code -1\)' -and @($r.Markdown).Count -eq 0) $r.Error
    $r = Invoke-AuditDeviceModule -Key 'Veeam' -Server 'veeam01' -Credential $cred -ScriptRoot $work
    Test-That 'a module not downloaded yet: a clear message' ($r.Error -match 'VeeamRestReport\.ps1 is not here') $r.Error
    Test-That 'no login files left behind' (@(Get-ChildItem ([System.IO.Path]::GetTempPath()) -Filter 'mose-audit-dev-*' -ErrorAction SilentlyContinue).Count -eq 0)
}
finally {
    if ($Keep) {
        Write-Host "The test folder: $work" -ForegroundColor Yellow
    }
    else {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n$($script:Passed) passed, $($script:Failures.Count) failed, in $([math]::Round(((Get-Date) - $started).TotalMinutes, 1)) minutes." -ForegroundColor $(if ($script:Failures.Count) { 'Red' } else { 'Green' })
if ($script:Failures.Count) {
    exit 1
}
