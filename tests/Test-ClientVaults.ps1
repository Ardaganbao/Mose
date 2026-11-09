[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'Keep the test folder, with the reports and the stand-in vault, instead of deleting it.')]
    [switch]$Keep
)

# Tests of the client vaults (-MultiClientMode) of Start.ps1, Configure.ps1 and Report.ps1. The vault
# is a stand-in of the SecretManagement and SecretStore modules, a file of the test folder, first in
# the module path of every PowerShell the tests start: the SecretStore of this Windows user is never
# read or changed. No server is contacted: the reports are dry runs. In Windows PowerShell, from the
# repository:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-ClientVaults.ps1

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
$repository = Split-Path -Parent $PSScriptRoot
$started = Get-Date
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:Passed = 0

function Test-Value {
    param(
        [string]$Name,
        $Actual,
        $Expected
    )

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
    param(
        [string]$Name,
        [bool]$Condition,
        [string]$Detail
    )

    Test-Value -Name $Name -Actual $(if ($Condition) { 'yes' } else { "no$(if ($Detail) { ": $Detail" })" }) -Expected 'yes'
}

function Write-Section {
    param(
        [string]$Title
    )

    Write-Host "`n$Title" -ForegroundColor Cyan
}

# The scripts run from a folder of their own, with every module already listed in modules.local.json:
# saving a configuration then downloads nothing.
$work = Join-Path ([System.IO.Path]::GetTempPath()) "mose-vault-test-$(Get-Random)"
New-Item -ItemType Directory -Path $work | Out-Null
Copy-Item -Path (Join-Path $repository '*.ps1'), (Join-Path $repository 'updater.config.json'), (Join-Path $repository 'latest-versions.json') -Destination $work
$moduleScripts = @((Get-Content -LiteralPath (Join-Path $work 'updater.config.json') -Raw | ConvertFrom-Json).Modules | ForEach-Object { $_ })
ConvertTo-Json -InputObject $moduleScripts | Set-Content -LiteralPath (Join-Path $work 'modules.local.json') -Encoding UTF8

# The stand-in modules, version 99.0.0: the secrets are in the JSON file $env:MOSE_TEST_VAULT, in plain
# text (test values only), and the vault password is the one below.
$fakeModules = Join-Path $work 'modules'
$management = Join-Path $fakeModules 'Microsoft.PowerShell.SecretManagement'
$store = Join-Path $fakeModules 'Microsoft.PowerShell.SecretStore'
New-Item -ItemType Directory -Path $management, $store | Out-Null
Set-Content -LiteralPath (Join-Path $management 'Microsoft.PowerShell.SecretManagement.psm1') -Encoding ASCII -Value @'
function Read-TestVault {
    if (-not (Test-Path -LiteralPath $env:MOSE_TEST_VAULT)) {
        return @()
    }
    @(Get-Content -LiteralPath $env:MOSE_TEST_VAULT -Raw | ConvertFrom-Json | ForEach-Object { $_ })
}
function Write-TestVault([object[]]$Entries) {
    ConvertTo-Json -InputObject @($Entries) -Depth 10 | Set-Content -LiteralPath $env:MOSE_TEST_VAULT -Encoding UTF8
}
function ConvertTo-TestPlain($Value) {
    if ($Value -is [securestring]) { return [System.Net.NetworkCredential]::new('', $Value).Password }
    return $Value
}
function Get-SecretVault {
    [CmdletBinding()]
    param([string]$Name)
    [pscustomobject]@{ Name = 'SecretStore1'; ModuleName = 'Microsoft.PowerShell.SecretStore'; IsDefault = $true }
}
function Register-SecretVault {
    [CmdletBinding()]
    param([string]$Name, [string]$ModuleName, [switch]$DefaultVault)
    throw 'The tests register no vault.'
}
function Get-SecretInfo {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$Name = '*', [string]$Vault)
    foreach ($entry in Read-TestVault) {
        if ($entry.Name -like $Name) {
            [pscustomobject]@{ Name = $entry.Name; Type = $entry.Type; VaultName = 'SecretStore1' }
        }
    }
}
function Get-Secret {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$Name, [string]$Vault, [switch]$AsPlainText)
    $entry = @(Read-TestVault | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
    if (-not $entry) {
        throw "The secret $Name was not found (stand-in of the tests)."
    }
    switch ($entry.Type) {
        'String' {
            if ($AsPlainText) { return $entry.Value }
            return (ConvertTo-SecureString $entry.Value -AsPlainText -Force)
        }
        'PSCredential' {
            return New-Object System.Management.Automation.PSCredential($entry.Value.UserName, (ConvertTo-SecureString $entry.Value.Password -AsPlainText -Force))
        }
        'Hashtable' {
            $table = @{}
            foreach ($property in $entry.Value.PSObject.Properties) {
                $table[$property.Name] = if (@($entry.Secure) -contains $property.Name -and -not $AsPlainText) { ConvertTo-SecureString $property.Value -AsPlainText -Force } else { $property.Value }
            }
            return $table
        }
    }
}
function Set-Secret {
    [CmdletBinding()]
    param([string]$Name, [object]$Secret, [string]$Vault)
    $secure = @()
    if ($Secret -is [pscredential]) {
        $type = 'PSCredential'
        $value = @{ UserName = $Secret.UserName; Password = $Secret.GetNetworkCredential().Password }
    }
    elseif ($Secret -is [System.Collections.IDictionary]) {
        $type = 'Hashtable'
        $value = @{}
        foreach ($key in $Secret.Keys) {
            if ($Secret[$key] -is [securestring]) { $secure += $key }
            $value[$key] = ConvertTo-TestPlain $Secret[$key]
        }
    }
    elseif ($Secret -is [securestring]) {
        $type = 'SecureString'
        $value = ConvertTo-TestPlain $Secret
    }
    else {
        $type = 'String'
        $value = "$Secret"
    }
    Write-TestVault (@(Read-TestVault | Where-Object { $_.Name -ne $Name }) + [pscustomobject]@{ Name = $Name; Type = $type; Value = $value; Secure = $secure })
}
function Remove-Secret {
    [CmdletBinding()]
    param([string]$Name, [string]$Vault)
    Write-TestVault @(Read-TestVault | Where-Object { $_.Name -ne $Name })
}
function Unlock-SecretVault {
    [CmdletBinding()]
    param([string]$Name, [securestring]$Password)
}
Export-ModuleMember -Function Get-SecretVault, Register-SecretVault, Get-SecretInfo, Get-Secret, Set-Secret, Remove-Secret, Unlock-SecretVault
'@
Set-Content -LiteralPath (Join-Path $store 'Microsoft.PowerShell.SecretStore.psm1') -Encoding ASCII -Value @'
function Unlock-SecretStore {
    [CmdletBinding()]
    param([securestring]$Password, [int]$PasswordTimeout)
    if ([System.Net.NetworkCredential]::new('', $Password).Password -cne 'stand-in-vault-password') {
        throw 'Wrong vault password (stand-in of the tests).'
    }
}
function Set-SecretStorePassword {
    [CmdletBinding()]
    param([securestring]$Password, [securestring]$NewPassword)
    throw 'The tests change no vault password.'
}
function Get-SecretStoreConfiguration {
    [CmdletBinding()]
    param()
    [pscustomobject]@{ Authentication = 'Password'; PasswordTimeout = 900 }
}
Export-ModuleMember -Function Unlock-SecretStore, Set-SecretStorePassword, Get-SecretStoreConfiguration
'@
New-ModuleManifest -Path (Join-Path $management 'Microsoft.PowerShell.SecretManagement.psd1') -ModuleVersion '99.0.0' -RootModule 'Microsoft.PowerShell.SecretManagement.psm1' -FunctionsToExport 'Get-SecretVault', 'Register-SecretVault', 'Get-SecretInfo', 'Get-Secret', 'Set-Secret', 'Remove-Secret', 'Unlock-SecretVault'
New-ModuleManifest -Path (Join-Path $store 'Microsoft.PowerShell.SecretStore.psd1') -ModuleVersion '99.0.0' -RootModule 'Microsoft.PowerShell.SecretStore.psm1' -FunctionsToExport 'Unlock-SecretStore', 'Set-SecretStorePassword', 'Get-SecretStoreConfiguration'
$modulePath = $env:PSModulePath
$env:PSModulePath = "$fakeModules;$modulePath"
$env:MOSE_TEST_VAULT = Join-Path $work 'vault.json'

# A PowerShell started here must load the stand-ins, or the tests would use this user's SecretStore.
# Started with its command as text, given a minute at most.
$start = New-Object System.Diagnostics.ProcessStartInfo
$start.FileName = (Get-Process -Id $PID).Path
$start.Arguments = '-NoProfile -Command "(Import-Module Microsoft.PowerShell.SecretManagement -PassThru).Version.ToString() + '' '' + (Import-Module Microsoft.PowerShell.SecretStore -PassThru).Version.ToString()"'
$start.UseShellExecute = $false
$start.RedirectStandardOutput = $true
$checking = [System.Diagnostics.Process]::Start($start)
$reading = $checking.StandardOutput.ReadToEndAsync()
if (-not $checking.WaitForExit(60000)) {
    $checking.Kill()
}
$loaded = if ($reading.Wait(5000)) { $reading.Result.Trim() } else { 'none' }
if ($loaded -ne '99.0.0 99.0.0') {
    $env:PSModulePath = $modulePath
    throw "A PowerShell started by the tests loads SecretManagement and SecretStore $loaded, not the stand-ins: the tests could change this user's SecretStore, so they stop."
}

# The vault at the start: the default client vault of Contoso, with a login and older Commvault tokens,
# and the client vault Fabrikam, with a login and Commvault tokens of its own.
$standIn = 'not-a-real-one'
$contosoLogin = 'MOSE:NAS:192.0.2.10'
$fabrikamLogin = 'MOSE:Fabrikam:iDRAC:192.0.2.20'
$contoso = [pscustomobject]@{ Client = 'Contoso'; Targets = @([pscustomobject]@{ Module = 'NAS'; Server = '192.0.2.10'; Secret = $contosoLogin; CertificateThumbprint = ''; AcceptAnyCertificate = $false }); Layout = $null; Software = @(); Machines = @() }
$fabrikam = [pscustomobject]@{ Client = 'Fabrikam Ltd'; Targets = @([pscustomobject]@{ Module = 'iDRAC'; Server = '192.0.2.20'; Secret = $fabrikamLogin }); Layout = $null; Software = @(); Machines = @() }
$tokens = @{ Type = 'Cloud'; AccessToken = $standIn; RefreshToken = $standIn; Ring = 'm1' }
ConvertTo-Json -Depth 10 -InputObject @(
    [pscustomobject]@{ Name = 'MOSE:Config'; Type = 'String'; Value = ($contoso | ConvertTo-Json -Depth 10); Secure = @() }
    [pscustomobject]@{ Name = 'MOSE:NAS:192.0.2.10'; Type = 'PSCredential'; Value = @{ UserName = 'CONTOSO\backup'; Password = $standIn }; Secure = @() }
    [pscustomobject]@{ Name = 'Contoso_Token'; Type = 'Hashtable'; Value = $tokens; Secure = @('AccessToken', 'RefreshToken') }
    [pscustomobject]@{ Name = 'MOSE:Fabrikam:Config'; Type = 'String'; Value = ($fabrikam | ConvertTo-Json -Depth 10); Secure = @() }
    [pscustomobject]@{ Name = 'MOSE:Fabrikam:iDRAC:192.0.2.20'; Type = 'PSCredential'; Value = @{ UserName = 'root'; Password = $standIn }; Secure = @() }
    [pscustomobject]@{ Name = 'MOSE:Fabrikam:CommvaultCloud:1'; Type = 'Hashtable'; Value = $tokens; Secure = @('AccessToken', 'RefreshToken') }
) | Set-Content -LiteralPath $env:MOSE_TEST_VAULT -Encoding UTF8

# The secrets of the stand-in vault, by name.
$readVault = {
    $entries = @{}
    foreach ($entry in @(Get-Content -LiteralPath $env:MOSE_TEST_VAULT -Raw | ConvertFrom-Json | ForEach-Object { $_ })) {
        $entries[$entry.Name] = $entry
    }
    $entries
}

# Runs a script in a PowerShell of its own, in strict mode as Start.ps1 runs it, with Read-Host and
# Get-Credential answered from a list of (question pattern, answer): each answer is used once, in
# order, so that the same question can get other answers. Notepad is not opened.
$runner = Join-Path $work 'Invoke-WithAnswers.ps1'
Set-Content -LiteralPath $runner -Encoding ASCII -Value @'
param([string]$Script, [string]$Answers, [string]$Arguments)
Set-StrictMode -Version Latest
$global:TestAnswers = New-Object System.Collections.Generic.List[object]
# Windows PowerShell gives a JSON list as one object: ForEach-Object takes its items out.
foreach ($answer in @(Get-Content -LiteralPath $Answers -Raw | ConvertFrom-Json | ForEach-Object { $_ })) { $global:TestAnswers.Add($answer) }
$global:TestQuestions = New-Object System.Collections.Generic.List[string]
function global:New-TestSecret([string]$Text) {
    $secure = New-Object System.Security.SecureString
    foreach ($character in $Text.ToCharArray()) { $secure.AppendChar($character) }
    $secure
}
function global:Read-Host {
    param([Parameter(Position = 0)][object]$Prompt, [switch]$AsSecureString)
    $global:TestQuestions.Add("$Prompt")
    $match = $null
    foreach ($answer in $global:TestAnswers) {
        if ("$Prompt" -match $answer.Question) { $match = $answer; break }
    }
    if (-not $match) { throw "Unexpected question: $Prompt" }
    [void]$global:TestAnswers.Remove($match)
    if ($AsSecureString) { return New-TestSecret "$($match.Answer)" }
    return "$($match.Answer)"
}
function global:Get-Credential {
    param([string]$Message, [string]$UserName)
    $global:TestQuestions.Add("Get-Credential: $Message")
    New-Object System.Management.Automation.PSCredential($(if ($UserName) { $UserName } else { 'TEST\reader' }), (New-TestSecret 'not-a-real-one'))
}
function global:Start-Process {
    param([string]$FilePath, [object]$ArgumentList)
    if ($FilePath -eq 'notepad.exe') { $global:TestQuestions.Add("Notepad: $ArgumentList"); return }
    Microsoft.PowerShell.Management\Start-Process @PSBoundParameters
}
$parameters = @{}
foreach ($pair in (Get-Content -LiteralPath $Arguments -Raw | ConvertFrom-Json).PSObject.Properties) { $parameters[$pair.Name] = $pair.Value }
try {
    & $Script @parameters | Out-Null
}
catch {
    "FAILED: $($_.Exception.Message)"
}
'QUESTIONS: ' + ($global:TestQuestions -join ' || ')
'LEFT: ' + (@($global:TestAnswers | ForEach-Object { $_.Question }) -join ' || ')
'@
$invoke = {
    param([string]$Script, [object[]]$Answers, [hashtable]$Arguments = @{})
    # In files: a command line would lose the quotes of the JSON.
    $answersFile = Join-Path $work "answers-$(Get-Random).json"
    ConvertTo-Json -InputObject @($Answers | ForEach-Object { [pscustomobject]@{ Question = $_[0]; Answer = $_[1] } }) | Set-Content -LiteralPath $answersFile -Encoding UTF8
    $argumentsFile = Join-Path $work "arguments-$(Get-Random).json"
    ConvertTo-Json -InputObject ([pscustomobject]$Arguments) | Set-Content -LiteralPath $argumentsFile -Encoding UTF8
    # Its errors are kept with its output: with Stop, the first one would end the tests.
    $ErrorActionPreference = 'Continue'
    $output = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner -Script (Join-Path $work $Script) -Answers $answersFile -Arguments $argumentsFile 2>&1 | ForEach-Object { "$_" })
    $questions = @(($output | Where-Object { $_ -like 'QUESTIONS: *' } | Select-Object -Last 1) -replace '^QUESTIONS: ', '' -split ' \|\| ' | Where-Object { $_ })
    $left = "$(($output | Where-Object { $_ -like 'LEFT: *' } | Select-Object -Last 1) -replace '^LEFT: ', '')"
    $failed = "$(($output | Where-Object { $_ -like 'FAILED: *' } | Select-Object -Last 1) -replace '^FAILED: ', '')"
    [pscustomobject]@{ Output = $output; Text = ($output -join "`n"); Questions = $questions; Left = $left; Failed = $failed }
}
$password = @('^Password for SecretStore vault', 'stand-in-vault-password')
$today = Get-Date -Format 'yyyy-MM-dd'

try {
    Write-Section 'The client vaults found, and the secrets of each'
    Set-Content -LiteralPath (Join-Path $work 'Probe.ps1') -Encoding ASCII -Value @'
. (Join-Path $PSScriptRoot 'helper.ps1')
Open-MoseVault
Write-Host ('VAULTS: ' + (@(Get-MoseClientVaults | Sort-Object -Property Name | ForEach-Object { "[$($_.Name)]=$($_.Client)" }) -join '; '))
$others = @(Get-MoseClientVaults | Where-Object { $_.Name } | ForEach-Object { $_.Name })
$names = 'MOSE:NAS:192.0.2.10', 'Contoso_Token', 'MOSE:Fabrikam:iDRAC:192.0.2.20', 'MOSE:fabrikam:CommvaultCloud:1'
Write-Host ('DEFAULT: ' + (@($names | ForEach-Object { "$_=$(Test-MoseClientVaultSecret $_ $others)" }) -join '; '))
Select-MoseClientVault
Write-Host ('CHOSEN: ' + "[$MoseClientVault] $MoseSecretPrefix $MoseConfigSecretName $(Get-MoseProperty (Get-MoseConfig) 'Client')")
Write-Host ('CHOSEN HAS: ' + (@($names | ForEach-Object { "$_=$(Test-MoseClientVaultSecret $_ $others)" }) -join '; '))
'@
    $line = { param($Run, $Name) "$(@($Run.Output | Where-Object { $_ -like "$($Name): *" }) | Select-Object -Last 1)" }
    $run = & $invoke 'Probe.ps1' @($password, @('^Number of the client vault', '2'))
    Test-Value 'the default one and Fabrikam, with their clients' (& $line $run 'VAULTS') 'VAULTS: []=Contoso; [Fabrikam]=Fabrikam Ltd'
    Test-Value 'the default one has the secrets of no other' (& $line $run 'DEFAULT') 'DEFAULT: MOSE:NAS:192.0.2.10=True; Contoso_Token=True; MOSE:Fabrikam:iDRAC:192.0.2.20=False; MOSE:fabrikam:CommvaultCloud:1=False'
    Test-That 'the client vaults listed, then the question' (($run.Text -match '(?s)1\. \(default\)\s+Contoso.*2\. Fabrikam\s+Fabrikam Ltd.*N\. A new empty client vault') -and $run.Questions[-1] -like 'Number of the client vault*') ($run.Questions -join ' | ')
    Test-Value 'number 2: Fabrikam, its secrets and configuration' (& $line $run 'CHOSEN') 'CHOSEN: [Fabrikam] MOSE:Fabrikam: MOSE:Fabrikam:Config Fabrikam Ltd'
    Test-Value 'Fabrikam has only its own secrets' (& $line $run 'CHOSEN HAS') 'CHOSEN HAS: MOSE:NAS:192.0.2.10=False; Contoso_Token=False; MOSE:Fabrikam:iDRAC:192.0.2.20=True; MOSE:fabrikam:CommvaultCloud:1=True'

    Write-Section 'A new empty client vault: the names refused'
    $run = & $invoke 'Probe.ps1' @($password,
        @('^Number of the client vault', 'x'), @('^Number of the client vault', 'N'), @('^Name of the new client vault', 'Bad:name'),
        @('^Number of the client vault', 'N'), @('^Name of the new client vault', 'nas'),
        @('^Number of the client vault', 'N'), @('^Name of the new client vault', 'Config'),
        @('^Number of the client vault', 'N'), @('^Name of the new client vault', 'Fabrikam'),
        @('^Number of the client vault', 'N'), @('^Name of the new client vault', 'Northwind'))
    Test-That 'a name with a colon' ($run.Text -match 'Not a name for a client vault')
    Test-That "a module's name (NAS)" ($run.Text -match "'nas' is a name MOSE uses for its own secrets")
    Test-That 'Config' ($run.Text -match "'Config' is a name MOSE uses for its own secrets")
    Test-That 'one that exists' ($run.Text -match "The client vault 'Fabrikam' already exists")
    Test-Value 'then Northwind, empty' (& $line $run 'CHOSEN') 'CHOSEN: [Northwind] MOSE:Northwind: MOSE:Northwind:Config '
    Test-That 'every answer used, nothing else asked' (-not $run.Left -and -not $run.Failed) "left: $($run.Left); failed: $($run.Failed)"
    Test-That 'nothing saved in the vault' (-not (& $readVault).ContainsKey('MOSE:Northwind:Config'))

    Write-Section 'Configure.ps1 -MultiClientMode: a new client vault configured'
    $run = & $invoke 'Configure.ps1' @($password, @('^Number of the client vault', 'N'), @('^Name of the new client vault', 'Northwind'),
        @('^Client name', ''), @('^Module number', '4'), @('^How many', ''), @(' - IP address or host name', '192.0.2.30'),
        @('^Trusted certificate', ''), @('^Accept any certificate', ''),
        @('^Module number', 'P'), @('^Number to edit or remove', ''), @('^Module number', 'S')) @{ MultiClientMode = $true }
    $vault = & $readVault
    Test-That 'every answer used, nothing else asked' (-not $run.Left -and -not $run.Failed) "left: $($run.Left); failed: $($run.Failed); asked: $($run.Questions -join ' | ')"
    Test-That 'said where it is saved' ($run.Text -match "Saved in the client vault 'Northwind' of the SecretStore vault 'SecretStore1'")
    Test-That 'the client name offered: the client vault' ($run.Questions -contains 'Client name (report title and file name) [Northwind]') ($run.Questions -join ' | ')
    $config = if ($vault.ContainsKey('MOSE:Northwind:Config')) { $vault['MOSE:Northwind:Config'].Value | ConvertFrom-Json }
    Test-Value 'its configuration saved in it' "$($config.Client) $(@($config.Targets).Count) $(@($config.Targets)[0].Secret)" 'Northwind 1 MOSE:Northwind:NAS:192.0.2.30'
    Test-Value 'the login saved in it' "$($vault['MOSE:Northwind:NAS:192.0.2.30'].Type) $($vault['MOSE:Northwind:NAS:192.0.2.30'].Value.UserName)" 'PSCredential TEST\reader'
    Test-Value 'the default one unchanged' "$(($vault['MOSE:Config'].Value | ConvertFrom-Json).Client) $(@(($vault['MOSE:Config'].Value | ConvertFrom-Json).Targets).Count)" 'Contoso 1'
    Test-That 'P lists its login only' ($run.Text -match 'MOSE:Northwind:NAS:192\.0\.2\.30' -and $run.Text -notmatch 'MOSE:NAS:192\.0\.2\.10|MOSE:Fabrikam|Contoso_Token') (($run.Output | Where-Object { $_ -match '^\s+\d+\. ' }) -join ' / ')
    Test-Value 'the modules of every client vault kept for the updates' (@((Get-Content -LiteralPath (Join-Path $work 'modules.local.json') -Raw | ConvertFrom-Json)) -join ', ') 'IDRAC.ps1, nas2.ps1'

    Write-Section 'Configure.ps1 without -MultiClientMode: the default client vault'
    $run = & $invoke 'Configure.ps1' @($password, @('^Module number', 'P'), @('^Number to edit or remove', ''), @('^Module number', 'Q'))
    Test-That 'every answer used, no client vault asked' (-not $run.Left -and -not $run.Failed -and ($run.Questions -notmatch 'client vault')) "left: $($run.Left); failed: $($run.Failed); asked: $($run.Questions -join ' | ')"
    Test-That 'Contoso' ($run.Text -match 'Modules for Contoso')
    Test-That 'P lists its login and tokens, not those of the others' ($run.Text -match 'MOSE:NAS:192\.0\.2\.10' -and $run.Text -match 'Contoso_Token' -and $run.Text -notmatch 'MOSE:Northwind|MOSE:Fabrikam') (($run.Output | Where-Object { $_ -match '^\s+\d+\. ' }) -join ' / ')

    Write-Section 'Report.ps1 -MultiClientMode -DryRun: the report of the client vault picked'
    $run = & $invoke 'Report.ps1' @($password, @('^Number of the client vault', '2')) @{ MultiClientMode = $true; DryRun = $true; NoOpen = $true }
    Test-That 'every answer used' (-not $run.Left -and -not $run.Failed) "left: $($run.Left); failed: $($run.Failed)"
    Test-That 'Fabrikam, then Northwind, after the default one' ($run.Text -match '(?s)1\. \(default\)\s+Contoso.*2\. Fabrikam\s+Fabrikam Ltd.*3\. Northwind\s+Northwind')
    Test-That "Fabrikam Ltd's sample report written" (Test-Path -LiteralPath (Join-Path $work "Fabrikam_Ltd_Report_$($today)_sample.md"))

    Write-Section 'Report.ps1 -MultiClientMode: a new empty client vault goes to its configuration'
    $run = & $invoke 'Report.ps1' @($password, @('^Number of the client vault', 'N'), @('^Name of the new client vault', 'Westwind'), @('^Client name', ''), @('^Module number', 'Q')) @{ MultiClientMode = $true; NoOpen = $true }
    Test-That 'every answer used' (-not $run.Left) "left: $($run.Left)"
    Test-That 'the configuration of that client vault, not asked again' ($run.Text -match "Saved in the client vault 'Westwind'" -and @($run.Questions -match '^Number of the client vault').Count -eq 1) ($run.Questions -join ' | ')
    Test-That 'nothing saved: no report' ($run.Failed -match 'No client configuration was saved' -and -not (& $readVault).ContainsKey('MOSE:Westwind:Config')) $run.Failed

    Write-Section 'Start.ps1 -MultiClientMode'
    $run = & $invoke 'Start.ps1' @($password, @('^Number of the client vault', '3')) @{ SkipUpdate = $true; MultiClientMode = $true; DryRun = $true }
    Test-That 'every answer used' (-not $run.Left -and -not $run.Failed) "left: $($run.Left); failed: $($run.Failed)"
    Test-That "with -DryRun: Northwind's sample report, opened" ((Test-Path -LiteralPath (Join-Path $work "Northwind_Report_$($today)_sample.md")) -and ($run.Questions -match "^Notepad: .*Northwind_Report_$($today)_sample\.md")) ($run.Questions -join ' | ')
    $run = & $invoke 'Start.ps1' @($password, @('^Number of the client vault', '1'), @('^Module number', 'Q')) @{ SkipUpdate = $true; MultiClientMode = $true; Configure = $true }
    Test-That 'with -Configure: the client vault picked' (-not $run.Left -and -not $run.Failed -and $run.Text -match 'Modules for Contoso') "left: $($run.Left); failed: $($run.Failed)"
    $run = & $invoke 'Start.ps1' @() @{ SkipUpdate = $true; MultiClientMode = $true; Gui = $true }
    Test-That 'with -Gui: refused, before anything' ($run.Failed -match '-MultiClientMode goes with the report .* not with -Gui\.' -and $run.Questions.Count -eq 0) "$($run.Failed) / asked: $($run.Questions -join ' | ')"
    $run = & $invoke 'Start.ps1' @(, $password) @{ SkipUpdate = $true; DryRun = $true }
    Test-That 'without it: the default client vault, nothing asked about it' (-not $run.Left -and -not $run.Failed -and ($run.Questions -notmatch 'client vault') -and (Test-Path -LiteralPath (Join-Path $work "Contoso_Report_$($today)_sample.md"))) "left: $($run.Left); failed: $($run.Failed); asked: $($run.Questions -join ' | ')"
}
finally {
    $env:PSModulePath = $modulePath
    Remove-Item -Path Env:\MOSE_TEST_VAULT -ErrorAction SilentlyContinue
}

Write-Host "`n$($script:Passed) passed, $($script:Failures.Count) failed, in $([math]::Round(((Get-Date) - $started).TotalMinutes, 1)) minutes." -ForegroundColor $(if ($script:Failures.Count) { 'Red' } else { 'Green' })
if ($Keep -or $script:Failures.Count) {
    Write-Host "The test folder: $work" -ForegroundColor Yellow
}
else {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
if ($script:Failures.Count) {
    exit 1
}
