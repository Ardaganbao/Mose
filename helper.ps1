
function Ensure-Module {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Version]$MinimumVersion = '1.0.0'
    )
    if (-not (Get-Module -ListAvailable -Name $Name | Where-Object { $_.Version -ge $MinimumVersion })) {
        Write-Host "Installing module '$Name' (min $MinimumVersion) for CurrentUser..." -ForegroundColor Cyan
        Install-Module -Name $Name -MinimumVersion $MinimumVersion -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    Import-Module $Name -ErrorAction Stop
}



function Ensure-SecretVault {
    param(
        [string]$VaultName = 'MySecretStore2',
        [string]$ModuleName = 'Microsoft.PowerShell.SecretStore'
    )

    # Ensure modules
    Ensure-Module -Name Microsoft.PowerShell.SecretManagement -MinimumVersion '1.1.0'
    Ensure-Module -Name $ModuleName -MinimumVersion '1.0.6'

    # Register vault if missing
    $existing = Get-SecretVault | Where-Object { $_.Name -eq $VaultName }
    if (-not $existing) {
        Write-Host "Registering secret vault '$VaultName'..." -ForegroundColor Cyan
        Register-SecretVault -Name $VaultName -ModuleName $ModuleName -DefaultVault
    }

    Write-Host "Vault '$VaultName' is registered." -ForegroundColor Green
}

function Unlock-SecretVaultIfNeeded {
    param(
        [string]$VaultName = 'MySecretStore2',
        [Security.SecureString]$Password
    )
    if (-not $Password) {
        $Password = Read-Host -Prompt "Password for SecretStore vault '$VaultName'" -AsSecureString
    }

    try {
        Unlock-SecretStore -Password $Password -ErrorAction Stop | Out-Null
    }
    catch {
        throw "Could not unlock SecretStore vault '$VaultName': $($_.Exception.Message)"
    }
}

function Set-AppSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [Security.SecureString]$Secret,
        [string]$Vault = 'MySecretStore2'
    )
    Set-Secret -Name $Name -Secret $Secret -Vault $Vault
}

function Get-AppSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Name,
        [string]$Vault = 'MySecretStore2',
        [switch]$AsPlainText
    )
    if ($AsPlainText) {
        return Get-Secret -Name $Name -Vault $Vault -AsPlainText
    } else {
        # Returns as the stored type; for secrets we recommend storing SecureString
        return Get-Secret -Name $Name -Vault $Vault
    }
}

function Get-AppCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$UserName,
        [Parameter(Mandatory)] [string]$PasswordSecretName,
        [string]$Vault = 'MySecretStore2'
    )
    $secure = Get-AppSecret -Name $PasswordSecretName -Vault $Vault
    if (-not $secure -or -not ($secure -is [Security.SecureString])) {
        throw "Secret '$PasswordSecretName' was not found or is not a SecureString."
    }
    return [pscredential]::new($UserName, $secure)
}

# Everything about the client stays in this vault, never in the scripts: the client name and
# servers (secret MOSE:Config, as JSON) and one credential or token secret per server.
$MoseVaultName = 'SecretStore1'
$MoseConfigSecretName = 'MOSE:Config'

# Modules a client configuration can use, in report order.
# DropTitle: the module starts its Markdown with a heading that only repeats the report section title.
$MoseModules = [ordered]@{
    iLO             = @{ Label = 'HPE iLO'; Script = 'iloreport.ps1' }
    iDRAC           = @{ Label = 'Dell iDRAC'; Script = 'IDRAC.ps1'; DropTitle = $true }
    BMC             = @{ Label = 'Lenovo BMC'; Script = 'BMCreport.ps1'; DropTitle = $true }
    NAS             = @{ Label = 'Synology NAS'; Script = 'nas2.ps1' }
    StorMagic       = @{ Label = 'StorMagic SvSAN'; Script = 'stormagicHealth.ps1'; DropTitle = $true }
    VMware          = @{ Label = 'VMware vCenter'; Script = 'vmwarereport.ps1'; DropTitle = $true }
    HyperV          = @{ Label = 'Microsoft Hyper-V'; Script = 'hypervreport.ps1'; DropTitle = $true }
    Veeam           = @{ Label = 'Veeam Backup & Replication local'; Script = 'VeeamReport.ps1'; DropTitle = $true }
    # The same report over Veeam's REST API: no Veeam console, PowerShell remoting or administrator rights needed.
    # SureBackup, which Veeam 13 doesn't give over REST, through VeeamReport.ps1 when the Veeam console is installed.
    VeeamApi        = @{ Label = 'Veeam Backup & Replication'; Script = 'VeeamRestReport.ps1'; Uses = @('VeeamReport.ps1'); DropTitle = $true }
    CommvaultCloud  = @{ Label = 'Commvault Cloud'; Script = 'CommvaultCloud report.ps1'; DropTitle = $true }
    CommvaultOnPrem = @{ Label = 'Commvault on-premises'; Script = 'CommvaultCloud report.ps1'; DropTitle = $true }
}

function Open-MoseVault {
    param(
        # Given by Report.ps1 to the Commvault module, which runs in its own process and reads the vault itself.
        [Security.SecureString]$Password
    )

    Ensure-Module -Name 'Microsoft.PowerShell.SecretManagement' -MinimumVersion '1.1.0'
    Ensure-Module -Name 'Microsoft.PowerShell.SecretStore' -MinimumVersion '1.0.6'
    if (-not $Password) {
        Ensure-SecretVault -VaultName $MoseVaultName
        $Password = Read-Host -Prompt "Password for SecretStore vault '$MoseVaultName'" -AsSecureString
    }
    Unlock-SecretVaultIfNeeded -VaultName $MoseVaultName -Password $Password
    $script:MoseVaultPassword = $Password
}

# Returns $null when this computer has no client configuration yet.
function Get-MoseConfig {
    param(
        [string]$Vault = $MoseVaultName
    )

    if (-not (Get-SecretInfo -Vault $Vault -Name $MoseConfigSecretName -ErrorAction SilentlyContinue)) {
        return $null
    }
    return Get-Secret -Vault $Vault -Name $MoseConfigSecretName -AsPlainText | ConvertFrom-Json
}

# $Layout: order, titles and groups of the report sections, $null for the default (see README, "Report layout").
function Save-MoseConfig {
    param(
        [Parameter(Mandatory)] [string]$Client,
        [object[]]$Targets = @(),
        [object]$Layout
    )

    $json = [pscustomobject]@{ Client = $Client; Targets = @($Targets); Layout = $Layout } | ConvertTo-Json -Depth 20
    Set-Secret -Vault $MoseVaultName -Name $MoseConfigSecretName -Secret $json
    Save-MoseModuleList -Targets $Targets
}

# The scripts run in strict mode from Start.ps1, where reading a missing JSON property is an error.
function Get-MoseProperty {
    param(
        [object]$InputObject,
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) {
        return $property.Value
    }
}

# Replaces the {Name} placeholders found in $Values; unknown ones are left as typed.
function Format-MoseTitle {
    param(
        [string]$Template,
        [hashtable]$Values = @{}
    )

    $evaluator = {
        param($match)
        if ($Values.ContainsKey($match.Groups[1].Value)) { "$($Values[$match.Groups[1].Value])" } else { $match.Value }
    }.GetNewClosure()
    return [regex]::Replace($Template, '\{(\w+)\}', $evaluator)
}

$MoseDefaultReportTitle = '{Client} report {Date}'

# Markdown heading of a report line. Markdown stops at ######, so a deeper level becomes a bold line
# instead of being merged with the level above.
function Format-MoseHeading {
    param(
        [int]$Level,
        [string]$Text
    )

    if ($Level -le 6) {
        return "$('#' * $Level) $Text"
    }
    return "**$Text**"
}

# Report layout of a client that has not changed it: three ## sections with their servers in ###.
# A module missing here goes at the end of the report.
$MoseDefaultLayout = [pscustomobject]@{
    Sections = @(
        [pscustomobject]@{ Title = 'Hardware'; Sections = @([pscustomobject]@{ Module = @('iLO', 'iDRAC', 'BMC') }) }
        [pscustomobject]@{ Title = 'Virtualization and storage'; Sections = @([pscustomobject]@{ Module = @('VMware', 'HyperV', 'StorMagic') }) }
        [pscustomobject]@{ Title = 'Backup'; Sections = @([pscustomobject]@{ Module = @('NAS', 'Veeam', 'VeeamApi', 'CommvaultCloud', 'CommvaultOnPrem') }) }
    )
}

# Title of a report section: its layout title, or by default the module and server.
function Get-MoseSectionTitle {
    param(
        [Parameter(Mandatory)] [object]$Section,
        [string]$Client,
        [string]$Date
    )

    $values = @{ Client = $Client; Date = $Date }
    $template = $Section.Title
    if ($Section.Target) {
        $site = Get-MoseProperty $Section.Target 'Site'
        $values += @{
            Module = $Section.Target.Module
            Label  = $MoseModules[$Section.Target.Module].Label
            Server = Get-MoseTargetName $Section.Target
            Site   = $site
        }
        if (-not $template) {
            $template = if ($site) { '{Label} {Server} ({Site})' } else { '{Label} {Server}' }
        }
    }
    return Format-MoseTitle $template $values
}

# Turns layout entries into report sections: a group (Title, Text written under its heading,
# Children) or one server (Target), with its layout Title ('' for the default) and Hide. An entry
# takes the servers it matches from $Remaining, so a server appears once, under the first entry
# that matches it.
function New-MoseReportSections {
    param(
        [object[]]$Entries,
        [System.Collections.Generic.List[object]]$Remaining
    )

    foreach ($entry in $Entries) {
        $title = "$(Get-MoseProperty $entry 'Title')"
        if ($entry.PSObject.Properties['Sections']) {
            $children = New-Object System.Collections.Generic.List[object]
            foreach ($child in @(New-MoseReportSections -Entries @(Get-MoseProperty $entry 'Sections' | Where-Object { $_ }) -Remaining $Remaining)) {
                $children.Add($child)
            }
            if ($title) {
                [pscustomobject]@{ Title = $title; Text = "$(Get-MoseProperty $entry 'Text')"; Target = $null; Children = $children; Hide = $false }
            }
            else {
                Write-Warning "Report layout: a group of sections has no Title, so its sections are listed without one."
                $children
            }
            continue
        }

        $patterns = @(Get-MoseProperty $entry 'Module' | Where-Object { $_ })
        if ($patterns.Count -eq 0) {
            Write-Warning "Report layout: an entry has neither Module nor Sections and is ignored."
            continue
        }
        $serverPattern = Get-MoseProperty $entry 'Server'
        foreach ($pattern in $patterns) {
            $modules = @($MoseModules.Keys | Where-Object { $_ -like $pattern })
            if ($modules.Count -eq 0) {
                Write-Warning "Report layout: no module matches '$pattern'. Modules: $($MoseModules.Keys -join ', ')."
            }
            foreach ($module in $modules) {
                $targets = @($Remaining | Where-Object {
                        $_.Module -eq $module -and (-not $serverPattern -or (Get-MoseTargetName $_) -like $serverPattern)
                    })
                foreach ($target in $targets) {
                    [void]$Remaining.Remove($target)
                    [pscustomobject]@{
                        Title    = $title
                        Text     = ''
                        Target   = $target
                        Children = New-Object System.Collections.Generic.List[object]
                        Hide     = [bool](Get-MoseProperty $entry 'Hide')
                    }
                }
            }
        }
    }
}

# Every configured server laid out by $Layout ($null for the default layout). The servers it does
# not place go at the end, in module order, shown unless the layout says Unlisted = Hide.
function Get-MoseReportSections {
    param(
        [object]$Layout,
        [object[]]$Targets = @()
    )

    if (-not $Layout) {
        $Layout = $MoseDefaultLayout
    }
    $remaining = New-Object System.Collections.Generic.List[object]
    foreach ($target in @($Targets | Where-Object { $_ })) {
        $remaining.Add($target)
    }

    $unlisted = Get-MoseProperty $Layout 'Unlisted'
    if ($unlisted -and $unlisted -notin 'End', 'Hide') {
        Write-Warning "Report layout: Unlisted is 'End' or 'Hide', not '$unlisted'. Using 'End'."
    }
    $entries = @(Get-MoseProperty $Layout 'Sections' | Where-Object { $_ }) +
        @($MoseModules.Keys | ForEach-Object { [pscustomobject]@{ Module = $_; Hide = $unlisted -eq 'Hide' } })

    $sections = New-Object System.Collections.Generic.List[object]
    foreach ($section in @(New-MoseReportSections -Entries $entries -Remaining $remaining)) {
        $sections.Add($section)
    }
    return , $sections
}

# Start.ps1 only downloads and updates the module scripts listed here, those of the client
# configured on this computer. File names only, no client data (kept out of the repository, see .gitignore).
$MoseModuleListPath = Join-Path $PSScriptRoot 'modules.local.json'

function Save-MoseModuleList {
    param(
        [object[]]$Targets = @()
    )

    $previous = @()
    if (Test-Path -LiteralPath $MoseModuleListPath) {
        # Inner parentheses: Windows PowerShell returns a JSON array as one object.
        $previous = @((Get-Content -LiteralPath $MoseModuleListPath -Raw | ConvertFrom-Json))
    }
    # With the other scripts a module runs (Uses).
    $scripts = @($Targets | Where-Object { $MoseModules.Contains($_.Module) } |
        ForEach-Object { $MoseModules[$_.Module].Script; $MoseModules[$_.Module]['Uses'] } | Where-Object { $_ } | Sort-Object -Unique)
    ConvertTo-Json -InputObject $scripts | Set-Content -LiteralPath $MoseModuleListPath -Encoding utf8

    # A module added since the last update is downloaded (or brought up to date) right away.
    $added = @($scripts | Where-Object { $previous -notcontains $_ })
    if ($added.Count -gt 0) {
        Write-Host "Downloading the modules: $($added -join ', ')" -ForegroundColor DarkGray
        & (Join-Path $PSScriptRoot 'Start.ps1') -UpdateOnly -Quiet | Out-Null
    }
}

# Runs the module of one server and returns its Markdown. Report.ps1 runs it in a process of its
# own, with the server's login ($Credential) read from the vault; Commvault reads the vault itself.
function Invoke-MoseModule {
    param(
        [Parameter(Mandatory)] [object]$Target,
        [pscredential]$Credential,
        [string]$Client,
        [int]$CommvaultJobLookbackDays = 30,
        # With Report.ps1 -DebugLog: where the modules that can write what their server answered do so.
        [string]$DebugDumpPath
    )

    # The module scripts were written without strict mode, which Start.ps1 turns on for the scripts it runs.
    Set-StrictMode -Off

    $scriptPath = Join-Path $PSScriptRoot $MoseModules[$Target.Module].Script
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "Module script was not found: $scriptPath. Run .\Start.ps1 -UpdateOnly to download it."
    }

    switch ($Target.Module) {
        'iLO' {
            $iloParameters = @{ server = $Target.Server; credential = $Credential }
            if ($DebugDumpPath) {
                $iloParameters.StorageDebugPath = $DebugDumpPath
            }
            & $scriptPath @iloParameters
        }
        { $_ -in 'iDRAC', 'BMC' } {
            & $scriptPath -server $Target.Server -credential $Credential
        }
        'NAS' {
            $nasParameters = @{ server = $Target.Server; user = $Credential.UserName; pass = $Credential.Password }
            if ($Target.CertificateThumbprint) {
                $nasParameters.CertificateThumbprint = $Target.CertificateThumbprint
            }
            if ($Target.AcceptAnyCertificate) {
                $nasParameters.AcceptAnyCertificate = $true
            }
            & $scriptPath @nasParameters
        }
        'StorMagic' {
            & $scriptPath -Server $Target.Server -Credential $Credential.GetNetworkCredential()
        }
        'VMware' {
            & $scriptPath -server $Target.Server -user $Credential.UserName -pass $Credential.Password -Client $Client -Site $Target.Site
        }
        'HyperV' {
            $hyperVParameters = @{ Server = $Target.Server; Site = $Target.Site }
            if ($Credential) {
                $hyperVParameters.Credential = $Credential
            }
            & $scriptPath @hyperVParameters
        }
        'Veeam' {
            $veeamParameters = @{ Server = $Target.Server; OutputPath = [System.IO.Path]::GetTempFileName(); NoOpen = $true }
            if ($Credential) {
                $veeamParameters.RemotingCredential = $Credential
            }
            try {
                & $scriptPath @veeamParameters
            }
            finally {
                Remove-Item -LiteralPath $veeamParameters.OutputPath -Force -ErrorAction SilentlyContinue
            }
        }
        'VeeamApi' {
            $veeamApiParameters = @{ Server = $Target.Server; Credential = $Credential }
            if ($Target.PSObject.Properties['CertificateThumbprint'] -and $Target.CertificateThumbprint) {
                $veeamApiParameters.CertificateThumbprint = $Target.CertificateThumbprint
            }
            if ($Target.PSObject.Properties['AcceptAnyCertificate'] -and $Target.AcceptAnyCertificate) {
                $veeamApiParameters.AcceptAnyCertificate = $true
            }
            if ($DebugDumpPath) {
                $veeamApiParameters.ApiDumpPath = $DebugDumpPath
            }
            & $scriptPath @veeamApiParameters
        }
        { $_ -in 'CommvaultCloud', 'CommvaultOnPrem' } {
            # The Commvault script writes its report to a file, read back here.
            $folder = Join-Path ([System.IO.Path]::GetTempPath()) ("CommvaultReport_{0}" -f [guid]::NewGuid().ToString('N'))
            New-Item -Path $folder -ItemType Directory | Out-Null
            try {
                & $scriptPath -ClientName $Target.Secret -Mode ($Target.Module -replace '^Commvault', '') -SecretSuffix '' `
                    -SecretVaultName $MoseVaultName -JobLookbackDays $CommvaultJobLookbackDays -OutputFolder $folder | Out-Null

                $files = @(Get-ChildItem -LiteralPath $folder -Filter 'CommvaultReport_*.md' -File)
                if ($files.Count -ne 1) {
                    throw "Expected one Commvault Markdown report in '$folder', found $($files.Count)."
                }
                Get-Content -LiteralPath $files[0].FullName -Raw
            }
            finally {
                Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        default {
            throw "Unknown module '$($Target.Module)'."
        }
    }
}

# Where an error stopped a module, e.g. "iloreport.ps1 line 835".
function Get-MoseErrorLocation {
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $info = $ErrorRecord.InvocationInfo
    if (-not $info -or -not $info.ScriptName) {
        return ''
    }
    return "$(Split-Path -Leaf $info.ScriptName) line $($info.ScriptLineNumber)"
}

# For -DebugLog: the error, the statement that failed and the calls that led to it, as lines.
function Get-MoseErrorDetail {
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $exception = $ErrorRecord.Exception
    $lines = @("  Error: $($exception.GetType().FullName): $($exception.Message)")
    for ($inner = $exception.InnerException; $inner; $inner = $inner.InnerException) {
        $lines += "  Because: $($inner.GetType().FullName): $($inner.Message)"
    }
    if ($ErrorRecord.InvocationInfo) {
        # The script, line and statement, with ~~~ under the part that failed.
        $lines += @($ErrorRecord.InvocationInfo.PositionMessage -split '\r?\n' | ForEach-Object { "  $_" })
    }
    if ($ErrorRecord.ScriptStackTrace) {
        $lines += '  Call stack:'
        $lines += @($ErrorRecord.ScriptStackTrace -split '\r?\n' | ForEach-Object { "    $_" })
    }
    return $lines
}

# A module's error as plain data, which reaches Report.ps1 intact from the module's own process.
function ConvertTo-MoseFailure {
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    [pscustomobject]@{
        MoseFailure          = $true
        Message              = $ErrorRecord.Exception.Message
        Location             = Get-MoseErrorLocation $ErrorRecord
        Detail               = @(Get-MoseErrorDetail $ErrorRecord)
        # Set by Veeam and Hyper-V when the server refused the login over PowerShell remoting.
        RemotingAccessDenied = [bool]$ErrorRecord.Exception.Data['RemotingAccessDenied']
        # Set by the Veeam REST API module: a refused login, or a certificate this computer doesn't trust.
        LoginRefused         = [bool]$ErrorRecord.Exception.Data['LoginRefused']
        UntrustedCertificate = "$($ErrorRecord.Exception.Data['UntrustedCertificate'])"
        CertificateSubject   = "$($ErrorRecord.Exception.Data['CertificateSubject'])"
    }
}

# Commvault keeps its tokens in the secret itself, so a target is named after that secret.
function Get-MoseTargetName {
    param(
        [Parameter(Mandatory)] [object]$Target
    )

    if ($Target.Server) {
        return $Target.Server
    }
    return $Target.Secret
}

# Vault secrets holding Commvault tokens in the format 'CommvaultCloud report.ps1' reads.
function Get-CommvaultSecretNames {
    param(
        [Parameter(Mandatory)] [ValidateSet('Cloud', 'OnPrem')] [string]$Mode,
        [string]$Vault = $MoseVaultName
    )

    foreach ($info in @(Get-SecretInfo -Vault $Vault | Where-Object { "$($_.Type)" -eq 'Hashtable' })) {
        $secret = Get-Secret -Vault $Vault -Name $info.Name -AsPlainText
        if ($secret -is [System.Collections.IDictionary] -and $secret['Type'] -eq $Mode) {
            $info.Name
        }
    }
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

# PowerShell remoting (Veeam, Hyper-V) only sends a login to an IP address that is in this
# computer's TrustedHosts, and only a login given explicitly. With the server's name in the
# domain, Kerberos needs neither.
function Test-MoseIPAddress {
    param(
        [string]$Server
    )

    $address = $null
    return [System.Net.IPAddress]::TryParse($Server, [ref]$address)
}

# Read with WSMan:\ when the WinRM service runs, else from the registry, where WinRM keeps it
# (the service is often stopped on a workstation). A list set by group policy replaces the local one.
function Get-MoseTrustedHosts {
    $policyList = Get-MoseProperty (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -ErrorAction SilentlyContinue) 'TrustedHostsList'
    try {
        $list = (Get-Item -Path WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value
    }
    catch {
        $list = $policyList
        if (-not $list) {
            $list = Get-MoseProperty (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client' -ErrorAction SilentlyContinue) 'trusted_hosts'
        }
    }
    return [pscustomobject]@{
        Hosts    = @("$list" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        ByPolicy = [bool]$policyList
    }
}

function Test-MoseTrustedHost {
    param(
        [string]$Server
    )

    return @((Get-MoseTrustedHosts).Hosts | Where-Object { $Server -like $_ }).Count -gt 0
}

# Adds $Server to TrustedHosts in a PowerShell window run as administrator (Windows asks first),
# starting the WinRM service for the change when it is stopped. Returns $true when it was added.
function Add-MoseTrustedHost {
    param(
        [string]$Server
    )

    if (-not (Test-MoseIPAddress $Server) -and $Server -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') {
        throw "'$Server' is not an IP address or a host name."
    }
    $command = @"
`$code = 0
`$stopped = (Get-Service -Name WinRM).Status -ne 'Running'
try {
    if (`$stopped) { Start-Service -Name WinRM -ErrorAction Stop }
    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value '$Server' -Concatenate -Force -ErrorAction Stop
}
catch {
    Write-Host "Could not add $Server to TrustedHosts: `$(`$_.Exception.Message)" -ForegroundColor Red
    Read-Host 'Press Enter to close'
    `$code = 1
}
finally {
    if (`$stopped) { Stop-Service -Name WinRM -ErrorAction SilentlyContinue }
}
exit `$code
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    try {
        $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -Wait -PassThru `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
    }
    catch {
        # Cancelled at the administrator prompt.
        Write-Host "TrustedHosts was not changed: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
    if ($process.ExitCode -ne 0) {
        return $false
    }
    Write-Host "Added $Server to this computer's TrustedHosts." -ForegroundColor Green
    return $true
}

# Offers to add $Server to TrustedHosts when it is not there; returns $true when it is there.
function Confirm-MoseTrustedHost {
    param(
        [string]$Server
    )

    if (Test-MoseTrustedHost $Server) {
        return $true
    }
    $manual = "As administrator: Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$Server' -Concatenate -Force"
    if ((Get-MoseTrustedHosts).ByPolicy) {
        Write-Host "$Server is not in TrustedHosts, which a group policy sets on this computer: ask its administrator to add it." -ForegroundColor Yellow
        return $false
    }
    # Windows does not check the identity of a server in TrustedHosts.
    if (-not (Read-YesNo "Add $Server to this computer's TrustedHosts now? Windows asks for administrator rights. Only on a network you trust, as Windows then doesn't check the server's identity")) {
        Write-Host "Not added. $manual" -ForegroundColor Yellow
        return $false
    }
    if (-not (Add-MoseTrustedHost $Server)) {
        Write-Host $manual -ForegroundColor Yellow
        return $false
    }
    return $true
}
