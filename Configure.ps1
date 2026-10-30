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

$config = Get-MoseConfig
$client = ''
$targets = New-Object System.Collections.Generic.List[object]
if ($config) {
    $client = $config.Client
    foreach ($target in @($config.Targets)) {
        $targets.Add($target)
    }
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
    Write-Host ""

    $choice = Read-Answer 'Module number to add servers, R to remove one, S to save, Q to quit without saving'
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
    elseif ($choice -match '^[Ss]$') {
        Save-MoseConfig -Client $client -Targets $targets.ToArray()
        Write-Host "Saved the configuration of $client ($($targets.Count) servers)." -ForegroundColor Green
        return
    }
    elseif ($choice -match '^[Qq]$') {
        Write-Host "Nothing was saved." -ForegroundColor Yellow
        return
    }
}
