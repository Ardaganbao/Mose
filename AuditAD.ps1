[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'A domain controller (name or address) or the domain name. Default: the domain of this computer.')]
    [string]$Server,

    [Parameter(HelpMessage = 'A domain account (DOMAIN\user). Default: the Windows user running the audit.')]
    [pscredential]$Credential,

    [Parameter(HelpMessage = 'Accounts not used for this many days are reported as stale.')]
    [int]$StaleDays = 90
)

# Audit of Active Directory over LDAP, with any domain account (no administrator rights, no RSAT): the
# domain and its controllers, the password policy, the privileged accounts, the users and computers
# with their Windows support, and the group policies. Passwords are never read: Active Directory
# doesn't give them, and LAPS is only checked for its expiry dates.

$ErrorActionPreference = 'Stop'
# Start.ps1 runs in strict mode, where an attribute or regex group that is missing is an error; this
# script expects $null for it. Off for this script only.
Set-StrictMode -Off
. (Join-Path $PSScriptRoot 'AuditCommon.ps1')
Add-Type -AssemblyName System.DirectoryServices
$area = 'Active Directory'
$prefix = if ($Server) { "LDAP://$Server/" } else { 'LDAP://' }
$staleSince = (Get-Date).AddDays(-$StaleDays)

function New-LdapEntry {
    param(
        [string]$DistinguishedName
    )

    if ($Credential) {
        return New-Object System.DirectoryServices.DirectoryEntry("$prefix$DistinguishedName", $Credential.UserName, $Credential.GetNetworkCredential().Password, [System.DirectoryServices.AuthenticationTypes]::Secure)
    }
    return New-Object System.DirectoryServices.DirectoryEntry("$prefix$DistinguishedName")
}

# A value in an LDAP filter: ( ) * \ and NUL are written as \hh.
function Format-LdapValue {
    param(
        [string]$Value
    )

    return $Value -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29' -replace "`0", '\00'
}

# The objects under Base that match Filter, with these attributes: one value, an array for several, or
# $null.
function Find-LdapObject {
    param(
        [string]$Base,
        [string]$Filter,
        [string[]]$Properties,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [string]$Scope = 'Subtree'
    )

    $searcher = New-Object System.DirectoryServices.DirectorySearcher((New-LdapEntry $Base), $Filter, $Properties, ([System.DirectoryServices.SearchScope]$Scope))
    $searcher.PageSize = 500
    $results = $searcher.FindAll()
    try {
        foreach ($result in $results) {
            $object = [ordered]@{}
            foreach ($name in $Properties) {
                $values = $result.Properties[$name.ToLower()]
                # Assigned in each branch: "= if ..." would unroll a byte array (objectSid) into an object array.
                if ($values.Count -gt 1) {
                    $object[$name] = @($values)
                }
                elseif ($values.Count -eq 1) {
                    $object[$name] = $values[0]
                }
                else {
                    $object[$name] = $null
                }
            }
            [pscustomobject]$object
        }
    }
    finally {
        $results.Dispose()
        $searcher.Dispose()
    }
}

# Active Directory times are 100-nanosecond counts since 1601; 0 and the largest value mean never.
function ConvertFrom-AdTime {
    param(
        $Value
    )

    if ($null -eq $Value -or [long]$Value -le 0 -or [long]$Value -ge [long]::MaxValue) {
        return $null
    }
    return [DateTime]::FromFileTimeUtc([long]$Value).ToLocalTime()
}

function ConvertTo-SidText {
    param(
        $Value
    )

    if ($Value -is [byte[]]) {
        return (New-Object System.Security.Principal.SecurityIdentifier($Value, 0)).Value
    }
    return $null
}

function Format-Date {
    param(
        $Value
    )

    if ($Value) {
        return ([datetime]$Value).ToString('yyyy-MM-dd')
    }
    return 'never'
}

$levels = @{ 0 = '2000'; 1 = '2003 interim'; 2 = '2003'; 3 = '2008'; 4 = '2008 R2'; 5 = '2012'; 6 = '2012 R2'; 7 = '2016'; 10 = '2025' }

Write-Progress -Id 30 -Activity 'Active Directory audit' -Status 'Domain' -PercentComplete 0
try {
    $rootDse = New-LdapEntry 'RootDSE'
    $defaultNC = "$($rootDse.Properties['defaultNamingContext'].Value)"
    $configNC = "$($rootDse.Properties['configurationNamingContext'].Value)"
    $rootNC = "$($rootDse.Properties['rootDomainNamingContext'].Value)"
    $domainLevel = [int]"$($rootDse.Properties['domainFunctionality'].Value)"
    $forestLevel = [int]"$($rootDse.Properties['forestFunctionality'].Value)"
    $answeringDc = "$($rootDse.Properties['dnsHostName'].Value)"
}
catch {
    $where = if ($Server) { $Server } else { "the domain of $env:COMPUTERNAME" }
    throw "Active Directory of $where could not be read: $($_.Exception.Message.Trim())"
}
if (-not $defaultNC) {
    throw "No Active Directory domain answered$(if ($Server) { " at $Server" })."
}

$domain = Find-LdapObject -Base $defaultNC -Scope Base -Filter '(objectClass=domainDNS)' -Properties name, objectSid, whenCreated, minPwdLength, pwdHistoryLength, maxPwdAge, lockoutThreshold, pwdProperties, 'ms-DS-MachineAccountQuota', fSMORoleOwner
$domainSid = ConvertTo-SidText $domain.objectSid
$partition = Find-LdapObject -Base "CN=Partitions,$configNC" -Filter "(&(objectClass=crossRef)(nCName=$(Format-LdapValue $defaultNC)))" -Properties nETBIOSName, dnsRoot | Select-Object -First 1
$upnSuffixes = @((Find-LdapObject -Base "CN=Partitions,$configNC" -Scope Base -Filter '(objectClass=crossRefContainer)' -Properties uPNSuffixes).uPNSuffixes | Where-Object { $_ })
$dnsName = "$($partition.dnsRoot)"
$netBiosName = "$($partition.nETBIOSName)"
$pdc = if ("$($domain.fSMORoleOwner)" -match '^CN=NTDS Settings,CN=([^,]+)') { $Matches[1] }
$recycleBin = $null
try {
    $feature = Find-LdapObject -Base "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Scope Base -Filter '(objectClass=*)' -Properties 'msDS-EnabledFeatureBL'
    $recycleBin = [bool]$feature.'msDS-EnabledFeatureBL'
}
catch {
    # Before Windows Server 2008 R2 there is no Recycle Bin.
}

Write-Progress -Id 30 -Activity 'Active Directory audit' -Status 'Domain controllers' -PercentComplete 10
$controllers = @(Find-LdapObject -Base $defaultNC -Filter '(&(objectCategory=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(userAccountControl:1.2.840.113556.1.4.803:=67108864)))' -Properties name, dNSHostName, operatingSystem, operatingSystemVersion, lastLogonTimestamp, userAccountControl |
        Sort-Object -Property name | ForEach-Object {
            [pscustomobject]@{
                Name      = $_.name
                DnsName   = $_.dNSHostName
                Os        = $_.operatingSystem
                Version   = $_.operatingSystemVersion
                ReadOnly  = [bool]([int]$_.userAccountControl -band 67108864)
                LastLogon = ConvertFrom-AdTime $_.lastLogonTimestamp
                Support   = Get-WindowsSupportEnd -Name $_.operatingSystem -Version $_.operatingSystemVersion
            }
        })

Write-Progress -Id 30 -Activity 'Active Directory audit' -Status 'Users' -PercentComplete 25
$users = @(Find-LdapObject -Base $defaultNC -Filter '(&(objectCategory=person)(objectClass=user))' -Properties sAMAccountName, displayName, userPrincipalName, userAccountControl, lastLogonTimestamp, pwdLastSet, whenCreated, description, servicePrincipalName, objectSid, mail |
        ForEach-Object {
            $flags = [int]$_.userAccountControl
            $sid = ConvertTo-SidText $_.objectSid
            [pscustomobject]@{
                Login                = $_.sAMAccountName
                Name                 = $_.displayName
                Upn                  = $_.userPrincipalName
                Mail                 = $_.mail
                Enabled              = -not ($flags -band 2)
                PasswordNeverExpires = [bool]($flags -band 65536)
                PasswordNotRequired  = [bool]($flags -band 32)
                NoPreauthentication  = [bool]($flags -band 4194304)
                Delegation           = [bool]($flags -band 524288)
                LastLogon            = ConvertFrom-AdTime $_.lastLogonTimestamp
                PasswordSet          = ConvertFrom-AdTime $_.pwdLastSet
                Created              = $_.whenCreated
                HasSpn               = [bool]$_.servicePrincipalName
                # Only whether the description looks like it holds a password: the text itself stays out of the audit.
                PasswordInDescription = "$($_.description)" -match '(?i)pass|pwd|mdp|mot de passe|wachtwoord|ww\s*:'
                Rid                  = $(if ($sid) { [int]($sid -split '-')[-1] })
                Sid                  = $sid
            }
        } | Sort-Object -Property Login)

# The privileged groups, by their well-known SIDs (their names depend on the language of the domain).
Write-Progress -Id 30 -Activity 'Active Directory audit' -Status 'Privileged groups' -PercentComplete 45
$privilegedSids = [ordered]@{
    "$domainSid-512" = 'Domain Admins'
    "$domainSid-519" = 'Enterprise Admins'
    "$domainSid-518" = 'Schema Admins'
    'S-1-5-32-544'   = 'Administrators'
    'S-1-5-32-548'   = 'Account Operators'
    'S-1-5-32-549'   = 'Server Operators'
    'S-1-5-32-551'   = 'Backup Operators'
    'S-1-5-32-550'   = 'Print Operators'
}
if ($rootNC -ne $defaultNC) {
    # Enterprise and Schema Admins are groups of the forest root domain.
    $privilegedSids.Remove("$domainSid-519")
    $privilegedSids.Remove("$domainSid-518")
}
$privileged = @(foreach ($sid in $privilegedSids.Keys) {
        $group = Find-LdapObject -Base $defaultNC -Filter "(&(objectClass=group)(objectSid=$sid))" -Properties distinguishedName, name | Select-Object -First 1
        if (-not $group) {
            continue
        }
        # Members of nested groups too.
        $members = @(Find-LdapObject -Base $defaultNC -Filter "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$(Format-LdapValue $group.distinguishedName)))" -Properties sAMAccountName |
                ForEach-Object { $_.sAMAccountName } | Sort-Object)
        [pscustomobject]@{ Group = $privilegedSids[$sid]; Name = $group.name; Members = $members }
    })
$adminLogins = @($privileged | Where-Object { $_.Group -in 'Domain Admins', 'Enterprise Admins', 'Administrators' } | ForEach-Object { $_.Members } | Select-Object -Unique)

Write-Progress -Id 30 -Activity 'Active Directory audit' -Status 'Computers' -PercentComplete 60
$computers = @(Find-LdapObject -Base $defaultNC -Filter '(objectCategory=computer)' -Properties name, dNSHostName, operatingSystem, operatingSystemVersion, lastLogonTimestamp, userAccountControl, whenCreated, 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime' |
        ForEach-Object {
            [pscustomobject]@{
                Name      = $_.name
                DnsName   = $_.dNSHostName
                Os        = $_.operatingSystem
                Version   = $_.operatingSystemVersion
                Enabled   = -not ([int]$_.userAccountControl -band 2)
                LastLogon = ConvertFrom-AdTime $_.lastLogonTimestamp
                Created   = $_.whenCreated
                Laps      = [bool]($_.'ms-Mcs-AdmPwdExpirationTime' -or $_.'msLAPS-PasswordExpirationTime')
                Support   = Get-WindowsSupportEnd -Name $_.operatingSystem -Version $_.operatingSystemVersion
            }
        } | Sort-Object -Property Name)

Write-Progress -Id 30 -Activity 'Active Directory audit' -Status 'Group policies' -PercentComplete 80
$policies = @(Find-LdapObject -Base "CN=Policies,CN=System,$defaultNC" -Filter '(objectClass=groupPolicyContainer)' -Properties displayName, whenChanged, flags |
        ForEach-Object { [pscustomobject]@{ Name = $_.displayName; Changed = $_.whenChanged; Disabled = [int]$_.flags -eq 3 } } | Sort-Object -Property Name)
$krbtgt = $users | Where-Object { $_.Rid -eq 502 } | Select-Object -First 1
$builtinAdmin = $users | Where-Object { $_.Rid -eq 500 } | Select-Object -First 1
$guest = $users | Where-Object { $_.Rid -eq 501 } | Select-Object -First 1
$syncAccounts = @($users | Where-Object { $_.Login -match '^(MSOL_|Sync_|AAD_|provAgentgMSA)' })
Write-Progress -Id 30 -Activity 'Active Directory audit' -Completed

# The people's accounts: not krbtgt, Guest or the sync accounts.
$enabledUsers = @($users | Where-Object { $_.Enabled -and $_.Rid -notin 501, 502 -and $_.Login -notmatch '^(MSOL_|Sync_|AAD_|provAgentgMSA)' })
$staleUsers = @($enabledUsers | Where-Object { -not $_.LastLogon -or $_.LastLogon -lt $staleSince })
$enabledComputers = @($computers | Where-Object { $_.Enabled })
$activeComputers = @($enabledComputers | Where-Object { $_.LastLogon -and $_.LastLogon -ge $staleSince })
$staleComputers = @($enabledComputers | Where-Object { -not $_.LastLogon -or $_.LastLogon -lt $staleSince })
$maxPasswordAge = if ($domain.maxPwdAge -and [long]$domain.maxPwdAge -ne [long]::MinValue -and [long]$domain.maxPwdAge -ne 0) { [math]::Round(-[long]$domain.maxPwdAge / 864000000000) }
$complexity = [bool]([int]$domain.pwdProperties -band 1)

"### Domain"
Format-AuditTable -Rows @(
    [pscustomobject]@{ Item = 'Domain'; Value = "$dnsName ($netBiosName)" }
    [pscustomobject]@{ Item = 'Forest'; Value = (($rootNC -replace '^DC=', '') -replace ',DC=', '.') }
    [pscustomobject]@{ Item = 'Functional level'; Value = "domain $($levels[$domainLevel]), forest $($levels[$forestLevel])" }
    [pscustomobject]@{ Item = 'Created'; Value = Format-Date $domain.whenCreated }
    [pscustomobject]@{ Item = 'PDC emulator'; Value = $pdc }
    [pscustomobject]@{ Item = 'Read from'; Value = $answeringDc }
    [pscustomobject]@{ Item = 'Recycle Bin'; Value = $(if ($null -eq $recycleBin) { 'n/a' } elseif ($recycleBin) { 'On' } else { 'Off' }) }
    [pscustomobject]@{ Item = 'UPN suffixes'; Value = $(if ($upnSuffixes.Count) { $upnSuffixes -join ', ' } else { 'none besides the domain' }) }
    [pscustomobject]@{ Item = 'Synchronised to Microsoft Entra ID'; Value = $(if ($syncAccounts.Count) { "Yes (account $(($syncAccounts | ForEach-Object { $_.Login }) -join ', '))" } else { 'No sync account found' }) }
    [pscustomobject]@{ Item = 'Machine account quota'; Value = "$($domain.'ms-DS-MachineAccountQuota')" }
) -Columns ' =Item', ' =Value'

"`n### Domain controllers"
Format-AuditTable -Rows ($controllers | Select-Object -Property *, @{ Name = 'SupportText'; Expression = { Format-WindowsSupport $_.Support } }, @{ Name = 'Seen'; Expression = { Format-Date $_.LastLogon } }) -Columns 'Name', 'DNS name=DnsName', 'Windows=Os', 'Version', 'Support=SupportText', 'Read-only=ReadOnly', 'Last logon=Seen'

"`n### Password policy"
Format-AuditTable -Rows @([pscustomobject]@{
        Length     = "$($domain.minPwdLength) characters"
        History    = "$($domain.pwdHistoryLength) passwords"
        MaxAge     = $(if ($maxPasswordAge) { "$maxPasswordAge days" } else { 'never expires' })
        Complexity = $(if ($complexity) { 'On' } else { 'Off' })
        Lockout    = $(if ([int]$domain.lockoutThreshold -gt 0) { "after $($domain.lockoutThreshold) wrong passwords" } else { 'never' })
    }) -Columns 'Minimum length=Length', 'History', 'Maximum age=MaxAge', 'Complexity', 'Lockout'
"Fine-grained password policies, if any, are not read."

"`n### Privileged accounts"
Format-AuditTable -Rows ($privileged | Where-Object { $_.Members.Count -gt 0 -or $_.Group -eq 'Domain Admins' } | ForEach-Object {
        [pscustomobject]@{ Group = $(if ($_.Name -ne $_.Group) { "$($_.Group) ($($_.Name))" } else { $_.Group }); Count = $_.Members.Count; Members = $_.Members }
    }) -Columns 'Group', 'Count', 'Members (nested groups included)=Members'

"`n### Users"
"$($users.Count) user accounts: $($enabledUsers.Count) enabled people's accounts, $(@($users | Where-Object { -not $_.Enabled }).Count) disabled, $($staleUsers.Count) enabled but not used for $StaleDays days."
""
Format-AuditTable -Rows ($enabledUsers | Select-Object -First 500 | ForEach-Object {
        $notes = @()
        if ($_.Login -in $adminLogins) { $notes += 'Admin' }
        if (-not $_.LastLogon) { $notes += 'Never logged on' } elseif ($_.LastLogon -lt $staleSince) { $notes += "Unused for $StaleDays days" }
        if ($_.PasswordNeverExpires) { $notes += 'Password never expires' }
        if ($_.PasswordNotRequired) { $notes += 'Password not required' }
        if ($_.HasSpn) { $notes += 'Service (SPN)' }
        if ($_.PasswordInDescription) { $notes += 'Description mentions a password' }
        [pscustomobject]@{ Login = $_.Login; Name = $_.Name; Upn = $_.Upn; LastLogon = Format-Date $_.LastLogon; PasswordSet = Format-Date $_.PasswordSet; Notes = $notes }
    }) -Columns 'Login', 'Name', 'UPN=Upn', 'Last logon=LastLogon', 'Password set=PasswordSet', 'Notes'
if ($enabledUsers.Count -gt 500) {
    "Only the first 500 of $($enabledUsers.Count) enabled users are listed; the JSON file has them all."
}

"`n### Computers"
"$($computers.Count) computer accounts: $($enabledComputers.Count) enabled, $($activeComputers.Count) of them used in the last $StaleDays days. Windows of those:"
""
Format-AuditTable -Rows ($activeComputers | Group-Object -Property { "$($_.Os)" } | Sort-Object -Property Count -Descending | ForEach-Object {
        $versions = @($_.Group | Group-Object -Property Version | Sort-Object -Property Name | ForEach-Object { "$($_.Name) ($($_.Count))" })
        $supports = @($_.Group | ForEach-Object { $_.Support } | Where-Object { $_ -and $_.End } | Sort-Object -Property End)
        [pscustomobject]@{ Os = $(if ($_.Name) { $_.Name } else { 'unknown' }); Count = $_.Count; Versions = $versions; Support = $(if ($supports.Count) { Format-WindowsSupport $supports[0] }) }
    }) -Columns 'Windows=Os', 'Count', 'Versions', 'Support (earliest end)=Support'
""
Format-AuditTable -Rows ($enabledComputers | Select-Object -First 500 | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Os = $_.Os; Version = $_.Version; Support = Format-WindowsSupport $_.Support; LastLogon = Format-Date $_.LastLogon; Laps = $(if ($_.Laps) { 'Yes' } else { 'No' }) }
    }) -Columns 'Name', 'Windows=Os', 'Version', 'Support', 'Last logon=LastLogon', 'LAPS=Laps'

"`n### Group policies"
if ($policies.Count -gt 0) {
    Format-AuditTable -Rows ($policies | Select-Object -Property Name, @{ Name = 'ChangedText'; Expression = { Format-Date $_.Changed } }, @{ Name = 'State'; Expression = { if ($_.Disabled) { 'Disabled' } else { '' } } }) -Columns 'Name', 'Changed=ChangedText', 'State'
}
else {
    "No group policy."
}

# Findings.
foreach ($controller in @($controllers | Where-Object { $_.Support -and $_.Support.Status -ne 'Supported' })) {
    $severity = if ($controller.Support.Status -eq 'Ended') { 'High' } else { 'Medium' }
    New-AuditFinding -Severity $severity -Area $area -Finding "Domain controller $($controller.Name) runs $($controller.Os), whose support $(if ($severity -eq 'High') { 'ended' } else { 'ends' }) on $($controller.Support.End.ToString('yyyy-MM-dd'))." -Recommendation 'Add a domain controller on a supported Windows Server, move the roles, then retire this one.'
}
if ($controllers.Count -eq 1) {
    New-AuditFinding -Severity Medium -Area $area -Finding "The domain has one domain controller ($($controllers[0].Name)): if it fails, nobody can log on and its backup is the only copy of the domain." -Recommendation 'Add a second domain controller, or make sure the backup restores it (test it).'
}
if ($domainLevel -lt 7) {
    New-AuditFinding -Severity Low -Area $area -Finding "The domain functional level is $($levels[$domainLevel]), so newer protections (e.g. the Protected Users group, AES Kerberos for every account) are not all available." -Recommendation 'Once every domain controller runs Windows Server 2016 or later, raise the domain and forest functional levels.'
}
if ([int]$domain.minPwdLength -lt 8 -or -not $complexity) {
    New-AuditFinding -Severity High -Area $area -Finding "Weak password policy: minimum $($domain.minPwdLength) characters, complexity $(if ($complexity) { 'on' } else { 'off' })." -Recommendation 'Require at least 12 characters (14 for administrators); prefer passphrases.'
}
elseif ([int]$domain.minPwdLength -lt 12) {
    New-AuditFinding -Severity Medium -Area $area -Finding "Passwords need only $($domain.minPwdLength) characters." -Recommendation 'Require at least 12 characters; prefer passphrases.'
}
if ([int]$domain.lockoutThreshold -eq 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding 'Accounts never lock out, so passwords can be guessed without limit.' -Recommendation 'Lock an account for 15 minutes after about 10 wrong passwords.'
}
$domainAdmins = @($privileged | Where-Object { $_.Group -eq 'Domain Admins' } | ForEach-Object { $_.Members })
if ($domainAdmins.Count -gt 4) {
    New-AuditFinding -Severity Medium -Area $area -Finding "$($domainAdmins.Count) accounts are Domain Admins: $($domainAdmins -join ', ')." -Recommendation 'Keep two to four named administrator accounts, used only for administration; remove the others.'
}
$adminNeverExpires = @($enabledUsers | Where-Object { $_.Login -in $adminLogins -and $_.PasswordNeverExpires })
if ($adminNeverExpires.Count -gt 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding "Administrator accounts whose password never expires: $(($adminNeverExpires | ForEach-Object { $_.Login }) -join ', ')." -Recommendation 'Give them long unique passwords kept in the password manager, changed when someone leaves.'
}
$staleAdmins = @($staleUsers | Where-Object { $_.Login -in $adminLogins })
if ($staleAdmins.Count -gt 0) {
    New-AuditFinding -Severity High -Area $area -Finding "Enabled administrator accounts not used for $StaleDays days: $(($staleAdmins | ForEach-Object { $_.Login }) -join ', ')." -Recommendation 'Disable them, or remove them from the administrator groups.'
}
$staleOthers = @($staleUsers | Where-Object { $_.Login -notin $adminLogins })
if ($staleOthers.Count -gt 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding "$($staleOthers.Count) enabled accounts not used for $StaleDays days: $(($staleOthers | Select-Object -First 30 | ForEach-Object { $_.Login }) -join ', ')$(if ($staleOthers.Count -gt 30) { ', ...' })." -Recommendation 'Disable the accounts of people who left, and of services no longer used.'
}
$noPassword = @($enabledUsers | Where-Object { $_.PasswordNotRequired })
if ($noPassword.Count -gt 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding "Accounts allowed to have an empty password: $(($noPassword | ForEach-Object { $_.Login }) -join ', ')." -Recommendation 'Clear the "password not required" flag (userAccountControl 32) and set a password.'
}
$asRep = @($enabledUsers | Where-Object { $_.NoPreauthentication })
if ($asRep.Count -gt 0) {
    New-AuditFinding -Severity High -Area $area -Finding "Kerberos pre-authentication is off for $(($asRep | ForEach-Object { $_.Login }) -join ', '): anyone can get data to crack their password offline." -Recommendation 'Turn pre-authentication back on for these accounts.'
}
$spnUsers = @($enabledUsers | Where-Object { $_.HasSpn })
if ($spnUsers.Count -gt 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding "Service accounts with an SPN, whose password any domain user can try to crack offline: $(($spnUsers | ForEach-Object { $_.Login }) -join ', ')." -Recommendation 'Give them passwords of 25+ random characters, or use group managed service accounts.'
}
$described = @($users | Where-Object { $_.PasswordInDescription })
if ($described.Count -gt 0) {
    New-AuditFinding -Severity High -Area $area -Finding "The description of $(($described | ForEach-Object { $_.Login }) -join ', ') mentions a password; every domain user can read it." -Recommendation 'Remove it from the description (and change that password); keep passwords in the password manager.'
}
if ($krbtgt -and $krbtgt.PasswordSet -and $krbtgt.PasswordSet -lt (Get-Date).AddYears(-1)) {
    New-AuditFinding -Severity Medium -Area $area -Finding "The krbtgt password was last changed on $(Format-Date $krbtgt.PasswordSet): a stolen copy of it would still work." -Recommendation "Reset it twice, some hours apart (Microsoft's New-KrbtgtKeys.ps1), then yearly."
}
if ($builtinAdmin -and $builtinAdmin.Enabled -and $builtinAdmin.PasswordSet -and $builtinAdmin.PasswordSet -lt (Get-Date).AddYears(-1)) {
    New-AuditFinding -Severity Medium -Area $area -Finding "The built-in Administrator account ($($builtinAdmin.Login)) is enabled, with a password from $(Format-Date $builtinAdmin.PasswordSet)." -Recommendation 'Give it a long password kept in the password manager, and use named administrator accounts day to day.'
}
if ($guest -and $guest.Enabled) {
    New-AuditFinding -Severity Medium -Area $area -Finding 'The Guest account is enabled.' -Recommendation 'Disable it.'
}
$endedComputers = @($activeComputers | Where-Object { $_.Support -and $_.Support.Status -eq 'Ended' })
if ($endedComputers.Count -gt 0) {
    New-AuditFinding -Severity High -Area $area -Finding "$($endedComputers.Count) computers in use run a Windows without security updates: $(($endedComputers | Select-Object -First 30 | ForEach-Object { "$($_.Name) ($($_.Os) $($_.Version))" }) -join ', ')$(if ($endedComputers.Count -gt 30) { ', ...' })." -Recommendation 'Update them to a supported Windows version (Windows 11 feature update, or a newer Windows Server), or replace them.'
}
$endingComputers = @($activeComputers | Where-Object { $_.Support -and $_.Support.Status -eq 'Ending' })
if ($endingComputers.Count -gt 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding "$($endingComputers.Count) computers run a Windows whose support ends soon: $(($endingComputers | Select-Object -First 30 | ForEach-Object { "$($_.Name) ($($_.Os) $($_.Version), $($_.Support.End.ToString('yyyy-MM-dd')))" }) -join ', ')$(if ($endingComputers.Count -gt 30) { ', ...' })." -Recommendation 'Plan their update (Windows 11 feature update) or replacement.'
}
$unknownVersions = @($activeComputers | Where-Object { $_.Support -and $_.Support.Status -eq 'Unknown' })
if ($unknownVersions.Count -gt 0) {
    New-AuditFinding -Severity Info -Area $area -Finding "$($unknownVersions.Count) computers run a Windows 11 version this audit has no end of support for ($(($unknownVersions | Group-Object -Property Version | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ', ')): an Insider or a newer build." -Recommendation 'Check that they run a released version; add its dates to $windowsSupportEnds in AuditCommon.ps1.'
}
if ($staleComputers.Count -gt 0) {
    New-AuditFinding -Severity Low -Area $area -Finding "$($staleComputers.Count) enabled computer accounts not used for $StaleDays days." -Recommendation 'Disable, then delete, the accounts of computers that are gone.'
}
# LAPS is for Windows computers other than the domain controllers (a NAS joined to the domain has none).
$lapsComputers = @($activeComputers | Where-Object { "$($_.Os)" -like 'Windows*' -and $_.Name -notin @($controllers | ForEach-Object { $_.Name }) })
$withoutLaps = @($lapsComputers | Where-Object { -not $_.Laps })
if ($withoutLaps.Count -gt 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding "$($withoutLaps.Count) of $($lapsComputers.Count) Windows computers in use have no LAPS: their local administrator passwords are probably the same everywhere." -Recommendation 'Turn on Windows LAPS by group policy, so that each computer gets its own local administrator password.'
}
if ($recycleBin -eq $false) {
    New-AuditFinding -Severity Low -Area $area -Finding 'The Active Directory Recycle Bin is off: a deleted account or OU comes back only from a backup.' -Recommendation 'Turn it on (Active Directory Administrative Center, or Enable-ADOptionalFeature).'
}
if ([int]$domain.'ms-DS-MachineAccountQuota' -gt 0) {
    New-AuditFinding -Severity Low -Area $area -Finding "Any domain user can join $($domain.'ms-DS-MachineAccountQuota') computers to the domain." -Recommendation 'Set ms-DS-MachineAccountQuota to 0 and let only IT join computers.'
}

New-AuditData -Name 'ActiveDirectory' -Value ([pscustomobject]@{
        Domain           = $dnsName
        NetBiosName      = $netBiosName
        UpnSuffixes      = $upnSuffixes
        FunctionalLevel  = $levels[$domainLevel]
        Controllers      = $controllers
        PasswordPolicy   = [pscustomobject]@{ MinimumLength = [int]$domain.minPwdLength; History = [int]$domain.pwdHistoryLength; MaximumAgeDays = $maxPasswordAge; Complexity = $complexity; LockoutThreshold = [int]$domain.lockoutThreshold }
        Privileged       = $privileged
        Users            = @($users | Select-Object -Property * -ExcludeProperty Sid)
        Computers        = $computers
        GroupPolicies    = $policies
        SyncedToEntra    = [bool]$syncAccounts.Count
    })
