[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'The tenant to sign in to: one of its domains or its ID. Default: the tenant of the account you sign in with.')]
    [string]$Tenant,

    [Parameter(HelpMessage = 'Sign in with a code on another device, when no browser can open here.')]
    [switch]$UseDeviceCode,

    [Parameter(HelpMessage = 'Users and devices not signed in for this many days are reported as stale.')]
    [int]$StaleDays = 90
)

# Audit of Microsoft 365 over Microsoft Graph, read only: the tenant and its domains, the licences, the
# users with their licences, MFA methods and last sign-in, the administrators, the security defaults
# and Conditional Access, and the devices in Entra ID. A Global Reader or Global Administrator signs
# in; the first time in a tenant, an administrator consents to the read permissions of Microsoft
# Graph PowerShell. The sign-in is kept in this PowerShell process only, and ended at the end.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'AuditCommon.ps1')
$area = 'Microsoft 365'
$staleSince = (Get-Date).AddDays(-$StaleDays)

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    $answer = Read-Host 'Microsoft 365 is read with the Microsoft Graph PowerShell module (Microsoft.Graph.Authentication), not installed here. Install it for this Windows user from the PowerShell Gallery? [Y/n]'
    if ($answer -match '^(n|no|non|nee)$') {
        throw 'Microsoft 365 skipped: the module Microsoft.Graph.Authentication is not installed (Install-Module Microsoft.Graph.Authentication -Scope CurrentUser).'
    }
    Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph.Authentication

# Every item of a Graph list, page after page, or the object itself.
function Get-Graph {
    param(
        [string]$Uri
    )

    $response = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
    if (-not $response.PSObject.Properties['value']) {
        return $response
    }
    $response.value
    while ($response.PSObject.Properties['@odata.nextLink'] -and $response.'@odata.nextLink') {
        $response = Invoke-MgGraphRequest -Method GET -Uri $response.'@odata.nextLink' -OutputType PSObject
        $response.value
    }
}

# A Graph call that a licence (Entra ID P1) or a permission may refuse: $null, and why in $script:Refused.
function Get-GraphOptional {
    param(
        [string]$Uri,
        [string]$What
    )

    try {
        # The comma keeps an empty list a list: none is not refused.
        return , @(Get-Graph $Uri)
    }
    catch {
        $reason = "$($_.Exception.Message)" -replace '\s+', ' '
        $script:Refused[$What] = if ($reason -match '(?i)premium|license|licence|P1|P2') { 'needs Microsoft Entra ID P1' } elseif ($reason -match '403|Forbidden|Authorization|denied') { 'refused: the account needs Global Reader' } else { $reason }
        Write-Verbose "$What not read: $reason"
        return $null
    }
}
$script:Refused = @{}

# Licence names from Microsoft's list, cached for 30 days: Business Standard rather than O365_BUSINESS_PREMIUM.
function Get-LicenceNames {
    $names = @{}
    $path = Get-AuditCacheFile -Name 'licence-names.csv' -Uri 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv' -MaxAgeDays 30
    if ($path) {
        foreach ($row in Import-Csv -LiteralPath $path) {
            if ($row.String_Id -and -not $names.ContainsKey($row.String_Id)) {
                $names[$row.String_Id] = $row.Product_Display_Name
            }
        }
    }
    return $names
}

function Format-Date {
    param(
        $Value
    )

    if ($Value) {
        return ([datetime]$Value).ToLocalTime().ToString('yyyy-MM-dd')
    }
    return 'never'
}

$connect = @{ Scopes = @('Organization.Read.All', 'Directory.Read.All', 'User.Read.All', 'Policy.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory'); NoWelcome = $true; ContextScope = 'Process' }
if ($Tenant) {
    $connect.TenantId = $Tenant
}
if ($UseDeviceCode) {
    $connect.UseDeviceCode = $true
}
Write-Host 'Sign in to Microsoft 365 with an administrator account of the client (Global Reader is enough)...' -ForegroundColor Cyan
Connect-MgGraph @connect
try {
    $context = Get-MgContext
    Write-Progress -Id 50 -Activity 'Microsoft 365 audit' -Status 'Tenant' -PercentComplete 0
    $organization = @(Get-Graph '/v1.0/organization')[0]
    $domains = @(Get-Graph '/v1.0/domains')
    $securityDefaults = Get-GraphOptional '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' 'Security defaults'
    $conditionalAccess = Get-GraphOptional '/v1.0/identity/conditionalAccess/policies' 'Conditional Access'

    Write-Progress -Id 50 -Activity 'Microsoft 365 audit' -Status 'Licences' -PercentComplete 10
    $licenceNames = Get-LicenceNames
    $skus = @(Get-Graph '/v1.0/subscribedSkus' | ForEach-Object {
            [pscustomobject]@{
                Id       = $_.skuId
                Part     = $_.skuPartNumber
                Name     = $(if ($licenceNames[$_.skuPartNumber]) { $licenceNames[$_.skuPartNumber] } else { $_.skuPartNumber })
                Total    = [int]$_.prepaidUnits.enabled
                Assigned = [int]$_.consumedUnits
                Status   = $_.capabilityStatus
                Warning  = [int]$_.prepaidUnits.warning
                Suspended = [int]$_.prepaidUnits.suspended
            }
        } | Sort-Object -Property Name)
    $skuNames = @{}
    foreach ($sku in $skus) {
        $skuNames[$sku.Id] = $sku.Name
    }

    Write-Progress -Id 50 -Activity 'Microsoft 365 audit' -Status 'Users' -PercentComplete 20
    $select = 'id,displayName,userPrincipalName,accountEnabled,userType,assignedLicenses,createdDateTime,onPremisesSyncEnabled'
    # The last sign-in needs Entra ID P1; without it, the users without it.
    $rawUsers = Get-GraphOptional "/v1.0/users?`$select=$select,signInActivity&`$top=999" 'Last sign-in'
    if ($null -eq $rawUsers) {
        $rawUsers = @(Get-Graph "/v1.0/users?`$select=$select&`$top=999")
    }

    Write-Progress -Id 50 -Activity 'Microsoft 365 audit' -Status 'MFA methods' -PercentComplete 40
    # The MFA methods of each user: from the registration report (Entra ID P1), else user by user.
    $methods = @{}
    $registrations = Get-GraphOptional '/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999' 'MFA registration report'
    if ($null -ne $registrations) {
        foreach ($registration in $registrations) {
            $methods[$registration.id] = @($registration.methodsRegistered | Where-Object { $_ -notin 'password', 'email', 'securityQuestion' })
        }
    }
    else {
        $people = @($rawUsers | Where-Object { $_.accountEnabled -and $_.userType -eq 'Member' } | Select-Object -First 300)
        $index = 0
        foreach ($person in $people) {
            $index++
            Write-Progress -Id 50 -Activity 'Microsoft 365 audit' -Status "MFA methods: $index of $($people.Count)" -PercentComplete (40 + 30 * $index / [math]::Max(1, $people.Count))
            try {
                $methods[$person.id] = @(Get-Graph "/v1.0/users/$($person.id)/authentication/methods" | ForEach-Object { "$($_.'@odata.type')" -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', '' } |
                        Where-Object { $_ -notin 'password', 'email' })
            }
            catch {
                Write-Verbose "MFA methods of $($person.userPrincipalName) not read: $($_.Exception.Message)"
            }
        }
    }

    Write-Progress -Id 50 -Activity 'Microsoft 365 audit' -Status 'Administrators' -PercentComplete 75
    $roles = @(Get-Graph '/v1.0/directoryRoles?$expand=members' | ForEach-Object {
            [pscustomobject]@{ Role = $_.displayName; Members = @($_.members | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } } | Sort-Object) }
        } | Where-Object { $_.Members.Count -gt 0 } | Sort-Object -Property Role)
    $userRoles = @{}
    foreach ($role in $roles) {
        foreach ($member in $role.Members) {
            $userRoles[$member] = @($userRoles[$member]) + $role.Role | Where-Object { $_ }
        }
    }

    Write-Progress -Id 50 -Activity 'Microsoft 365 audit' -Status 'Devices' -PercentComplete 85
    $rawDevices = Get-GraphOptional '/v1.0/devices?$select=displayName,operatingSystem,operatingSystemVersion,trustType,approximateLastSignInDateTime,isCompliant,isManaged,accountEnabled&$top=999' 'Devices'
    $devices = if ($null -ne $rawDevices) { @($rawDevices | ForEach-Object {
            $lastSignIn = if ($_.approximateLastSignInDateTime) { ([datetime]$_.approximateLastSignInDateTime).ToLocalTime() }
            [pscustomobject]@{
                Name       = $_.displayName
                Os         = $_.operatingSystem
                Version    = $_.operatingSystemVersion
                Join       = $(switch ("$($_.trustType)") { 'AzureAd' { 'Entra joined' } 'ServerAd' { 'Hybrid joined' } 'Workplace' { 'Registered' } default { "$($_.trustType)" } })
                Managed    = [bool]$_.isManaged
                Compliant  = $_.isCompliant
                Enabled    = [bool]$_.accountEnabled
                LastSignIn = $lastSignIn
                Support    = $(if ("$($_.operatingSystem)" -match '^Windows') { Get-WindowsSupportEnd -Name 'Windows' -Version $_.operatingSystemVersion })
            }
        } | Sort-Object -Property Name) }
    Write-Progress -Id 50 -Activity 'Microsoft 365 audit' -Completed
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}

$users = @($rawUsers | ForEach-Object {
        $lastSignIn = $null
        if ($_.PSObject.Properties['signInActivity'] -and $_.signInActivity) {
            $dates = @($_.signInActivity.lastSignInDateTime, $_.signInActivity.lastNonInteractiveSignInDateTime, $_.signInActivity.lastSuccessfulSignInDateTime) | Where-Object { $_ } | ForEach-Object { ([datetime]$_).ToLocalTime() } | Sort-Object
            $lastSignIn = @($dates)[-1]
        }
        # No method is an empty list, unknown is $null: assigned here, since $(...) would make both $null.
        $mfa = $null
        if ($methods.ContainsKey($_.id)) {
            $mfa = [string[]]@($methods[$_.id])
        }
        [pscustomobject]@{
            Upn        = $_.userPrincipalName
            Name       = $_.displayName
            Enabled    = [bool]$_.accountEnabled
            Guest      = $_.userType -eq 'Guest'
            Synced     = [bool]$_.onPremisesSyncEnabled
            Licences   = @($_.assignedLicenses | ForEach-Object { if ($skuNames[$_.skuId]) { $skuNames[$_.skuId] } else { $_.skuId } } | Sort-Object)
            Mfa        = $mfa
            LastSignIn = $lastSignIn
            Created    = $_.createdDateTime
            Roles      = @($userRoles[$_.userPrincipalName] | Where-Object { $_ })
        }
    } | Sort-Object -Property Upn)
$members = @($users | Where-Object { -not $_.Guest })
$enabledMembers = @($members | Where-Object { $_.Enabled })
$guests = @($users | Where-Object { $_.Guest })
$signInKnown = -not $script:Refused.ContainsKey('Last sign-in')
$enabledPolicies = @($conditionalAccess | Where-Object { $_.state -eq 'enabled' })
$passwordDays = @($domains | Where-Object { $_.isVerified -and $_.authenticationType -eq 'Managed' } | ForEach-Object { [long]$_.passwordValidityPeriodInDays } | Where-Object { $_ -gt 0 -and $_ -lt 2147483647 })

"### Tenant"
Format-AuditTable -Rows @(
    [pscustomobject]@{ Item = 'Organisation'; Value = "$($organization.displayName)$(if ($organization.countryLetterCode) { " ($($organization.countryLetterCode))" })" }
    [pscustomobject]@{ Item = 'Tenant ID'; Value = $organization.id }
    [pscustomobject]@{ Item = 'Created'; Value = Format-Date $organization.createdDateTime }
    [pscustomobject]@{ Item = 'Read as'; Value = $context.Account }
    [pscustomobject]@{ Item = 'Domains'; Value = @($domains | Sort-Object -Property id | ForEach-Object { "$($_.id)$(if ($_.isDefault) { ' (default)' })$(if (-not $_.isVerified) { ' (not verified)' })$(if ($_.authenticationType -eq 'Federated') { ' (federated)' })" }) }
    [pscustomobject]@{ Item = 'Synchronised from Active Directory'; Value = $(if ($organization.onPremisesSyncEnabled) { "Yes, last sync $(if ($organization.onPremisesLastSyncDateTime) { ([datetime]$organization.onPremisesLastSyncDateTime).ToLocalTime().ToString('yyyy-MM-dd HH:mm') } else { 'never' })" } else { 'No' }) }
    [pscustomobject]@{ Item = 'Security defaults'; Value = $(if ($null -eq $securityDefaults) { "n/a ($($script:Refused['Security defaults']))" } elseif (@($securityDefaults)[0].isEnabled) { 'On' } else { 'Off' }) }
    [pscustomobject]@{ Item = 'Conditional Access'; Value = $(if ($null -eq $conditionalAccess) { "n/a ($($script:Refused['Conditional Access']))" } elseif ($conditionalAccess.Count -eq 0) { 'No policy' } else { @($conditionalAccess | ForEach-Object { "$($_.displayName) ($($_.state))" }) }) }
    [pscustomobject]@{ Item = 'Passwords expire'; Value = $(if ($passwordDays.Count) { "after $(($passwordDays | Select-Object -Unique) -join ', ') days" } else { 'never' }) }
) -Columns ' =Item', ' =Value'

"`n### Licences"
if ($skus.Count -gt 0) {
    Format-AuditTable -Rows ($skus | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Total = $_.Total; Assigned = $_.Assigned; Free = $_.Total - $_.Assigned; Status = $(if ($_.Status -ne 'Enabled') { ":warning: $($_.Status)" } else { 'Active' }) } }) -Columns 'Licence=Name', 'Bought=Total', 'Assigned', 'Free', 'Status'
}
else {
    "No licence."
}

"`n### Users"
"$($users.Count) accounts: $($enabledMembers.Count) enabled members, $(@($members | Where-Object { -not $_.Enabled }).Count) disabled, $($guests.Count) guests.$(if (-not $signInKnown) { " The last sign-in is not shown: it $($script:Refused['Last sign-in'])." })$(if ($script:Refused.ContainsKey('MFA registration report')) { ' MFA methods were read user by user (the first 300 enabled members).' })"
""
Format-AuditTable -Rows ($members | ForEach-Object {
        [pscustomobject]@{
            Upn        = $_.Upn
            Name       = $_.Name
            Enabled    = $(if ($_.Enabled) { 'Yes' } else { 'No' })
            Licences   = $_.Licences
            Mfa        = $(if ($null -eq $_.Mfa) { 'n/a' } elseif ($_.Mfa.Count -eq 0) { ':x: none' } else { $_.Mfa })
            LastSignIn = $(if ($signInKnown) { Format-Date $_.LastSignIn } else { 'n/a' })
            Roles      = $_.Roles
        }
    }) -Columns 'Login=Upn', 'Name', 'Enabled', 'Licences', 'MFA methods=Mfa', 'Last sign-in=LastSignIn', 'Admin roles=Roles'
if ($guests.Count -gt 0) {
    ""
    "Guests: $(($guests | ForEach-Object { $_.Upn -replace '#EXT#.*$', '' -replace '_(?=[^_]+$)', '@' }) -join ', ')."
}

"`n### Administrators"
if ($roles.Count -gt 0) {
    Format-AuditTable -Rows $roles -Columns 'Role', 'Members'
}
else {
    "No administrator role has members."
}

"`n### Devices"
if ($null -eq $devices -or $script:Refused.ContainsKey('Devices')) {
    "Not read: $($script:Refused['Devices'])."
}
elseif ($devices.Count -eq 0) {
    "No device in Entra ID."
}
else {
    $activeDevices = @($devices | Where-Object { $_.Enabled -and $_.LastSignIn -and $_.LastSignIn -ge $staleSince })
    "$($devices.Count) devices in Entra ID, $($activeDevices.Count) signed in during the last $StaleDays days:"
    ""
    Format-AuditTable -Rows ($devices | Group-Object -Property Os, Join | Sort-Object -Property Count -Descending | ForEach-Object { [pscustomobject]@{ Os = $_.Group[0].Os; Join = $_.Group[0].Join; Count = $_.Count } }) -Columns 'System=Os', 'Join type=Join', 'Count'
    ""
    Format-AuditTable -Rows ($devices | Select-Object -First 300 | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Os = $_.Os; Version = $_.Version; Support = Format-WindowsSupport $_.Support; Join = $_.Join; Compliant = $(if ($null -eq $_.Compliant) { '' } elseif ($_.Compliant) { 'Yes' } else { 'No' }); LastSignIn = Format-Date $_.LastSignIn }
        }) -Columns 'Name', 'System=Os', 'Version', 'Support', 'Join type=Join', 'Compliant', 'Last sign-in=LastSignIn'
}

# Findings.
$defaultsOn = $securityDefaults -and @($securityDefaults)[0].isEnabled
if (-not $defaultsOn -and $null -ne $conditionalAccess -and $enabledPolicies.Count -eq 0) {
    New-AuditFinding -Severity High -Area $area -Finding 'Nothing makes users sign in with MFA: security defaults are off and no Conditional Access policy is on.' -Recommendation 'Turn security defaults on, or (with Entra ID P1) Conditional Access policies requiring MFA for every user and blocking legacy authentication.'
}
elseif (-not $defaultsOn -and $null -eq $conditionalAccess) {
    New-AuditFinding -Severity Medium -Area $area -Finding "Security defaults are off, and Conditional Access could not be read ($($script:Refused['Conditional Access']))." -Recommendation 'Check how MFA is enforced; without Entra ID P1, turn security defaults on.'
}
$adminsWithoutMfa = @($enabledMembers | Where-Object { $_.Roles.Count -gt 0 -and $null -ne $_.Mfa -and $_.Mfa.Count -eq 0 })
if ($adminsWithoutMfa.Count -gt 0) {
    New-AuditFinding -Severity High -Area $area -Finding "Administrators with no MFA method: $(($adminsWithoutMfa | ForEach-Object { $_.Upn }) -join ', ')." -Recommendation 'Register MFA for them now (Authenticator app or security key), and keep their credentials in the password manager.'
}
$usersWithoutMfa = @($enabledMembers | Where-Object { $_.Roles.Count -eq 0 -and $_.Licences.Count -gt 0 -and $null -ne $_.Mfa -and $_.Mfa.Count -eq 0 })
if ($usersWithoutMfa.Count -gt 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding "$($usersWithoutMfa.Count) licensed users have no MFA method: $(($usersWithoutMfa | Select-Object -First 30 | ForEach-Object { $_.Upn }) -join ', ')$(if ($usersWithoutMfa.Count -gt 30) { ', ...' })." -Recommendation 'Have them register the Microsoft Authenticator app; shared mailboxes should be shared mailboxes, not users.'
}
$globalAdmins = @($roles | Where-Object { $_.Role -eq 'Global Administrator' } | ForEach-Object { $_.Members })
if ($globalAdmins.Count -gt 4) {
    New-AuditFinding -Severity Medium -Area $area -Finding "$($globalAdmins.Count) accounts are Global Administrators: $($globalAdmins -join ', ')." -Recommendation 'Keep two to four; give the others a smaller role (e.g. User Administrator, Exchange Administrator).'
}
elseif ($globalAdmins.Count -eq 1) {
    New-AuditFinding -Severity Low -Area $area -Finding "Only one Global Administrator ($($globalAdmins[0])): losing its access locks the tenant." -Recommendation 'Add a second, emergency administrator account, kept in the password manager.'
}
$dailyAdmins = @($enabledMembers | Where-Object { $_.Upn -in $globalAdmins -and $_.Licences.Count -gt 0 })
if ($dailyAdmins.Count -gt 0) {
    New-AuditFinding -Severity Low -Area $area -Finding "Global Administrators that are also licensed (used day to day for mail): $(($dailyAdmins | ForEach-Object { $_.Upn }) -join ', ')." -Recommendation 'Use separate, unlicensed accounts for administration.'
}
$freeSkus = 'FREE|TRIAL|EXPLORATORY|VIRAL|POWER_BI_STANDARD|WINDOWS_STORE|STREAM|RIGHTSMANAGEMENT_ADHOC|PHONESYSTEM_VIRTUALUSER|DEVELOPER|_DEV$|FORMS_PRO|CCIBOTS'
$unused = @($skus | Where-Object { $_.Status -eq 'Enabled' -and $_.Total -gt $_.Assigned -and $_.Part -notmatch $freeSkus })
if ($unused.Count -gt 0) {
    New-AuditFinding -Severity Low -Area $area -Finding "Licences paid but not assigned: $(($unused | ForEach-Object { "$($_.Total - $_.Assigned) $($_.Name)" }) -join ', ')." -Recommendation 'Assign them or lower the number at the next renewal.'
}
$expiring = @($skus | Where-Object { $_.Status -ne 'Enabled' -and $_.Assigned -gt 0 })
if ($expiring.Count -gt 0) {
    New-AuditFinding -Severity Medium -Area $area -Finding "Licences no longer active but still assigned: $(($expiring | ForEach-Object { "$($_.Name) ($($_.Status))" }) -join ', ')." -Recommendation 'Renew them, or move the users to another licence before their data is deleted.'
}
$licensedDisabled = @($members | Where-Object { -not $_.Enabled -and $_.Licences.Count -gt 0 })
if ($licensedDisabled.Count -gt 0) {
    New-AuditFinding -Severity Low -Area $area -Finding "Disabled accounts that keep a licence: $(($licensedDisabled | ForEach-Object { $_.Upn }) -join ', ')." -Recommendation 'Convert their mailbox to a shared mailbox if it is still needed, then remove the licence.'
}
if ($signInKnown) {
    $staleUsers = @($enabledMembers | Where-Object { $_.Licences.Count -gt 0 -and (-not $_.LastSignIn -or $_.LastSignIn -lt $staleSince) -and $_.Created -and ([datetime]$_.Created) -lt $staleSince })
    if ($staleUsers.Count -gt 0) {
        New-AuditFinding -Severity Low -Area $area -Finding "Licensed accounts not signed in for $StaleDays days: $(($staleUsers | ForEach-Object { $_.Upn }) -join ', ')." -Recommendation 'Disable the accounts of people who left; a mailbox only read by others can become a shared mailbox.'
    }
}
if ($organization.onPremisesSyncEnabled -and $organization.onPremisesLastSyncDateTime -and ([datetime]$organization.onPremisesLastSyncDateTime) -lt (Get-Date).AddDays(-1)) {
    New-AuditFinding -Severity High -Area $area -Finding "The synchronisation from Active Directory last ran on $(([datetime]$organization.onPremisesLastSyncDateTime).ToLocalTime().ToString('yyyy-MM-dd HH:mm')): it has stopped." -Recommendation 'Check the Entra Connect server (or Cloud Sync agent) and its service.'
}
if ($passwordDays.Count -gt 0) {
    New-AuditFinding -Severity Info -Area $area -Finding "Microsoft 365 passwords expire after $(($passwordDays | Select-Object -Unique) -join ', ') days." -Recommendation 'With MFA, Microsoft and NIST advise passwords that never expire, changed only when compromised.'
}
if ($guests.Count -gt 0) {
    New-AuditFinding -Severity Info -Area $area -Finding "$($guests.Count) guest accounts from other organisations have access to the tenant." -Recommendation 'Review them yearly (Entra ID access reviews, or by hand).'
}
if ($devices) {
    $oldDevices = @($devices | Where-Object { $_.Enabled -and $_.LastSignIn -ge $staleSince -and $_.Support -and $_.Support.Status -eq 'Ended' })
    if ($oldDevices.Count -gt 0) {
        New-AuditFinding -Severity High -Area $area -Finding "$($oldDevices.Count) devices in use run a Windows without security updates: $(($oldDevices | Select-Object -First 30 | ForEach-Object { "$($_.Name) ($($_.Version))" }) -join ', ')." -Recommendation 'Update them to a supported Windows version, or replace them.'
    }
}

New-AuditData -Name 'Microsoft365' -Value ([pscustomobject]@{
        Organization     = $organization.displayName
        TenantId         = $organization.id
        Domains          = @($domains | ForEach-Object { [pscustomobject]@{ Name = $_.id; Verified = $_.isVerified; Default = $_.isDefault; Authentication = $_.authenticationType } })
        SecurityDefaults = $(if ($securityDefaults) { [bool]@($securityDefaults)[0].isEnabled } else { $null })
        ConditionalAccess = $(if ($null -ne $conditionalAccess) { @($conditionalAccess | ForEach-Object { [pscustomobject]@{ Name = $_.displayName; State = $_.state } }) })
        Licences         = $skus
        Users            = $users
        Roles            = $roles
        Devices          = $devices
        NotRead          = $script:Refused
    })
