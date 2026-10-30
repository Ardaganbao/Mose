# Path to helper script
$helperPath = Join-Path $PSScriptRoot 'helper.ps1'

if (Test-Path $helperPath) {
    # Check if functions from helper are already loaded
    if (-not (Get-Command -Name 'MyHelperFunction' -ErrorAction SilentlyContinue)) {
        Write-Host "Loading helper functions from $helperPath..." -ForegroundColor Cyan
        . $helperPath
    } else {
        Write-Host "Helper functions already loaded." -ForegroundColor Yellow
    }
} else {
    Write-Error "Helper script not found at $helperPath"
}


$ModuleName = 'Microsoft.PowerShell.SecretStore'
Ensure-Module -Name Microsoft.PowerShell.SecretManagement -MinimumVersion '1.1.0'
Ensure-Module -Name $ModuleName -MinimumVersion '1.0.6'
$MySecretStore = "VBBSecretStore1"

Ensure-SecretVault -VaultName $MySecretStore 
Unlock-SecretVaultIfNeeded -VaultName $MySecretStore 



if (-not (Get-SecretInfo -Vault $MySecretStore -Name 'srv-vcenter02:administrator@vsphere.local' -ErrorAction SilentlyContinue)) {
   $cred5 =  Get-Credential -Message "please, Provide the Vcenter 02 credential" -UserName "administrator@vsphere.local"
    Set-AppSecret  -Vault $MySecretStore -Name 'srv-vcenter02:administrator@vsphere.local' -Secret $cred5.Password
}
if (-not (Get-SecretInfo -Vault $MySecretStore -Name 'vcenter67-drp:administrator@vsphere.local' -ErrorAction SilentlyContinue)) {
   $cred6 =  Get-Credential -Message "please, Provide the Vcenter DRP credential" -UserName "administrator@vsphere.local"
    Set-AppSecret  -Vault $MySecretStore -Name 'vcenter67-drp:administrator@vsphere.local' -Secret $cred6.Password
}
if (-not (Get-SecretInfo -Vault $MySecretStore -Name 'IDRAC:ESXi05-3E-IDRAC' -ErrorAction SilentlyContinue)) {
   $cred7 =  Get-Credential -Message "please, Provide the ESXi05 credential" -UserName "systemat"
    Set-AppSecret  -Vault $MySecretStore -Name 'IDRAC:ESXi05-3E-IDRAC' -Secret $cred7.Password
}
if (-not (Get-SecretInfo -Vault $MySecretStore -Name 'IDRAC:ESXi06-3E-IDRAC' -ErrorAction SilentlyContinue)) {
   $cred8 =  Get-Credential -Message "please, Provide the ESXi06 credential" -UserName "systemat"
    Set-AppSecret  -Vault $MySecretStore -Name 'IDRAC:ESXi06-3E-IDRAC' -Secret $cred8.Password
}
if (-not (Get-SecretInfo -Vault $MySecretStore -Name 'IDRAC:ESXi07-3E-IDRAC' -ErrorAction SilentlyContinue)) {
   $cred9 =  Get-Credential -Message "please, Provide the ESXi07 credential" -UserName "systemat"
    Set-AppSecret -Vault $MySecretStore -Name 'IDRAC:ESXi07-3E-IDRAC' -Secret $cred9.Password
}
if (-not (Get-SecretInfo -Vault $MySecretStore -Name 'IDRAC:ESXiDRPDRAC' -ErrorAction SilentlyContinue)) {
   $cred10 =  Get-Credential -Message "please, Provide the ESXiDRPDRAC credential" -UserName "VBB"
    Set-AppSecret -Vault $MySecretStore -Name 'IDRAC:ESXiDRPDRAC' -Secret $cred10.Password
}
if (-not (Get-SecretInfo -Vault $MySecretStore -Name 'IDRAC:NASVEEAM' -ErrorAction SilentlyContinue)) {
   $credNAS =  Get-Credential -Message "please, Provide the NAS vEEAM credential : Synadmin" -UserName "Synadmin"
    Set-AppSecret -Vault $MySecretStore -Name 'IDRAC:NASVEEAM' -Secret $credNAS.Password
}
 
$srvvcenter02  =  Get-AppCredential -Vault $MySecretStore -UserName 'administrator@vsphere.local' -PasswordSecretName 'srv-vcenter02:administrator@vsphere.local'  
$vcenter67drp  =  Get-AppCredential -Vault $MySecretStore -UserName 'administrator@vsphere.local' -PasswordSecretName 'vcenter67-drp:administrator@vsphere.local'  
$ESXi05IDRAC  =  Get-AppCredential -Vault $MySecretStore -UserName 'systemat' -PasswordSecretName 'IDRAC:ESXi05-3E-IDRAC'
$ESXi06IDRAC  =  Get-AppCredential -Vault $MySecretStore -UserName 'systemat' -PasswordSecretName 'IDRAC:ESXi06-3E-IDRAC'
$ESXi07IDRAC  =  Get-AppCredential -Vault $MySecretStore -UserName 'systemat' -PasswordSecretName 'IDRAC:ESXi07-3E-IDRAC'
$ESXi07IDRAC  =  Get-AppCredential -Vault $MySecretStore -UserName 'systemat' -PasswordSecretName 'IDRAC:ESXi07-3E-IDRAC'
$ESXiDRPDRAC =  Get-AppCredential -Vault $MySecretStore -UserName 'VBB' -PasswordSecretName 'IDRAC:ESXiDRPDRAC'
$credNAS =  Get-AppCredential -Vault $MySecretStore -UserName 'Synadmin' -PasswordSecretName 'IDRAC:NASVEEAM'

$servers = (
("172.28.3.100",$ESXi05IDRAC,"ESXi05IDRAC"),
("172.28.3.101",$ESXi06IDRAC,"ESXi06IDRAC"),
("172.28.3.102",$ESXi07IDRAC,"ESXi07IDRAC"),
("10.0.8.1",$ESXiDRPDRAC,"ESXi1DRPDRAC"),
("10.0.8.2",$ESXiDRPDRAC,"ESXi2DRPDRAC")
) 


$report = [System.Collections.Generic.List[string]]::new()
$report.Add('## IDRAC')
$idracScript = Join-Path $PSScriptRoot 'IDRAC.ps1'

foreach ($server in $servers) {
    try {
        $section = & $idracScript -server $server[0] -credential $server[1]
        $report.Add(($section -join [Environment]::NewLine).Trim())
    }
    catch {
        $report.Add("### iDRAC $($server[0])`nCollection failed: $($_.Exception.Message)")
        Write-Warning "iDRAC collection failed for $($server[0]): $($_.Exception.Message)"
    }
}

$vmwareScript = Join-Path $PSScriptRoot 'vmwarereport.ps1'
$report.Add('## VMware')

$server = 'srv-vcenter02.vbbdomain.vanbaelbellis.com'
$report.Add('### Main Datacenter')
try {
    $section = @(& $vmwareScript -server $server -user $srvvcenter02.UserName -pass $srvvcenter02.Password -Client 'vbb' -Site 'DC' | Where-Object { $_ -is [string] })
    $content = ($section -join [Environment]::NewLine).Trim() -replace '^### VMware\s*', ''
    $report.Add($content)
}
catch {
    $report.Add("Collection failed: $($_.Exception.Message)")
    Write-Warning "VMware collection failed for $server`: $($_.Exception.Message)"
}

$server = 'vcenter67-drp.vbbdomain.vanbaelbellis.com'
$report.Add('### DRP')
try {
    $section = @(& $vmwareScript -server $server -user $vcenter67drp.UserName -pass $vcenter67drp.Password -Client 'vbb' -Site 'DRP' | Where-Object { $_ -is [string] })
    $content = ($section -join [Environment]::NewLine).Trim() -replace '^### VMware\s*', ''
    $report.Add($content)
}
catch {
    $report.Add("Collection failed: $($_.Exception.Message)")
    Write-Warning "VMware collection failed for $server`: $($_.Exception.Message)"
}

$server = '10.20.19.222'
$nasScript = Join-Path $PSScriptRoot 'nas2.ps1'
$report.Add('## NAS')
try {
    $section = & $nasScript -server $server -user $credNAS.UserName -pass $credNAS.Password
    $report.Add(($section -join [Environment]::NewLine).Trim())
}
catch {
    $report.Add("### NAS $server`nCollection failed: $($_.Exception.Message)")
    Write-Warning "NAS collection failed for $server`: $($_.Exception.Message)"
}

$reportPath = Join-Path $PSScriptRoot "Infrastructure_Report_$(Get-Date -Format 'yyyy-MM-dd').md"
Set-Content -Path $reportPath -Value ($report -join "`r`n`r`n") -Encoding utf8
Write-Host "Consolidated report written to $reportPath" -ForegroundColor Green

