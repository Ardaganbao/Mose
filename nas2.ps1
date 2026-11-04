param (
    [Parameter(Mandatory = $true)]
    [string]$server,

    [Parameter(Mandatory = $true)]
    [string]$user,

    [Parameter(Mandatory = $true)]
    $pass,

    [Parameter(HelpMessage = 'Optional SHA-1 thumbprint pin for this NAS certificate. Use only after verifying the thumbprint through a trusted channel.')]
    [string]$CertificateThumbprint,

    [Parameter(HelpMessage = 'Accept any server certificate during this NAS script run. This disables certificate identity and trust checks and is vulnerable to interception.')]
    [switch]$AcceptAnyCertificate,

    [Parameter(HelpMessage = '2-step verification code of the account, for its first sign-in from this computer: the NAS then trusts this computer and gives its DeviceId.')]
    [string]$OtpCode,

    [Parameter(HelpMessage = 'ID the NAS gave this computer when it was trusted with a 2-step verification code, to sign in without a code.')]
    [string]$DeviceId
)



function Convert-Bytes
{
  param(
    [long]$bytes,
    [bool]$unit=$true
  )
  
  if (($bytes / 1TB) -gt 1) {
    $check = "{0:N2}" -f ($bytes / 1TB)
    $unit_s = " TB"
  } else {
      if (($bytes / 1GB) -gt 1) {
        $check = "{0:N2}" -f ($bytes / 1GB)
        $unit_s = " GB"
      } else {
        $check = "{0:N2}" -f ($bytes / 1MB)
        $unit_s = " MB"
      }
  }
  if($unit){
  $check += $unit_s
  }
  return $check
}

function Invoke-NasWebRequest {
  param (
    [Parameter(Mandatory = $true)]
    [string]$Uri,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Get', 'Post')]
    [string]$Method,

    [hashtable]$Body,

    [Parameter(Mandatory = $true)]
    [string]$Stage
  )

  $requestUri = [System.Uri]$Uri
  if ($requestUri.Scheme -ne [System.Uri]::UriSchemeHttps) {
    throw "Refusing non-HTTPS NAS request for stage '$Stage'."
  }

  $request = [System.Net.HttpWebRequest]::Create($requestUri)
  $request.Method = $Method
  $request.Accept = 'application/json'
  $request.UserAgent = 'MOSE-NAS-Report/1.0'
  $request.Timeout = 30000
  $request.ReadWriteTimeout = 30000
  $request.KeepAlive = $false
  $request.ServerCertificateValidationCallback = [Delegate]::CreateDelegate(
    [System.Net.Security.RemoteCertificateValidationCallback],
    [NASRemoteCertificateValidationV5],
    'Validate'
  )
  [NASRemoteCertificateValidationV5]::ResetDetails()
  $servicePoint = $request.ServicePoint
  $originalExpect100Continue = $servicePoint.Expect100Continue

  try {
    if ($null -ne $Body) {
    $servicePoint.Expect100Continue = $false
    $formFields = foreach ($key in $Body.Keys) {
      $fieldName = [System.Uri]::EscapeDataString([string]$key)
      $fieldValue = if ($null -eq $Body[$key]) { '' } else { [string]$Body[$key] }
      $encodedValue = [System.Uri]::EscapeDataString($fieldValue)
      "$fieldName=$encodedValue"
    }
    $requestBody = [System.Text.Encoding]::UTF8.GetBytes(($formFields -join '&'))
    $request.ContentType = 'application/x-www-form-urlencoded; charset=UTF-8'
    $request.ContentLength = $requestBody.Length

    $requestStream = $request.GetRequestStream()
    try {
      $requestStream.Write($requestBody, 0, $requestBody.Length)
    }
    finally {
      $requestStream.Dispose()
    }
    }

    $response = [System.Net.HttpWebResponse]$request.GetResponse()
    try {
      $responseStream = $response.GetResponseStream()
      $reader = New-Object System.IO.StreamReader($responseStream, [System.Text.Encoding]::UTF8)
      try {
        $content = $reader.ReadToEnd()
      }
      finally {
        $reader.Dispose()
      }
      [pscustomobject]@{
        Content = $content
        StatusCode = [int]$response.StatusCode
        StatusDescription = $response.StatusDescription
      }
    }
    finally {
      $response.Dispose()
    }
  }
  catch {
    $exception = $_.Exception
    $innerDetails = if ($exception.InnerException) { $exception.InnerException.ToString() } else { 'No inner exception was provided.' }
    $responseDetails = $null
    $failedResponse = $null
    $webException = $exception
    while ($null -ne $webException -and
      $webException -isnot [System.Net.WebException] -and
      $null -ne $webException.InnerException) {
      $webException = $webException.InnerException
    }
    if ($webException -is [System.Net.WebException] -and $null -ne $webException.Response) {
      $failedResponse = [System.Net.HttpWebResponse]$webException.Response
      try {
        $errorStream = $failedResponse.GetResponseStream()
        if ($null -ne $errorStream) {
          $errorReader = New-Object System.IO.StreamReader($errorStream, [System.Text.Encoding]::UTF8)
          try {
            $errorContent = $errorReader.ReadToEnd()
            if ($errorContent.Length -gt 2000) {
              $errorContent = $errorContent.Substring(0, 2000) + ' [truncated]'
            }
            $responseDetails = "HTTP $([int]$failedResponse.StatusCode) $($failedResponse.StatusDescription). Response: $errorContent"
          }
          finally {
            $errorReader.Dispose()
          }
        }
      }
      finally {
        $failedResponse.Dispose()
      }
    }
    $endpoint = $requestUri.GetLeftPart([System.UriPartial]::Path)
    $protocols = [System.Net.ServicePointManager]::SecurityProtocol
    $certificateDetails = if ('NASRemoteCertificateValidationV5' -as [type]) {
      [NASRemoteCertificateValidationV5]::LastDetails
    }
    else {
      'Unavailable'
    }
    throw "NAS $Stage request ($Method) to '$endpoint' failed. PowerShell $($PSVersionTable.PSVersion); enabled TLS protocols: $protocols. Certificate details: $certificateDetails. Error: $($exception.Message) Inner details: $innerDetails. $responseDetails"
  }
  finally {
    if ($null -ne $Body) {
      $servicePoint.Expect100Continue = $originalExpect100Continue
    }
  }
}

#first login
$passwordBstr = [IntPtr]::Zero
$plainPassword = $null
$sid = $null
$authpath = $null
$url = $null
$originalSecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol

[System.Net.ServicePointManager]::SecurityProtocol = $originalSecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
try {
  if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint) -and $CertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
    throw 'CertificateThumbprint must be a 40-character SHA-1 certificate thumbprint with no separators.'
  }
  if (-not ('NASRemoteCertificateValidationV5' -as [type])) {
    Add-Type -TypeDefinition @"
      using System;
      using System.Linq;
      using System.Net;
      using System.Net.Security;
      using System.Security.Cryptography.X509Certificates;
      public static class NASRemoteCertificateValidationV5 {
        public static string ExpectedHost { get; set; }
        public static string ExpectedThumbprint { get; set; }
        public static bool AcceptAnyCertificate { get; set; }
        public static string LastDetails { get; private set; }
        public static void ResetDetails() {
          LastDetails = "Certificate validation was not invoked.";
        }
        public static bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
          var cert = certificate as X509Certificate2 ?? new X509Certificate2(certificate);
          var chainStatus = chain == null
            ? "Unavailable"
            : String.Join(", ", chain.ChainStatus.Select(status => status.Status + ": " + status.StatusInformation.Trim()));
          var san = String.Join("; ", cert.Extensions
            .Cast<X509Extension>()
            .Where(extension => extension.Oid != null && extension.Oid.Value == "2.5.29.17")
            .Select(extension => extension.Format(false)));
          var request = sender as HttpWebRequest;
          var requestHostMatches = request != null &&
            String.Equals(request.RequestUri.Host, ExpectedHost, StringComparison.OrdinalIgnoreCase);
          var thumbprintMatches = !String.IsNullOrEmpty(ExpectedThumbprint) &&
            String.Equals(cert.GetCertHashString(), ExpectedThumbprint, StringComparison.OrdinalIgnoreCase);
          LastDetails = "Policy errors: " + errors +
            "; Subject: " + cert.Subject +
            "; Issuer: " + cert.Issuer +
            "; SHA-1 thumbprint: " + cert.GetCertHashString() +
            "; Expires: " + cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss zzz") +
            "; Subject Alternative Name: " + (String.IsNullOrEmpty(san) ? "not present" : san) +
            "; Chain status: " + (String.IsNullOrEmpty(chainStatus) ? "None" : chainStatus) +
            "; Request host matched: " + requestHostMatches +
            "; Thumbprint pin accepted: " + (requestHostMatches && thumbprintMatches) +
            "; Accept-any-certificate mode: " + (requestHostMatches && AcceptAnyCertificate);
          return errors == SslPolicyErrors.None ||
            (requestHostMatches && (thumbprintMatches || AcceptAnyCertificate));
        }
      }
"@ -ErrorAction Stop
  }
  [NASRemoteCertificateValidationV5]::ExpectedHost = $server
  [NASRemoteCertificateValidationV5]::ExpectedThumbprint = if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
    $null
  }
  else {
    $CertificateThumbprint
  }
  [NASRemoteCertificateValidationV5]::AcceptAnyCertificate = [bool]$AcceptAnyCertificate

$passwordBstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass)
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordBstr)
$url = "https://$($server):5001/webapi/query.cgi?api=SYNO.API.Info&method=Query&version=1&query=SYNO.API.Auth,SYNO.Storage.CGI.Storage,SYNO.Core.System,SYNO.Core.Network,SYNO.Core.Upgrade.Server"
$response = Invoke-NasWebRequest -Uri $url -Method Get -Stage 'API discovery'

$json = $response.Content 

# Always validate before parsing
if (-not $json) {
    throw "Empty response from Synology API (check URL or connectivity)"
}

$apiList = (ConvertFrom-Json $json).data
$authpath = (ConvertFrom-Json $json).data.'SYNO.API.Auth'.path
$storagepath= (ConvertFrom-Json $json).data.'SYNO.Storage.CGI.Storage'.path 
$infopath = (ConvertFrom-Json $json).data.'SYNO.Core.System'.path
if ([string]::IsNullOrWhiteSpace([string]$authpath) -or
  [string]::IsNullOrWhiteSpace([string]$storagepath) -or
  [string]::IsNullOrWhiteSpace([string]$infopath)) {
throw "Synology API discovery did not return all required API paths. Response: $json"
}

$url = "https://$($server):5001/webapi/$($authpath)"
$loginBody = @{
api = 'SYNO.API.Auth'
method = 'login'
  version = 6
  account = $user
  passwd = $plainPassword
  session = 'InfrastructureReport'
  format = 'cookie'
}
# An account with 2-step verification: the code once, and the NAS trusts this computer, under this
# device name, with the device ID it gives; later sign-ins give that ID instead of a code.
$deviceName = "MOSE report $env:COMPUTERNAME"
if ($OtpCode) {
  $loginBody.otp_code = $OtpCode
  $loginBody.enable_device_token = 'yes'
  $loginBody.device_name = $deviceName
}
elseif ($DeviceId) {
  $loginBody.device_id = $DeviceId
  $loginBody.device_name = $deviceName
}
$response = Invoke-NasWebRequest -Uri $url -Method Post -Stage 'API login' -Body $loginBody
$url = $null
$loginBody = $null

$json = $response.Content
$loginResponse = ConvertFrom-Json $json
if (-not $loginResponse.success -or [string]::IsNullOrWhiteSpace([string]$loginResponse.data.sid)) {
  $errorCode = if ($loginResponse.error.code) { $loginResponse.error.code } else { 'unknown' }
  # DSM's sign-in error codes. The answer for a 2-step verification account holds a sign-in token,
  # which stays out of the report.
  $reason = switch ("$errorCode") {
    '400' { "The account $user does not exist or its password is wrong." }
    '401' { "The account $user is disabled." }
    '402' { "The account $user has no permission to sign in to DSM." }
    { $_ -in '403', '406' } { "The account $user has 2-step verification$(if ($DeviceId) { ', and the NAS no longer trusts this computer' }): the report asks for its code when it runs in a window." }
    '404' { "The 2-step verification code of the account $user was wrong or expired." }
    '407' { "The NAS blocks the IP address of this computer (Control Panel > Security > Protection)." }
    { $_ -in '408', '409', '410' } { "The password of the account $user expired or must be changed." }
    default { "Verify the NAS account, password, and account policy. Response: $($json -replace '"token"\s*:\s*"[^"]*"', '"token":"<hidden>"')" }
  }
  $exception = [System.Exception]::new("Synology API login failed (error code $errorCode). $reason")
  # For Report.ps1, which then asks for the code and runs this NAS again.
  $exception.Data['OtpRequired'] = "$errorCode" -in '403', '404', '406'
  throw $exception
}
$sid = $loginResponse.data.sid
if ($OtpCode) {
  # DSM 7 names it device_id, DSM 6 did.
  $newDeviceId = "$(if ($loginResponse.data.device_id) { $loginResponse.data.device_id } else { $loginResponse.data.did })"
  if ($newDeviceId) {
    # For Report.ps1, which saves it with the NAS in the client configuration.
    [pscustomobject]@{ MoseNasDeviceId = $newDeviceId }
  }
  else {
    Write-Warning "The NAS signed in with the code but gave no device ID: the report will ask for a code again next time."
  }
}

 

$url = "https://$($server):5001/webapi/$($storagepath)?api=SYNO.Storage.CGI.Storage&version=1&method=load_info&_sid=$($sid)"


$response = Invoke-NasWebRequest -Uri $url -Method Get -Stage 'Storage collection'
$json = $response.Content 
$volumes = (ConvertFrom-Json $json).data.volumes
$disks = (ConvertFrom-Json $json).data.disks
$url = "https://$($server):5001/webapi/$($infopath)?api=SYNO.Core.System&version=3&method=info&_sid=$($sid)"
$response = Invoke-NasWebRequest -Uri $url -Method Get -Stage 'System information'

$json = $response.Content
$info = (ConvertFrom-Json $json).data

# For the report's Physical System table (Report.ps1): the NAS by its name, and whether its DSM is
# the latest. Both are optional: an older DSM without them still reports.
$nasName = ''
$dsmUpToDate = $null
$dsmLatest = ''
try {
  $networkApi = $apiList.'SYNO.Core.Network'
  if ($networkApi) {
    $response = Invoke-NasWebRequest -Uri "https://$($server):5001/webapi/$($networkApi.path)?api=SYNO.Core.Network&version=1&method=get&_sid=$($sid)" -Method Get -Stage 'Host name'
    $nasName = "$((ConvertFrom-Json $response.Content).data.server_name)"
  }
  # DSM's own update check offers neither a new major DSM nor an update not out in its region yet:
  # its "no update" proves nothing, an update it offers is one.
  $upgradeApi = $apiList.'SYNO.Core.Upgrade.Server'
  if ($upgradeApi) {
    $response = Invoke-NasWebRequest -Uri "https://$($server):5001/webapi/$($upgradeApi.path)?api=SYNO.Core.Upgrade.Server&version=$($upgradeApi.maxVersion)&method=check&_sid=$($sid)" -Method Get -Stage 'DSM update check'
    $check = (ConvertFrom-Json $response.Content).data
    # DSM 7 gives the update under "update", older versions at the top.
    $update = if ($check -and $check.PSObject.Properties['update']) { $check.update } else { $check }
    if ($update -and $update.available -eq $true) {
      $dsmUpToDate = $false
      $dsmLatest = "$($update.version)"
    }
  }
}
catch {
  Write-Verbose "NAS host name or DSM update check: $($_.Exception.Message)"
}
if (-not $nasName) {
  $nasName = "$server"
}
# The latest DSM of this model, from synology.com's release notes, when this computer can reach it.
try {
  $releaseNotes = Invoke-RestMethod -Uri "https://www.synology.com/api/releaseNote/findChangeLog?identify=DSM&lang=en-us&model=$([System.Uri]::EscapeDataString("$($info.model)"))" -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
  # A model synology.com does not know gets the page of no model ("DSM"), without versions.
  if ("$($releaseNotes.info.dname)" -eq "$($info.model)") {
    $modelLatest = "$(@($releaseNotes.info.versions.DSM.all_versions | Where-Object { $_.version -and -not $_.is_rc })[0].version)"
    $installed = ConvertTo-DsmVersion "$($info.firmware_ver)"
    $newest = ConvertTo-DsmVersion $modelLatest
    if ($installed -and $newest) {
      if ($installed.Build -lt $newest.Build -or ($installed.Build -eq $newest.Build -and $installed.Update -lt $newest.Update)) {
        $dsmUpToDate = $false
        $dsmLatest = $modelLatest
      }
      elseif ($null -eq $dsmUpToDate) {
        $dsmUpToDate = $true
      }
    }
  }
}
catch {
  Write-Verbose "Latest DSM of the $($info.model) on synology.com: $($_.Exception.Message)"
}
$dsmMark = if ($dsmUpToDate -eq $true) { ':white_check_mark:' } elseif ($dsmUpToDate -eq $false) { ":warning: (latest $dsmLatest)" } else { ':question:' }
[pscustomobject]@{ MoseInventory = 'Machine'; Source = 'NAS'; Name = $nasName; Brand = 'Synology'; Model = "$($info.model)"; Serial = "$($info.serial)"; ProductId = ''; Bios = ''; Server = $server }
[pscustomobject]@{ MoseInventory = 'Service'; Machine = $nasName; MachineSerial = "$($info.serial)"; Name = 'NAS storage'; Version = "$($info.firmware_ver)"; Product = 'DSM'
  UpToDate = $dsmUpToDate; Latest = $dsmLatest; Server = $server
}

$Body = "#### Check NAS Synology $($info.model) ( $($server) - SN: $($info.serial)) :`n"
$Body += "| disk           | status                     |  model             |  size_total       |SMART status       |`n"
$Body += "|------------------|----------------------------|--------------|---------|---------|`n"
$status = "normal"
foreach ($disk in $disks){
$Body += "|$($disk.name)|$($disk.status)|$($disk.model)|$(Convert-Bytes ($disk.size_total))|$($disk.smart_status)|`n"
 if($disk.smart_status -ne "normal") {
    $status = $disk.smart_status
 }
  if($disk.status -ne "normal") {
    $status = $disk.smart_status
 }
}
if($status-eq "normal" ){
   $Body += "`n- :white_check_mark: All disk normal!`n"
} else {
   $Body += "`n- :warning: Check the disk !`n"
}

 $Body += "- NAS version : $($info.firmware_ver) $dsmMark`n"

$Body += "`n| volume           | status                     |  Available             |  Used       |`n"
$Body += "|------------------|----------------------------|--------------|---------|`n"
$extradetail =""
#### Check Nas Synology <model> ( <NAS IP> - SN: <serial number>) :
foreach ($vol in $volumes){
 $size = $vol.size
$Body += "|$($vol.id)|$($vol.status)|$(Convert-Bytes ($vol.size.total - $vol.size.used))|$(Convert-Bytes $vol.size.used)|`n"
 
$extradetail += "`n``````NasVolume                     `n"
$extradetail += "| Volume (in TB) | free | used | `n"
$extradetail += "|----------------|------|------| `n"
$extradetail += "| $($vol.id)       | $($vol.size.total - $vol.size.used ) | $( $vol.size.used   ) |`n"
$extradetail += "```````n"
}
$Body +=$extradetail
 
return $Body
}
finally {
  if ($sid -and $authpath) {
    try {
      $logoutUrl = "https://$($server):5001/webapi/$($authpath)?api=SYNO.API.Auth&method=Logout&version=6&session=InfrastructureReport&_sid=$([System.Uri]::EscapeDataString($sid))"
      Invoke-NasWebRequest -Uri $logoutUrl -Method Get -Stage 'Session logout' | Out-Null
    }
    catch {
      Write-Warning "Could not close Synology session: $($_.Exception.Message)"
    }
  }
  $url = $null
  $logoutUrl = $null
  $plainPassword = $null
  if ($passwordBstr -ne [IntPtr]::Zero) {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordBstr)
  }
  [System.Net.ServicePointManager]::SecurityProtocol = $originalSecurityProtocol
}