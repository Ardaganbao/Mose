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
    [switch]$AcceptAnyCertificate
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
$url = "https://$($server):5001/webapi/query.cgi?api=SYNO.API.Info&method=Query&version=1&query=SYNO.API.Auth,SYNO.Storage.CGI.Storage,SYNO.Core.System"
$response = Invoke-NasWebRequest -Uri $url -Method Get -Stage 'API discovery'

$json = $response.Content 

# Always validate before parsing
if (-not $json) {
    throw "Empty response from Synology API (check URL or connectivity)"
}

$authpath = (ConvertFrom-Json $json).data.'SYNO.API.Auth'.path
$storagepath= (ConvertFrom-Json $json).data.'SYNO.Storage.CGI.Storage'.path 
$infopath = (ConvertFrom-Json $json).data.'SYNO.Core.System'.path
if ([string]::IsNullOrWhiteSpace([string]$authpath) -or
  [string]::IsNullOrWhiteSpace([string]$storagepath) -or
  [string]::IsNullOrWhiteSpace([string]$infopath)) {
throw "Synology API discovery did not return all required API paths. Response: $json"
}

$url = "https://$($server):5001/webapi/$($authpath)"
$response = Invoke-NasWebRequest -Uri $url -Method Post -Stage 'API login' -Body @{
api = 'SYNO.API.Auth'
method = 'login'
  version = 6
  account = $user
  passwd = $plainPassword
  session = 'InfrastructureReport'
  format = 'cookie'
}
$url = $null

$json = $response.Content 
$loginResponse = ConvertFrom-Json $json
if (-not $loginResponse.success -or [string]::IsNullOrWhiteSpace([string]$loginResponse.data.sid)) {
  $errorCode = if ($loginResponse.error.code) { $loginResponse.error.code } else { 'unknown' }
  throw "Synology API login failed (error code $errorCode). Verify the NAS account, password, and account policy. Response: $json"
}
$sid = $loginResponse.data.sid

 

$url = "https://$($server):5001/webapi/$($storagepath)?api=SYNO.Storage.CGI.Storage&version=1&method=load_info&_sid=$($sid)"


$response = Invoke-NasWebRequest -Uri $url -Method Get -Stage 'Storage collection'
$json = $response.Content 
$volumes = (ConvertFrom-Json $json).data.volumes
$disks = (ConvertFrom-Json $json).data.disks
$url = "https://$($server):5001/webapi/$($infopath)?api=SYNO.Core.System&version=3&method=info&_sid=$($sid)"
$response = Invoke-NasWebRequest -Uri $url -Method Get -Stage 'System information'

$json = $response.Content 
$info = (ConvertFrom-Json $json).data

$Body = "#### Check NAS Synology $($info.model) ( $($server) - SN: $($info.serial)) :`n"
$Body += "| disk           | status                     |  model             |  size_total       |SMART status       |`n"
$Body += "|------------------|----------------------------|--------------|---------|`n"
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
   $Body += "`n- :heavy_check_mark: All disk normal!`n"
} else {
   $Body += "`n- :warning: Check the disk !`n"
}

 $Body += "- NAS version : $($info.firmware_ver)`n"

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