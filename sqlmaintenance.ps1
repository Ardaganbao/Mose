[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'SQL Server: the cluster or host name, or HOST\INSTANCE, with ,port if it is not the default one.')]
    [string]$Server,

    [Parameter(HelpMessage = 'A SQL Server login, or a Windows account (DOMAIN\user). Without it, the Windows account running the report.')]
    [pscredential]$Credential,

    [Parameter(HelpMessage = 'Days of maintenance plan history in the report.')]
    [ValidateRange(1, 365)]
    [int]$Days = 16
)

# SQL Server maintenance plans: their runs of the last $Days days, read from msdb (the Maintenance
# Plans log of the SQL Server Management Studio log viewer). One row per plan and day: Success when
# every run of the plan that day succeeded, else one error row per failed subplan. A subplan that
# runs every few hours (e.g. an index reorganization) so adds no rows while it succeeds.

$ErrorActionPreference = 'Stop'
$progressActivity = "SQL Server maintenance plans: $Server"

# Runs in a process of its own when another Windows account is used, so it takes everything it needs
# as parameters. Writes the server's version first (ProductVersion), then the runs (PlanName).
$readMaintenanceLog = {
    param([string]$ConnectionString, [int]$Days)

    $versionQuery = @'
SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) AS ProductVersion,
       CAST(SERVERPROPERTY('ProductLevel') AS nvarchar(128)) AS ProductLevel,
       CAST(SERVERPROPERTY('ProductUpdateLevel') AS nvarchar(128)) AS ProductUpdateLevel,
       CAST(SERVERPROPERTY('IsHadrEnabled') AS int) AS IsHadrEnabled;
'@
    $query = @'
SELECT ISNULL(p.name, N'') AS PlanName, ISNULL(sp.subplan_name, N'') AS SubPlanName,
       l.start_time AS StartTime, l.end_time AS EndTime, l.succeeded AS Succeeded
FROM msdb.dbo.sysmaintplan_log AS l
LEFT JOIN msdb.dbo.sysmaintplan_subplans AS sp ON sp.subplan_id = l.subplan_id
LEFT JOIN msdb.dbo.sysmaintplan_plans AS p ON p.id = l.plan_id
WHERE l.start_time >= DATEADD(day, -@Days, CAST(GETDATE() AS date))
ORDER BY l.start_time DESC;
'@
    $connection = New-Object System.Data.SqlClient.SqlConnection $ConnectionString
    try {
        $connection.Open()
        $command = $connection.CreateCommand()
        $command.CommandText = $versionQuery
        $reader = $command.ExecuteReader()
        if ($reader.Read()) {
            [pscustomobject]@{
                ProductVersion     = [string]$reader['ProductVersion']
                ProductLevel       = [string]$reader['ProductLevel']
                ProductUpdateLevel = [string]$reader['ProductUpdateLevel']
                AlwaysOn           = ($reader['IsHadrEnabled'] -isnot [System.DBNull]) -and [int]$reader['IsHadrEnabled'] -eq 1
            }
        }
        $reader.Close()

        $command = $connection.CreateCommand()
        $command.CommandText = $query
        $command.CommandTimeout = 120
        [void]$command.Parameters.AddWithValue('@Days', $Days)
        $reader = $command.ExecuteReader()
        while ($reader.Read()) {
            [pscustomobject]@{
                PlanName    = [string]$reader['PlanName']
                SubPlanName = [string]$reader['SubPlanName']
                StartTime   = [datetime]$reader['StartTime']
                Finished    = -not ($reader['EndTime'] -is [System.DBNull])
                Succeeded   = ($reader['Succeeded'] -isnot [System.DBNull]) -and [bool]$reader['Succeeded']
            }
        }
        $reader.Close()
    }
    finally {
        $connection.Dispose()
    }
}

# One row per plan and day, newest day first: the plan when all its runs that day succeeded, else
# "plan - subplan" for each subplan that failed. A run still going (started less than a day ago) is
# left out; an older one that never finished counts as failed.
function ConvertTo-MaintenanceRows {
    param(
        [object[]]$Runs
    )

    $recent = (Get-Date).AddDays(-1)
    $kept = @($Runs | Where-Object { $_.PlanName -and ($_.Finished -or $_.StartTime -lt $recent) })
    foreach ($day in @($kept | Group-Object -Property { $_.StartTime.Date } | Sort-Object -Property { [datetime]$_.Group[0].StartTime.Date } -Descending)) {
        $date = $day.Group[0].StartTime.ToString('dd/MM/yyyy')
        foreach ($plan in @($day.Group | Group-Object -Property PlanName | Sort-Object -Property Name)) {
            $failed = @($plan.Group | Where-Object { -not $_.Succeeded } | ForEach-Object {
                    if ($_.Finished) { $_.SubPlanName } else { "$($_.SubPlanName) (did not finish)" }
                } | Sort-Object -Unique)
            if ($failed.Count -eq 0) {
                [pscustomobject]@{ Date = $date; Severity = 'Success :white_check_mark:'; Plan = $plan.Name }
            }
            foreach ($subplan in $failed) {
                [pscustomobject]@{ Date = $date; Severity = 'error :x:'; Plan = "$($plan.Name) - $subplan" }
            }
        }
    }
}

# The version as people name it, e.g. "2019 CU20 (15.0.4298.1)".
function Format-SqlVersion {
    param(
        [object]$Info
    )

    $years = @{ 10 = '2008'; 11 = '2012'; 12 = '2014'; 13 = '2016'; 14 = '2017'; 15 = '2019'; 16 = '2022'; 17 = '2025' }
    $parts = @()
    $number = $null
    if ([version]::TryParse($Info.ProductVersion, [ref]$number)) {
        if ($number.Major -eq 10 -and $number.Minor -eq 50) {
            $parts += '2008 R2'
        }
        elseif ($years.ContainsKey($number.Major)) {
            $parts += $years[$number.Major]
        }
    }
    if ($Info.ProductLevel -and $Info.ProductLevel -ne 'RTM') {
        $parts += $Info.ProductLevel
    }
    if ($Info.ProductUpdateLevel) {
        $parts += $Info.ProductUpdateLevel
    }
    $parts += "($($Info.ProductVersion))"
    return $parts -join ' '
}

# Table cells must not contain a | or a line break.
function Format-Cell {
    param($Value)
    return ("$Value" -replace '\|', '/' -replace '\r?\n', ' ').Trim()
}

try {
    Write-Progress -Id 10 -Activity $progressActivity -Status "Connecting to $Server" -PercentComplete 10
    $builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $builder['Data Source'] = $Server
    $builder['Initial Catalog'] = 'msdb'
    $builder['Application Name'] = 'MOSE report'
    $builder['Connect Timeout'] = 30

    if ($Credential -and $Credential.UserName -notmatch '[\\@]') {
        # A SQL Server login.
        $builder['User ID'] = $Credential.UserName
        $builder['Password'] = $Credential.GetNetworkCredential().Password
        $results = @(& $readMaintenanceLog $builder.ConnectionString $Days)
    }
    elseif ($Credential) {
        # SQL Server only knows the Windows account of the process connecting: the query runs in a
        # process of that account.
        $builder['Integrated Security'] = $true
        $job = Start-Job -Credential $Credential -ScriptBlock $readMaintenanceLog -ArgumentList $builder.ConnectionString, $Days
        try {
            $results = @(Receive-Job -Job $job -Wait -ErrorAction Stop)
            if ($job.State -eq 'Failed') {
                throw $job.ChildJobs[0].JobStateInfo.Reason
            }
        }
        finally {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        $builder['Integrated Security'] = $true
        $results = @(& $readMaintenanceLog $builder.ConnectionString $Days)
    }
    # Typed again: from the process of another account they come back deserialized.
    $runs = @($results | Where-Object { $_.PSObject.Properties['PlanName'] } | ForEach-Object {
            [pscustomobject]@{ PlanName = $_.PlanName; SubPlanName = $_.SubPlanName; StartTime = [datetime]$_.StartTime; Finished = [bool]$_.Finished; Succeeded = [bool]$_.Succeeded }
        })

    # For the report's Software table (Report.ps1).
    $info = $results | Where-Object { $_.PSObject.Properties['ProductVersion'] } | Select-Object -First 1
    if ($info) {
        $purpose = if ($info.AlwaysOn) { 'SQL database (with Always On)' } else { 'SQL database' }
        [pscustomobject]@{ MoseInventory = 'Software'; Name = 'msSQL'; Version = Format-SqlVersion $info; Purpose = $purpose; Server = $Server }
    }

    Write-Progress -Id 10 -Activity $progressActivity -Status 'Building the report' -PercentComplete 80
    $rows = @(ConvertTo-MaintenanceRows -Runs $runs)
    $Body = "## Maintenance plan - $Days Days:`n"
    if ($rows.Count -eq 0) {
        $Body += "No maintenance plan ran in the last $Days days.`n"
    }
    else {
        $Body += "| Date       | Severity | Plan Name |`n"
        $Body += "|------------|----------|-----------|`n"
        foreach ($row in $rows) {
            $Body += "| $($row.Date) | $($row.Severity) | $(Format-Cell $row.Plan) |`n"
        }
    }
    $Body
}
catch {
    $account = if ($Credential) { $Credential.UserName } else { "$env:USERDOMAIN\$env:USERNAME (the account running the report)" }
    # SQL Server's own message, without PowerShell's "Exception calling ..." around it.
    $cause = $_.Exception
    if ($cause -is [System.Management.Automation.MethodInvocationException] -and $cause.InnerException) {
        $cause = $cause.InnerException
    }
    throw "Could not read the maintenance plans of SQL Server $Server as $($account): $($cause.Message) The account needs to read msdb (for example its db_datareader role, or sysadmin), and the server name may need its instance (HOST\INSTANCE) or port (HOST,1433)."
}
finally {
    Write-Progress -Id 10 -Activity $progressActivity -Completed
}
