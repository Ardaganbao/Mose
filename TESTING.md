# Module tests

Every module runs once against a real server before a release candidate is tagged, and again after its script changes. A module is validated when its report section and its rows in the [inventory tables](README.md#inventory-tables) came out right.

Write no client name, server name or address here: the repository holds no client data.

✅ validated · 🔁 to test again after a change · ⬜ not tested yet

| Module | Script | Status | Last tested | To check |
|---|---|---|---|---|
| HPE iLO | `iloreport.ps1` | ⬜ | | Health and storage; the server in Physical System. |
| Dell iDRAC | `IDRAC.ps1` | ✅ | 2026-11-04 | Health; the server in Physical System. |
| Lenovo BMC | `BMCreport.ps1` | ⬜ | | Health; the server in Physical System. |
| Synology NAS | `nas2.ps1` | ✅ | 2026-11-04 | Volumes, disks and the DSM version mark; the NAS in Physical System. With a 2-step verification account: the code asked once, then the next reports sign in without it. |
| StorMagic SvSAN | `stormagicHealth.ps1` | ⬜ | | VSA and witness state; the VSAs and the witness in Physical System. |
| VMware vCenter | `vmwarereport.ps1` | ⬜ | | Hosts and VMs; the hosts in Physical System, the VMs in Virtual System. |
| Microsoft Hyper-V | `hypervreport.ps1` | ✅ | 2026-11-04 | Hosts or cluster nodes and VMs; the hosts in Physical System, the VMs in Virtual System. |
| Veeam (PowerShell module) | `VeeamReport.ps1` | ⬜ | | Jobs, Backup Copy, SureBackup and licence; Veeam in Software. |
| Veeam (REST API) | `VeeamRestReport.ps1` | 🔁 | 2026-11-04 | Passed: licence, backup jobs, Backup Copy with the restore points counted, repositories; Veeam in Software. To fix: a failover cluster agent job, refused by the API, is not shown ("no session of it was found"); an Azure Blob repository shows -1,024.00 MB for its capacity and free space instead of n/a. |
| Commvault Cloud | `CommvaultCloud report.ps1` | ✅ | 2026-11-04 | The licenses from the Subscriptions CSV (asked once, then reused), SLA and job history; its lines and `Commvault API time:` on screen and in the debug log. |
| Commvault on-premises | `CommvaultCloud report.ps1` | ⬜ | | The same report with a Command Center access token. |
| SQL Server maintenance plans | `sqlmaintenance.ps1` | ⬜ | | The plan runs of the last 16 days; SQL Server in Software. |

## To do

- Commvault Cloud: how the storage used evolved over one year.
- Commvault Cloud: the other licenses.

## Client vaults

`tests\Test-ClientVaults.ps1` tests `-MultiClientMode` with a stand-in vault: its 41 checks passed on 2026-11-09. What it cannot show, to check once with the real SecretStore on a technician's computer:

- [ ] `.\Start.ps1 -MultiClientMode`: the client vaults listed with their client, the default one first; a new one created, configured with `-Configure`, then its report.
- [ ] The configuration and logins of the new one under `MOSE:<name>:` (`Get-SecretInfo -Vault SecretStore1`), the default one unchanged, and `P` listing only those of the client vault in use.
- [ ] A computer with one client, without `-MultiClientMode`: nothing asked about client vaults, the report as before.
- [ ] The weekly Commvault token renewal with Commvault Cloud tokens in two client vaults: both renewed.
