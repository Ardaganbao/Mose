# Module tests

Every module runs once against a real server before a release candidate is tagged, and again after its script changes. A module is validated when its report section and its rows in the [inventory tables](README.md#inventory-tables) came out right.

Write no client name, server name or address here: the repository holds no client data.

✅ validated · 🔁 to test again after a change · ⬜ not tested yet

| Module | Script | Status | Last tested | To check |
|---|---|---|---|---|
| HPE iLO | `iloreport.ps1` | ⬜ | | Health and storage; the server in Physical System. |
| Dell iDRAC | `IDRAC.ps1` | ✅ | 2026-11-04 | Health; the server in Physical System. |
| Lenovo BMC | `BMCreport.ps1` | ⬜ | | Health; the server in Physical System. |
| Synology NAS | `nas2.ps1` | 🔁 | 2026-11-04, failed | Since `4695e14`, with a 2-step verification account: the report asks for the code, the NAS then trusts the computer, and the next report signs in without a code. Volumes, disks and the DSM version mark; the NAS in Physical System. |
| StorMagic SvSAN | `stormagicHealth.ps1` | ⬜ | | VSA and witness state; the VSAs and the witness in Physical System. |
| VMware vCenter | `vmwarereport.ps1` | ⬜ | | Hosts and VMs; the hosts in Physical System, the VMs in Virtual System. |
| Microsoft Hyper-V | `hypervreport.ps1` | ✅ | 2026-11-04 | Hosts or cluster nodes and VMs; the hosts in Physical System, the VMs in Virtual System. |
| Veeam (PowerShell module) | `VeeamReport.ps1` | ⬜ | | Jobs, Backup Copy, SureBackup and licence; Veeam in Software. |
| Veeam (REST API) | `VeeamRestReport.ps1` | 🔁 | 2026-11-04, failed | Since `cc53b45`: a job of a type the API refuses (a failover cluster agent job) shown from its sessions; the restore points counted in the Backup Copy details; SureBackup through `VeeamReport.ps1`. |
| Commvault Cloud | `CommvaultCloud report.ps1` | 🔁 | 2026-11-04 | No `---` rule and no `Report generated` line. The report asks for the Subscriptions CSV and shows it as the license table; the next report reuses the kept copy without asking. Passed with `ddeb985`: its lines on screen and in the debug log, with `Commvault API time:`; the licences refused on one line (the account's role cannot read them). |
| Commvault on-premises | `CommvaultCloud report.ps1` | ⬜ | | The same report with a Command Center access token. |
| SQL Server maintenance plans | `sqlmaintenance.ps1` | ⬜ | | The plan runs of the last 16 days; SQL Server in Software. |
