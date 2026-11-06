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

## IT audit

`tests\Test-Audit.ps1` tests the audit on one computer, with fake devices and made-up computers (see [Test the audit](README.md#test-the-audit)): its 178 checks passed on 2026-11-07. What still needs a real client network:

| Part | Script | Status | Last tested | To check |
|---|---|---|---|---|
| Network | `AuditNetwork.ps1` | ⬜ | | A full scan of a client network; real switches, UPS and printers over SNMP (models, VLANs, LLDP/CDP neighbours, battery); UPnP and WS-Discovery devices (printers, cameras); the other networks offered and scanned behind the firewall; the diagram opened in draw.io. |
| Speed test | `AuditNetwork.ps1` | ⬜ | | `librespeed-cli` downloaded, checked and run (`-RunSpeedTest` of the tests, or a real audit); not blocked by the antivirus. |
| Active Directory | `AuditAD.ps1` | ⬜ | | A real domain, from a computer in it and from one outside it (`-ADServer`). |
| Servers and computers | `AuditInventory.ps1` | 🔁 | 2026-11-07 | Read this computer over DCOM; its findings checked with made-up computers. To check: servers over WinRM (roles, software, SQL Server, a UPS on USB), computers over DCOM from outside the domain, and a computer refusing the account. |
| Microsoft 365 | `AuditM365.ps1` | ⬜ | | A real tenant with a Global Reader. |
| Domains and e-mail | `AuditDomain.ps1` | ✅ | 2026-11-03 | Public domains. |

### The first audit on a real client network

What no test on one computer can show. Tick each item, note what went wrong in the To do list below, and write no client name or address here.

- [ ] Agreed on the scan with the client beforehand; its firewall or intrusion detection said nothing, or what it said is noted.
- [ ] A network of a few hundred devices: how long the scan took, and no device missed that is known to be there.
- [ ] Switches, UPS and printers of several makers over SNMP: their model, serial number, firmware, VLANs, LLDP/CDP neighbours and UPS battery are right (compare with their web page). Note the makers that gave nothing.
- [ ] UPnP and WS-Discovery answered through this computer's firewall: printers and cameras show their maker and model.
- [ ] The other networks offered after the scan are the client's VLANs (not this computer's VPN), and scanning one behind the firewall finds its devices.
- [ ] The speed test ran: not blocked by the antivirus or SmartScreen, through the client's proxy if any, and close to the line's speed when this computer is wired.
- [ ] Servers read over WinRM with a domain administrator: roles, installed software, SQL Server and a UPS on USB are right.
- [ ] Computers read over DCOM from a computer outside the domain; one refusing the account says why.
- [ ] A large domain (hundreds of computers): the inventory ends in reasonable time.
- [ ] Active Directory read from outside the domain with `-ADServer` and a domain account.
- [ ] Microsoft 365: the consent the first time in the tenant, then a Global Reader's sign-in.
- [ ] The diagram opened in draw.io: readable, and a useful start to draw the real network.
- [ ] The prompts in a console and from the Script Manager's **IT audit** button: the SNMP community typed hidden, the Get-Credential windows, each question clear.
- [ ] The audit read by a technician: each finding true, its severity fair, nothing important missing.
- [ ] Once on a French or Dutch Windows: the Wi-Fi labels read, and a refused computer says "access denied".

## To do

- Commvault Cloud: how the storage used evolved over one year.
- Commvault Cloud: the other licenses.
