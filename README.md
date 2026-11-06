# MOSE

Monthly infrastructure reports (MOSE), kept up to date from GitHub.

Each computer installs this folder once. Every run downloads only the scripts that changed on GitHub, then builds the report of the client configured on that computer. No more zip files to copy by hand, except on a computer that can't reach GitHub ([below](#a-computer-without-github-access)).

It is built on the [powershellRepo](https://github.com/Ardaganbao/powershellRepo) updater (`Start.ps1`, `Manager.ps1`, `Update-FromGitHub.ps1`).

## No client data in this repository

The scripts are the same for every client. Everything about a client (its name, servers, IP addresses, user names, passwords and API tokens) is entered once on its computer and saved in that Windows user's SecretStore vault, never in a file of this repository.

Keep it that way: never commit a client name, IP address, host name or user name. Reports (`*_Report_*.md`) and saved passwords or tokens are listed in `.gitignore`.

## Files

| File | What it does |
|---|---|
| `Start.ps1` | Entry point. Updates every file from GitHub, then runs `Report.ps1`. |
| `Configure.ps1` | Asks for the client: its name, the servers of each module, their credentials and the report layout. Saves everything in the vault. |
| `Report.ps1` | Runs every configured module and writes `<Client>_Report_<yyyy-MM-dd>.md`, with the client's report layout. Starts `Configure.ps1` when nothing is configured yet. |
| `Manager.ps1` | Script Manager window: configure the client, turn reports on/off and run them. |
| `Update-FromGitHub.ps1` | Manual updater (whole project, or the latest release). |
| `updater.config.json` | Repository, files every computer updates (`Files`), module scripts updated only where the client uses them (`Modules`), the Keeper scripts, downloaded only with `-Keeper` or once present (`Keeper`), and reports shown in the Script Manager (`Scripts`). |
| `Keeper.ps1` | Imports or exports Keeper entries over its API, independent of the report: `.\Start.ps1 -Keeper` or **Keeper import/export** in the Script Manager. Export: asks for the address and login of a Keeper Connection Manager, then writes its RDP connections with their drive settings (drive redirection, upload and download) to `KCM-RDP-Drive-Report_<yyyy-MM-dd_HHmmss>.csv` and opens it. Import: not written yet. |
| `helper.ps1` | SecretStore helpers, the client configuration and the list of modules. |
| `latest-versions.json` | The latest ESXi, StorMagic, DSM and Windows Server versions, for the [Physical System](#inventory-tables) check marks when they can't be read online. |
| `iloreport.ps1`, `IDRAC.ps1`, `BMCreport.ps1` | Modules: HPE iLO, Dell iDRAC, Lenovo BMC. |
| `nas2.ps1` | Module: Synology NAS. |
| `stormagicHealth.ps1` | Module: StorMagic SvSAN. |
| `vmwarereport.ps1` | Module: VMware vCenter. |
| `hypervreport.ps1` | Module: Microsoft Hyper-V host or failover cluster, over PowerShell remoting. |
| `VeeamReport.ps1` | Module: Veeam Backup & Replication, with the Veeam PowerShell module (on the Veeam server, or there over PowerShell remoting). |
| `VeeamRestReport.ps1` | Module: Veeam Backup & Replication over its REST API; SureBackup through `VeeamReport.ps1`. |
| `CommvaultCloud report.ps1` | Module: Commvault Cloud and on-premises. |
| `sqlmaintenance.ps1` | Module: SQL Server maintenance plans (the runs of the last 16 days, from msdb), and the SQL Server version. |
| `Renew-CommvaultToken.ps1` | Weekly renewal of the Commvault Cloud tokens (scheduled task). |
| `TESTING.md` | Which modules were tested against a real server, and when. Not copied to the client computers. |

## Install on a computer

Run this in PowerShell as the Windows user that will run the reports:

```powershell
irm https://raw.githubusercontent.com/Ardaganbao/Mose/main/Start.ps1 | iex
```

It installs to `$HOME\Mose`, downloads every script and opens the Script Manager. To install to another folder:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Ardaganbao/Mose/main/Start.ps1))) -InstallPath C:\script
```

You can also copy `Start.ps1` alone into any folder and run it: the first run there downloads every file.

### While the repository is private

GitHub then needs a token that can read it: a fine-grained token with **Repository access: only `Mose`** and **Permissions: Contents → Read-only**. A first run asks for it when GitHub refuses the files without one, or take it with `-GitHubToken`:

```powershell
.\Start.ps1 -GitHubToken <token> -Gui
```

The token is saved to `github-token.xml`, encrypted so only this Windows user on this computer can read it. When it expires, save a new one with `.\Start.ps1 -SaveToken -UpdateOnly`.

### A computer without GitHub access

Each release (`v1.0.0-rc.15`...) has a zip, `Mose-<version>.zip`, with every script and `installed-version.txt` naming its commit. Unzip it and copy the content of its `Mose` folder over the install folder (e.g. `C:\script`): the configuration, the vault and the reports stay as they are. Then run `.\Start.ps1 -SkipUpdate`, so it doesn't wait for GitHub; without it, the local scripts run after a warning that GitHub can't be reached.

## Configure the client

The first report on a computer asks for the client. To change it later, run `.\Start.ps1 -Configure`, or click **Configure client** in the Script Manager.

1. Enter the client name. It is the report title and file name. It is asked only the first time; `C` in the menu changes it.
2. Pick a module by its number (iLO, iDRAC, NAS, vCenter, Hyper-V, Veeam, Commvault...), then how many servers to add.
3. For each server, enter its IP address or host name and its login. Servers of the same module can share one login.
4. Repeat for every module, `R` to remove a server, `L` for the [report layout](#report-layout), then `S` to save.

The vault password is asked first. Logins are saved as `MOSE:<module>:<server>` and the configuration as `MOSE:Config`, in the vault `SecretStore1`.

`I` in the menu holds what the report's [inventory tables](#inventory-tables) cannot read. `A` adds a line; its number changes it (Enter keeps a value, `-` empties it) or removes it.

- `S`, Software: the lines no module reads, e.g. Microsoft Defender, with a version and a purpose.
- `M`, Physical System: a machine by the name the report shows (e.g. `esxi01`) or its serial number, with its warranty end date (`yyyy-MM-dd`) and a note, the service to show (e.g. `NAS store for Veeam backup`), and for a machine no module reads (e.g. the StorMagic witness) its brand, model, Product ID and BIOS.

`P` in the menu lists every login and token in the vault with the servers that use it. Pick one to edit it: the user name and password, or the Commvault tokens and ring or URL (Enter keeps each value). Or remove it: only a login or token no server uses can be removed, and it leaves the vault when you save with `S`.

`V` in the menu changes the vault password: the current one, then the new one twice. It changes at once, not on `S`, and everything in the vault stays. SecretStore has one password per Windows user and computer, so it is the password of that user's every vault there. When the weekly Commvault token renewal is set up (`Renew-CommvaultToken.ps1 -Register`), its copy of the password is saved again with the new one. A forgotten vault password cannot be recovered: `Reset-SecretStore` empties the vault, and the client is configured again.

A computer only downloads the module scripts its client uses. Saving downloads the modules just added, and every run of `Start.ps1` checks them for updates. They are listed in `modules.local.json` (file names only), so `Start.ps1` knows them without opening the vault.

Commvault tokens already in the vault (for example saved by an older report script) are offered for reuse, so a Commvault Cloud token chain keeps going.

### Hyper-V

Enter a Hyper-V host, or a failover cluster name to report every node of the cluster. The report connects over PowerShell remoting (WinRM) as the current Windows user, or as another account when asked. On the hosts, PowerShell remoting must be enabled (`Enable-PSRemoting`), and an IP address or a host outside the domain must be in this computer's TrustedHosts. Hyper-V cannot see the free space inside a VM, so the VM disks show how full each virtual disk file is.

### Veeam and Hyper-V by IP address

PowerShell remoting only connects to an IP address that is in this computer's TrustedHosts, and only with a login given explicitly. With the server's name in the domain, Kerberos needs neither and checks the server's identity, so prefer the name. For an IP address, the configuration asks for the login, and both the configuration and the report offer to add the address to TrustedHosts. Windows asks for administrator rights for that. The report also shows the server's name when DNS knows it. By hand, as administrator: `Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<IP>' -Concatenate -Force`. Add an address only on a network you trust: Windows does not check the identity of a server in TrustedHosts.

### SQL Server maintenance plans

Enter the SQL Server: the cluster or host name, `HOST\INSTANCE` for a named instance, with `,port` if it is not the default one. The report reads the maintenance plan runs of the last 16 days from `msdb` (the Maintenance Plans log of the Management Studio log viewer): one row per plan and day, `Success` when every run of the plan that day succeeded, else one `error` row per failed subplan (`plan - subplan`). A subplan that runs every few hours adds no rows while it succeeds.

It connects as the Windows account running the report, or with a SQL Server login, or as another Windows account (`DOMAIN\user`, the query then runs in a process of that account). The account needs to read `msdb`, for example through its `db_datareader` role.

### Synology NAS with 2-step verification

When the NAS account has 2-step verification, the report asks for its code (from the authenticator app) once every server ran, then runs that NAS again. The NAS then trusts this computer, as `MOSE report <computer>`, and gives it a device ID, saved with the NAS in the client configuration: the next reports need no code. When the NAS no longer trusts the computer, e.g. after its trusted devices were removed in DSM, the report asks again. A report run without a window, such as a scheduled task, cannot ask: run it once in a window first.

### Veeam over the REST API

**Veeam Backup & Replication (REST API)** reads the same report from Veeam's REST API (Veeam 11 or later, HTTPS port 9419 of the Veeam server), with the repositories' free space too. Except for SureBackup (below), it needs no Veeam console, no PowerShell remoting and no Windows administrator rights on the Veeam server: only port 9419 open from this computer, and a Veeam account with a role (Users and Roles in the Veeam console, e.g. Veeam Backup Viewer), entered as `DOMAIN\user`, or `SERVER\user` for an account of the Veeam server itself, `SERVER` being its computer name (not its IP address).

Veeam 13's REST API gives no SureBackup jobs or runs, so the module reads SureBackup through the Veeam PowerShell module (`VeeamReport.ps1 -SureBackupOnly`), with the same Veeam account:

- When the Veeam Backup & Replication Console of the same version is installed on this computer, through it, with no PowerShell remoting. When this computer is the Veeam server itself (configured by its name, full name or one of its addresses), it connects to it as `localhost` and accepts its certificate, which Veeam 13 otherwise refuses with no one to accept it ("The remote certificate was rejected"): the connection does not leave this computer.
- Otherwise on the Veeam server, over PowerShell remoting: `VeeamReport.ps1` is copied to a temporary file there, runs there (in PowerShell 7 when the Veeam module needs it, as Veeam 13's does), and its result comes back; the file is removed after. The Veeam account must then be allowed to use PowerShell remoting on the Veeam server: an administrator of it, or a member of its **Remote Management Users** group. An IP address also needs this computer's TrustedHosts, which the report offers to set ([Veeam and Hyper-V by IP address](#veeam-and-hyper-v-by-ip-address)).

A local account of the Veeam server, even in its Administrators group, is refused over remoting ("Access is denied"): Windows removes the administrator rights of local accounts that connect over the network, except the built-in Administrator. Either use a domain account in the server's Administrators group (better), or set `LocalAccountTokenFilterPolicy` to 1 on the Veeam server, which gives every local administrator account its rights over the network. As administrator on the Veeam server:

```powershell
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -PropertyType DWord -Force
```

To check it from this computer, with the Veeam login of the report: `Enter-PSSession <Veeam server> -Credential SERVER\user`. When that opens a prompt on the Veeam server, the report reads SureBackup too. When neither way works, the SureBackup section says why, e.g. that the Veeam server refused the login.

Agent backup jobs and policies (Veeam Agent computers) get no computer details from the REST API: it refuses them for an agent session (HTTP 500, "ESessionType ... AgentManagement"), and lists no session for some agent jobs. Their job table shows the last session, or the last run and result from the job's state. Their details list the computers in the job's backups, with the newest restore point and the number of restore points of each: the backups of the job, else those named after it that are no other job's, such as a policy's backup of each computer. Under Session log come the session's result message and its log as the Veeam console shows it, with what happened on each computer; of a log longer than 50 lines, only its warnings and errors.

Veeam refuses a whole list when one of its items has a type its API version cannot give (HTTP 500, "Job type WindowsAgentBackupFailoverCluster is not supported in this API version", for a failover cluster agent job in Veeam 13). The report then reads that list in halves, down to the refused item, and leaves it out. A refused job is shown from its sessions of the last 31 days, as an agent job: the backup sessions of a job that is not listed, when there are as many such jobs as refused ones; otherwise a line under Backup jobs names the missing type.

The REST API usually has Veeam's own certificate, which this computer doesn't trust. Give its SHA-1 thumbprint when adding the server, or leave it empty: the first report then shows the certificate's thumbprint and offers to trust it for this server, after you checked it on the Veeam server. When Veeam refuses the login, the report offers to enter another one. With `-DebugLog`, every API answer is written to `<Client>_Debug_<date>_VeeamApi_<server>.log`, to adapt the module to another Veeam version.

## Run the report

```powershell
cd $HOME\Mose
.\Start.ps1              # update, then run the report
.\Start.ps1 -Configure   # update, then change the client configuration
.\Start.ps1 -DryRun      # update, then preview the report with sample data
.\Start.ps1 -DebugLog    # update, then run the report with a debug log
.\Start.ps1 -Only veeam,sql  # update, then a partial report: only these servers
.\Start.ps1 -Choose      # update, then a partial report of servers picked from a list
.\Start.ps1 -Keeper      # update, then import or export Keeper entries over its API (not the report)
.\Start.ps1 -Gui         # update, then open the Script Manager
.\Manager.ps1            # open the Script Manager without updating
.\Start.ps1 -UpdateOnly  # update only
.\Start.ps1 -SkipUpdate  # run without checking GitHub
.\Start.ps1 -Version v1.0.0-rc.1  # update to a tag, branch or commit instead of the latest
```

- The report asks for the SecretStore vault password.
- From the Script Manager, the report and the configuration open in their own window to ask for it. The output also appears at the bottom of the Script Manager.
- The report is saved next to the scripts as `<Client>_Report_<yyyy-MM-dd>.md` and opened in Notepad.
- Each server's module runs in a PowerShell process of its own, so what one changes for its process (such as accepting any certificate of its server, or the TLS versions) can't affect the others. Up to 4 servers run at once; `.\Report.ps1 -ThrottleLimit 8` runs more, `-ThrottleLimit 1` one after the other. Their messages and warnings appear in the report window with the server's name in front, and each server has its own progress bar. Questions (TrustedHosts, a login) come before the servers start, and the offer of a new login after a refused one once they all ended. The report keeps the layout order.
- `-DryRun` (or **Sample report (dry run)** in the Script Manager, or `P` in the report layout menu) writes `<Client>_Report_<yyyy-MM-dd>_sample.md` with sample data, to check the sections, titles and heading levels in a few seconds. No server, API or saved login is used. Without any server configured, it shows one sample server per module.
- A partial report runs only some servers: `-Only veeam,sql` takes those whose module, module name or server name contains one of the words: `iLO`, `iDRAC`, `BMC`, `NAS`, `StorMagic`, `VMware`, `HyperV`, `Veeam` (both Veeam modules), `VeeamApi` (the REST API one only), `Commvault` (Cloud and on-premises), `CommvaultCloud`, `CommvaultOnPrem`, `SQL`, or a server name or IP address (`*` and `?` also work; Tab completes the module words), and `-Choose` (or **Report of some servers** in the Script Manager) lists the servers to pick them by number (`2,3` or `2-4`) or by words. It is written to `<Client>_Report_<yyyy-MM-dd>_part-veeam-sql.md` (or `_part.md`), with a line saying which servers it has, so the full report of the day stays as it was. It works with `-DebugLog` and `-DryRun` too.
- When a server fails, the report says `Collection failed: <error>` and the console shows the script and line where it stopped. `-DebugLog` (or **Report with debug log** in the Script Manager) runs the report and writes `<Client>_Debug_<yyyy-MM-dd_HHmmss>.log` next to the scripts: for each server how long it took and its warnings and, when it failed, the error, the statement that failed and the call stack, then a summary. When the report itself stops (not a server), the console shows the script and line, and the log the statement and the call stack too. Add `-SkipUpdate` where GitHub can't be reached. The log contains the client's server names and addresses, so git ignores it like the report.
- If GitHub can't be reached, the local scripts run and a warning is shown. On the first run in a folder there are no local scripts yet, so it stops instead.

## Report layout

The report title is `#`. By default the report has these `##` sections, each with its servers or tables in `###` (`<Module> <server>`):

| Section | Servers and tables |
|---|---|
| Infrastructure detail | The [inventory tables](#inventory-tables): Physical System, Virtual System, Software |
| Hardware | iLO, iDRAC, BMC |
| Virtualization and storage | VMware vCenter, Hyper-V, StorMagic |
| Backup | Synology NAS, Veeam, Commvault |
| Databases | SQL Server maintenance plans |

To change it, press `L` in the client configuration (`.\Start.ps1 -Configure`). The menu shows the heading level of each line:

| Key | What it does |
|---|---|
| `N` | New section, or a subsection inside a section, with the servers and tables you put in it (`2,3,4` or `2-4`). |
| `A` | Attach servers, tables or subsections to a section. |
| `M` | Move a section, a server or a table before another one, or to the end of the report. |
| `T` | Change the title of a server, a table or a section. It shows the current and default titles; Enter keeps the title, `-` goes back to the default (`<Module> <server>`, the table's name). Placeholders: `{Label}`, `{Server}`, `{Site}` (servers), `{Client}`, `{Date}`. |
| `W` | Write the text of a section or subsection, shown under its title before its servers: type it here (a line with only `.` ends it) or edit it in Notepad. Markdown is allowed, with `{Client}` and `{Date}`. A section with text is shown even without servers, e.g. a Summary. |
| `H` | Hide or show a server, a table or a section with all it holds. A section whose servers and tables are all hidden is left out too. A hidden server does not run, so the inventory tables get nothing from it either. |
| `X` | Remove a section, keeping its servers and tables in its place. |
| `R` | Report title. |
| `J` | Edit the layout as JSON in Notepad, for wildcards or sections inside sections. |
| `D` | Back to the default layout. |

The layout is saved with the client configuration in the vault (`S`), since titles can name servers. A server added later goes into its default section with the default layout, or at the end of the report once the layout is changed.

The JSON (`J`) looks like this:

```json
{
    "Title": "{Client} monthly report {Date}",
    "Sections": [
        { "Title": "Infrastructure detail", "Text": "### Schema\n![schema](https://example.com/schema.png)", "Sections": [
            { "Table": "PhysicalSystem" },
            { "Table": "Software", "Title": "Software and purpose" }
        ] },
        { "Table": "VirtualSystem" },
        { "Title": "Backup", "Sections": [
            { "Module": "Veeam" },
            { "Module": "Commvault*", "Title": "{Label}" }
        ] },
        { "Module": "VMware", "Title": "vCenter {Site}" },
        { "Title": "Hardware", "Sections": [
            { "Module": "iLO", "Server": "192.0.2.10", "Hide": true },
            { "Module": ["iLO", "iDRAC", "BMC"], "Title": "Server {Server}" }
        ] }
    ],
    "Unlisted": "End"
}
```

- `Sections` lists the report sections in order. An entry with `Module` adds one `###` per configured server of that module (a name, a wildcard like `Commvault*`, or a list). `Server` keeps only the matching servers (wildcards allowed).
- An entry with `Table` adds one of the [inventory tables](#inventory-tables): `PhysicalSystem`, `VirtualSystem` or `Software`, with its name as title unless it has a `Title`.
- A server goes under the first entry that matches it, and so does a table. `"Hide": true` leaves the servers or the table it matches out of the report, and on a section, the section with all it holds.
- An entry with `Title` and `Sections` is a section: a heading with its servers one level below. Sections can be nested. `Text` adds Markdown under its heading.
- `Title` placeholders: `{Client}` and `{Date}` everywhere, and for a server `{Label}` (module name), `{Module}`, `{Server}` and `{Site}`.
- `Unlisted`: servers that no entry matches are added at the end (`End`, the default) or left out (`Hide`). A server added later then still shows up. Tables that no entry places (a layout saved before there were tables) go at the start, in a section `Infrastructure detail`.

Each module's own headings are moved one level below its server heading, whatever level the module uses and however deep the server is in subsections. The heading that only repeated the server title is removed (`DropTitle` in `$MoseModules`). Markdown stops at `######`, so a deeper heading becomes a bold line.

### Inventory tables

Three tables made from what the modules read, once every server ran. By default they are in the section `Infrastructure detail`, at the start of the report; in the layout each one is a line of its own, placed, renamed or hidden like a server:

| Table | What it holds |
|---|---|
| Physical System | A row per machine: name, brand, model, serial number, Product ID and BIOS, from the iLO, iDRAC or BMC, the VMware or Hyper-V host and the NAS, merged by serial number or name. A serial number also matches another module's Product ID: Dell's iDRAC gives the board's serial number with the service tag as Product ID, and VMware gives either as the serial number. Below each other, the services it runs with their version: the ESXi or Windows of a host, the StorMagic VSA it runs (from the VMware VMs) with its support end and the name of its witness in the first column, the NAS's DSM. The witness has a row of its own only when a module reads it or a line entered with `I` names it. Then the warranty end entered with `I`; a line can give the serial number or the service tag. A machine with no name anywhere (an iDRAC that reports no host name, for a server no other module reads) is named by the address of its board. The StorMagic module reads its own VSA's version and support: its mirror partners and witness get the same unless they are StorMagic servers of the report too. |
| Virtual System | The VMs of the VMware vCenters, a table per VM folder (Production, Acceptance...), with their operating system as VMware Tools reports it, else as configured: `Windows 2019`, `Windows 11`, `CentOS 9`. vSphere's own cluster VMs (`vCLS`) are left out. |
| Software | Veeam with its version (both Veeam modules), msSQL with the SQL Server version (`2019 CU20 (15.0.4298.1)`) and `(with Always On)` when it is on (SQL Server maintenance plans module), then the lines entered with `I` in the configuration. A line with the name of one read (`Veeam`, `msSQL`) gives its purpose, or a version to show instead. Servers with the same version share a line. |

A version gets :white_check_mark: when it is the latest of its product, :warning: with the latest one when it is not, :question: when the latest is not known (a release no list has, like Windows Server 2012 R2):

| Product | The latest version |
|---|---|
| ESXi | The newest build of the host's release (8.0...) on its newest update line (8.0.3), from [virten.net](https://www.virten.net/repo/esxiReleases.json) when this computer can reach it, else from `latest-versions.json`. A newer patch of an older update line (8.0 Update 2) is not the latest. |
| DSM | The newest DSM of the NAS's model in [Synology's release notes](https://www.synology.com/releaseNote/DSM) when this computer can reach them, or an update DSM's own update check offers, else `latest-versions.json` for its major version. DSM's own "no update" proves nothing: it offers no new major DSM. The NAS section's `NAS version` gets the same mark, without `latest-versions.json`. |
| StorMagic | `latest-versions.json`, or a newer version read on a server of the report. |
| Windows (Hyper-V hosts) | The newest cumulative update of the host's release (`20348.5773` for Windows Server 2022), from [Microsoft's release information](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info) when this computer can reach it, else from `latest-versions.json`. A hotpatched server on the latest hotpatch is up to date too. The version shows the release name and the patch level: `Windows Server 2025 Datacenter 24H2 (26100.4349)`. |

`latest-versions.json` comes with MOSE (and its updates); `Updated` says when it was written. A warranty or support end gets :white_check_mark: more than 60 days before it, :warning: in the last 60 days, :x: once past.

The text of their section (`W`) goes before them, e.g. a schema of the network. A table with nothing to show is left out: a partial report has only the tables of its servers, without the lines entered by hand for other machines or software.

## Commvault Cloud licenses

Commvault's API gives the licenses from its License Summary report, which is for CommCell administrators. Commvault Cloud runs the CommCell, so it refuses them to every tenant account, even an administrator's (HTTP 403). The report then asks, once every server ran, for the Subscriptions page of Commvault Cloud exported as CSV, and shows it as the license table, with the date it was exported. A copy is kept next to the scripts (`Subscriptions_<secret>.csv`, which git ignores), so the next reports reuse it; the report asks for a new export when the copy is older than 25 days. A subscription ending within 45 days is marked :warning:, an ended one :no_entry:.

## Commvault Cloud token renewal

Commvault Cloud deletes a token chain that is not renewed for 14 days. On a computer with a Commvault Cloud, register the weekly renewal once, from the install folder:

```powershell
.\Renew-CommvaultToken.ps1 -Register
```

It renews every Commvault Cloud token saved in the vault.

## Add a module

1. Add the script to `Modules` in `updater.config.json`.
2. Add it to `$MoseModules` in `helper.ps1`, with `DropTitle = $true` if its Markdown starts with a heading that only names the module or server, and `Uses` for the other scripts it runs.
3. In `Configure.ps1` (`Read-Target`), ask for anything it needs besides the server and login.
4. In `helper.ps1` (`Invoke-MoseModule`), call it with those values. It runs in a process of its own and returns its Markdown as strings.
5. For the [inventory tables](#inventory-tables), it can also return objects with a `MoseInventory` property: `Machine` (Name, Brand, Model, Serial, ProductId, Bios, Source), `Service` (Machine or MachineSerial, Name, Version, and Product for the version check), `VM` (Name, Folder, Os, Host) or `Software` (Name, Version, Purpose). See `vmwarereport.ps1`.
6. In `Report.ps1`, give it sample Markdown for `-DryRun` (`Get-SampleMarkdown`, and `Get-SampleInventory` for its objects), and add its word to the `-Only` completion in `Report.ps1` and `Start.ps1`.

Commit and push to `main`: every computer picks up the change on its next run. Keep the flat folder layout: `Report.ps1` finds the modules next to it.

## Move a computer from an older version

Older versions had one report script per client, with its servers inside.

1. Run `.\Start.ps1 -Configure` and enter the client's servers. Reuse the Commvault tokens when asked.
2. Run the report once and compare it with the last one.
3. Delete the old client script (`mose_<Client>.ps1`) from the folder. It is no longer updated or run.

## Passwords and secrets

Never put passwords or tokens in a script. A pre-commit hook blocks commits that look like they contain a secret. Enable it once in every clone:

```powershell
git config core.hooksPath .githooks
```

## Notes

- `.gitattributes` keeps files byte-identical to GitHub, so the updater's hash check matches. Don't change it.
- If scripts are blocked from running: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
