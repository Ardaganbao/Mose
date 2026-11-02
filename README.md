# MOSE

Monthly infrastructure reports (MOSE), kept up to date from GitHub.

Each computer installs this folder once. Every run downloads only the scripts that changed on GitHub, then builds the report of the client configured on that computer. No more zip files to copy by hand.

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
| `updater.config.json` | Repository, files every computer updates (`Files`), module scripts updated only where the client uses them (`Modules`) and reports shown in the Script Manager (`Scripts`). |
| `helper.ps1` | SecretStore helpers, the client configuration and the list of modules. |
| `iloreport.ps1`, `IDRAC.ps1`, `BMCreport.ps1` | Modules: HPE iLO, Dell iDRAC, Lenovo BMC. |
| `nas2.ps1` | Module: Synology NAS. |
| `stormagicHealth.ps1` | Module: StorMagic SvSAN. |
| `vmwarereport.ps1` | Module: VMware vCenter. |
| `hypervreport.ps1` | Module: Microsoft Hyper-V host or failover cluster, over PowerShell remoting. |
| `VeeamReport.ps1` | Module: Veeam Backup & Replication. |
| `CommvaultCloud report.ps1` | Module: Commvault Cloud and on-premises. |
| `Renew-CommvaultToken.ps1` | Weekly renewal of the Commvault Cloud tokens (scheduled task). |

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

## Configure the client

The first report on a computer asks for the client. To change it later, run `.\Start.ps1 -Configure`, or click **Configure client** in the Script Manager.

1. Enter the client name. It is the report title and file name. It is asked only the first time; `C` in the menu changes it.
2. Pick a module by its number (iLO, iDRAC, NAS, vCenter, Hyper-V, Veeam, Commvault...), then how many servers to add.
3. For each server, enter its IP address or host name and its login. Servers of the same module can share one login.
4. Repeat for every module, `R` to remove a server, `L` for the [report layout](#report-layout), then `S` to save.

The vault password is asked first. Logins are saved as `MOSE:<module>:<server>` and the configuration as `MOSE:Config`, in the vault `SecretStore1`.

A computer only downloads the module scripts its client uses. Saving downloads the modules just added, and every run of `Start.ps1` checks them for updates. They are listed in `modules.local.json` (file names only), so `Start.ps1` knows them without opening the vault.

Commvault tokens already in the vault (for example saved by an older report script) are offered for reuse, so a Commvault Cloud token chain keeps going.

### Hyper-V

Enter a Hyper-V host, or a failover cluster name to report every node of the cluster. The report connects over PowerShell remoting (WinRM) as the current Windows user, or as another account when asked. On the hosts, PowerShell remoting must be enabled (`Enable-PSRemoting`), and an IP address or a host outside the domain must be in this computer's TrustedHosts. Hyper-V cannot see the free space inside a VM, so the VM disks show how full each virtual disk file is.

## Run the report

```powershell
cd $HOME\Mose
.\Start.ps1              # update, then run the report
.\Start.ps1 -Configure   # update, then change the client configuration
.\Start.ps1 -DryRun      # update, then preview the report with sample data
.\Start.ps1 -DebugLog    # update, then run the report with a debug log
.\Start.ps1 -Gui         # update, then open the Script Manager
.\Manager.ps1            # open the Script Manager without updating
.\Start.ps1 -UpdateOnly  # update only
.\Start.ps1 -SkipUpdate  # run without checking GitHub
.\Start.ps1 -Version v1.0.0-rc.1  # update to a tag, branch or commit instead of the latest
```

- The report asks for the SecretStore vault password.
- From the Script Manager, the report and the configuration open in their own window to ask for it. The output also appears at the bottom of the Script Manager.
- The report is saved next to the scripts as `<Client>_Report_<yyyy-MM-dd>.md` and opened in Notepad.
- `-DryRun` (or **Sample report (dry run)** in the Script Manager, or `P` in the report layout menu) writes `<Client>_Report_<yyyy-MM-dd>_sample.md` with sample data, to check the sections, titles and heading levels in a few seconds. No server, API or saved login is used. Without any server configured, it shows one sample server per module.
- When a server fails, the report says `Collection failed: <error>` and the console shows the script and line where it stopped. `-DebugLog` (or **Report with debug log** in the Script Manager) runs the report and writes `<Client>_Debug_<yyyy-MM-dd_HHmmss>.log` next to the scripts: everything shown while it runs and, for each failed server, the error, the statement that failed and the call stack. Add `-SkipUpdate` where GitHub can't be reached. The log contains the client's server names and addresses, so git ignores it like the report.
- If GitHub can't be reached, the local scripts run and a warning is shown. On the first run in a folder there are no local scripts yet, so it stops instead.

## Report layout

The report title is `#`. By default the report has three `##` sections, each with its servers in `###` (`<Module> <server>`):

| Section | Servers |
|---|---|
| Hardware | iLO, iDRAC, BMC |
| Virtualization and storage | VMware vCenter, Hyper-V, StorMagic |
| Backup | Synology NAS, Veeam, Commvault |

To change it, press `L` in the client configuration (`.\Start.ps1 -Configure`). The menu shows the heading level of each line:

| Key | What it does |
|---|---|
| `N` | New section, or a subsection inside a section, with the servers you put in it (`2,3,4` or `2-4`). |
| `A` | Attach servers or subsections to a section. |
| `M` | Move a section or a server before another one, or to the end of the report. |
| `T` | Change the title of a server or a section. It shows the current and default titles; Enter keeps the title, `-` goes back to the default (`<Module> <server>`). Placeholders: `{Label}`, `{Server}`, `{Site}`, `{Client}`, `{Date}`. |
| `W` | Write the text of a section or subsection, shown under its title before its servers: type it here (a line with only `.` ends it) or edit it in Notepad. Markdown is allowed, with `{Client}` and `{Date}`. A section with text is shown even without servers, e.g. a Summary. |
| `H` | Hide or show a server. A section whose servers are all hidden is left out. |
| `X` | Remove a section, keeping its servers in its place. |
| `R` | Report title. |
| `J` | Edit the layout as JSON in Notepad, for wildcards or sections inside sections. |
| `D` | Back to the default layout. |

The layout is saved with the client configuration in the vault (`S`), since titles can name servers. A server added later goes into its default section with the default layout, or at the end of the report once the layout is changed.

The JSON (`J`) looks like this:

```json
{
    "Title": "{Client} monthly report {Date}",
    "Sections": [
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
- A server goes under the first entry that matches it. `"Hide": true` leaves the servers it matches out of the report.
- An entry with `Title` and `Sections` is a section: a heading with its servers one level below. Sections can be nested. `Text` adds Markdown under its heading.
- `Title` placeholders: `{Client}` and `{Date}` everywhere, and for a server `{Label}` (module name), `{Module}`, `{Server}` and `{Site}`.
- `Unlisted`: servers that no entry matches are added at the end (`End`, the default) or left out (`Hide`). A server added later then still shows up.

Each module's own headings are moved one level below its server heading, whatever level the module uses and however deep the server is in subsections. The heading that only repeated the server title is removed (`DropTitle` in `$MoseModules`). Markdown stops at `######`, so a deeper heading becomes a bold line.

## Commvault Cloud token renewal

Commvault Cloud deletes a token chain that is not renewed for 14 days. On a computer with a Commvault Cloud, register the weekly renewal once, from the install folder:

```powershell
.\Renew-CommvaultToken.ps1 -Register
```

It renews every Commvault Cloud token saved in the vault.

## Add a module

1. Add the script to `Modules` in `updater.config.json`.
2. Add it to `$MoseModules` in `helper.ps1`, with `DropTitle = $true` if its Markdown starts with a heading that only names the module or server.
3. In `Configure.ps1` (`Read-Target`), ask for anything it needs besides the server and login.
4. In `Report.ps1` (`Invoke-Target`), call it with those values.

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
