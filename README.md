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
| `Configure.ps1` | Asks for the client: its name, the servers of each module and their credentials. Saves everything in the vault. |
| `Report.ps1` | Runs every configured module and writes `<Client>_Report_<yyyy-MM-dd>.md`. Starts `Configure.ps1` when nothing is configured yet. |
| `Manager.ps1` | Script Manager window: configure the client, turn reports on/off and run them. |
| `Update-FromGitHub.ps1` | Manual updater (whole project, or the latest release). |
| `updater.config.json` | Repository, files every computer updates (`Files`), module scripts updated only where the client uses them (`Modules`) and reports shown in the Script Manager (`Scripts`). |
| `helper.ps1` | SecretStore helpers, the client configuration and the list of modules. |
| `iloreport.ps1`, `IDRAC.ps1`, `BMCreport.ps1` | Modules: HPE iLO, Dell iDRAC, Lenovo BMC. |
| `nas2.ps1` | Module: Synology NAS. |
| `stormagicHealth.ps1` | Module: StorMagic SvSAN. |
| `vmwarereport.ps1` | Module: VMware vCenter. |
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

1. Enter the client name. It is the report title and file name.
2. Pick a module by its number (iLO, iDRAC, NAS, vCenter, Veeam, Commvault...), then how many servers to add.
3. For each server, enter its IP address or host name and its login. Servers of the same module can share one login.
4. Repeat for every module, `R` to remove a server, then `S` to save.

The vault password is asked first. Logins are saved as `MOSE:<module>:<server>` and the configuration as `MOSE:Config`, in the vault `SecretStore1`.

A computer only downloads the module scripts its client uses. Saving downloads the modules just added, and every run of `Start.ps1` checks them for updates. They are listed in `modules.local.json` (file names only), so `Start.ps1` knows them without opening the vault.

Commvault tokens already in the vault (for example saved by an older report script) are offered for reuse, so a Commvault Cloud token chain keeps going.

## Run the report

```powershell
cd $HOME\Mose
.\Start.ps1              # update, then run the report
.\Start.ps1 -Configure   # update, then change the client configuration
.\Start.ps1 -Gui         # update, then open the Script Manager
.\Manager.ps1            # open the Script Manager without updating
.\Start.ps1 -UpdateOnly  # update only
.\Start.ps1 -SkipUpdate  # run without checking GitHub
```

- The report asks for the SecretStore vault password.
- From the Script Manager, the report and the configuration open in their own window to ask for it. The output also appears at the bottom of the Script Manager.
- The report is saved next to the scripts as `<Client>_Report_<yyyy-MM-dd>.md` and opened in Notepad.
- If GitHub can't be reached, the local scripts run and a warning is shown. On the first run in a folder there are no local scripts yet, so it stops instead.

## Commvault Cloud token renewal

Commvault Cloud deletes a token chain that is not renewed for 14 days. On a computer with a Commvault Cloud, register the weekly renewal once, from the install folder:

```powershell
.\Renew-CommvaultToken.ps1 -Register
```

It renews every Commvault Cloud token saved in the vault.

## Add a module

1. Add the script to `Modules` in `updater.config.json`.
2. Add it to `$MoseModules` in `helper.ps1`.
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
