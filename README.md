# MOSE

Monthly infrastructure reports (MOSE) for On IT clients, kept up to date from GitHub.

Each client computer installs this folder once. Every run downloads only the scripts that changed on GitHub, then runs the report turned on for that computer. No more zip files to copy by hand.

It is built on the [powershellRepo](https://github.com/Ardaganbao/powershellRepo) updater (`Start.ps1`, `Manager.ps1`, `Update-FromGitHub.ps1`), with three changes for MOSE:

- **Private repository.** `Start.ps1` sends a GitHub token, saved once per computer.
- **Reports start turned off.** A computer only runs the reports checked on it, so the EURID server never runs the Clait report.
- **Reports run in their own window** from the Script Manager, because they ask for the vault password and for any credential not yet saved.

## Keep this repository private

The report scripts contain client names, IP addresses and host names. Keep the GitHub repository **private**. Reports (`*_Report_*.md`) and saved passwords or tokens are listed in `.gitignore` and must never be committed.

## Files

| File | What it does |
|---|---|
| `Start.ps1` | Entry point. Updates every file from GitHub, then runs the reports turned on for this computer. |
| `Manager.ps1` | Script Manager window: turn reports on/off for this computer and run them. |
| `Update-FromGitHub.ps1` | Manual updater (whole project, or the latest release). |
| `updater.config.json` | Repository, files to update (`Files`) and reports shown in the Script Manager (`Scripts`). |
| `helper.ps1` | SecretStore helpers used by every report. |
| `mose_EURID.ps1`, `mose_clait.ps1`, `mose_VBB.ps1` | One report per client. Reads its credentials from the vault, runs the checks, writes `<Client>_Report_<date>.md`. |
| `IDRAC.ps1`, `iloreport.ps1`, `BMCreport.ps1` | Server hardware: Dell iDRAC, HPE iLO, BMC. |
| `nas2.ps1` | Synology NAS. |
| `stormagicHealth.ps1` | StorMagic SvSAN. |
| `vmwarereport.ps1` | VMware vCenter. |
| `VeeamReport.ps1` | Veeam Backup & Replication. |
| `CommvaultCloud report.ps1` | Commvault Cloud and on-premises. |
| `Renew-CommvaultToken.ps1` | Weekly renewal of the EURID Commvault Cloud token (scheduled task). |

## Install on a client computer

You need a GitHub token that can read this repository. Create a fine-grained token with **Repository access: only `Mose`** and **Permissions: Contents → Read-only**.

Run this in PowerShell as the Windows user that will run the reports:

```powershell
$env:GITHUB_TOKEN = [Net.NetworkCredential]::new('', (Read-Host 'GitHub token' -AsSecureString)).Password
irm https://raw.githubusercontent.com/Ardaganbao/Mose/main/Start.ps1 -Headers @{ Authorization = "Bearer $env:GITHUB_TOKEN" } | iex
```

This:

1. installs to `$HOME\Mose`,
2. saves the token to `github-token.xml` there, encrypted so only this Windows user on this computer can read it,
3. downloads every script and opens the Script Manager.

In the Script Manager, **check the report for this client** (for example `mose_EURID.ps1`). Leave the others unchecked.

To install to another folder, add `-InstallPath`:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Ardaganbao/Mose/main/Start.ps1 -Headers @{ Authorization = "Bearer $env:GITHUB_TOKEN" }))) -InstallPath C:\Scripts\MOSE
```

## Run the report

```powershell
cd $HOME\Mose
.\Start.ps1              # update, then run the reports checked on this computer
.\Start.ps1 -Gui         # update, then open the Script Manager
.\Manager.ps1            # open the Script Manager without updating
.\Start.ps1 -UpdateOnly  # update only
.\Start.ps1 -SkipUpdate  # run without checking GitHub
```

- The report asks for the SecretStore vault password, then for any credential or API token not yet in the vault (first run only).
- From the Script Manager, each report opens in its own window to ask for these. Its output also appears at the bottom of the Script Manager.
- The report is saved next to the scripts as `<Client>_Report_<yyyy-MM-dd>.md` and opened in Notepad.
- If GitHub can't be reached, the local scripts run and a warning is shown.

## Replace an expired GitHub token

Fine-grained tokens expire. When one does, `Start.ps1` warns that the update check failed and keeps running the local scripts. Create a new token, then on each computer:

```powershell
.\Start.ps1 -SaveToken -UpdateOnly
```

## Change a report

Edit the script, commit and push to `main`. Every client computer picks up the change on its next run.

- **New check script** (collector): add its name to `Files` in `updater.config.json`.
- **New client**: copy `mose_clait.ps1` to `mose_<Client>.ps1`, change the secret names, user names and servers, and add it to both `Files` and `Scripts`.

Keep file names and the flat folder layout the same: the client reports find the check scripts next to them.

## Passwords and secrets

Never put passwords or tokens in a script. Each report stores its credentials in the local SecretStore vault (`SecretStore1`, `VBBSecretStore1` for VBB) the first time it runs. The vault belongs to the Windows user, not to this folder, so moving or reinstalling the folder keeps the secrets.

A pre-commit hook blocks commits that look like they contain a secret. Enable it once in every clone:

```powershell
git config core.hooksPath .githooks
```

## Move a computer from the zip to this repository

1. Install with the one-liner above, as the same Windows user as before. The vault and its secrets are reused.
2. Check the client's report in the Script Manager and run it once.
3. **EURID only:** register the Commvault token renewal again from the new folder, so the scheduled task points to it:

   ```powershell
   .\Renew-CommvaultToken.ps1 -Register
   ```

4. Delete the old folder (`C:\script` or `C:\scripts`) once the new report looks right.

## Notes

- `.gitattributes` keeps files byte-identical to GitHub, so the updater's hash check matches. Don't change it.
- If scripts are blocked from running: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
