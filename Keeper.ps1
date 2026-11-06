[CmdletBinding()]
param(
    # Import entries into Keeper, or export them from it. Asked when not given.
    [ValidateSet('Import', 'Export')]
    [string]$Action
)

# Imports entries into Keeper, or exports them from it, over the Keeper API. Independent of the
# report: .\Start.ps1 -Keeper, or Keeper import/export in the Script Manager.
# An export holds passwords: write it as Keeper_Export_*, which git ignores.

$ErrorActionPreference = 'Stop'

if (-not $Action) {
    $answer = "$(Read-Host -Prompt 'Import entries into Keeper or export them from it? (I/E)')".Trim()
    if ($answer -match '^i') {
        $Action = 'Import'
    }
    elseif ($answer -match '^e') {
        $Action = 'Export'
    }
    else {
        throw 'Answer I to import or E to export.'
    }
}

switch ($Action) {
    'Import' {
        Write-Warning 'The Keeper import is not written yet.'
    }
    'Export' {
        Write-Warning 'The Keeper export is not written yet.'
    }
}
