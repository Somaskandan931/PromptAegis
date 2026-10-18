# Moves superseded and invalid result artifacts out of results\ into results_archive\ (nothing is deleted).
# Run from the project root (the folder that contains "results"):
#   .\cleanup_results.ps1 -DryRun     # show what would move
#   .\cleanup_results.ps1             # do it
param([switch]$DryRun)
$ErrorActionPreference = "Stop"
$root = Get-Location
if (-not (Test-Path "$root\results\study")) { throw "Run this from the project root: results\study not found." }
$arch = "$root\results_archive"
if (-not $DryRun) { New-Item -ItemType Directory -Force -Path $arch | Out-Null }

function Move-ToArchive($relPath) {
    $src = Join-Path $root $relPath
    if (-not (Test-Path $src)) { return }
    $dst = Join-Path $arch $relPath
    Write-Host ("MOVE  " + $relPath)
    if ($DryRun) { return }
    New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
    Move-Item -Path $src -Destination $dst -Force
}

# 1. Superseded benchmark generations (older protocols and commits)
foreach ($d in "governance","raw","derived","statistical","v2","historical","adversarial_runs") {
    Move-ToArchive "results\$d"
}
# 2. AgentDojo traces (removed from the project)
Move-ToArchive "results\external\agentdojo_traces"

# 3. Invalid study runs listed in results\study\CONTAMINATED_RUNS.md, with their audit chains
$bad = "governance_dev_20261017T150138Z_1881b9e2","governance_dev_20261017T150220Z_f1b1d695",
       "llm_20261017T160401Z_cb0698be","llm_20261017T160819Z_412f4a36"
foreach ($id in $bad) {
    Get-ChildItem "results\study" -Filter "$id*" -ErrorAction SilentlyContinue | ForEach-Object { Move-ToArchive ("results\study\" + $_.Name) }
    Get-ChildItem "results\study\audit" -Filter "$id*" -ErrorAction SilentlyContinue | ForEach-Object { Move-ToArchive ("results\study\audit\" + $_.Name) }
}

Write-Host ""
Write-Host "Kept in place: results\study, results\review, results\provenance, results\external\prompt_corpora_*"
Write-Host "Not touched (status unclear, check by hand): governance_dev_20261017T150603Z_53f7e2ca*, llm_20261017T171832Z_804a0a30.json"
if ($DryRun) { Write-Host "Dry run only: nothing was moved." }
