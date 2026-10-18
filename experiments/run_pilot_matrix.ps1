<#
.SYNOPSIS
  Run the closed-loop LLM pilot for every gateway configuration (and optionally several models),
  strictly one after another, then build the paper tables from the results.

.NOTES
  Runs MUST NOT overlap: they share one local SQLite environment (see results/study/CONTAMINATED_RUNS.md).
  This script waits for each run to finish before starting the next.
  The FIRST run (first model, first configuration) is the primary run used for the paper's numbers,
  so keep 'full' first in -Configurations.

.EXAMPLE
  .\experiments\run_pilot_matrix.ps1
  .\experiments\run_pilot_matrix.ps1 -Models "llama3.1:8b","qwen2.5:7b"
#>
param(
    [string[]]$Models = @("llama3.1:8b"),
    [string[]]$Configurations = @("full", "baseline", "rbac_only", "policy_only"),
    [string]$Manifest = "backend\data\governance_benchmark\llm_pilot_tasks.jsonl",
    [string]$Provider = "ollama"
)

# Do not turn native-command stderr output into terminating errors; exit codes are checked below.
$ErrorActionPreference = "Continue"
Set-Location (Join-Path $PSScriptRoot "..")

$runs = @()
foreach ($model in $Models) {
    foreach ($config in $Configurations) {
        Write-Host ""
        Write-Host "=== model=$model configuration=$config ===" -ForegroundColor Cyan
        $log = python experiments\run_research.py llm $Manifest --provider $Provider --model $model --configuration $config 2>&1 |
            Tee-Object -Variable captured
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Run failed (exit code $LASTEXITCODE). Stopping so no later run is started on a bad state." -ForegroundColor Red
            exit $LASTEXITCODE
        }
        $m = [regex]::Match(($captured | Out-String), '\[OK\] wrote (\S+\.json)')
        if (-not $m.Success) {
            Write-Host "Could not find the result path in the runner output. Stopping." -ForegroundColor Red
            exit 1
        }
        $runs += $m.Groups[1].Value
    }
}

Write-Host ""
Write-Host "=== building paper tables from $($runs.Count) run(s) ===" -ForegroundColor Cyan
python experiments\study\summarize_llm_pilot.py @runs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host ""
Write-Host "Done. Upload paper\generated\ together with the .tex file." -ForegroundColor Green
