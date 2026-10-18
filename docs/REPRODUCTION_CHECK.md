# Reproduction check of the canonical development run

Canonical run: `results/study/governance_dev_20261017T182314Z_2a97d190.json` (12 configurations, 106 scenarios,
100 in scope). It is the only stored run whose recorded gateway, validator, sandbox, scenario and manifest hashes all
equal the files in this tree at the time of the check. The older four-configuration run
`governance_dev_20261017T150806Z_056a4792` was produced from earlier gateway, validator and runner files and is kept
only as the "original run" in the latency comparison.

## What was re-executed

`python experiments/run_research.py benchmark --split dev --all-configs` on an unpacked copy of the repository
(Python 3.12.3, Linux x86-64, one CPU; the original run was made on Windows). Source hashes of the gateway,
validator, sandbox runtime, scenario file and manifest were identical to the canonical run.

| Comparison | Result |
|---|---|
| Scenario-by-configuration pairs compared | 1,272 (106 scenarios x 12 configurations) |
| Pairs whose per-call decisions differed | 0 |
| Pairs whose unsafe-effect flags, effect types, state-change flag or task result differed | 0 |
| First-blocking-stage sequence, all 12 configurations | identical |
| Headline counts (agreement, unsafe-effect scenarios, task checks, audit coverage) | identical to README and manuscript |

## One edit after the canonical run

`experiments/study/run_benchmark.py` changed after the canonical run, so its recorded `runner_sha256` no longer
matches. The edit added a `--all-configs` flag (previously the default ran only four configurations and the
twelve-configuration run needed `--config` repeated twelve times), a create-exclusive lock that refuses to start
while another benchmark is active, and an `environment` and `configuration_order` record in the output. The
evaluation loop, scenario handling, metrics and hashing were not touched. The re-execution above used the edited runner.

## What this does not establish

* No Git revision was recorded for the canonical run (`git_revision` is `null`) and the re-execution had no Git
  metadata either. Freezing still requires committing the tree and re-running from a clean checkout, then citing that
  run. After that, run `python experiments/run_research.py registry ...` to rebuild the claim registry.
* The re-execution's per-call latencies were not kept and are not evidence about overhead. Latency stays exploratory.
* A reproduction by the same authors on the same labels is not independent validation of the labels or the oracle.
