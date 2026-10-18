# Reproduction check of the canonical development run

Canonical run: `results/study/governance_dev_20261018T081010Z_9e7d0639.json` (12 configurations, 106 scenarios,
100 in scope). It was produced by `python experiments/run_research.py benchmark --split dev --all-configs` from Git
revision `909a5b128b6f91826d3f68a684c07d4968f6c9c3` and records `git_worktree_dirty: false`. The dirty check excludes
the `results/` output directory, because the runner writes its own audit chains there. Its recorded scenario,
manifest, runner, gateway, validator and sandbox-runtime hashes equal the files at that revision.

Earlier runs are kept as history only: `governance_dev_20261017T150806Z_056a4792` (four configurations, earlier
gateway, validator and runner files; used as the "original run" in the latency comparison), the twelve-configuration
runs `governance_dev_20261017T182314Z_2a97d190` and `governance_dev_20261018T072638Z_13a891ae`, whose recorded revisions
do not give a clean-worktree freeze.

## Consistency across executions

| Comparison | Result |
|---|---|
| Headline counts of the canonical run versus the two earlier twelve-configuration runs (agreement, unsafe-effect scenarios, task checks, audit coverage) | identical |
| Earlier Linux re-execution (Python 3.12.3, one CPU) versus the earlier Windows run: scenario-by-configuration pairs compared | 1,272 (106 scenarios x 12 configurations) |
| Pairs whose per-call decisions, unsafe-effect flags, effect types, state-change flag, task result or first-blocking stage differed | 0 |

The pair-by-pair comparison was made between the earlier Windows run and the Linux re-execution. The canonical run
was checked against those runs at the level of headline counts and decisions summarised in the analysis file.

## What this does not establish

* The re-execution's per-call latencies were not kept and are not evidence about overhead. Latency stays exploratory.
* A reproduction by the same authors on the same labels is not independent validation of the labels or the oracle.
* No held-out run has been made; all evidence is development-split and author-labelled.