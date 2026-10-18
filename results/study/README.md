# Governance study outputs

New canonical benchmark runs and their generated analyses are stored here. Each raw JSON result must remain beside its `audit/` JSONL files. Use the exact result path printed by the runner when analyzing; do not select a file based only on modification time.

The `governance_dev_20261017T150806Z_056a4792` run is the sequential current-source four-configuration development replay cited by the current manuscript. It is descriptive evidence from project-authored labels and a project-authored sandbox oracle; the Git worktree was dirty. It is not a held-out evaluation.

The `llm_20261017T171952Z_9c41232a` run is the valid exploratory closed-loop pilot (Ollama `llama3.1:8b`, full configuration). Earlier `llm_` runs recorded model refusals as gateway denials and are excluded.

`CONTAMINATED_RUNS.md` identifies outputs that must be excluded (overlapping processes sharing the same local database, or the pre-fix pilot harness). The files are retained for the execution record.
