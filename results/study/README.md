# Governance study outputs

New canonical benchmark runs and their generated analyses are stored here. Each raw JSON result must remain beside its `audit/` JSONL files. Use the exact result path printed by the runner when analyzing; do not select a file based only on modification time.

The `governance_dev_20261017T182314Z_2a97d190` run is the **canonical** twelve-configuration development run. It is the only stored run whose recorded gateway, validator, sandbox, scenario and manifest hashes match the source in the repository, and it is the file behind every table and figure in the manuscript and README (a byte-identical copy sits at `paper/results/ablation_run.json`). It is descriptive evidence from project-authored labels and a project-authored sandbox oracle, it is not a held-out evaluation, and no Git revision was recorded for it. See `docs/REPRODUCTION_CHECK.md`.

The `governance_dev_20261017T150806Z_056a4792` run (four configurations) was produced from earlier gateway, validator and runner files. It is kept only as the "original run" in the exploratory latency comparison; do not take decision or effect counts from it. `governance_dev_20261017T150603Z_53f7e2ca` (one configuration) is likewise superseded.

The `llm_20261017T171952Z_9c41232a` run is the valid exploratory closed-loop pilot (Ollama `llama3.1:8b`, full configuration). Earlier `llm_` runs recorded model refusals as gateway denials and are excluded.

`CONTAMINATED_RUNS.md` identifies outputs that must be excluded (overlapping processes sharing the same local database, or the pre-fix pilot harness). The files are retained for the execution record.
