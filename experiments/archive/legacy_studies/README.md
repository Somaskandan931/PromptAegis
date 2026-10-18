# Historical experiment scripts

These scripts are retained to explain or reproduce older result streams. They are not part of the supported run path. They may use the preserved `governance.legacy_interceptor` and historical fixtures; do not combine their outputs with the canonical sandbox study.

Use `python experiments/run_research.py ...` for supported commands.

## 600-scenario controlled benchmark (superseded)

`run_governance_benchmark.py`, `build_claim_registry.py` and `generate_paper_figures.py` belong to the earlier
600-scenario benchmark (`backend/data/benchmark/*.json`, results under `results/governance/`, registry version 2.0).
That stream is not the evidence base for the manuscript, which reports the 106-scenario development split
(`backend/data/governance_benchmark/`). The scenario files remain because the web UI's experiment page still
loads them; they are not research evidence for the paper. The earlier registry is kept in
`results/provenance/legacy/`.
