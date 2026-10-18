# Runs to exclude from analysis

On 17 October 2026, two development benchmark commands were started before the first had completed. They share the benchmark SQLite environment and their JSONL audit events overlap in time. One process was interrupted; the other completed. Neither output is valid for paper metrics.

Exclude these run IDs and all their associated audit chains:

- `governance_dev_20261017T150138Z_1881b9e2`
- `governance_dev_20261017T150220Z_f1b1d695` (interrupted)

The files are retained to preserve the execution record. Do not analyze them or cite them. Run the benchmark again only after confirming no other benchmark process is active, and wait for the runner's `[OK]` line before starting any next run.

## LLM pilot runs with misattributed denials

The following `llm` pilot runs (`llama3.1:8b`, `full`) recorded unparseable model replies as empty tool calls and sent them to the gateway, where they were logged as `DENY` / `INVALID_REQUEST`. In both runs 5 of the 6 attack tasks were affected, so `decision_counts` overstates governance blocking. The model's raw replies were not saved, so the cause (refusal versus a different JSON shape) cannot be recovered from these files.

- `llm_20261017T160401Z_cb0698be`
- `llm_20261017T160819Z_412f4a36`

Do not cite either run. Re-run the pilot with the fixed runner, which records `agent_outcome`, `agent_error` and `raw_model_output` per task and does not send agent failures to the gateway.
