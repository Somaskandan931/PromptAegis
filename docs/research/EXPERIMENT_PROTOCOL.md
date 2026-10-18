# PromptAegis experiment protocol

## Status

The current governance study is a research-development protocol, not a completed external benchmark. Its scenarios and expected labels are project-authored. An independent review record does not yet exist. The test and validation splits are therefore locked by the runner. Run only `dev` or `tune` while implementing the system; do not cite those scores as held-out performance.

## Design

- Scenarios are grouped by both `group_id` and `gateway_key`; all rows sharing either key must remain in one split.
- Split assignments are generated with a fixed seed and recorded in `backend/data/governance_benchmark/manifest.json`.
- `dev` is for debugging; `tune` is for changes to policy/contracts. Validation and test stay unopened until at least two independent reviewers have reviewed labels and a review record is bound to the exact scenario SHA-256.
- The runner creates a fresh isolated SQLite database and in-memory business world. It uses scripted calls only, a deterministic virtual clock and no network or model API.
- Rate-limit scenarios reset counters between scenarios, but preserve the call sequence and explicit clock advance within each scenario.
- `scope=out_of_scope_requires_provenance` cases are preserved in outputs but excluded from in-scope aggregate metrics because the gateway does not receive provenance.
- Exact decision agreement, task-check outcomes, observed unsafe side effects, state changes and audit coverage are separate measures. A pending approval is not a denial; an approval retry is recorded separately.

## Development command

```powershell
conda activate base
python experiments\run_research.py benchmark --split dev
```

Use `--config full` or repeat `--config` to run a selected configuration. Outputs are written under `results/study/`; each configuration has a hash-chained JSONL audit file. The script refuses validation/test execution until a review record matches the manifest's scenario hash and records at least two independent reviewers.

## Freeze and confirmatory runs

Before validation/test, freeze the scenario file, generator, policy-contract version, gateway, sandbox, runner, runtime, and exact environment. Obtain independent labels and add `backend/data/governance_benchmark/independent_review.json` with:

```json
{
  "scenarios_sha256": "<exact scenarios.json SHA-256>",
  "independent_reviewer_count": 2,
  "labels_status": "independently_reviewed",
  "review_protocol": "<short description of blinded review and adjudication>"
}
```

Run validation first to catch protocol or execution defects. Any subsequent policy/dataset changes invalidate the old validation and require a new version. Run test once after the frozen protocol passes validation. Store the exact git revision, clean/dirty state, source hashes, dataset hashes, runtime version, configuration list and result outputs. Do not use a holdout to tune the detector or contracts.

## Interpretation limits

The scripted agent replays a proposed action and does not model how an LLM interpreted a prompt or tool output. The prompt-injection-labelled cases cannot establish resistance to prompt injection unless an agent produces those calls in a controlled closed-loop experiment. The sandbox and outcome oracle are project-authored; independent review reduces but does not eliminate shared-author bias. The approval approver is simulated, not an authenticated human workflow.
