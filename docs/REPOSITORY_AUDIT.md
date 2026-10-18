# PromptAegis repository audit

Audit date: 17 October 2026. This describes the checkout and the evidence available in it; it is not a security certification.

## Project map

| Path | Purpose |
|---|---|
| `backend/app.py`, `backend/api/` | FastAPI app, authentication, governance, experiment, and environment APIs. |
| `backend/governance/` | API interceptor and the canonical research gateway, including validation, risk and rate controls, and audit-chain support. |
| `backend/database/` | SQLite schema/queries and environment/credential registries. Runtime databases and credential files must remain local. |
| `backend/sandbox/` | in-memory business world, protected tool runtime, and scripted proposal agent. |
| `frontend/` | React/Vite dashboard and experiment UI; built assets may be generated under `dist/`. |
| `experiments/` | Historical gateway replay; prompt-corpus, controlled sandbox benchmark, dataset generator, and statistics helpers. |
| `backend/data/benchmark/` | historical controlled scenario fixtures. |
| `backend/data/governance_benchmark/` | project-authored scenarios, split manifest, and dataset card. Validation/test are locked pending independent review. |
| `backend/data/external/`, `data/` | downloaded/external data and project data; inspect licences and avoid committing large raw datasets. |
| `results/` | Raw, derived, statistical, governance, external, and sandbox-study outputs. Outputs are evidence and should be retained with provenance, not confused across experiments. |
| `paper/` | LaTeX manuscripts, bibliography, figures, and Overleaf instructions. |
| `docs/` | PRD traceability, experiment reconciliation, threat model, protocol, limitations, and readiness notes. |
| `tests/` | API environment/security checks, provenance checks, frontend contract checks, and sandboxed gateway/sandbox tests. |

## Runtime and enforcement boundary

The backend is Python/FastAPI with SQLite; the UI is React/Vite. The application API/adapter calls a dictionary-returning compatibility façade in `governance.interceptor`; that façade delegates to the same `governance.gateway.Gateway` used directly by the canonical research runner. Historical replay code imports `governance.legacy_interceptor` explicitly. The gateway checks request identity and tool registration, then enabled RBAC, schema, policy, rate, and approval stages. `ProtectedRuntime` calls sandbox tools only after an allowed result or a correctly bound one-time approval. The sandbox is an in-memory test world, not operating-system isolation. Calls made outside the adapter are not mediated.

Audit events are written to SQLite and, in sandboxed experiments, to a local hash-chained JSONL file. Gateway exceptions and audit failures fail closed. A chain append failure after the SQLite write attempts to correct the database outcome to `DENY`; if both writes fail, the caller still receives denial but durable audit completeness cannot be guaranteed. Hash chaining is not externally anchored and does not prevent an actor with full filesystem control from rewriting the whole chain.

Approval identity is a harness allowlist in the current research runtime, not a production identity provider. The connected-application key must be supplied through an environment variable with at least 32 characters; the retired deterministic live-looking demo key is denied. Test credentials require explicit `PROMPTAEGIS_ALLOW_TEST_CREDENTIALS=1`. Never set that opt-in in a deployed environment. Rotate any real secret that was ever committed or shared.

## Experiments and evidence

### historical controlled replay

`experiments/run_governance_benchmark.py` replays historical project-authored fixtures through the API interceptor. It uses no LLM and does not execute downstream tools. Historical results include source-hash mismatches, dirty worktree state, wall-clock dependent burst behavior, and a principal-selection bug. A fixed virtual clock, strict agent mapping, missing-scenario failure, and interpolated latency percentiles have since been added. That historical runner is not part of the supported research workflow; its percentages must not be presented as current primary evidence.

### sandboxed replay

`experiments/run_research.py benchmark --split dev` dispatches to `experiments/study/run_benchmark.py`, which executes scripted proposals against a fresh local database and sandbox. It reports decision-label agreement, task checks, observed unsafe side effects, audit coverage, and chain validity separately. The current-source sequential development result is `results/study/governance_dev_20261017T150806Z_056a4792.json`; its recorded runner, gateway, validator, sandbox-runtime, and scenario SHA-256 values match the files used for that run. The worktree was dirty. It reports 106 scenarios, 100 in scope; the full configuration had zero oracle-detected unsafe-effect scenarios and all configurations passed 43 applicable author-authored task checks. The labels and oracle await independent review, so these are development observations only. No validation or test split was run. Prompt-corpus runs are a separate detector experiment. AgentDojo is retired from the supported workflow; see `docs/EXTERNAL_DATA_EVALUATION.md` for the proposed InjecAgent adapter.

## Code and research gaps

1. Obtain independent review of the current study labels and task checks; freeze the reviewed dataset hash.
2. Validate the protocol on the validation split, resolve defects on a new version, then run the test split once.
3. Implement and validate a closed-loop adapter for an external tool-agent benchmark so untrusted content reaches an actual model and its tool calls pass through PromptAegis. Scripted proposals alone do not test prompt injection.
4. Add coverage for authenticated human approval, bypass paths, concurrency, audit-store outages, and tool failures before any deployment claim.
5. Measure latency on a controlled machine with repeated runs and a separately measured persistence baseline; current local timings include SQLite/audit costs.
6. Record a clean Git revision and clean-clone instructions for final evidence. Do not edit frozen result JSON by hand.

## Test status

An earlier full-suite run reported 53 passed and two FastAPI `on_event` deprecation warnings. After the current consolidation, the focused gateway suite reports 11 passed and Python compilation succeeds. The API environment integration suite stalled during startup at its first test in this shell and needs a separate rerun. LaTeX compiled before the latest result-path edit and should be recompiled. These checks do not validate benchmark labels or demonstrate production security.

## Manuscripts and preserved materials

The new main manuscript is `paper/PromptAegis_Governance_Study.tex`. Preserve `paper/references.bib`, figures, datasets, outputs, and protocol documents as supporting evidence. Once the new paper compiles and is checked, remove superseded `.tex` drafts only; do not remove benchmark or result files as part of manuscript cleanup.
