# PromptAegis status — 17 October 2026

## Current implementation

- Layered gateway, argument contract validator, deterministic virtual clock, isolated SQLite experiment environment, in-memory sandbox, and scripted scenario adapter are implemented.
- Approval retries are one-time and bound to an allowlisted approver plus the exact agent, tool, and arguments. The allowlist is a test-harness mechanism, not authenticated human identity.
- Gateway and pre-execution audit failures fail closed. A database decision is corrected to `DENY` if the subsequent hash-chain append fails, when that corrective write succeeds.
- Hash-chain startup verifies existing entries and rejects an invalid chain. This is local tamper evidence, not external anchoring.
- Validation/test splits remain locked until independent review has been completed and bound to the current scenario hash.

## Evidence

The current-source sequential development artifact is `results/study/governance_dev_20261017T150806Z_056a4792.json`; recorded runner, gateway, validator, sandbox-runtime, and dataset hashes match the files used for that run, while the Git worktree was dirty. It reports 106 scenarios (100 in scope), with 43 applicable task checks. The full configuration recorded zero oracle-detected unsafe-effect scenarios; all configurations passed the 43 authored task checks and had complete audit coverage with valid local chains. These are descriptive development results only. A second run produced the same values on this same development set; do not pool repeated executions or treat them as independent evidence. No validation or test split was opened. No model API or external tool is part of the runner.

A separate Ollama `llama3.1:8b` pilot (`results/study/llm_20261017T171952Z_9c41232a.json`) ran 12 project-authored prompts through the sandbox and full gateway. The model proposed a tool call for all six benign prompts (all allowed) and declined five of six injected tasks with a prose refusal before any tool call; the sixth produced one structured proposal that the gateway denied. Refusals are recorded as agent outcomes and are not sent to the gateway. Task-check, unsafe-effect and latency counts are produced by `experiments/study/summarize_llm_pilot.py`. This is not evidence that the gateway stopped valid attacks; the pilot is exploratory, not independently reviewed, and not confirmatory. Two earlier runs recorded refusals as gateway denials and are excluded (`results/study/CONTAMINATED_RUNS.md`).

## Verification

The earlier full-suite record was 53 passed with two FastAPI deprecation warnings. After the current consolidation, the focused gateway suite passes (11 tests), and Python compilation passes. The API environment integration suite did not complete in this shell: it stalled during app startup at its first test, before reaching the gateway adapter. The updated manuscript compiled with the desktop editor's compiler. These checks do not validate benchmark labels or establish production security.

## Required research work

1. Have two independent reviewers assess expected decisions and task checks using a documented blinded procedure; adjudicate disagreements.
2. Freeze the reviewed scenario hash, code revision, policies, contracts, environment, and metrics.
3. Run validation; resolve implementation/protocol defects on a new version.
4. Run test once after freeze. Do not tune on test results.
5. Expand the closed-loop LLM pilot with independently reviewed natural-language tasks and valid malicious tool proposals; report task completion, model output validity, and unsafe effects separately.
6. Verify clean-clone reproduction and record all source hashes, audit chains, and environment versions.
