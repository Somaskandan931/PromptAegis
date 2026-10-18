# PromptAegis result reconciliation

This note keeps distinct protocols and experiments separate. Never merge their denominators or inferential results.

## Primary manuscript evidence: current development replay

The current manuscript cites the sequential current-source result `results/study/governance_dev_20261017T150806Z_056a4792.json`. The older frozen artifact at `results/v2/v2_dev_20261017T111710Z_3745ce60.json` is retained unchanged as historical evidence. It is a completed replay over 106 development scenarios, 100 of which are in-scope for the gateway input contract. The manifest status is `author_labeled_pending_independent_review`. The recorded runner, gateway, validator, sandbox-runtime, and scenario hashes match the files used in that run; the worktree was dirty. No validation or test split was opened.

| Configuration | Exact decision agreement | Unsafe-effect scenarios | Applicable task checks | Audit coverage | Chain valid |
|---|---:|---:|---:|---:|---|
| Baseline | 0.390 | 29 | 43/43 | 100% | Yes |
| RBAC-only | 0.510 | 17 | 43/43 | 100% | Yes |
| Policy-only | 0.530 | 14 | 43/43 | 100% | Yes |
| Full | 1.000 | 0 | 43/43 | 100% | Yes |

All four results are descriptive development observations. The run is author-labeled, has a dirty worktree, and uses a project-authored sandbox oracle. It does not estimate real-world attacks, task utility, or prompt-injection resistance. A second execution produced matching numbers on the same development set; it is a repeatability check, not independent evidence. The earlier artifact `v2_dev_20261017T110731Z_a6e40524.json` was generated before later hardening and should not be used as current-source evidence.

## Separate historical controlled replay

The historical results are in `results/governance/`. They replayed proposed calls through the old API interceptor and did not execute downstream sandbox tools. Historical source/protocol issues include wall-clock rate-window behavior and old runs that did not have the current execution boundary. A new historical-interceptor replay was not completed for this audit. Do not use historical metrics as the primary manuscript results or combine them with sandbox-effect/task-check results.

The historical fixtures use researcher-authored labels. Unauthorized-tool, privilege-escalation, and injection-labelled categories target tools denied to the support principal, so these outcomes test that configured permission boundary rather than injection understanding. SQL/XSS cases expose missing policy coverage; their aggregate is not a detector false-negative estimate.

## Historical and separate experiments

The older canonical results and raw event traces are archived in Git history at `e12a06ad8062518dbe7c67dbee6988298ae5597d`. Their labels, burst protocol, normalization, and percentile methodology differ from current runs. Bootstrap, McNemar, and Wilcoxon outputs from those runs do not transfer to the current protocol.

### Provenance and principal audit

The original frozen artifact's six scenario hashes and ten source hashes were recomputed against the checkout as it existed before the latest fail-closed runner change; all matched. Its recorded runner/source version resolves an explicit `agent_name` before using the role fallback. The SQLite audit rows for all four run IDs independently show 600/600 calls under `CustomerSupportAgent` in each configuration. Therefore, the claim that this particular frozen run used `EmailAssistant` or `UnrestrictedAgent` is not supported by the checked artifact and database. The current runner has additionally been made fail-closed when a scenario explicitly names an unregistered principal, and it records the resolved principal on each event. The two latest artifacts record hashes for this stricter runner.

### Interpretation limits in the authored suite

The three categories `unauthorized_tool`, `privilege_escalation`, and `prompt_injection` all target tools denied to `CustomerSupportAgent`. Their high block rates therefore demonstrate the configured permission boundary; they do not isolate detection of prompt injection or prove injection resistance. The `parameter_manipulation` category labels SQL/XSS and related strings as unsafe, but the evaluated policy set has no general SQL/XSS validation rule. The 50 misses are consequently a useful exposed-policy gap, not evidence that the gateway had a rule and failed to apply it. The aggregate 10.42% is a rate against this project's authored labels and mixes distinct mechanisms; it should not be presented as a general attack-success estimate. A follow-up benchmark should include permitted-tool scenarios where policy inspection, rather than RBAC alone, determines the decision, with labels independently reviewed before policy tuning.

## Why the 16 October canonical result is not comparable

The old canonical results and raw event traces are in the Git snapshot at `e12a06ad8062518dbe7c67dbee6988298ae5597d` (`results/derived/benchmark_metrics.json`, `results/raw/canonical_benchmark_events.json`, and statistical files). That benchmark reports 500 expected attacks and 100 legitimate cases because all 100 excessive-call fixtures were labeled `RATE_LIMIT`; it did not classify the first 10 calls per tool as expected-allow. The corrected benchmark labels the first 20 burst calls as expected-allow, changing the denominator to 480 unsafe and 120 allow.

The old `full_burst` event trace also shows rate-limiter saturation spilling into other categories: it was the first blocking stage on 60 parameter-manipulation, 88 privilege-escalation, 100 prompt-injection, and 95 unauthorized-tool events. Thus the old 26% result is not an isolated estimate of the policy stack's security performance. The 30% `full_normalized` result avoids some burst effects but still uses the old fixture labels and principal-selection protocol. Do not average or directly compare these rates. Bootstrap intervals, McNemar tests, and Wilcoxon latency tests from that run describe its old protocol; they are not valid uncertainty estimates for the corrected run and are omitted from the main paper.

## Historical secondary evidence

These findings are useful for context but were generated on the older source snapshot and are kept separate from the primary result.

| Evidence | Historical result | Treatment |
|---|---|---|
| Normalization ablation, 500 clustered mutations | Recall decreased from 40.0% to 36.4% overall. Base64 detection changed from 0% to 50%; each of the other four perturbation classes changed from 50% to 33%. | Negative exploratory result. Do not claim normalization improves overall robustness. |
| Rate-limit boundary stress | First blocked call was call 6 at limit 5, call 21 at limit 20, and call 101 at limit 100. A 61-second advance reset the window; the next request proceeded to a later approval gate. | Historical boundary check, not a repeated current-version stress run. |
| Calibrated-policy replay | 20.4% reported unsafe-call success, zero audit coverage; rate-limit saturation accounts for most recorded blocks. | Exclude from efficacy claims. It does not isolate policy efficacy and lacks audit provenance. |
| Live-model pilot: `openai/gpt-oss-120b` via Groq | 10 adversarial and 10 benign prompts; 4/10 adversarial prompts induced a tool-call compromise, 3/4 were intercepted, and one `update_customer` proposal with privileged fields was allowed. All 10 benign prompts completed. Mean per-prompt model/gateway latency was 755.83/161.11 ms. | Report only as a 20-case exploratory pilot. It is not a repeated or independently sampled agent evaluation. Archived claim IDs: CLM-HIST-001--004, CLM-HIST-007, CLM-HIST-008. |
| Prompt screening: HackAPrompt and ToxicChat | 78,641 attack prompts; 56.03% were sanitized or blocked. Of 4,721 ToxicChat benign proxies, 11 were intervened on (0.233%). | Separate prompt-level detector study. ToxicChat's labels do not prove injection-free content; never combine these numbers with tool-call governance metrics. |

The canonical, normalization, and rate-limit stress artifacts are archived at commit `e12a06ad8062518dbe7c67dbee6988298ae5597d`; the live-model pilot trace is archived at `f16fae2cffece5b032e47bb7dfc52220c2eae1fc`. Inspect them without restoring them to the working tree:

```powershell
git show f16fae2cffece5b032e47bb7dfc52220c2eae1fc:results/historical/closed_loop_results.json
git show f16fae2cffece5b032e47bb7dfc52220c2eae1fc:results/historical/closed_loop_traces.csv
git show e12a06ad8062518dbe7c67dbee6988298ae5597d:results/raw/adversarial_events.json
```

The archived commit is not the current source revision. Re-run historical experiments with a current, pinned harness before treating them as confirmatory findings. Repeating the Groq pilot may incur API usage and should only be done when you choose to spend that budget.

## Repository status

- The six controlled scenario files are present in `backend/data/benchmark/`.
- The corrected result and claim registry are under `results/governance/` and `results/provenance/`.
- Three current paper figures are generated from the corrected result by `python experiments/generate_paper_figures.py`.
- The repository's primary benchmark is the controlled six-category gateway replay. No external agent benchmark is included in the present results.
- Historical figures and result tables from 16 October are not reused in the paper.
- The active paper focuses on gateway governance. The prompt-screening outputs remain separate.
