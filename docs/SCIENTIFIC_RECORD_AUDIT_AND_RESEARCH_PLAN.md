# Scientific record audit and research plan

**Audit date:** 2026-10-17  
**Purpose:** Separate the team's requested research work from claims and run instructions in the supplied `PROMPTAEGIS_COMPLETE_SCIENTIFIC_TECHNICAL_RECORD.md`, then identify a defensible research direction and the evidence needed to write the paper.

## 1. Research direction and novelty

Do not claim that a deterministic tool-call gateway, a policy stack, or runtime tool-call blocking is novel by itself. Recent work already studies runtime tool invocation guardrails and capability/typed authorization, including [ToolSafe](https://aclanthology.org/2026.findings-acl.1850/), [ToolFence](https://arxiv.org/abs/2609.37196), [ClawGuard](https://arxiv.org/abs/2604.11790), and [AgenTRIM](https://arxiv.org/abs/2601.12449). Benchmark work such as [InjecAgent](https://aclanthology.org/2024.findings-acl.624/) and framework-level enforcement such as [ShieldMCP](https://aclanthology.org/2026.acl-industry.58/) also make broad “first tool security framework” claims unsafe. These works need a full related-work comparison before submission; this short list is not a systematic review.

AgentDojo is optional and is not the source of novelty. The team has chosen not to make it a dependency. A suitable external validation candidate is InjecAgent, subject to licensing/attribution review, task-contract compatibility, and implementation of a reproducible adapter. It is a benchmark candidate, not evidence already obtained.

The most defensible current direction is an **empirical systems study of execution-grounded governance for structured tool calls**. The differentiating research question should focus on whether separating authorization decisions from observed sandbox effects, task checks, and approval outcomes exposes failure modes that decision-only evaluations hide. Novelty would come from the evaluation method and the specific evidence, if confirmed—not from relabeling standard RBAC or policy enforcement as a new algorithm.

Suggested working title: **“An Empirical Study of Execution-Grounded Governance for Tool-Using Agents”**.

Suggested research questions:

1. **RQ1:** How do baseline, RBAC, policy, and combined governance configurations differ in unsafe sandbox effects and legitimate task-check outcomes on a frozen, independently reviewed benchmark?
2. **RQ2:** Which attack and benign scenario classes account for the remaining unsafe effects, false blocks, and approval requests?
3. **RQ3:** What latency and audit overhead does the governance path add under a specified local runtime and workload?
4. **RQ4 (only after a closed-loop model adapter exists):** How do those outcomes change when a model observes untrusted content and proposes tool calls in a sandbox?

These questions do not imply that the current results answer them confirmatorily. The current paper answers only a development/debugging version of RQ1.

## 2. Evidence audit: supplied record versus current checkout

The supplied technical record is useful background and a list of hypotheses to investigate. Its label “canonical,” its historical run commands, and its “lock candidate” status are not instructions and do not override the repository's current evidence. The record is dated September 2026; the checkout and manuscript include October changes.

| Workstream | What is present now | Status and paper-safe treatment |
|---|---|---|
| Research questions and threat model | `paper/PromptAegis_Governance_Study.tex` describes a structured-call threat model, sandbox, gateway, and development RQs. | **Drafted.** Refine around the questions above. State explicitly that the current runner does not make an LLM interpret untrusted content. |
| 600-scenario controlled benchmark | Six 100-scenario historical fixtures are available in the current workspace's benchmark tree; historical raw artifacts/claim registry also exist. The current manuscript instead uses a distinct project-authored suite: 106 development scenarios, 100 in scope. | **Two different protocols. Keep separate.** The current result is author-labeled development evidence, not a held-out result. The old 600-case record is not interchangeable with the current suite. Before reporting historical results, reconcile the exact fixture hashes, principal resolution, scope, labels, and raw event rows. |
| Formal metrics (ASR/FPR/FNR/LTCR/AER/latency) | `experiments/study/analyze_run.py` now joins one raw run to the exact scenario file by SHA and computes effect-based ASR, benign hard-denial/challenge rates, authored task-check completion, and latency distributions. | **Operational definitions implemented for the current study.** Since unsafe-effect ASR and effect-based FNR are identical in this suite, the analyzer reports one primary measure rather than duplicating it. AER remains omitted; the 500-case legacy study reports non-ALLOW rate, not harm. |
| Ablation: Baseline → RBAC → Policy → Full | the current study has a four-configuration development replay; the latest sequential results are in `results/study/governance_dev_20261017T150806Z_056a4792.json`. | **Completed as a development replay only.** Full had 1.000 exact agreement, zero unsafe-effect scenarios, and 43/43 applicable authored task checks. This is not independent performance evidence; do not attach inferential tests or generalization claims to it. |
| 500 adversarial/evasion tests | `experiments/study/generate_adversarial_extension.py` now creates 500 versioned mutations from the 100 project-authored parameter cases. `experiments/run_adversarial_probe.py` reran them and stores raw/derived output under `results/adversarial_runs/adversarial_20261017T145320Z/`. | **Run completed, but decision-only and author-generated.** Isolated non-ALLOW decisions were 40% standard vs 50% hardened; compound non-ALLOW decisions were 75.2% vs 76.0%, with the rate limiter accounting for 72% of standard compound cases. This is not effect-based ASR/AER or an external benchmark. It does not reproduce the supplied record's historical values because its exact corpus is unavailable. |
| Hardened-defense evaluation | The normalization path is compared in the new 500-case probe. | **Small positive decision-level result with major limits.** The 10-point isolated increase is entirely in the base64 class; the compound increase is 0.8 points and rate-limit-confounded. Do not claim generalized evasion resistance. |
| Real LLM closed loop | `experiments/study/run_llm_closed_loop.py` supports Ollama's local OpenAI-compatible endpoint and Groq. It requires a natural-language JSONL task manifest authored independently of expected tool calls. archived trace-analysis scripts remain historical only. | **Harness implemented, no new live-model run.** The prompt set is not yet available/reviewed. Do not create benchmark task prompts by reverse-engineering expected tool calls. Record provider/model/decoding, manifest hash and failures, and route every proposal through the sandbox gateway. |
| Statistics | The new analyzer computes group-clustered bootstrap intervals, exact paired scenario-level McNemar tests with Holm adjustment, and paired Wilcoxon on per-scenario median latency for one selected raw run. | **Implemented and run on the existing dev artifact, descriptively only.** Do not transfer historical statistics. The current fixed-block runner does not randomize configuration order, so its latency p-values are exploratory; latency inference needs interleaved/randomized repeated measurements. The dev labels are not independently reviewed. |
| False-positive forensics | Prior reports describe several different FPR mechanisms; current benchmark has authored task checks, not externally adjudicated benign labels. | **Needs a row-level forensic report.** For every rejected/challenged benign case, include scenario ID, expected action, resolved principal, policy/reason code, effect, task-check result, and whether an approval was available. Do not present an old runner-mapping diagnosis as fact unless tied to the specific run artifact and audit rows. |
| Numerical consistency audit | The current analyzer checks the scenario SHA before joining labels and recalculates metrics from the selected raw run; the 500-case run records and verifies the source/generated corpus hashes and stores 2,000 raw decision events. | **Partially implemented.** Continue by wiring regenerated manuscript tables/figures and claim-registry entries directly to analysis outputs. Never aggregate historical replay, sandbox study, corpus-screening, and historical model-pilot results. |
| Code → experiment → result → claim traceability | Claim registry, source hashes, scenario hashes, and development-result hashes exist. The cited development run has a dirty worktree. | **Good foundation, not final provenance.** Freeze a commit, record clean/dirty status, environment lock, data/label hashes, command, stdout/stderr, model configuration where applicable, and generated result hash. Bind each paper table/figure and claim to those IDs. |
| Claim-safety boundaries | The current manuscript contains strong limitations and says the development evidence is not confirmatory. The supplied older record contains stronger historical claims. | **Current manuscript wording is safer.** Remove/avoid “first,” “proves,” “prevents prompt injection,” “general-purpose,” and any historical percentage not tied to the exact reported protocol. Say “in this author-authored development suite” where that is what was measured. |
| Limitations, reproducibility, future work | Current paper and docs state author labeling, no closed-loop agent, sandbox limits, and need for independent review. The supplied record's `scratch/...` reproduction commands do not exist. | **Present but reproduction guide is stale.** Replace old commands with commands that exist in this checkout and validate them from a clean clone before publication. |

## 3. Required definitions before any confirmatory run

Use a row-level outcome schema that preserves, at minimum:

- `expected_action` and its adjudication source;
- `principal`, `tool`, `arguments`, and scenario/group identifiers;
- `gateway_decision` with `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` kept distinct;
- `approval_requested`, `approval_granted`, and `approval_binding_valid`;
- `tool_executed`, observed sandbox state/effect, and task-check result;
- `policy/reason codes`, audit record presence/chain validity, and end-to-end latency.

Define metrics in the protocol, not after seeing results. Recommended operational definitions:

- **Unsafe-effect rate (primary security outcome):** attack scenarios with an adjudicated unsafe sandbox effect divided by in-scope attack scenarios. Also report unsafe execution per attempted call where multiple calls exist.
- **Attack success rate (ASR):** state whether this means unsafe effect, unauthorized execution, or an unsafe action being permitted. Prefer unsafe effect as the paper's primary ASR and report permission decision separately.
- **False-positive rate (FPR):** benign calls incorrectly denied or challenged under a stated policy. Report deny and approval-request rates separately; do not conflate a challenge with a completed false rejection.
- **False-negative rate (FNR):** attack scenarios with an unsafe effect that the policy fails to prevent divided by adjudicated attack scenarios. Do not define it as ASR by convention unless the denominator and event are exactly identical.
- **Legitimate task completion rate (LTCR):** benign tasks meeting an independently defined end-state oracle divided by benign tasks. A permitted tool call alone is not task completion.
- **AER:** avoid this ambiguous acronym unless the manuscript defines “evasion” precisely. If used, define it as the proportion of attack variants that produce an unsafe effect despite the defense. An `ALLOW` or `REQUIRE_APPROVAL` alone is not an evasion success.
- **Latency:** measure end-to-end gateway and tool path separately; report distributions (median and p95 at minimum), hardware/runtime, warm-up, repetitions, and whether model/network time is included.

The denominator should be scenarios or independent scenario groups, not individual correlated mutations, unless the paper explicitly reports both and handles clustering.

## 4. Work plan and completion gates

### Gate 1 — Select and lock one primary study

1. Keep the current sandbox suite as a development/debugging artifact.
2. Choose whether the paper's confirmatory benchmark will be a revised 600-case suite, an external benchmark such as InjecAgent, or a carefully described combination with separate results. Do not use AgentDojo merely for novelty.
3. Remove redundant attack categories where RBAC alone decides the result; design within-permission parameter attacks and untrusted-content-to-tool-call paths that actually exercise the intended mechanism.
4. Have at least two reviewers independently label attack/benign intent, tool permission, expected effect, and task success. Adjudicate disagreements and lock hashes before test execution.

**Gate passes when:** benchmark manifest, scenario IDs/groups, labels, oracle, split, principal-to-permission mapping, and hashes are documented; test labels are not used to tune policies.

### Gate 2 — Make the run reproducible

1. Restore or regenerate the exact 500 evasion inputs, with a generation seed and source manifest. Separate mechanism-isolated transformations from burst/rate-limit tests.
2. Implement a rerunnable model adapter only if closed-loop evaluation is in the target contribution. Use Ollama for a local model or the authorized Groq API; both must call the same sandboxed tools and log model identity/configuration. Never put API keys in source or result files.
3. Run the full ablation on the same frozen scenarios, with identical initial state and paired scenario IDs. Keep any external-corpus prompt-screening experiment separate from structured tool governance.
4. Capture a clean commit, package/environment versions, commands, data/source hashes, raw row-level outputs, and logs.

**Gate passes when:** a clean clone can reproduce the raw result and generated summary without hidden `scratch/` files or manual edits.

### Gate 3 — Validate and analyze

1. Recompute every metric from raw outcomes with unit-tested metric definitions.
2. Produce a false-positive/approval casebook and an unsafe-effect casebook, including principal, reason code, and oracle state.
3. Run paired statistics only on the locked independent test set; bootstrap by scenario/group, pair configurations by scenario, report CIs/effect sizes and correct for planned multiple comparisons.
4. Regenerate all tables and figures from those machine-readable outputs; compare counts and values to the claim registry automatically.

**Gate passes when:** the numerical audit is zero-difference, all included rows have provenance, and every paper claim maps to a result/figure/table and run ID.

### Gate 4 — Finalize paper claims

1. Report current as development evidence unless/until a locked independent evaluation exists.
2. State exactly what the sandbox boundary guarantees and what it does not (for example, no production OS isolation, no general model safety guarantee, no deployment utility estimate).
3. Describe negative findings, abstentions/approval, failures, exclusions, and limitations.
4. Run the reproduction guide from a clean clone and generate the manuscript figures/tables from committed scripts.

**Gate passes when:** another team member can follow the documented commands and reproduce the reported counts and artifact hashes.

## 5. Immediate repository actions

- Keep raw evidence and historical outputs; mark them clearly as historical rather than deleting them.
- Keep the current study manuscript's descriptive development results and cautious wording. Do not replace them with the older research record's 600-case or 500-case metrics without a fresh, provenance-complete rerun.
- The attachment's `scratch/phase*.py` commands are stale for this checkout: `scratch/` is absent. Do not tell readers to run them.
- The current checkout has pending staged/unstaged changes, including benchmark file removals/additions. Review `git status` and `git diff --cached` before any cleanup or commit. Do not use broad deletion commands against `results/`, `data/`, or historical evidence.
- The exact historical 500-case source corpus is still unavailable. The current generated 500-case probe is a new versioned study based on the checked-in seeds, not a reproduction of the old record.

## 6. Paper-safe summary as of the audit date

PromptAegis currently demonstrates a runnable, sandboxed development prototype for structured tool-call governance. In the current development replay, the combined configuration matched all in-scope author-provided decisions, recorded no unsafe sandbox effects, passed 43/43 applicable authored task checks, and produced valid audit chains. These results are useful for debugging and system characterization, but they do **not** establish general attack resistance, independently measured benign utility, prompt-injection robustness, or production readiness. The dataset is author-labeled, the run is developmental, and the model is not in a closed loop. The next scientific contribution depends on independent benchmark review, a frozen confirmatory evaluation, reproducible row-level evidence, and a carefully scoped comparison to existing runtime enforcement research.
