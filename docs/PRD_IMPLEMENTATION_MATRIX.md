# PRD implementation matrix

Last reviewed: 18 October 2026, against `paper/PromptAegis_Governance_Study.tex` and runs `056a4792` (4 configurations) and `2a97d190` (12 configurations, re-execution on the delivered source).

"Implemented" means a code path exists and was exercised on the **development split only**. It does not mean production readiness, independent validation, or generalization.

## 1. Requirements (PRD sections 12-20, 32)

| PRD requirement | Current implementation | Status |
|---|---|---|
| FR-01/02 Agent and tool registry | SQLite registries; `POST /tools` with persisted argument contract; unregistered tools fail closed | Implemented |
| FR-03 Fine-grained permissions | Agent-to-tool allow/deny, default deny (RBAC stage) | Implemented |
| FR-04 Configurable policies | Tool, role, parameter, trusted-context rules; allow-type policies refused | Implemented; policy language is limited |
| FR-05/06/07 Interception, evaluation, ALLOW/DENY/REQUIRE_APPROVAL/RATE_LIMIT | `Gateway` + `ProtectedRuntime`; only ALLOW or a single-use bound approval executes | Implemented |
| Risk evaluation (PRD 17) | Deterministic composite score, approval gate at 7.0, advisory only | Implemented; weights not empirically justified; no ablation of the score itself |
| FR-09 Rate limiting | Per-agent/per-tool 60 s tumbling counter on a virtual clock | Implemented; enforcement shown (Fig. rate), containment of a real attack not measured |
| FR-08 Audit logging | SQLite row plus SHA-256 hash chain per decision; audit failure converts to DENY | Implemented; tamper-evident, not externally anchored |
| FR-10 Experiment execution | `experiments/run_research.py benchmark/analyze/adversarial/llm/corpora` | Implemented |
| FR-11 Metrics | Exact agreement, ASR, approval bypass, benign false block, task checks, executed calls (tool-call reduction), audit coverage, p50/p95/p99 latency | Implemented (`paper/make_prd_figures.py`) |
| FR-12 Comparison of configurations | 12 configurations: baseline, RBAC-only, policy-only, schema-only, RBAC+schema, RBAC+policy, full, five leave-one-out | Implemented (exceeds PRD's 4 groups) |
| FR-13 Export | Timestamped JSON with hashes and per-call records; CSV via API | Implemented |
| Agent adapter (PRD 12.1) | Custom Python adapter; scripted agent; Ollama/Groq function-call harness | Partial; no LangGraph/LangChain/MCP adapter |
| PostgreSQL / Redis | SQLite, in-process counters | Not implemented (deliberate; future work) |
| Dashboard (PRD 29) | React UI and experiment page | Prototype |

## 2. Research design (PRD sections 6-8, 21-28, 36-38)

| PRD item | Where addressed | Status / gap |
|---|---|---|
| RQ1 policy-controlled vs unrestricted | Paper main-results table and ablation figure | Answered on dev split; ASR 25/49 -> 0/49 |
| RQ2 permissions vs legitimate completion | Paper trade-off section, Fig. security-utility | 43/43 task checks and 0/39 false blocks everywhere; suite cannot expose over-blocking (6 benign template groups) |
| RQ3 latency overhead | Paper latency table and Fig. latency | Ordering consistent across runs (56.4->171.3 ms median in canonical run 9e7d0639, 65.7->190.4 ms in exploratory run 056a4792); absolute values machine-dependent, so no overhead estimate |
| RQ4 distinguishing legitimate from unsafe calls | Exact agreement; benign false block | Answered within suite; labels author-assigned |
| RQ5 rate limiting | Paper rate-limit paragraph, Fig. rate | Enforcement of limit shown; no attack-containment or legitimate-burst cost measured |
| RQ6 best security-utility mix | 12-configuration ablation | RBAC+Schema reaches 0/49 ASR; Approval needed to hold the 4 approval-required exports; utility flat so trade-off is not discriminated |
| H1-H5 | Descriptive evidence only | H4 (audit improves traceability) supported only as coverage and chain validity |
| Threat model T1-T5 (PRD 38) | `docs/research/THREAT_MODEL.md` | T1, T4, T5 exercised by scripted scenarios; T2/T3 (external content, compromised tool output) only through the 12-task pilot, and the model refused 5 of 6 |
| Benchmark size 600 (100 per category) | 376 scenarios / 709 calls, 65 template groups; dev 106 (100 in scope) | Below PRD target; categories differ (adds negative control, context-sensitive, approval-required, rate-limit sequences) |
| Repeated runs for LLM variability | Pilot repeated once for `full` | Not met: one model, 12 tasks |
| Independent label review | Protocol in `docs/research/INDEPENDENT_LABEL_REVIEW.md` | Not done; validation and test locked |
| Ablation (PRD 28) | Done, 12 configurations | Done |

## 3. Success criteria (PRD 42)

| Criterion | Status |
|---|---|
| Agent invokes sandboxed tools | Met (scripted and LLM) |
| All protected calls pass through the gateway | Met for `ProtectedRuntime`; bypass paths out of scope |
| Permissions / policies configurable | Met |
| Unauthorized actions blocked | Met on dev split |
| Rate limits enforced | Met |
| Every action auditable | Met (coverage 1.00, chain valid) |
| Legitimate tasks execute | Met |
| Attack scenarios reproducible | Met (re-execution reproduced all scenario-level outcomes) |
| Baseline and governed experiments | Met |
| Security and utility metrics | Met (separately reported, as PRD 24.8 advises) |
| Ablation | Met |
| Results exportable | Met |
| Entire experiment reproducible | Partly: no run frozen at a clean commit; latency not reproducible across machines |

## 4. Figures and the PRD

| Figure | Script | PRD item |
|---|---|---|
| Architecture | `paper/make_architecture_figure.py` | 11 |
| Ablation, category heatmap, pilot flow | `paper/make_figures.py` | 27-28, 36 |
| Security-utility panel, stage attribution, rate-limit effect, latency distributions | `paper/make_prd_figures.py` | 6, 19, 24 |

Regenerate from `paper/`:

```powershell
python make_figures.py results\ablation_run.json <pilot_full.json>
python make_prd_figures.py results\ablation_run.json ..\results\study\governance_dev_20261017T150806Z_056a4792.json
```

## 5. Priority gaps

1. Independent review of labels, then validation and a single test run on a frozen commit.
2. Scenarios in which exactly one control is decisive, and attacks that satisfy the schema while violating policy (RBAC is currently redundant with policy).
3. Larger closed-loop study: several models, reviewed prompts, repeated trials, and prompts that elicit valid malicious calls so gateway blocking is tested directly.
4. A volume criterion in the oracle, and a benign burst scenario, so RQ5 can measure containment and legitimate cost.
5. Latency with interleaved or randomized configuration order, profiling, and hardware recorded.
6. Optional: LangGraph/MCP adapter; Postgres/Redis backends.
