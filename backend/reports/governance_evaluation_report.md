# PromptAegis 2.0 — Current Tool-Governance Evaluation Report

## Evidence boundary

The primary experiment is a deterministic replay of 600 researcher-authored scenarios through the gateway. It invokes no LLM, does not execute downstream tools, and does not measure task completion or realized attack success. Do not combine these results with the separate prompt-screening experiment or historical diagnostics.

Primary result: `results/governance/governance_benchmark_20261017T061036Z.json`. Repeated executions: `results/governance/governance_benchmark_20261017T060058Z.json` and `results/governance/governance_benchmark_20261017T055353Z.json`.

## Latest replay

Each configuration processed 600 proposed calls: 480 expected-unsafe and 120 expected-allow. All three runs reproduced the same decision counts. Latency is local and varied between runs.

| Configuration | Unsafe-call allow | Legitimate-call allow | False rejection | Exact-label agreement | Median latency | p95 latency | Audit coverage |
|---|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 100.00% | 100.00% | 0.00% | 20.00% | 13.974 ms | 15.728 ms | 100% |
| RBAC-only | 37.50% | 100.00% | 0.00% | 70.00% | 31.571 ms | 36.647 ms | 100% |
| Policy-only | 30.21% | 100.00% | 0.00% | 56.67% | 63.894 ms | 108.634 ms | 100% |
| Full gateway | 10.42% | 100.00% | 0.00% | 91.67% | 104.606 ms | 193.238 ms | 100% |

The full gateway allowed 50/480 expected-unsafe proposals. All 50 were parameter-manipulation fixtures: 30 SQL-like `search_customer` queries and 20 manipulated `update_customer` requests. The full gateway allowed all 120 expected-allow proposals. Its p95 latency was 84.604 ms higher than policy-only in the latest run.

Exact-label agreement requires the gateway disposition to match the fixture's expected label; `REQUIRE_APPROVAL` is not treated as a denial. The 100% audit coverage is an implementation-path observation, not an independent assessment of audit quality or tamper resistance.

## Valid interpretation

Three categories—unauthorized tool, privilege escalation, and prompt injection—target tools already denied to `CustomerSupportAgent`; these primarily test the configured authorization boundary. The gateway does not receive the scenario's natural-language prompt, and every case uses the same approved context. Therefore, the experiment does not evaluate prompt understanding, prompt-injection resistance, or context-policy efficacy. The parameter fixtures include inputs labelled unsafe for which the current policy set has no general SQL/XSS validator; their outcomes expose a policy-coverage gap rather than a measured detector miss rate.

The repeated runs use the same fixed suite, so they demonstrate decision-count stability, not independent sampling or population-level uncertainty. Latency includes local database and audit-write costs and should not be presented as pure incremental governance overhead.

## Next research work

1. Independently review and label scenarios; group near-duplicates and freeze a held-out split before policy changes.
2. Add adversarial cases against tools the support principal is permitted to use, and vary trusted runtime context.
3. Execute sandboxed tools and verify whether blocked calls cause no side effects.
4. Run paired agent trajectories with untrusted prompt/tool-output content if injection resistance is a research claim.
5. Measure task completion, unsafe state changes, false rejections, and gateway decisions together.
6. Repeat latency measurements under documented machine/software conditions and separate gateway cost from database/audit cost.
7. Reproduce from a clean pinned revision and archive source/scenario hashes and generated outputs.
