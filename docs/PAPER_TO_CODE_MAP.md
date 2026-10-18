# Paper-to-code map

Where each claim in `paper/PromptAegis_Governance_Study.tex` is implemented, tested and recorded. Paths are relative to the repository root. The canonical run is `results/study/governance_dev_20261017T182314Z_2a97d190.json` (12 configurations, 106 scenarios, 100 in scope). All evidence is development-split, author-labelled, and descriptive.

## Enforcement pipeline (paper: Threat model and system)

| Claim | Implementation | Test |
|---|---|---|
| Fixed stage order: request checks, RBAC, schema, policy, rate limit, approval; the first blocking stage decides | `backend/governance/gateway.py` `Gateway._decide` | `tests/test_gateway_failure_modes.py::test_stages_run_in_the_documented_order`, `::test_stage_order_decides_attribution_when_several_controls_would_block` |
| Stage 0: malformed request, unknown agent, unknown tool are denied and always on | `Gateway._decide` (reason codes `INVALID_REQUEST`, `UNKNOWN_AGENT`, `UNKNOWN_TOOL`) | `::test_invalid_or_unknown_identifiers_are_denied_before_any_control` |
| RBAC on the (agent, tool) pair | `backend/governance/permission_engine.py` `check_permission` | `::test_schema_valid_call_outside_the_role_is_stopped_by_rbac_not_by_the_contract` |
| Allowlist argument contracts (names, types, lengths, character classes, e-mail domain, identifier formats) | `backend/governance/param_validator.py` `validate_arguments`, per-tool `_validate_*` | `tests/test_governance_study.py::test_contract_accepts_valid_request_and_rejects_sql_injection`, `::test_registered_custom_tool_contract_is_persistent_and_enforced`, `tests/test_gateway_failure_modes.py::test_unknown_argument_names_are_rejected_by_the_contract` |
| Policy rules over tool, role, parameters, trusted context; ALLOW-action policies refused | `backend/governance/policy_engine.py` `evaluate_policies`; guard in `Gateway._decide` | `tests/test_gateway_failure_modes.py::test_schema_valid_call_violating_trusted_context_is_stopped_by_policy` |
| Tumbling 60 s rate limit per (agent, tool); rejected calls do not consume budget; atomic under concurrency | `backend/governance/rate_limiter.py` `check_and_increment` | `::test_rate_limit_boundary_is_exact`, `::test_rejected_calls_do_not_consume_the_rate_budget`, `::test_concurrent_calls_cannot_exceed_the_rate_limit` |
| Approval from tool metadata or risk score >= 7.0; single-use, bound to agent, tool and argument digest | `Gateway._decide` (approval stage), `backend/governance/risk_scorer.py` `compute_risk_score`, `backend/sandbox/runtime.py` `ProtectedRuntime.approve` / `_approval_binding` | `tests/test_governance_study.py::test_approval_is_required_then_only_explicitly_approved_retry_executes` |
| Approval in the experiments is a harness allowlist, not authenticated human approval | `ProtectedRuntime.approved_approvers`; benchmark passes `{"sandbox_test_approver"}` | (stated limitation, not a tested property) |
| Fail-closed on any engine error | `Gateway.evaluate` (`GATEWAY_ERROR` handler) | `tests/test_gateway_failure_modes.py::test_exception_in_any_stage_denies_and_does_not_execute` |
| Denied or non-allowed calls never reach a tool | `ProtectedRuntime.call` | `::test_runtime_never_executes_a_non_allowed_call`, `tests/test_governance_study.py::test_denied_request_does_not_reach_sandbox` |
| Every decision is written to SQLite and a hash chain; audit failure becomes DENY | `Gateway._audit`, `backend/governance/audit_chain.py` `AuditChain`, `redact`, `args_digest` | `tests/test_governance_study.py::test_audit_failure_fails_closed_before_tool_execution`, `::test_audit_chain_failure_corrects_database_decision_and_fails_closed` |
| Chain is tamper-evident, not tamper-proof | `audit_chain.py` `verify_chain` | `::test_audit_chain_detects_tampering_and_refuses_to_resume` |

## Execution, oracle and benchmark (paper: Materials and methods)

| Claim | Implementation | Test or record |
|---|---|---|
| In-memory business sandbox, deterministic virtual clock | `backend/sandbox/world.py` `SandboxWorld`; `experiments/study/env.py` `build` | `tests/test_environment_isolation.py`, `tests/test_governance_study.py::test_environment_builder_refuses_to_overwrite_user_database` |
| Effect oracle records unsafe state changes separately from decisions | `backend/sandbox/world.py` `unsafe_effects`; fields in `CallRecord` (`backend/sandbox/runtime.py`) | per-call fields in the canonical run |
| 376 scenarios, 106 in the dev split, 100 in scope, 21 template groups | `backend/data/governance_benchmark/scenarios.json`, `manifest.json`; `experiments/study/generate_benchmark.py` | `experiments/study/run_benchmark.py` `_load` checks hashes and split leakage |
| Validation and test locked pending two-reviewer record bound to the scenario hash | `run_benchmark.py` `_load` | `tests/test_governance_study.py::test_holdout_split_is_locked_without_independent_review` |
| Twelve configurations (baseline, single controls, pairs, full, leave-one-out) | `backend/governance/gateway.py` `CONFIGURATIONS` | canonical run, `configurations` |
| Decisions, exact agreement, unsafe-effect scenarios, task checks, audit coverage | `experiments/study/run_benchmark.py` `run`, `_task_success`; `experiments/study/analyze_run.py` | `tests/test_provenance_and_reproducibility.py::test_registry_counts_recompute_from_raw_events` |
| Descriptive intervals use template groups as the resampling unit | `analyze_run.py` `bootstrap_group_rate`; `experiments/study/stats.py` | `results/study/*_analysis.json` |

## Results, reproduction and provenance

| Claim | Where it comes from | Test |
|---|---|---|
| Headline numbers in abstract, tables and README | canonical run; `paper/make_prd_figures.py` writes `paper/generated/prd_metrics*.{json,tex}` | `test_headline_numbers_in_readme_and_paper_match_the_canonical_run` |
| Every number is traceable to raw events | `experiments/study/build_claim_registry.py` writes `results/provenance/claim_registry.json` | `test_claim_registry_points_at_existing_canonical_run` |
| Source hashes of the canonical run match the code except the documented runner edit | recorded `*_sha256` fields | `test_canonical_run_sources_match_current_code_except_documented_runner_edit` |
| Re-execution on Linux: 1,272 pairs, 0 differences | `docs/REPRODUCTION_CHECK.md` | (manual re-execution, not a unit test) |
| Each configuration has a valid audit chain | `results/study/audit/*.jsonl` | `test_every_configuration_has_a_valid_audit_chain_file` |
| Older 600-scenario pipeline is archived, not current | `experiments/archive/legacy_studies/`, `results/provenance/legacy/` | `test_legacy_600_scenario_pipeline_is_archived_not_current` |
| No secrets in the repository | | `test_secret_scan` |

## Closed-loop pilot (paper: Exploratory closed-loop LLM pilot)

| Claim | Implementation | Record |
|---|---|---|
| Model proposes one tool call; a reply with no tool call is an agent outcome, not a gateway denial | `backend/sandbox/agent.py` `LLMAgent`, `parse_tool_call`; `experiments/study/run_llm_closed_loop.py` | `tests/test_llm_agent_parsing.py` |
| Ollama `llama3.1:8b`, temperature 0, seed 0, full configuration | `run_llm_closed_loop.py` | `results/study/llm_20261017T171952Z_9c41232a.json` |
| Table and macros in the paper | `experiments/study/summarize_llm_pilot.py` | `paper/generated/llm_pilot_*` |
| Runs that predate the harness fix are excluded | | `results/study/CONTAMINATED_RUNS.md` |

## Latency (paper: Per-call latency, exploratory)

| Claim | Where | Note |
|---|---|---|
| Table values come from the earlier four-configuration run | `results/study/governance_dev_20261017T150806Z_056a4792.json`, `paper/make_prd_figures.py` | fixed configuration order, one machine |
| Timed span is gateway decision plus audit writes, not the sandbox tool call | `backend/sandbox/runtime.py` `ProtectedRuntime.call` (`total_latency_ms` is taken right after `Gateway.evaluate`) | corrected in the manuscript captions |
| Warm-up, randomized order, repetitions, raw timings, paired differences | `experiments/study/run_latency_protocol.py` (`run_research.py latency`) | `tests/test_llm_provider_and_latency.py`; no result from it is in the paper yet |

## Not claimed by the code

Independent label review, a held-out run, valid malicious proposals in the LLM pilot, authenticated human approval, and externally anchored audit logs are future work in the paper and have no implementation here.
