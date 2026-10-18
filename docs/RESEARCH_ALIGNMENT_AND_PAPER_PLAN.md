# Research scope and reporting plan

## Primary study: tool-call governance

The proposal's central question concerns whether a separate gateway can reduce unsafe tool requests while preserving useful allowed behavior. The primary experiment therefore compares `baseline`, `rbac_only`, `policy_only`, and `full` on six controlled categories: legitimate requests, unauthorized tools, parameter manipulation, prompt injection, privilege escalation, and excessive calls.

The current 600-case suite is researcher-defined and sandbox-oriented. It is not a naturally collected real-world dataset. It supports deterministic checks of gateway policy behavior, but not attack-prevalence claims. Per run, 480 cases are expected unsafe and 120 expected allowed; burst labels allow the first ten calls per tool and rate-limit subsequent calls.

## Current measured scope

`experiments/run_governance_benchmark.py` invokes the gateway interceptor directly. It does not invoke an LLM, call external systems, execute mock tools, or observe user-task completion. Therefore:

- Use **unsafe-call allow rate**, not realized attack success rate (ASR).
- Use **legitimate-call allow rate**, not legitimate task completion rate (LTCR).
- Interpret false rejection as expected-allow proposals rejected by the gateway.
- Report latency as local gateway decision latency; it is not end-to-end agent latency.
- Report audit coverage from observed audit-record count, not a hard-coded value.
- State that three repeated executions produced identical decision counts; they are fixed-suite repeats, not independent samples, so they do not support population-level confidence intervals.

The latest replay is `results/governance/governance_benchmark_20261017T061036Z.json`; its repeats are `results/governance/governance_benchmark_20261017T060058Z.json` and `results/governance/governance_benchmark_20261017T055353Z.json`. All three record source and fixture hashes and identical decision counts. The latest artifact also records and verifies actual principal counts from the audit log. A read-only audit of the original frozen run also confirmed 600/600 calls per configuration used `CustomerSupportAgent`; the claim that it selected `EmailAssistant` was not supported by the run's source hash or audit rows. The current runner now refuses to fall back when an explicitly named principal is missing. Do not combine governance metrics with prompt-detector metrics.

In all three runs, the full configuration allowed 50/480 expected-unsafe calls, all from parameter manipulation (30 SQL-like search strings and 20 update requests containing injection-like values). Policy-only produced `REQUIRE_APPROVAL` for 115 expected-unsafe cases. Count these as not directly allowed, but do not equate a pending approval with a definitive denial. Three adversarial categories target tools already denied to the support agent, so they test authorization rather than prompt-injection detection. SQL/XSS-like labels also lack matching general validation policies. The 20-prompt live-model pilot and older rate-limit/statistical outputs are kept separate because they use different protocols.

## Separate prompt-screening experiment

`experiments/run_real_data_evaluation.py` evaluates the classifier on held-out HackAPrompt and ToxicChat subsets. ToxicChat is a real-user benign proxy labelled non-toxic and non-jailbreak, not a verified injection-free dataset. That experiment may be cited as a separate component or removed from a governance-only submission; it is not evidence of tool authorization or task utility.

## Before final submission

1. Have the supervisor approve the final research question, threat model, scenario labels, and target paper template.
2. Have an independent reviewer validate expected decisions and identify duplicate or policy-leaking scenarios.
3. Add sandbox tool executors and measure completed legitimate tasks and blocked unsafe side effects.
4. Repeat each configuration, report environment/version metadata, and estimate uncertainty for latency and outcome rates.
5. Keep human-authored controlled cases distinct from external real-world prompt datasets and disclose their origin.
6. Replace author placeholders, verify citations and dataset terms, and compile the final venue-format manuscript.
