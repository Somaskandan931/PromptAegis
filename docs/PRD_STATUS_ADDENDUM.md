> [!info] Implementation status (18 Oct 2026) - paste at the end of the Prompt Aegis 2.0 PRD
> Source of truth: `docs/PRD_IMPLEMENTATION_MATRIX.md` in the repository.
>
> **Done:** sections 12-20 (gateway, registry, permissions, policy, risk, rate limit, audit), 21-23 and 27-28 (scenario framework, four-plus configurations; 12 configurations run), 24 (ASR, false block, task checks, tool-call reduction, p50/p95/p99, audit coverage), 32 FR-01 to FR-13, 42 success criteria.
> **Changed from the PRD:** benchmark is 376 scenarios in 65 template groups, not 600; FNR is reported as ASR because numerator and denominator coincide; SQLite replaces PostgreSQL/Redis; approval is simulated.
> **Not done:** independent label review, validation/test runs, multi-model repeated LLM trials (pilot: 1 model, 12 tasks), LangGraph/MCP adapter, tool-output-injection (T3) evidence, rate-limit containment of a real attack, defensible latency overhead.
> **Rule for the paper:** every claim stays descriptive and development-split only.
