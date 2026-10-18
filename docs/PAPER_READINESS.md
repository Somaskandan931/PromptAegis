# Paper readiness

## Current manuscript and status

The main manuscript is `paper/PromptAegis_Governance_Study.tex`. It follows an Elsevier `elsarticle` structure with a single-paragraph abstract, highlights, numbered sections, tables, numbered citations, and declarations. It compiled successfully with the desktop LaTeX editor on 17 October 2026. The Elsevier class is provisional; SRM/supervisor requirements take precedence. This is a concise research draft, not yet comparable in length or evidence depth to the supplied published papers. Do not pad the paper or fabricate new claims/citations to match their length.

The primary table reports the sequential current-source development run: `results/study/governance_dev_20261017T150806Z_056a4792.json`. Recorded runner, gateway, validator, sandbox-runtime, and scenario hashes match the files used for that run. The worktree was dirty. It contains 106 scenarios, 100 in scope, 43 applicable task checks, and author-generated labels pending independent review. Full configuration: exact decision agreement 1.000, zero oracle-detected unsafe-effect scenarios, task checks 43/43, full audit coverage, and valid local chain. This is a development observation on a project-authored suite, not held-out performance or a real-world security rate. A second replay has matching numbers but is not independent evidence.

The legacy gateway-only result set is historical and distinct: it evaluates proposed calls through the API interceptor, not through sandboxed tool execution. Several older outputs have known protocol, timing, or provenance issues. The prompt-screening results are a separate detector study. AgentDojo is retired; no live-model tool-agent result is currently supported. InjecAgent is only a candidate until an adapter is implemented and evaluated.

## Required before confirmatory claims

1. Obtain independent blinded review of expected decisions and task checks from at least two reviewers; document adjudication and bind the review to the exact scenario SHA-256.
2. Freeze the dataset, code, contracts, policies, environment, metric definitions, and a clean Git revision.
3. Run validation, resolve defects on a new version if required, then run the test split once. Do not tune on test outcomes.
4. For prompt-injection claims, run closed-loop model trials where untrusted content reaches an agent and proposed tool calls go through the protected runtime.
5. Report decision outcomes, task completion, unsafe sandbox effects, false rejections, approvals, latency, and uncertainty separately.
6. Test audit reconstruction and failure cases; verify reviewer identity and bypass resistance before making deployment/security claims.
7. Confirm SRM's required manuscript template, page limits, authorship, funding, CRediT, and AI-use declaration.

## What the current evidence supports

- The current source can execute scripted proposals through a deterministic gateway and in-memory sandbox while recording decisions and effects.
- In the development run cited above, full governance matched all author-expected decisions in scope and the sandbox oracle detected no unsafe-effect scenario; all four configurations passed the same 43 applicable authored checks.
- These outcomes describe implementation behavior on the development fixtures only. The labels/oracle share project authorship, and the cases were available during development.

They do not establish generalization, prompt-injection resistance, real-user task utility, production security, or population-level performance.
