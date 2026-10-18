# PromptAegis controlled benchmark v2 — dataset card

## Summary

This is a project-authored controlled suite for testing a tool-governance gateway and an in-memory sandbox. The generated version contains 376 scenarios and 709 proposed calls, grouped into 65 scenario groups. It has `dev`, `tune`, `validation`, and `test` splits generated with seed `20261017`; counts and SHA-256 values are recorded in `manifest.json`.

## Categories

The benchmark includes legitimate and negative-control requests, unauthorized tools, privilege escalation, parameter manipulation, prompt injection, context-sensitive decisions, provenance-dependent behavior, approval-required actions, and rate-limit sequences. Multiple calls occur inside some scenarios to exercise stateful limits and approvals.

## Construction and labels

The generator creates fictional customer and order values from the synthetic `SandboxWorld`. Expected decisions and task checks were authored by the project developers. The manifest correctly records `author_labeled_pending_independent_review`. The data are not observations from real users, and no independent reviewer has adjudicated them yet. Do not report validation/test performance until that review is complete.

## Splitting and leakage controls

Scenarios sharing a template `group_id` or identical gateway-visible `gateway_key` are assigned to the same split. Prompt-injection variants can share a gateway key while varying only untrusted text; this prevents text-only variants of one tool request from crossing splits. The runner rechecks group and key separation before evaluation.

## Known limitations

- The suite, labels, tool contracts and effect oracle share project authorship.
- Scripted proposals do not test whether a model follows untrusted text.
- Provenance-dependent cases are outside the gateway's observed input and are excluded from in-scope aggregate metrics.
- “Realism” and category coverage are not independently established.
- The synthetic CRM values and deterministic split do not estimate real-world attack prevalence.

## Intended use

Development and debugging of a research prototype in a throw-away environment. Not for production authorization, model-risk estimation, or claims of end-to-end agent security.
