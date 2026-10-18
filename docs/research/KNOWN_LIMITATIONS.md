# PromptAegis known limitations

- All benchmark scenarios and expected labels are project-authored and pending independent review.
- A development run is not a confirmatory result. The held-out validation and test splits are locked until reviewer metadata is attached to the exact dataset hash.
- The scripted agent replays tool calls; it does not reproduce LLM reasoning or injection susceptibility.
- The context policy sees explicit runtime attributes, not provenance that was not supplied by the adapter.
- The approval flow's approver is a simulated string; no identity or separation-of-duties control is implemented.
- The hash chain is optional/persisted per experiment. It detects edits only when the chain head or log cannot also be rewritten; it is not tamper-proof or externally anchored.
- The sandbox outcome oracle and parameter contracts have the same authoring team, so “independent” means independently implemented code paths, not independent human validation.
- The mock search tool deliberately concatenates SQL inside an in-memory database to make over-disclosure observable. It must never be connected to real data.
- One 12-task Ollama pilot with a single model is recorded. It is project-authored and not independently reviewed; the model declined five of six injected tasks with a prose refusal before any tool call, so only one structured proposal reached the gateway. It does not establish gateway defense efficacy. No throughput study, production integration, or population-level task-utility estimate is included.
