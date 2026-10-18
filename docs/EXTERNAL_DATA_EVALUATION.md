# External model-in-the-loop evaluation: decision and next steps

## Decision

AgentDojo is retired from the supported workflow. It is a valid benchmark, but
it is not necessary for novelty, and its installation/runner problems make it
a poor choice for this project right now. Existing code and traces remain as
historical material for reproducibility; no new result should depend on them.

InjecAgent is the best-fit candidate to investigate next because it targets
indirect prompt injection against tool-integrated LLM agents and publishes
cases, reference code, and an MIT license. The authors report 1,054 test cases
across 17 user tools and 62 attacker tools. It is not automatically a novelty
claim: the research contribution must come from PromptAegis's mechanism and a
careful evaluation of security and legitimate task utility.

## Required adapter work before running it

The benchmark data cannot simply be sent through the existing scripted
scenario runner. Implement and validate a separate adapter that:

1. Loads the official InjecAgent test cases and records the upstream commit and
   data hashes.
2. Invokes a tool-calling model (Ollama can be the local provider) on both
   benign user tasks and the benchmark's injected tool outputs.
3. Routes every model-proposed tool call through the same PromptAegis gateway
   before the benchmark's simulated tool executes.
4. Preserves the benchmark's original outcome checks for direct harm and data
   stealing; do not substitute “malicious tool was called” for verified impact.
5. Runs baseline and governed modes against the same frozen cases, then reports
   attack success, benign task completion, injected task utility, false blocks,
   audit coverage, and latency separately.
6. Starts with a small development pilot, fixes adapter issues there, then runs
   the complete official test set once. Do not tune on the final test cases.

Until these steps are complete, use the deterministic PromptAegis sandbox
benchmark only for mechanism debugging and describe its scenarios as
project-authored. Do not claim external validation, a live-LLM result, or
InjecAgent performance.

Official sources: [InjecAgent paper](https://aclanthology.org/2024.findings-acl.624/),
[authors' benchmark repository](https://github.com/uiuc-kang-lab/InjecAgent).
