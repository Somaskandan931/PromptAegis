# PromptAegis: second audit package

Unzip over the repository root (same folder layout). Nothing here deletes files, and `backend/.env` is deliberately NOT included.

## Do first
1. Edit `backend/.env` yourself: remove the `GROQ_API_KEY=...` line (or copy `backend/.env.example` over it). If that key was ever live, revoke it in the Groq console. Then check: `git ls-files backend/.env backend/database/credentials.json` (should print nothing).
2. Make sure the three legacy scripts from the first package are gone: `experiments/run_governance_benchmark.py`, `experiments/build_claim_registry.py`, `experiments/generate_paper_figures.py` (`git rm` them if still present; the provenance test fails otherwise).
3. `python -m pytest -q tests` (102 passed in the sandbox).
4. `git add -A && git commit -m "Ollama default, paper edits, latency protocol, paper-to-code map"`

## Then freeze the evidence (still your steps)
5. From the clean checkout: `python experiments\run_research.py benchmark --split dev --all-configs`, then `analyze`, then `registry` (commands in the README and in the first package).
6. Copy the new run to `paper\results\ablation_run.json`, rerun `paper\make_prd_figures.py`, and update the run ID in README.md, results/study/README.md, `CANONICAL_RUN` in the provenance test, and `\canonicalRun` in the .tex.
7. In the .tex set `\repoURL` and `\repoRevision` (they are placeholders), rebuild the PDF.
8. Optional: `python experiments\run_research.py latency --repetitions 10 --warmup 2` on an otherwise idle machine.
9. GitHub About text: "Deterministic policy-enforcement gateway for tool-using AI agents: RBAC, argument contracts, policy rules, rate limits, approval gating and hash-chained audit, with a sandboxed effect oracle."

## What changed
- Ollama (llama3.1:8b, no key) is the default downstream LLM for the demo chat and sandbox agent; Groq is optional (`LLM_PROVIDER=groq`). Files: backend/config.py, core/llm_client.py, api/chat.py, sandbox/agent.py, .env.example, frontend AegisChat.jsx, docker-compose.yml (host.docker.internal), README, docs/research/RUN_THE_STUDY.md. No reported result changes; the pilot already used Ollama.
- Paper: author block, data-and-code availability section, reference page-range/DOI separator, provenance, reproducibility and limitations text rewritten for the canonical run; latency captions corrected (timed span is gateway decision plus audit writes, not the sandbox tool). PDF rebuilt.
- experiments/study/run_latency_protocol.py (+ `latency` command): warm-up, shuffled order, repetitions, fresh database per block, raw timings, paired differences. experiments/study/analyze_run.py: latency description corrected.
- docs/PAPER_TO_CODE_MAP.md: claim to code, test and record.
- tests/test_llm_provider_and_latency.py.

## Still open
Placeholders `\repoURL` / `\repoRevision`; no run frozen at a Git revision; independent label review and held-out run; valid malicious proposals in the LLM pilot; latency results from the new protocol; no department or co-authors in the author block (check with your supervisor).
