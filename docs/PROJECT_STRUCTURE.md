# Project structure and supported run paths

PromptAegis is one research project with separate evaluation protocols. The
canonical commands live in `experiments/run_research.py`. Frozen result paths
retain their original names so their provenance remains verifiable; new runs
use the `results/study/` directory.

| Area | Purpose |
|---|---|
| `backend/governance/` | Tool-call mediation, identity/permission checks, policy enforcement, rate limits, approvals, and audit. |
| `backend/sandbox/` | In-memory simulated tools used by the controlled gateway benchmark; not OS/container isolation. |
| `backend/api/`, `frontend/` | Optional local prototype UI and API. |
| `backend/data/governance_benchmark/` | Project-authored scenarios and manifest. Labels require independent review before confirmatory claims. |
| `experiments/` | Canonical run entry point, benchmark runners, analysis, and historical experiments. |
| `results/` | Raw outputs, audit traces, derived analyses, and provenance. Preserve raw results. |
| `paper/` | Manuscript, references, figures, and Overleaf instructions. |
| `docs/` | Threat model, methods, repository audit, paper readiness, and decisions. |
| `tests/` | Automated implementation and reproducibility checks. |

## Commands

From Anaconda PowerShell at the repository root:

```powershell
conda activate base
python -m pip install -r backend\requirements.txt

# Primary controlled gateway benchmark; deterministic, no LLM/API call.
python experiments\run_research.py benchmark --split dev

# One mechanism configuration.
python experiments\run_research.py benchmark --split dev --config full

# Separate local prompt corpus detector evaluation. Requires the prepared CSVs.
python experiments\run_research.py corpora --batch-size 256
```

The primary benchmark is a project-authored controlled sandbox, not an external
real-world dataset. Its validation/test splits remain locked pending independent
label review. Do not report development scores as held-out or real-world
performance.

## LLM evaluation decision

AgentDojo is no longer part of the supported run path because its installation
and execution caused repeated problems. Its adapter scripts were removed;
existing run traces are retained as historical evidence and should not be used
for new primary results.

An opt-in Ollama/Groq pilot harness exists at `experiments/study/run_llm_closed_loop.py` and routes model proposals through the canonical sandbox runtime. No reviewed natural-language task manifest or new live-model run is included. InjecAgent remains a candidate external benchmark requiring an adapter and evaluation before making benchmark claims. See [EXTERNAL_DATA_EVALUATION.md](EXTERNAL_DATA_EVALUATION.md).

Ollama can run the pilot locally; it does not replace a reviewed benchmark or establish novelty by itself.
