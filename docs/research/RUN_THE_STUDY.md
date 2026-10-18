# Running the PromptAegis studies

This guide targets the current sandbox governance study. Run commands from the repository root in Anaconda PowerShell. Run **one benchmark process at a time**: each uses the same local benchmark database and concurrent runs invalidate the evidence.

## 1. Environment

```powershell
conda activate base
python --version
python -m pip install -r backend/requirements.txt
```

Keep API keys out of files and manifests. The deterministic benchmark below makes no model or network request.

## 2. Reproduce the development ablation

```powershell
python -u experiments/run_research.py benchmark --split dev
```

The runner writes one JSON result and four audit-chain JSONL files under `results/study/`. Wait for `[OK]` and the result path before starting any other run. The ablation is `baseline`, `rbac_only`, `policy_only`, and `full` on the same scenarios. It is development evidence because the suite is author-labeled and used during development.

Analyze the exact result path printed by the runner:

```powershell
python experiments/run_research.py analyze results/study/<RUN_ID>.json --iterations 5000
```

For example, replace `<RUN_ID>.json` with the exact output filename; do not automatically select the newest result because a partial or contaminated attempt may be newer. The analysis verifies the benchmark SHA before joining labels to outcomes, computes group-clustered bootstrap intervals, paired exact McNemar tests for unsafe effects, and paired per-scenario Wilcoxon latency comparisons when SciPy is installed. Its output is beside the input as `<RUN_ID>_analysis.json`.

Metric semantics are recorded in that JSON. In particular, unsafe effects are the primary security outcome, approval requests are not counted as denials, and task completion is based on authored task checks. The current protocol has no distinct operational FNR from effect-based ASR, so the report labels the equivalence instead of presenting two independent measurements. “AER” is omitted because its meaning is ambiguous.

## 3. Run the corpus screening experiment separately

```powershell
python experiments/run_research.py corpora --batch-size 256
```

This is a text-classification/prompt-screening study. Its datasets and labels differ from structured tool-call governance. Never merge its metrics into the current study ablation.

## 4. Optional closed-loop LLM pilot

First create a JSONL manifest of **natural-language user tasks authored independently of expected tool calls**. Required fields are `task_id`, `group_id`, `task_prompt`, `principal`, `context`, and `label` (`attack` or `benign`). Optional fields include `untrusted_content`, `category`, `task_check`, and `expected_effect`. Keep a copy of the prompt set and its hash. The model output is parsed as one proposed tool call and all calls go through `ProtectedRuntime` and the sandbox.

For Ollama, start the local service and pull the model you plan to identify in the paper:

```powershell
ollama pull llama3.1:8b
$env:OLLAMA_BASE_URL = "http://localhost:11434/v1"
python experiments/run_research.py llm path\to\reviewed_tasks.jsonl --provider ollama --model llama3.1:8b --configuration full
```

For Groq (optional; check the current model ID in the Groq console, retired IDs return HTTP 404):

```powershell
$env:GROQ_API_KEY = "<your key>"
python experiments/run_research.py llm path\to\reviewed_tasks.jsonl --provider groq --model openai/gpt-oss-120b --configuration full
Remove-Item Env:GROQ_API_KEY
```

Run configurations one after another, never in parallel (they share one local database); `experiments/run_pilot_matrix.ps1` does this and then builds the paper tables with `experiments/study/summarize_llm_pilot.py`. A reply with no tool call (for example a refusal) is recorded as an agent outcome with its raw text and is not sent to the gateway. Use the current model name available to your account, and record model/version, endpoint, decoding settings, prompts, run date, and all failures. The runner marks this as a pilot. Do not call a tool permission result “task completion”; use an independently defined `task_check` and report it separately. Start with a small `--max-tasks` smoke run; then run the frozen set once. LLM outputs are nondeterministic even when a seed is supplied.

## 5. Validation/test gate

The runner intentionally refuses `validation` or `test` unless `backend/data/governance_benchmark/independent_review.json` is bound to the current scenario SHA and records at least two independent reviewers and `labels_status: independently_reviewed`. Do not create that record for convenience: reviewers must actually adjudicate the labels. If you change scenarios after review, the hash changes and review must be repeated.

## 6. Project-authored 500-case normalization probe

The old derived metrics cannot be reproduced from the exact historical source corpus because that input is unavailable. A new, explicitly labeled project-authored probe can be generated from the 100 current parameter-manipulation seed cases and evaluated as a decision/interception study:

```powershell
python experiments/run_research.py generate-probe
python experiments/run_research.py adversarial
```

The generator records source, generator, and generated-corpus SHA-256 values. The runner saves each run in a new `results/adversarial_runs/<run_id>/` directory. Its non-ALLOW rate is not an outcome-based attack success or evasion rate because this legacy path does not execute sandbox tools. The run completed on 2026-10-17: isolated non-ALLOW rate was 40% standard and 50% hardened; compound rate was 75.2% and 76.0%, with rate limiting responsible for 72% of standard compound cases. These are descriptive results on author-generated mutations, not independent or external-benchmark evidence.

Historical analysis scripts are retained under `experiments/archive/legacy_studies/`; they are not part of the supported run path. Use the canonical `llm` command above for a new pilot with independently authored natural-language tasks. Old scratch commands in the supplied record are not present in this checkout.

## 7. Provenance checklist for every paper run

Before reporting a run, save its command, commit ID, dirty-tree status, Python/dependency versions, scenario and manifest hashes, raw result, audit chains, analysis output, and the corresponding table/figure claim ID. Review `git status --short` before and after. Do not change labels/policies and rerun the test split until the stated evaluation protocol allows it.
