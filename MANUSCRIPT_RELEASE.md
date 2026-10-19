# PromptAegis — Manuscript Release Policy

This file documents how to obtain the paper manuscript, which research artifacts are
publicly available in the repository, and which are withheld or separately managed.

> **Important:** The `paper/` directory is excluded from Git tracking by `.gitignore`
> (added in commit `e6cdacc`). A standard `git clone` will **not** retrieve the
> manuscript source, figures, or PDF.

---

## What IS in the public repository

| Path | Description |
|------|-------------|
| `backend/` | Gateway, runner, policy engine, sandbox, rate limiter, audit chain |
| `experiments/study/run_benchmark.py` | Canonical benchmark runner |
| `experiments/study/run_llm_closed_loop.py` | LLM pilot runner |
| `experiments/study/build_claim_registry.py` | Claim registry builder |
| `backend/data/governance_benchmark/` | Scenario set (version 2.0.0, seed 20261017) |
| `results/study/governance_dev_20261018T081010Z_9e7d0639.json` | **Canonical benchmark run** (SHA-256: `eebe2f501b1aac4901fb7bb187ab39323e82813a93950b2dd44560cf475bbe16`) |
| `results/study/governance_dev_20261018T081010Z_9e7d0639_analysis.json` | Pre-computed analysis |
| `results/study/governance_dev_20261017T150806Z_056a4792.json` | Earlier exploratory run (latency figure left panel) |
| `results/study/governance_dev_20261017T182314Z_2a97d190.json` | 12-config re-execution (latency figure right panel) |
| `results/provenance/claim_registry.json` | Links every reported number to its source |
| `results/study/CONTAMINATED_RUNS.md` | Excluded/contaminated run log |
| `paper/make_prd_figures.py` | Figure generation script |
| `paper/make_figures.py` | Figure generation script |
| `paper/make_architecture_figure.py` | Architecture figure script |
| `paper/results/` | Ablation run JSON used by figure scripts |
| `tests/` | 102 provenance, governance, and consistency tests |
| `docs/images/` | Rendered PNG figures used in README |
| `MANUSCRIPT_RELEASE.md` | This file — manuscript availability statement |

## What is NOT in the public repository

| Item | Reason |
|------|--------|
| `paper/*.tex` | Excluded by `.gitignore` (maintained separately) |
| `paper/*.bib` | Excluded by `.gitignore` |
| `paper/*.pdf` | Excluded by `.gitignore` |
| `paper/figures/` | Excluded by `.gitignore` (regenerable from scripts) |
| `paper/generated/` | Excluded by `.gitignore` (regenerable from scripts) |
| Validation split (79 scenarios) | Locked — requires independent label review |
| Test split (113 scenarios) | Locked — requires independent label review |
| `results/study/governance_dev_20261018T072638Z_13a891ae.*` | Contaminated concurrent-run; see CONTAMINATED_RUNS.md |

---

## How to obtain the manuscript

### Option A — GitHub release (recommended for readers)

A release will be created at `https://github.com/Somaskandan931/PromptAegis/releases`
containing the LaTeX source, bibliography, compiled PDF, figures, and checksums.

### Option B — Request from author

Contact: `somaskandan931@gmail.com` with subject `[PromptAegis] Manuscript Request`.

---

## Canonical research record

| Item | Value |
|------|-------|
| Repository | `https://github.com/Somaskandan931/PromptAegis` |
| Branch | `main` |
| Canonical run ID | `governance_dev_20261018T081010Z_9e7d0639` |
| Canonical run SHA-256 | `eebe2f501b1aac4901fb7bb187ab39323e82813a93950b2dd44560cf475bbe16` |
| `git_worktree_dirty` for canonical run | `false` |
| `gateway_sha256` for canonical run | `2a6051d7ac17dcd9103b26c08de1fea40105b5b6244a864d9048480643db7eb6` |
| Scenario file SHA-256 | `119400b9f0f198272f5970356dba646c7372dec131745b52ba94f5d6df80efd3` |
| Code revision at time of canonical run | `909a5b128b6f91826d3f68a684c07d4968f6c9c3` (short: `909a5b1`) |

---

## Run chronology

| Run ID | Gateway SHA | `git_worktree_dirty` | Role |
|--------|------------|---------------------|------|
| `056a4792` | `5d432035` | **true** | Earlier 4-config latency run (left panel Fig. 8); prior gateway version |
| `2a97d190` | `2a6051d7` | null | 12-config re-execution (right panel Fig. 8); same gateway as canonical |
| `13a891ae` | `2a6051d7` | null | Contaminated concurrent run; excluded |
| **`9e7d0639`** | **`2a6051d7`** | **false** | **Canonical run — all decision/effect tables and primary latency table** |

---

## Reproducibility command

From a clean checkout (any revision that includes `results/study/9e7d0639` result files):

```bash
python experiments/study/run_benchmark.py --split dev --all-configs
```

No API key, network access, or commercial service is required. All reported decision
and effect counts are deterministic given the scenario file hash and the code.

> **Note:** The manuscript's latency table (Tab. 7) is sourced from the **canonical run
> `9e7d0639`** — computed from raw call records: baseline median 56.4 ms, RBAC-only
> 56.6 ms, policy-only 148.8 ms, full 171.3 ms. These differ from the earlier exploratory
> run `056a4792` values (65.7/85.5/152.2/190.4 ms) due to a different gateway version.

---

## Manuscript artifact checksums (local, post-revision, MiKTeX 25.12)

These checksums are for the locally compiled artifacts. The `paper/` directory is not
tracked in Git; obtain these files via GitHub release or author request (see above).

| File | SHA-256 | Size |
|------|---------|------|
| `paper/PromptAegis_Governance_Study.pdf` (Master) | `101EE57BC4F37089E6F1969FD177EDB0CED218DF3FD8BA6819A5DC323D38A2EF` | 515,927 bytes |
| `paper/PromptAegis_Governance_Study.tex` (Master) | `922B368BA956067D6BB52E7023F3430DE61D9AAE294B10BC8F9110D9CFD37971` | 58,223 bytes |
| `paper/PromptAegis_Governance_Study_Anonymized.pdf` (Anonymized) | `6E1A9CE7A97FA9CC05A86DCFC6D252DD6337526A31FEFC120F913369F5084075` | 494,428 bytes |
| `paper/PromptAegis_Governance_Study_Anonymized.tex` (Anonymized) | `330DE42CD364F4BF1E150FDF583FD46FAF8DB1DBA1022673E12ADB81AFDFF9A9` | 58,183 bytes |
| `paper/references.bib` | `99EECBAB04EFCB743CA3E4F6C39DE2F457E2C191DA81CA2333F08D69134C7613` | 7,529 bytes |
| `paper/figures/fig_latency.pdf` | `FA6C788DA19975B963AD2D2D2A3A48D894EB219A6AA6F70298B3E35EC78E3710` | 17,362 bytes |
| `docs/images/fig_latency.png` | `0EC9C3377A3DC74F9B05A1C89979CE80142D712331FC3125A2E73A3FDD63A0E4` | 53,307 bytes |

Compilation: `pdflatex` × 3 + `bibtex` × 1 using `elsarticle` class (MiKTeX 25.12).
Result: 16 pages, 0 LaTeX errors, 0 undefined references, 0 overfull boxes.

---

## Held-out splits

The validation (79 scenarios) and test (113 scenarios) splits are **locked** and have not
been executed. The benchmark runner refuses to open them without a documented independent-review
record bound to the exact scenario SHA-256.

No pre-registration was filed before the development run. The development split was open
to the authors throughout gateway implementation.

---

## What a fresh clone provides

A `git clone https://github.com/Somaskandan931/PromptAegis` at HEAD provides:
- All gateway, runner, and sandbox source code
- Canonical benchmark run JSON and analysis
- Scenario set, manifest, and claim registry
- Figure generation scripts
- Public documentation and rendered figure images in `docs/images/`
- Manuscript TeX/PDF/figures are local-only (excluded by `.gitignore`)
- Validation and test splits (withheld by design)

Do not claim clean-clone reproducibility of the compiled PDF; it requires the manuscript
package, which is maintained separately from the code repository.
