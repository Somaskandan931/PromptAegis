# Overleaf setup
1. Upload this whole folder; main file PromptAegis_Governance_Study.tex; compile with pdfLaTeX + BibTeX (elsarticle class).
2. Keep figures/ next to the .tex file.
3. Figures: python make_figures.py results/study/governance_dev_20261017T182314Z_2a97d190.json <pilot llm_..._full.json>
4. results/study/governance_dev_20261017T182314Z_2a97d190.json = 12-configuration dev re-run on the delivered source (run 2a97d190). Re-run on your own machine at a frozen git commit before submission (python -m experiments.study.run_benchmark --split dev --config ...).
5. Verify the bib entries saltzer1975, sandhu1996, schneier1999, perez2022, camel2025 and the author list of progent2025.
6. Fill in author, funding, AI-use and CRediT declarations; confirm venue template.

7. Also upload paper/generated/prd_metrics_table.tex (included by the trade-off table) and the four new figures: fig_security_utility, fig_stage_attribution, fig_rate_limit, fig_latency. Regenerate with python make_prd_figures.py results/ablation_run.json ../results/study/governance_dev_20261017T150806Z_056a4792.json
