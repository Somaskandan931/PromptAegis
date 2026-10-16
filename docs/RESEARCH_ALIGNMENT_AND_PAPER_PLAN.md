# Research Alignment and Paper Plan

## Purpose

This note aligns the current PromptAegis repository with the research proposal *Security and Governance Mechanisms for Tool-Using AI Agents* and the supplied sample papers. The proposal and samples are reference material; they do not override repository evidence or authorize deleting project artifacts.

## Scope alignment

The repository already implements the proposal's central idea: an external gateway mediates structured tool calls. Its implemented controls include tool permissions, parameter policies, risk-based approval, rate limiting, audit records, sandbox-style benchmark tools, and experiment runners. The project is therefore a concrete prototype and evaluation of tool-use governance.

The current repository also includes prompt-injection detection and broader application/UI work. For the paper, keep the research claim narrow: evaluate post-generation governance of tool invocations. Describe prompt-injection detection only where it provides context or is explicitly part of a measured experiment. Do not imply that the gateway prevents prompt injection or secures tools that bypass the gateway.

The proposal is a plan, not evidence. Its suggested 600-case dataset, component list, thresholds, and expected behaviors must not be reported as completed results unless supported by the checked-in benchmark, runner, raw events, and derived metrics. The manuscript's numerical claims must be reconciled against the canonical claim registry and current artifact provenance before submission.

## Recommended paper structure

The supplied empirical papers generally lead with a focused title, abstract, keywords, and introduction; establish prior work and a conceptual or theoretical frame; explain the research design and data; present results; then discuss implications, limitations, and conclusions. The engineering samples also make system architecture and implementation explicit. Use that pattern, adapted to this experimental computer-security study:

1. Title, abstract, and keywords
2. Introduction and research questions
3. Background and related work
4. Threat model and problem formulation
5. System architecture and governance policies
6. Benchmark, experimental design, configurations, and metrics
7. Results (with sample sizes, denominators, uncertainty, and latency distributions)
8. Discussion and mechanism attribution
9. Threats to validity and limitations
10. Conclusion and artifact/reproducibility statement
11. References and supplementary material

Keep the abstract self-contained: motivation, gap, approach, benchmark/design, principal measured results, and bounded conclusion. Avoid listing all implementation features there. Use tables and figures to make the experimental groups and results easy to compare. Match the final citation style and formatting to the target venue once selected; the sample papers are examples of scholarly organization, not a license to copy their text, figures, or exact layout.

## Evidence and manuscript corrections required

- Select one primary research question centered on security-utility trade-offs for mediated tool calls. Treat the existing subquestions as secondary only if the data support them.
- State exactly which evaluations are deterministic gateway replay, synthetic benchmark, or live-model pilot. Do not conflate them.
- Present isolated-control results separately from compound/full-pipeline results so rate limiting is not credited with semantic-policy effects.
- Report denominators and raw counts beside percentages, plus confidence intervals where available. Treat repeated templates as clustered observations when interpreting inferential tests.
- Describe policy calibration and benchmark construction, including overlap between rule development and evaluation. Do not claim out-of-sample generalization without a held-out set.
- Distinguish tool-call interception from completed task utility. A decision-level benchmark alone does not establish end-to-end agent task success.
- Verify each manuscript result against `results/provenance/claim_registry.json`, raw events, derived metrics, and the experiment scripts. Resolve any stale commit hashes, absolute paths, or mismatched result values before submission.
- Retain negative findings, bypass conditions, and semantic parameter-smuggling examples. These define the boundary of the contribution rather than detract from it.

## Document and artifact disposition

Keep the root README, active experiment reports, source code, benchmark inputs, raw and derived results, claim registry, and both manuscript variants. The master and anonymous submissions serve different publication workflows. Historical audits and superseded results are already grouped under `docs/archive/` and `results/historical/`; they document provenance and should not be removed as “unnecessary.” The sample PDFs remain external reference material and should not be copied into this repository.

No project files were deleted as part of this alignment pass. A future cleanup should remove only demonstrably generated duplicates after their source and reproducibility role are documented.

## Next paper-preparation steps

1. Freeze the research question, threat boundary, and target venue with the supervisor.
2. Reconcile the manuscript's claims and citation records with the canonical evidence files.
3. Revise the manuscript into the structure above and remove unsupported or overbroad claims.
4. Run the documented clean reproduction and preserve the resulting manifest before submission.
