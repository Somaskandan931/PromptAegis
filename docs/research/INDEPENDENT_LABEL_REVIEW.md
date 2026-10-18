# Independent benchmark label review

## Current state

The 376 scenarios in `backend/data/governance_benchmark/scenarios.json` are project-authored and author-labeled. Independent review has **not** been completed. Validation and test runs must remain locked until two independent reviewers finish the process below and an exact-hash review record is added. Do not create or edit that record on a reviewer's behalf.

## Prepare a blinded worksheet

From the repository root, run:

```powershell
python experiments\study\export_label_review.py
```

Send `results\review\reviewer_worksheet.csv` and `results\review\review_metadata.json` to each reviewer separately. Keep `results\review\private_key.csv` private and out of Git; `.gitignore` excludes the whole local review directory. The exporter randomizes row order, checks the dataset hash against its manifest, and omits scenario IDs, dataset labels, categories, threat names, split assignments, and the authored task-check oracle. It leaves independent judgment fields blank. Each export has new random review IDs; use the same worksheet file for both reviewers.

Give both reviewers the same frozen protocol and the same tool, agent-permission, context, and benchmark semantics. Reviewers must work independently and must not see the current labels, each other's answers, or study outcomes. At minimum each reviewer should fill:

- `reviewer_label`: `benign`, `adversarial`, or `ambiguous` based on the untrusted content and proposed tool call together.
- `reviewer_expected_decisions_json`: one `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, or `RATE_LIMIT` per call under the frozen full-gateway policy and call sequence.
- `reviewer_expected_tool_effect`: intended safe effect, or `none` if no effect should occur.
- `reviewer_in_scope`: whether the gateway has the information required to make the expected decision.
- `reviewer_ambiguous` and `reviewer_rationale`: explain uncertainty and cite the relevant rule/contract/permission.

These benchmark rows are structured proposed-action scenarios, not natural-language end-user tasks. This review covers action-level labels; it does not validate whether an LLM understood a natural-language task. An untrusted message asking an agent to ignore its task is not, by itself, enough to call a tool action malicious: assess the proposed action against available scenario evidence and the frozen permissions, contracts, and policies. For provenance-dependent cases, explicitly mark `reviewer_in_scope=false` when required provenance is absent from the gateway request. Do not force an in-scope security claim from information the gateway cannot observe.

## Adjudication and record

After both independent sheets are returned, merge them using the private key, report raw agreement for each label dimension, list disagreements, and have a third person adjudicate disagreements without changing the original reviewer entries. Preserve the two original files and the adjudication log. Then create `backend/data/governance_benchmark/independent_review.json` with the exact SHA-256 of the reviewed `scenarios.json`, reviewer count `2`, status `independently_reviewed`, and a concise description of blinding, rubric, disagreement handling, and reviewer independence. Only claim independent review after this has actually happened. Any scenario edit changes the hash and invalidates the record.

## Important limitation

The worksheet is a review aid, not evidence that review occurred. The code intentionally does not generate `independent_review.json` automatically. The paper must describe reviewers and agreement only after the review is completed and documented.
