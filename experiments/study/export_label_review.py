"""Export a blinded worksheet for independent review of benchmark labels.

Share only reviewer_worksheet.csv. Keep private_key.csv local and do not
commit it; it maps the opaque review IDs back to benchmark scenario IDs.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "backend/data/governance_benchmark/scenarios.json"
MANIFEST = ROOT / "backend/data/governance_benchmark/manifest.json"
DEFAULT_OUT = ROOT / "results/review"


def export(out_dir: Path) -> tuple[Path, Path]:
    scenario_bytes = SCENARIOS.read_bytes()
    digest = hashlib.sha256(scenario_bytes).hexdigest()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if digest != manifest.get("scenarios_sha256"):
        raise RuntimeError("Scenario file hash differs from manifest; reconcile before exporting review material.")
    rows = json.loads(scenario_bytes)
    out_dir.mkdir(parents=True, exist_ok=True)
    worksheet = out_dir / "reviewer_worksheet.csv"
    private_key = out_dir / "private_key.csv"
    order = list(range(len(rows)))
    secrets.SystemRandom().shuffle(order)
    used: set[str] = set()
    worksheet_rows = []
    key_rows = []
    for ix in order:
        row = rows[ix]
        review_id = secrets.token_hex(6)
        while review_id in used:
            review_id = secrets.token_hex(6)
        used.add(review_id)
        worksheet_rows.append({
            "review_id": review_id,
            "agent": row.get("agent", ""),
            "context_json": json.dumps(row.get("context", {}), sort_keys=True, ensure_ascii=False),
            "setup_json": json.dumps(row.get("setup", {}), sort_keys=True, ensure_ascii=False),
            "calls_json": json.dumps(row.get("calls", []), sort_keys=True, ensure_ascii=False),
            "untrusted_content": row.get("untrusted_content", ""),
            # Empty fields are for reviewers. Do not populate from the source labels.
            "reviewer_label": "",
            "reviewer_expected_decisions_json": "",
            "reviewer_expected_tool_effect": "",
            "reviewer_in_scope": "",
            "reviewer_ambiguous": "",
            "reviewer_rationale": "",
        })
        key_rows.append({"review_id": review_id, "scenario_id": row["scenario_id"],
                         "source_split": row.get("split", "")})
    fields = list(worksheet_rows[0]) if worksheet_rows else []
    with worksheet.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(worksheet_rows)
    with private_key.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["review_id", "scenario_id", "source_split"])
        writer.writeheader()
        writer.writerows(key_rows)
    (out_dir / "review_metadata.json").write_text(json.dumps({
        "scenarios_sha256": digest,
        "scenario_count": len(rows),
        "dataset_version": manifest.get("dataset_version"),
        "worksheet_sha256": hashlib.sha256(worksheet.read_bytes()).hexdigest(),
    }, indent=2) + "\n", encoding="utf-8")
    return worksheet, private_key


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    worksheet, key = export(args.out_dir.resolve())
    print(f"Reviewer copy (share this): {worksheet}")
    print(f"Private ID mapping (do not share/commit): {key}")
    print("No source labels, categories, threat names, or split assignments were copied into the reviewer worksheet.")


if __name__ == "__main__":
    main()
