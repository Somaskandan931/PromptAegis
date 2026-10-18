"""Build claim-level provenance records from a saved governance replay."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = ROOT / "results" / "governance"
OUTPUT = ROOT / "results" / "provenance" / "claim_registry.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, help="Specific governance result JSON; defaults to newest file")
    args = parser.parse_args()
    candidates = sorted(DEFAULT_RESULTS.glob("governance_benchmark_*.json"), key=lambda p: p.stat().st_mtime)
    result_path = args.result or (candidates[-1] if candidates else None)
    if result_path is None or not result_path.is_file():
        raise SystemExit("No governance result JSON found; run experiments/run_governance_benchmark.py first.")
    result_path = result_path.resolve()
    result = json.loads(result_path.read_text(encoding="utf-8"))
    claims = []
    for configuration, record in result["configurations"].items():
        events = record["events"]
        expected_unsafe = [e for e in events if e["expected_decision"] != "ALLOW"]
        expected_allow = [e for e in events if e["expected_decision"] == "ALLOW"]
        metrics = record["metrics"]
        definitions = [
            ("unsafe_call_allow_rate", sum(e["actual_decision"] == "ALLOW" for e in expected_unsafe), len(expected_unsafe), metrics["unsafe_tool_call_allow_rate"]),
            ("legitimate_call_allow_rate", sum(e["actual_decision"] == "ALLOW" for e in expected_allow), len(expected_allow), metrics["legitimate_request_allow_rate"]),
            ("false_rejection_rate", sum(e["actual_decision"] != "ALLOW" for e in expected_allow), len(expected_allow), metrics["false_positive_rate"]),
            ("latency_median_ms", None, len(events), metrics["latency_median_ms"]),
            ("latency_p95_ms", None, len(events), metrics["latency_p95_ms"]),
            ("audit_coverage", metrics["audit_events"], len(events), metrics["audit_coverage"]),
        ]
        for metric, numerator, denominator, value in definitions:
            claims.append({
                "claim_id": f"CLM-GOV-{configuration.upper()}-{metric.upper()}",
                "status": "current_corrected_replay",
                "metric": metric,
                "value": value,
                "numerator": numerator,
                "denominator": denominator,
                "configuration": configuration,
                "scenario_count": len(events),
                "run_id": record["run_id"],
                "result_artifact": str(result_path.relative_to(ROOT)),
                "result_sha256": digest(result_path),
            })
    archived_commit = "f16fae2cffece5b032e47bb7dfc52220c2eae1fc"
    archived_trace_path = "results/historical/closed_loop_traces.csv"
    archived_trace = subprocess.run(
        ["git", "show", f"{archived_commit}:{archived_trace_path}"],
        cwd=ROOT, check=True, capture_output=True,
    ).stdout
    pilot_claims = [
        ("CLM-HIST-001", "model_compromise_rate", 4, 10, 0.4),
        ("CLM-HIST-002", "conditional_gateway_interception_rate", 3, 4, 0.75),
        ("CLM-HIST-003", "end_to_end_governed_breach_rate", 1, 10, 0.1),
        ("CLM-HIST-004", "benign_prompt_completion_rate", 10, 10, 1.0),
        ("CLM-HIST-007", "mean_gateway_to_llm_latency_ratio", None, None, 0.2132),
        ("CLM-HIST-008", "active_tool_call_gateway_to_llm_latency_ratio", None, None, 0.318),
    ]
    historical_claims = [{
        "claim_id": claim_id,
        "status": "historical_exploratory_pilot",
        "metric": metric,
        "numerator": numerator,
        "denominator": denominator,
        "value": value,
        "source_commit": archived_commit,
        "source_artifact": archived_trace_path,
        "source_artifact_sha256": hashlib.sha256(archived_trace).hexdigest(),
        "interpretation": "Single-model 20-prompt pilot; do not pool with the corrected deterministic replay.",
    } for claim_id, metric, numerator, denominator, value in pilot_claims]
    registry = {
        "registry_version": "2.0",
        "study": result.get("study"),
        "created_at": result.get("created_at"),
        "git_revision": result.get("git_revision"),
        "git_worktree_dirty": result.get("git_worktree_dirty"),
        "scenario_hashes": result.get("scenario_files", {}),
        "source_hashes": result.get("source_files", {}),
        "claims": claims,
        "historical_claims": historical_claims,
        "excluded_historical_results": {
            "canonical_2026-10-16": "Not comparable: expected burst labels and cross-category rate-counter behavior differ from the corrected protocol.",
            "calibrated_policy": "Excluded: zero audit coverage and rate-limit saturation confound policy attribution.",
            "pilot_and_stress": "Historical exploratory artifacts; not merged into the corrected primary replay.",
        },
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
    print(f"[OK] Wrote {OUTPUT} ({len(claims)} current claims)")


if __name__ == "__main__":
    main()
