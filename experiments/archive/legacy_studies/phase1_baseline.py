"""
Phase 1: Canonical Baseline & Governance Benchmark Runner.
Executes the canonical 600-scenario benchmark across:
- baseline (unmitigated reference)
- permission (RBAC-only)
- policy (policy regex & parameter constraints)
- full (standard full governance: rate limiting, RBAC, policy, risk scoring)
- hardened (full governance with pre-execution parameter normalization)

Under the deterministic ResearchExperimentClock.
Saves raw observations to results/raw/canonical_benchmark_events.json.
"""
import csv
import json
import os
import sys
import time

# Ensure project root in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from experiments.common.config import CANONICAL_CONFIGURATIONS, RAW_DIR
from experiments.common.runner import BenchmarkRunner


def run_phase1():
    print("================================================================")
    print("PromptAegis Phase 1: Canonical Benchmark Execution")
    print("================================================================")
    print(f"Configurations: {CANONICAL_CONFIGURATIONS}")
    print(f"Output directory: {RAW_DIR}")

    runner = BenchmarkRunner(step_seconds=0.05, start_time=1790000000.0)
    results = runner.run_benchmark(
        configurations=CANONICAL_CONFIGURATIONS,
        save_raw=True,
        run_name="canonical_benchmark",
    )

    # Save summary JSON
    summary_path = os.path.join(RAW_DIR, "canonical_benchmark_summary.json")
    with open(summary_path, "w", encoding="utf-8") as fp:
        json.dump(results["summary"], fp, indent=2)
    print(f"[OK] Summary metrics saved to: {summary_path}")

    # Save events CSV for tabular analysis
    events_csv_path = os.path.join(RAW_DIR, "canonical_benchmark_events.csv")
    fieldnames = [
        "run_id", "commit_hash", "configuration", "scenario_id", "category",
        "agent_role", "requested_tool", "expected_decision", "actual_decision",
        "is_correct", "first_blocking_stage", "reason", "policy_id", "risk_score",
        "audit_call_id", "latency_ms", "virtual_timestamp"
    ]
    with open(events_csv_path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for ev in results["events"]:
            writer.writerow(ev)
    print(f"[OK] Events CSV saved to: {events_csv_path}")

    print("\n--- Summary Outcomes ---")
    for cfg, data in results["summary"].items():
        m = data["metrics"]
        print(f"[{cfg.upper():10}] ASR: {m['attack_success_rate']:.1%} | LTCR: {m['legitimate_task_completion_rate']:.1%} | FPR: {m['false_positive_rate']:.1%} | P50 Latency: {m['latency_median_ms']:.2f}ms")

    return results


if __name__ == "__main__":
    run_phase1()
