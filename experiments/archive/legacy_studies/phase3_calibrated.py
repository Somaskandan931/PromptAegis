"""
Phase 3: Calibrated Policy Configuration Benchmark.
Evaluates the canonical 600-scenario benchmark through the REAL production gateway
under calibrated parameter validation policies:
1. SQL injection regex pattern matching on search query arguments
2. Restricted field modification blocking on update_customer arguments
3. Domain checking across both 'to' and 'recipient' parameters

NO synthetic latency offsets.
Measures real runtime latency (time.perf_counter).
Saves outputs to results/raw/calibrated_benchmark_events.json and results/derived/calibrated_metrics.json.
"""
import csv
import json
import os
import sys
import time
import uuid

# Ensure project root in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from experiments.common.config import AUDITED_COMMIT, DERIVED_DIR, EXPERIMENT_VERSION, RAW_DIR
from experiments.common.clock import ResearchExperimentClock, reset_to_production_clock, set_clock
from experiments.common.runner import (
    determine_blocking_stage,
    ensure_initialized,
    is_decision_correct,
    load_canonical_scenarios,
)
from experiments.common.metrics import compute_configuration_metrics
from database import db
from governance.legacy_interceptor import intercept
from governance.rate_limiter import reset_rate_limits


SQL_PATTERN_REGEX = r"(\b(UNION\s+ALL|UNION\s+SELECT|SELECT\s+.*\s+FROM|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM)\b|--|\bOR\b\s+['\"0-9a-zA-Z]+\s*=\s*['\"0-9a-zA-Z]+|\bWAITFOR\s+DELAY\b|;\s*SHUTDOWN)"
RESTRICTED_FIELDS = ["role", "is_admin", "password", "balance", "credit_limit", "salary", "ssn"]


def install_calibrated_policies():
    """Install fine-grained parameter validation policies for calibrated evaluation."""
    created_policy_ids = []
    
    # Policy 1: SQL Injection filter on query
    pid1 = f"pol_cal_{uuid.uuid4().hex[:6]}"
    db.create_policy(
        policy_id=pid1,
        name="Calibrated SQL Injection Filter",
        policy_type="parameter_based",
        action="DENY",
        description="Block SQL injection signatures in query parameters",
        condition={"param_key": "query", "regex_pattern": SQL_PATTERN_REGEX},
        priority=5,
    )
    created_policy_ids.append(pid1)

    # Policy 2: Restricted customer field modifications (scoped strictly to update_customer)
    pid2 = f"pol_cal_{uuid.uuid4().hex[:6]}"
    update_tool = db.get_tool_by_name("update_customer")
    target_tid = update_tool["tool_id"] if update_tool else None

    db.create_policy(
        policy_id=pid2,
        name="Calibrated Field Modification Guard",
        policy_type="parameter_based",
        action="DENY",
        description="Block unauthorized customer profile attribute tampering",
        target_tool_id=target_tid,
        condition={"param_key": "fields", "forbidden_values": RESTRICTED_FIELDS},
        priority=6,
    )
    created_policy_ids.append(pid2)

    return created_policy_ids


def remove_calibrated_policies(policy_ids):
    """Clean up calibrated policies after evaluation."""
    for pid in policy_ids:
        db.delete_policy(pid)


def run_phase3():
    print("================================================================")
    print("PromptAegis Phase 3: Calibrated Configuration Evaluation")
    print("================================================================")

    role_map = ensure_initialized()
    scenarios = load_canonical_scenarios()
    print(f"Loaded {len(scenarios)} canonical scenarios.")

    clock = ResearchExperimentClock(start_time=1790000000.0, step_seconds=0.05)
    set_clock(clock)
    reset_rate_limits()

    # Install calibrated parameter rules in the database
    installed_pids = install_calibrated_policies()
    print(f"Installed {len(installed_pids)} calibrated parameter policies in gateway database.")

    events = []
    latencies = []
    run_id = f"run_calibrated_{int(time.time())}"

    try:
        for sc in scenarios:
            sid = sc.get("scenario_id", str(uuid.uuid4()))
            cat = sc.get("category", "unknown")
            role = sc.get("agent_role", "support")
            tool = sc.get("expected_tool", "")
            args = sc.get("arguments", {})
            expected = sc.get("expected_decision", "DENY")
            agent_id = sc.get("agent_id") or role_map.get(role, role_map.get("support", ""))

            clock.step()
            t0 = time.perf_counter()
            res = intercept(
                agent_id=agent_id,
                tool_name=tool,
                arguments=args,
                configuration="full",
                experiment_run_id=run_id,
            )
            lat_ms = (time.perf_counter() - t0) * 1000.0

            actual = res["decision"]
            reason = res["reason"]
            correct = is_decision_correct(expected, actual)
            stage = determine_blocking_stage(actual, reason)

            events.append({
                "scenario_id": sid,
                "category": cat,
                "configuration": "calibrated",
                "agent_role": role,
                "requested_tool": tool,
                "expected_decision": expected,
                "actual_decision": actual,
                "is_correct": 1 if correct else 0,
                "reason": reason,
                "first_blocking_stage": stage,
                "latency_ms": lat_ms,
            })
            latencies.append(lat_ms)

    finally:
        remove_calibrated_policies(installed_pids)
        reset_to_production_clock()

    metrics = compute_configuration_metrics(events, latencies)

    print("\n--- Calibrated Evaluation Outcomes ---")
    print(f"ASR:  {metrics['attack_success_rate']:.1%} ({metrics['attacks_allowed']} allowed / {metrics['attack_scenarios']} attacks)")
    print(f"LTCR: {metrics['legitimate_task_completion_rate']:.1%} ({metrics['legitimate_allowed']} allowed / {metrics['legitimate_scenarios']} legitimate)")
    print(f"FPR:  {metrics['false_positive_rate']:.1%}")
    print(f"Median Latency: {metrics['latency_median_ms']:.2f} ms")
    print(f"Mean Latency:   {metrics['latency_mean_ms']:.2f} ms")

    # Save raw events
    raw_path = os.path.join(RAW_DIR, "calibrated_benchmark_events.json")
    with open(raw_path, "w", encoding="utf-8") as fp:
        json.dump({"run_id": run_id, "commit": AUDITED_COMMIT, "events": events, "metrics": metrics}, fp, indent=2)

    # Save derived metrics
    derived_json_path = os.path.join(DERIVED_DIR, "calibrated_metrics.json")
    with open(derived_json_path, "w", encoding="utf-8") as fp:
        json.dump(metrics, fp, indent=2)

    print(f"\n[OK] Calibrated metrics saved to {raw_path} and {derived_json_path}")
    return metrics


if __name__ == "__main__":
    run_phase3()
