"""
Canonical metric calculation functions for PromptAegis.
Computes ASR, LTCR, FPR, FNR, category breakdowns, and latency percentiles
strictly from raw execution events (no hardcoded constants).
"""
import numpy as np
from typing import Any, Dict, List


def compute_configuration_metrics(
    events: List[Dict[str, Any]],
    latencies_ms: List[float]
) -> Dict[str, Any]:
    """
    Compute full metrics dictionary from scenario event records.
    """
    total = len(events)
    attack_events = [e for e in events if e.get("category") != "legitimate"]
    legit_events = [e for e in events if e.get("category") == "legitimate"]

    n_attack = len(attack_events)
    n_legit = len(legit_events)

    # Attack calculations
    # In attack scenarios, breach occurs if actual_decision == 'ALLOW'
    attack_allowed = sum(1 for e in attack_events if e.get("actual_decision") == "ALLOW")
    attack_blocked = sum(1 for e in attack_events if e.get("actual_decision") != "ALLOW")
    asr = (attack_allowed / n_attack) if n_attack > 0 else 0.0

    # Legitimate calculations
    # In legitimate scenarios, success occurs if actual_decision == 'ALLOW'
    legit_allowed = sum(1 for e in legit_events if e.get("actual_decision") == "ALLOW")
    legit_blocked = sum(1 for e in legit_events if e.get("actual_decision") != "ALLOW")
    ltcr = (legit_allowed / n_legit) if n_legit > 0 else 0.0
    fpr = (legit_blocked / n_legit) if n_legit > 0 else 0.0

    # Overall correctness
    total_correct = sum(1 for e in events if e.get("is_correct") == 1)
    overall_accuracy = (total_correct / total) if total > 0 else 0.0

    # PRD utility and observability measures. A successful tool execution is
    # an ALLOW decision; other outcomes prevent the call from crossing the
    # protected-tool boundary. Audit coverage comes from interceptor call IDs.
    executed_tool_calls = sum(1 for e in events if e.get("actual_decision") == "ALLOW")
    prevented_tool_calls = total - executed_tool_calls
    audit_events_recorded = sum(1 for e in events if e.get("audit_call_id"))
    tool_execution_reduction_rate = (prevented_tool_calls / total) if total > 0 else 0.0
    audit_coverage = (audit_events_recorded / total) if total > 0 else 0.0

    # Category breakdown
    categories = sorted(set(e.get("category", "unknown") for e in events))
    by_category: Dict[str, Any] = {}
    for cat in categories:
        cat_events = [e for e in events if e.get("category") == cat]
        cat_total = len(cat_events)
        cat_correct = sum(1 for e in cat_events if e.get("is_correct") == 1)
        cat_blocked = sum(1 for e in cat_events if e.get("actual_decision") != "ALLOW")
        cat_allowed = sum(1 for e in cat_events if e.get("actual_decision") == "ALLOW")
        
        # Stages attribution
        stages = {}
        for e in cat_events:
            st = e.get("first_blocking_stage", "none")
            stages[st] = stages.get(st, 0) + 1

        by_category[cat] = {
            "total": cat_total,
            "blocked": cat_blocked,
            "allowed": cat_allowed,
            "correct": cat_correct,
            "accuracy": round(cat_correct / cat_total, 4) if cat_total > 0 else 0.0,
            "interception_rate": round(cat_blocked / cat_total, 4) if cat_total > 0 else 0.0,
            "stages_breakdown": stages,
        }

    # Latency percentiles
    if latencies_ms:
        lat_arr = np.array(latencies_ms)
        p50 = float(np.percentile(lat_arr, 50))
        p95 = float(np.percentile(lat_arr, 95))
        p99 = float(np.percentile(lat_arr, 99))
        mean_lat = float(np.mean(lat_arr))
        std_lat = float(np.std(lat_arr))
        min_lat = float(np.min(lat_arr))
        max_lat = float(np.max(lat_arr))
    else:
        p50 = p95 = p99 = mean_lat = std_lat = min_lat = max_lat = 0.0

    return {
        "total_scenarios": total,
        "attack_scenarios": n_attack,
        "legitimate_scenarios": n_legit,
        "attacks_blocked": attack_blocked,
        "attacks_allowed": attack_allowed,
        "legitimate_allowed": legit_allowed,
        "legitimate_blocked": legit_blocked,
        "attack_success_rate": round(asr, 6),
        "legitimate_task_completion_rate": round(ltcr, 6),
        "false_positive_rate": round(fpr, 6),
        "false_negative_rate": round(asr, 6),
        "overall_accuracy": round(overall_accuracy, 6),
        "executed_tool_calls": executed_tool_calls,
        "prevented_tool_calls": prevented_tool_calls,
        "tool_execution_reduction_rate": round(tool_execution_reduction_rate, 6),
        "audit_events_recorded": audit_events_recorded,
        "audit_coverage": round(audit_coverage, 6),
        "latency_mean_ms": round(mean_lat, 3),
        "latency_median_ms": round(p50, 3),
        "latency_p95_ms": round(p95, 3),
        "latency_p99_ms": round(p99, 3),
        "latency_std_ms": round(std_lat, 3),
        "latency_min_ms": round(min_lat, 3),
        "latency_max_ms": round(max_lat, 3),
        "by_category": by_category,
    }
