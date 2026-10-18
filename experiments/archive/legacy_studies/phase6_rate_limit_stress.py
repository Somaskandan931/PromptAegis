"""
Phase 6: Dedicated Rate-Limiting Stress Benchmark.
Evaluates the PromptAegis 60-second tumbling-window rate limiter under controlled load:
1. Threshold saturation verification across distinct tool quotas (5, 20, 100)
2. Boundary behavior (first call blocked at limit + 1)
3. Fixed-window reset behavior (advancing beyond 60s boundary resets counter)
4. Virtual clock determinism

Outputs results to results/raw/rate_limit_stress_events.json and results/derived/rate_limit_stress_metrics.json.
Generates findings for RATE_LIMIT_STRESS_REPORT.md.
"""
import json
import os
import sys
import time

# Ensure project root in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from experiments.common.config import AUDITED_COMMIT, DERIVED_DIR, RAW_DIR
from experiments.common.clock import ResearchExperimentClock, reset_to_production_clock, set_clock
from experiments.common.runner import ensure_initialized
from governance.legacy_interceptor import intercept
from governance.rate_limiter import reset_rate_limits, get_limit


def run_rate_limit_stress():
    print("================================================================")
    print("PromptAegis Phase 6: Rate Limiting Stress Benchmark")
    print("================================================================")

    role_map = ensure_initialized()
    agent_id = role_map.get("admin") or role_map.get("support")

    clock = ResearchExperimentClock(start_time=1790000000.0, step_seconds=0.1)
    set_clock(clock)
    reset_rate_limits()

    stress_tests = [
        {"tool": "execute_sql", "limit": 5, "requests": 15, "role": "admin"},
        {"tool": "update_customer", "limit": 20, "requests": 40, "role": "admin"},
        {"tool": "search_customer", "limit": 100, "requests": 150, "role": "admin"},
    ]

    all_events = []
    test_summaries = {}

    try:
        for test in stress_tests:
            tool = test["tool"]
            limit = test["limit"]
            req_count = test["requests"]
            role = test["role"]
            aid = role_map.get(role, agent_id)

            print(f"\nEvaluating '{tool}' (Limit: {limit}/60s, Invocations: {req_count})...")
            reset_rate_limits()
            clock.reset(1790000000.0)

            accepted = 0
            blocked = 0
            first_blocked_index = None

            for i in range(1, req_count + 1):
                clock.step()
                t0 = time.perf_counter()
                res = intercept(
                    agent_id=aid,
                    tool_name=tool,
                    arguments={"query": f"test_{i}"},
                    configuration="full",
                    experiment_run_id=f"stress_{tool}",
                )
                lat_ms = (time.perf_counter() - t0) * 1000.0
                dec = res["decision"]

                if dec in ("ALLOW", "REQUIRE_APPROVAL"):
                    accepted += 1
                elif dec == "RATE_LIMIT":
                    blocked += 1
                    if first_blocked_index is None:
                        first_blocked_index = i

                all_events.append({
                    "test": f"saturation_{tool}",
                    "invocation_index": i,
                    "tool": tool,
                    "limit": limit,
                    "decision": dec,
                    "reason": res["reason"],
                    "latency_ms": lat_ms,
                })

            test_summaries[tool] = {
                "configured_limit": limit,
                "total_requests": req_count,
                "accepted_count": accepted,
                "blocked_count": blocked,
                "saturation_threshold": limit,
                "first_blocked_at_index": first_blocked_index,
                "threshold_precision": "EXACT" if (accepted == limit and first_blocked_index == limit + 1) else "MISMATCH",
            }
            print(f"  Accepted: {accepted}/{req_count} | Blocked: {blocked}/{req_count} | First Blocked Call: #{first_blocked_index}")

        # 4. Window Reset Verification
        print("\nEvaluating Tumbling-Window Boundary Reset (advancing virtual clock +61s)...")
        tool = "execute_sql"
        limit = 5
        aid = role_map.get("admin", agent_id)

        reset_rate_limits()
        clock.reset(1790000000.0)

        # Fire 5 calls (saturate limit)
        for _ in range(5):
            clock.step()
            intercept(agent_id=aid, tool_name=tool, arguments={"query": "test"}, configuration="full")

        # 6th call in same window: must be RATE_LIMIT
        res_6 = intercept(agent_id=aid, tool_name=tool, arguments={"query": "test"}, configuration="full")
        call_6_blocked = (res_6["decision"] == "RATE_LIMIT")

        # Advance clock by 61 seconds into the next window
        clock.advance(61.0)
        res_post_window = intercept(agent_id=aid, tool_name=tool, arguments={"query": "test"}, configuration="full")
        post_window_accepted = (res_post_window["decision"] != "RATE_LIMIT")

        window_reset_test = {
            "initial_window_saturated": call_6_blocked,
            "advanced_seconds": 61.0,
            "next_window_reset_success": post_window_accepted,
            "next_window_decision": res_post_window["decision"],
        }
        print(f"  Initial Window Saturates at limit (Call #6 blocked): {call_6_blocked}")
        print(f"  Advancing virtual time by 61.0s resets bucket (New call allowed): {post_window_accepted}")

    finally:
        reset_to_production_clock()

    payload = {
        "commit": AUDITED_COMMIT,
        "experiment_name": "RATE_LIMIT_STRESS",
        "description": "Dedicated rate limiter saturation and boundary evaluation",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool_saturation_tests": test_summaries,
        "window_reset_test": window_reset_test,
    }

    raw_path = os.path.join(RAW_DIR, "rate_limit_stress_events.json")
    with open(raw_path, "w", encoding="utf-8") as fp:
        json.dump({"events": all_events}, fp, indent=2)

    derived_path = os.path.join(DERIVED_DIR, "rate_limit_stress_metrics.json")
    with open(derived_path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2)

    print(f"\n[OK] Rate limit stress metrics saved to {derived_path}")
    return payload


if __name__ == "__main__":
    run_rate_limit_stress()
