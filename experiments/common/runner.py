"""
Deterministic benchmark runner for PromptAegis.
Executes scenarios through the real production gateway pipeline in-process
using the deterministic ResearchExperimentClock.
"""
import glob
import json
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from experiments.common.config import (
    AUDITED_COMMIT,
    BENCHMARK_DIR,
    CANONICAL_BENCHMARK_FILES,
    EXPERIMENT_VERSION,
    RAW_DIR,
)
from experiments.common.clock import (
    ResearchExperimentClock,
    get_clock,
    reset_to_production_clock,
    set_clock,
)

# Backend imports
from database import db
from governance.legacy_interceptor import intercept
from governance.rate_limiter import reset_rate_limits
from api.governance import seed_defaults


def ensure_initialized() -> Dict[str, str]:
    """Ensure database schema and default seeds exist. Returns role -> agent_id mapping."""
    db.init_db()
    seed_defaults()
    agents = db.list_agents()
    role_to_agent: Dict[str, str] = {}
    
    # Priority mapping for support role: prefer CustomerSupportAgent
    for a in agents:
        if a["name"] == "CustomerSupportAgent":
            role_to_agent["support"] = a["agent_id"]
        elif a["name"] == "AdminAgent":
            role_to_agent["admin"] = a["agent_id"]
        elif a["name"] == "UnrestrictedAgent":
            role_to_agent["baseline"] = a["agent_id"]

    # Fallback for any unmapped roles
    for a in agents:
        role = a.get("role", "default")
        if role not in role_to_agent:
            role_to_agent[role] = a["agent_id"]

    return role_to_agent


def load_canonical_scenarios(selected_files: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Load canonical benchmark scenarios from disk."""
    files = selected_files or CANONICAL_BENCHMARK_FILES
    scenarios: List[Dict[str, Any]] = []
    for fname in files:
        fpath = os.path.join(BENCHMARK_DIR, fname)
        if not os.path.exists(fpath):
            raise FileNotFoundError(f"Canonical benchmark file not found: {fpath}")
        with open(fpath, "r", encoding="utf-8") as fp:
            data = json.load(fp)
            scenarios.extend(data)
    return scenarios


def determine_blocking_stage(decision: str, reason: str) -> str:
    """Identify the exact security mechanism stage responsible for the decision."""
    if decision == "RATE_LIMIT":
        return "rate_limiter"
    elif decision == "DENY":
        if "UNKNOWN_TOOL" in reason or "PERMISSION_DENIED" in reason:
            return "permission_engine"
        elif "POLICY" in reason or "VIOLATION" in reason or "ROLE_RESTRICTION" in reason:
            return "policy_engine"
        return "permission_engine"
    elif decision == "REQUIRE_APPROVAL":
        if "APPROVAL_REQUIRED" in reason or "HIGH_RISK" in reason:
            return "risk_scorer"
        elif "POLICY" in reason:
            return "policy_engine"
        return "risk_scorer"
    elif decision == "ALLOW":
        return "none"
    return "unknown"


def is_decision_correct(expected: str, actual: str) -> bool:
    """
    Check if actual decision matches expectation.
    For attack scenarios, expected is DENY or RATE_LIMIT:
    Blocking via DENY, RATE_LIMIT, or REQUIRE_APPROVAL is considered successful containment.
    """
    if expected in ("DENY", "RATE_LIMIT"):
        return actual in ("DENY", "RATE_LIMIT", "REQUIRE_APPROVAL")
    elif expected == "ALLOW":
        return actual == "ALLOW"
    return actual == expected


class BenchmarkRunner:
    """Orchestrates deterministic benchmark runs across configurations."""

    def __init__(self, step_seconds: float = 0.05, start_time: float = 1790000000.0):
        self.step_seconds = step_seconds
        self.start_time = start_time
        self.clock = ResearchExperimentClock(start_time=start_time, step_seconds=step_seconds)
        self.role_map = ensure_initialized()

    def run_benchmark(
        self,
        configurations: Optional[List[str]] = None,
        scenarios: Optional[List[Dict[str, Any]]] = None,
        save_raw: bool = True,
        run_name: str = "canonical",
    ) -> Dict[str, Any]:
        """
        Run the complete benchmark across specified configurations.
        """
        configs = configurations or ["baseline", "permission", "policy", "full"]
        bench_scenarios = scenarios or load_canonical_scenarios()
        run_id = f"run_{run_name}_{int(time.time())}"

        # Activate deterministic research clock
        set_clock(self.clock)

        all_events: List[Dict[str, Any]] = []
        runs_summary: Dict[str, Any] = {}

        try:
            for cfg in configs:
                # Reset rate limits and clock before each configuration for strict independence
                reset_rate_limits()
                self.clock.reset(self.start_time)

                # Configure virtual clock step based on traffic regime:
                # full_normalized uses 70s spacing so requests do not artificially saturate rate limits
                # full_burst and hardened use 0.05s spacing to evaluate high-frequency burst behavior
                if cfg == "full_normalized":
                    self.clock.step_seconds = 70.0
                    interceptor_cfg = "full"
                elif cfg in ("full_burst", "full"):
                    self.clock.step_seconds = 0.05
                    interceptor_cfg = "full"
                elif cfg == "rbac_only":
                    self.clock.step_seconds = 0.05
                    interceptor_cfg = "rbac_only"
                elif cfg == "policy_only":
                    self.clock.step_seconds = 0.05
                    interceptor_cfg = "policy_only"
                else:
                    self.clock.step_seconds = 0.05
                    interceptor_cfg = cfg

                cfg_events: List[Dict[str, Any]] = []
                cfg_latencies: List[float] = []

                for sc in bench_scenarios:
                    sid = sc.get("scenario_id", str(uuid.uuid4()))
                    cat = sc.get("category", "unknown")
                    role = sc.get("agent_role", "support")
                    tool = sc.get("expected_tool", "")
                    args = sc.get("arguments", {})
                    expected = sc.get("expected_decision", "DENY")
                    agent_id = sc.get("agent_id") or self.role_map.get(role, self.role_map.get("support", ""))

                    # Deterministically advance research clock
                    virtual_ts = self.clock.step()

                    # High-precision real latency boundary
                    t0 = time.perf_counter()
                    intercept_result = intercept(
                        agent_id=agent_id,
                        tool_name=tool,
                        arguments=args,
                        configuration=interceptor_cfg,
                        experiment_run_id=run_id,
                        context={"environment": "research_benchmark", "session_state": "approved"},
                    )
                    measured_latency_ms = (time.perf_counter() - t0) * 1000.0

                    actual = intercept_result["decision"]
                    reason = intercept_result["reason"]
                    policy_id = intercept_result["policy_id"]
                    risk_score = intercept_result["risk_score"]
                    correct = is_decision_correct(expected, actual)
                    stage = intercept_result.get("first_blocking_stage") or determine_blocking_stage(actual, reason)
                    stage_evals = intercept_result.get("stage_evaluations", {})

                    event_record = {
                        "run_id": run_id,
                        "commit_hash": AUDITED_COMMIT,
                        "experiment_version": EXPERIMENT_VERSION,
                        "virtual_timestamp": virtual_ts,
                        "real_timestamp": time.time(),
                        "scenario_id": sid,
                        "category": cat,
                        "configuration": cfg,
                        "traffic_regime": "normalized" if cfg == "full_normalized" else "burst",
                        "agent_role": role,
                        "agent_id": agent_id,
                        "requested_tool": tool,
                        "arguments": args,
                        "expected_decision": expected,
                        "actual_decision": actual,
                        "is_correct": 1 if correct else 0,
                        "reason": reason,
                        "policy_id": policy_id,
                        "audit_call_id": intercept_result.get("call_id", ""),
                        "context": {"environment": "research_benchmark", "session_state": "approved"},
                        "risk_score": risk_score,
                        "first_blocking_stage": stage,
                        "blocking_mechanism": stage,
                        "blocking_reason": reason,
                        "rate_limit_state": stage_evals.get("rate_limiter", {}),
                        "permission_result": stage_evals.get("permission_engine", {}),
                        "policy_result": stage_evals.get("policy_engine", {}),
                        "risk_result": stage_evals.get("risk_scorer", {}),
                        "latency_ms": measured_latency_ms,
                    }

                    cfg_events.append(event_record)
                    cfg_latencies.append(measured_latency_ms)

                all_events.extend(cfg_events)

                # Compute configuration metrics
                from experiments.common.metrics import compute_configuration_metrics
                cfg_metrics = compute_configuration_metrics(cfg_events, cfg_latencies)
                runs_summary[cfg] = {
                    "configuration": cfg,
                    "traffic_regime": "normalized" if cfg == "full_normalized" else "burst",
                    "total_scenarios": len(cfg_events),
                    "metrics": cfg_metrics,
                }

        finally:
            # Restore production runtime clock
            reset_to_production_clock()

        result_payload = {
            "run_id": run_id,
            "commit_hash": AUDITED_COMMIT,
            "experiment_version": EXPERIMENT_VERSION,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "configurations": configs,
            "total_events": len(all_events),
            "summary": runs_summary,
            "events": all_events,
        }

        if save_raw:
            raw_path = os.path.join(RAW_DIR, f"{run_name}_events.json")
            with open(raw_path, "w", encoding="utf-8") as fp:
                json.dump(result_payload, fp, indent=2)
            print(f"[OK] Raw benchmark events saved to: {raw_path}")

        return result_payload
