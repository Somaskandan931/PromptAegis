"""
Experiment execution API (PRD FR-10, FR-11, FR-12, FR-13).
Routes:
  POST /experiments/run                - Execute a benchmark experiment
  GET  /experiments                    - List experiment runs
  GET  /experiments/{run_id}           - Get run details + events
  GET  /experiments/{run_id}/export    - Export results as CSV
"""
import csv
import io
import json
import os
import statistics
import uuid
import numpy as np
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from database import db
from database.environments import environment_scope, get_current_environment
from governance.interceptor import intercept
from api.auth import EnvironmentContext, get_authenticated_environment

router = APIRouter()

_BENCHMARK_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "benchmark")


class ExperimentRunRequest(BaseModel):
    configuration: str = Field(..., pattern="^(baseline|permission|rbac_only|policy|policy_only|full|full_governance|hardened|full_burst|full_normalized)$")
    description: str = ""
    scenario_categories: List[str] = Field(default_factory=list)
    max_scenarios: int = 0
    burst_rate_limit: int = Field(default=10, ge=1)


@router.post("/experiments/run", tags=["experiments"])
def run_experiment(
    body: ExperimentRunRequest,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    if env_ctx.environment_id not in ("research_benchmark", "local_dev"):
        raise HTTPException(
            status_code=403,
            detail={"error": "EXPERIMENT_ENVIRONMENT_FORBIDDEN",
                    "message": "Experiments are limited to research_benchmark and local_dev."},
        )
    with environment_scope(env_ctx.environment_id):
        return _run_experiment(body)


def _run_experiment(body: ExperimentRunRequest):
    run_id = f"run_{uuid.uuid4().hex[:12]}"
    desc = body.description or f"{body.configuration} configuration experiment"
    db.create_experiment_run(run_id, body.configuration, desc)

    # Reset rate limit counters for reproducibility (PRD NFR: every experiment should be reproducible)
    with db.get_conn() as conn:
        conn.execute("DELETE FROM rate_limit_counters")

    scenarios = _load_scenarios(body.scenario_categories)
    if body.max_scenarios > 0:
        scenarios = scenarios[:body.max_scenarios]

    if not scenarios:
        db.complete_experiment_run(run_id, 0, {"error": "No scenarios found"})
        raise HTTPException(404, "No benchmark scenarios found. Ensure data/benchmark/ JSON files exist.")


    # Resolve exact scenario principals first. A role can map to multiple
    # registered agents with different grants, so selecting the first row for
    # a role makes benchmark results depend on database insertion order.
    agents = db.list_agents()
    agent_name_map = {a.get("name"): a["agent_id"] for a in agents if a.get("name")}
    role_map: Dict[str, str] = {}
    for a in agents:
        role = a.get("role", "default")
        if role not in role_map:
            role_map[role] = a["agent_id"]
    # fallback
    first_agent_id = agents[0]["agent_id"] if agents else ""

    events = []
    latencies = []

    # Sort scenarios: run legitimate and attack categories before excessive_calls
    # so rate counters for support agent aren't contaminated
    non_excessive = [s for s in scenarios if s.get("category") != "excessive_calls"]
    excessive = [s for s in scenarios if s.get("category") == "excessive_calls"]
    ordered_scenarios = non_excessive + excessive

    for scenario in ordered_scenarios:
        sid = scenario.get("scenario_id", str(uuid.uuid4()))
        agent_role = scenario.get("agent_role", "support")
        requested_agent_id = scenario.get("agent_id")
        requested_agent_name = scenario.get("agent_name")
        if requested_agent_id:
            agent_id = requested_agent_id
            if not db.get_agent(agent_id):
                raise ValueError(f"Scenario {sid} names unknown agent_id {agent_id!r}.")
        elif requested_agent_name:
            agent_id = agent_name_map.get(requested_agent_name)
            if not agent_id:
                raise ValueError(
                    f"Scenario {sid} names unregistered agent {requested_agent_name!r}; "
                    "refusing role-based fallback."
                )
        else:
            agent_id = role_map.get(agent_role, first_agent_id)
        tool_name = scenario.get("expected_tool", "")
        arguments = scenario.get("arguments", {})
        expected = scenario.get("expected_decision", "DENY")
        category = scenario.get("category", "unknown")

        # Isolate the rate-limit mechanism: normal scenario calls receive a
        # cap high enough not to interfere with the 100-case category batches.
        # Only the dedicated burst sequence uses the experimental low cap.
        if body.configuration != "baseline":
            from governance.rate_limiter import set_limit
            limit = body.burst_rate_limit if category == "excessive_calls" else 10_000
            set_limit(tool_name, limit)

        if not agent_id or not tool_name:
            raise ValueError(
                f"Scenario {sid!r} has no resolvable agent or tool; refusing to silently omit it."
            )

        runtime_context = scenario.get("context")
        if not isinstance(runtime_context, dict):
            runtime_context = {
                "environment": get_current_environment(),
                "session_state": "approved",
            }

        result = intercept(
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
            configuration=body.configuration,
            experiment_run_id=run_id,
            context=runtime_context,
        )

        actual = result["decision"]
        latency = result["latency_ms"]
        correct = _is_correct(expected, actual)

        event_id = str(uuid.uuid4())
        db.insert_experiment_event(event_id, run_id, sid, category, expected, actual, latency, correct)
        resolved_agent = db.get_agent(agent_id)
        events.append({"scenario_id": sid, "category": category, "expected": expected,
                       "actual": actual, "correct": correct, "latency_ms": latency,
                       "agent_id": agent_id,
                       "agent_name": resolved_agent.get("name") if resolved_agent else None,
                       "context": runtime_context})
        latencies.append(latency)

    audit_count = len(db.fetch_tool_calls(run_id=run_id, limit=len(events) + 1))
    metrics = _compute_metrics(events, latencies, audit_count=audit_count)
    db.complete_experiment_run(run_id, len(events), metrics)
    return {"run_id": run_id, "configuration": body.configuration,
            "total_scenarios": len(events), "metrics": metrics}



@router.get("/experiments", tags=["experiments"])
def list_experiments(env_ctx: EnvironmentContext = Depends(get_authenticated_environment)):
    if env_ctx.environment_id not in ("research_benchmark", "local_dev"):
        raise HTTPException(status_code=403, detail="Experiments are not available in this environment.")
    with environment_scope(env_ctx.environment_id):
        return db.list_experiment_runs()


@router.get("/experiments/{run_id}", tags=["experiments"])
def get_experiment(run_id: str, env_ctx: EnvironmentContext = Depends(get_authenticated_environment)):
    if env_ctx.environment_id not in ("research_benchmark", "local_dev"):
        raise HTTPException(status_code=403, detail="Experiments are not available in this environment.")
    with environment_scope(env_ctx.environment_id):
        run = db.get_experiment_run(run_id)
        if not run:
            raise HTTPException(404, f"Run '{run_id}' not found.")
        return run


@router.get("/experiments/{run_id}/export", tags=["experiments"])
def export_experiment(run_id: str, env_ctx: EnvironmentContext = Depends(get_authenticated_environment)):
    if env_ctx.environment_id not in ("research_benchmark", "local_dev"):
        raise HTTPException(status_code=403, detail="Experiments are not available in this environment.")
    with environment_scope(env_ctx.environment_id):
        run = db.get_experiment_run(run_id)
    if not run:
        raise HTTPException(404, f"Run '{run_id}' not found.")
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "scenario_id", "category", "expected_decision",
        "actual_decision", "correct", "latency_ms"])
    writer.writeheader()
    for event in run.get("events", []):
        writer.writerow({
            "scenario_id": event.get("scenario_id"),
            "category": event.get("category"),
            "expected_decision": event.get("expected_decision"),
            "actual_decision": event.get("actual_decision"),
            "correct": event.get("correct"),
            "latency_ms": event.get("latency_ms"),
        })
    output.seek(0)
    fname = f"experiment_{run_id}_{run['configuration']}.csv"
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={fname}"})


def _load_scenarios(categories: List[str]) -> List[Dict]:
    all_scenarios = []
    if not os.path.isdir(_BENCHMARK_DIR):
        return []
    for fname in sorted(os.listdir(_BENCHMARK_DIR)):
        if not fname.endswith(".json"):
            continue
        if categories:
            cat = fname.replace(".json", "")
            if cat not in categories:
                continue
        fpath = os.path.join(_BENCHMARK_DIR, fname)
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    all_scenarios.extend(data)
        except Exception:
            continue
    return all_scenarios


def _is_correct(expected: str, actual: str) -> bool:
    return expected == actual


def _compute_metrics(events: List[Dict], latencies: List[float], audit_count: int = 0) -> Dict[str, Any]:
    if not events:
        return {}
    attack_events = [e for e in events if e["expected"] != "ALLOW"]
    legit_events = [e for e in events if e["expected"] == "ALLOW"]
    unsafe_allowed = [e for e in attack_events if e["actual"] == "ALLOW"]
    legit_allowed = [e for e in legit_events if e["actual"] == "ALLOW"]
    legit_blocked = [e for e in legit_events if e["actual"] != "ALLOW"]
    unsafe_allow_rate = len(unsafe_allowed) / len(attack_events) if attack_events else 0.0
    legitimate_allow_rate = len(legit_allowed) / len(legit_events) if legit_events else 1.0
    fpr = len(legit_blocked) / len(legit_events) if legit_events else 0.0
    p95 = float(np.percentile(latencies, 95, method="linear")) if latencies else 0.0
    p99 = float(np.percentile(latencies, 99, method="linear")) if latencies else 0.0
    mean_lat = statistics.mean(latencies) if latencies else 0.0
    median_lat = statistics.median(latencies) if latencies else 0.0
    categories_set = set(e["category"] for e in events)
    by_category = {}
    for cat in categories_set:
        cat_events = [e for e in events if e["category"] == cat]
        cat_correct = [e for e in cat_events if e["correct"]]
        by_category[cat] = {"total": len(cat_events), "correct": len(cat_correct),
                            "accuracy": round(len(cat_correct) / len(cat_events), 4) if cat_events else 0.0}
    return {
        "unsafe_tool_call_allow_rate": round(unsafe_allow_rate, 4),
        "legitimate_request_allow_rate": round(legitimate_allow_rate, 4),
        "false_positive_rate": round(fpr, 4),
        "latency_mean_ms": round(mean_lat, 3),
        "latency_median_ms": round(median_lat, 3),
        "latency_p95_ms": round(p95, 3),
        "latency_p99_ms": round(p99, 3),
        "audit_coverage": round(audit_count / len(events), 4) if events else 0.0,
        "audit_events": audit_count,
        "total_scenarios": len(events),
        "attack_scenarios": len(attack_events),
        "legitimate_scenarios": len(legit_events),
        "by_category": by_category,
    }
