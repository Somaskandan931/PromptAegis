"""Run the controlled, sandbox-only tool-governance benchmark.

This is a deterministic gateway-replay experiment, not a live LLM-agent trial.
Scenarios are authored benchmark fixtures required to test tool authorization;
they are separate from the externally sourced prompt corpora used by the
standalone prompt-screening study.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import platform
import sys
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from api.auth import EnvironmentContext  # noqa: E402
from api.experiments import ExperimentRunRequest, _run_experiment  # noqa: E402
from api.governance import seed_defaults  # noqa: E402
from database import db  # noqa: E402
from database.db import init_db  # noqa: E402
from database.environments import EnvironmentRegistry, environment_scope  # noqa: E402
from governance.rate_limiter import reset_rate_limits  # noqa: E402
from governance.clock import ResearchExperimentClock, reset_to_production_clock, set_clock  # noqa: E402

SCENARIO_DIR = BACKEND / "data" / "benchmark"
OUTPUT_DIR = ROOT / "results" / "governance"
CONFIGURATIONS = ("baseline", "rbac_only", "policy_only", "full")
SCENARIO_FILES = (
    "legitimate.json",
    "unauthorized_tool.json",
    "parameter_manipulation.json",
    "prompt_injection.json",
    "privilege_escalation.json",
    "excessive_calls.json",
)
SOURCE_FILES = (
    "experiments/run_governance_benchmark.py",
    "backend/api/experiments.py",
    "backend/api/governance.py",
    "backend/governance/interceptor.py",
    "backend/governance/permission_engine.py",
    "backend/governance/policy_engine.py",
    "backend/governance/rate_limiter.py",
    "backend/governance/risk_scorer.py",
    "backend/database/db.py",
    "backend/database/environments.py",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rate-limit", type=int, default=10,
                        help="Calls per 60-second window for search_customer during the burst scenarios.")
    args = parser.parse_args()
    if args.rate_limit < 1:
        parser.error("--rate-limit must be positive")

    missing = [name for name in SCENARIO_FILES if not (SCENARIO_DIR / name).is_file()]
    if missing:
        raise SystemExit("Missing benchmark scenario files: " + ", ".join(missing))

    init_db(env="research_benchmark")
    env = EnvironmentRegistry.get_environment("research_benchmark", sanitize=True) or {}
    context = EnvironmentContext("research_benchmark", env, role="benchmark_runner")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    virtual_clock = ResearchExperimentClock(start_time=1790000000.0, step_seconds=0.0)
    set_clock(virtual_clock)

    configurations = {}
    scenario_metadata = {}
    for name in SCENARIO_FILES:
        for scenario in json.loads((SCENARIO_DIR / name).read_text(encoding="utf-8")):
            scenario_metadata[scenario["scenario_id"]] = {
                "agent_name": scenario.get("agent_name"),
                "tool_name": scenario.get("expected_tool"),
            }
    with environment_scope("research_benchmark"):
        seeded = seed_defaults(context)
        for configuration in CONFIGURATIONS:
            virtual_clock.reset(1790000000.0)
            reset_rate_limits("research_benchmark")
            request = ExperimentRunRequest(
                configuration=configuration,
                description="Controlled sandbox gateway replay; no external tool execution",
                burst_rate_limit=args.rate_limit,
            )
            result = _run_experiment(request)
            run = db.get_experiment_run(result["run_id"])
            events = run.get("events", []) if run else []
            for event in events:
                event.update(scenario_metadata.get(event.get("scenario_id"), {}))
            audit_rows = db.fetch_tool_calls(run_id=result["run_id"], limit=result["total_scenarios"] + 1)
            actual_agent_counts = Counter()
            for audit_row in audit_rows:
                agent = db.get_agent(audit_row["agent_id"])
                actual_agent_counts[agent["name"] if agent else "<missing-agent>"] += 1
            expected_agent_counts = Counter(
                metadata.get("agent_name") for metadata in scenario_metadata.values()
            )
            if actual_agent_counts != expected_agent_counts:
                raise RuntimeError(
                    f"Resolved-principal audit mismatch for {configuration}: "
                    f"expected {dict(expected_agent_counts)}, observed {dict(actual_agent_counts)}"
                )
            configurations[configuration] = {
                "run_id": result["run_id"],
                "scenario_count": result["total_scenarios"],
                "metrics": result["metrics"],
                "events": events,
                "actual_agent_counts": dict(actual_agent_counts),
            }
            print(f"[OK] {configuration}: {result['total_scenarios']} scenarios; "
                  f"unsafe_allow={result['metrics'].get('unsafe_tool_call_allow_rate')} "
                  f"legitimate_allow={result['metrics'].get('legitimate_request_allow_rate')} "
                  f"FPR={result['metrics'].get('false_positive_rate')} "
                  f"p95={result['metrics'].get('latency_p95_ms')} ms")

    reset_to_production_clock()

    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    outpath = OUTPUT_DIR / f"governance_benchmark_{timestamp}.json"
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, check=True,
            capture_output=True, text=True,
        ).stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        revision, dirty = None, None
    payload = {
        "study": "PromptAegis controlled tool-governance benchmark",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "execution_mode": "deterministic gateway replay; no LLM, external services, or real tool side effects",
        "scenario_origin": "researcher-authored controlled sandbox cases; not a naturalistic real-world dataset",
        "rate_limit_per_minute": args.rate_limit,
        "rate_limit_clock": "fixed virtual timestamp; counters reset before each configuration",
        "scenario_files": {name: sha256(SCENARIO_DIR / name) for name in SCENARIO_FILES},
        "source_files": {name: sha256(ROOT / name) for name in SOURCE_FILES},
        "git_revision": revision,
        "git_worktree_dirty": dirty,
        "runtime": {"python": sys.version, "platform": platform.platform()},
        "seed_status": seeded,
        "configurations": configurations,
        "interpretation_boundary": (
            "Measures policy decisions on proposed tool-call scenarios. It does not measure live-agent task completion, "
            "model variability, or real external tool execution. The legitimate-request allow rate is not a task-completion metric."
        ),
    }
    outpath.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[OK] Wrote {outpath}")


if __name__ == "__main__":
    main()
