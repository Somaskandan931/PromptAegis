"""Latency protocol for the governance gateway (audit item R09).

The manuscript's original timings came from one run with configurations in fixed
blocks, and a rerun on the same code differed by more than an order of magnitude.
This script measures per-call time under a protocol that removes the known
confounders:

* warm-up passes whose timings are discarded (imports, caches, SQLite page cache);
* several measured repetitions, with the configuration order shuffled in every
  repetition from a recorded seed, so order cannot be mistaken for a control's cost;
* a fresh SQLite database and sandbox world for every (repetition, configuration)
  block, so database growth does not accumulate across configurations;
* raw per-call timings stored in the output file, next to the summary;
* three spans kept separate: gateway decision only, decision plus audit writes (the
  runner's historical "total_latency_ms"), and the whole ProtectedRuntime.call including
  the sandbox tool (measured here with a wall clock around the call);
* paired differences against the baseline, computed per call (same scenario, same
  call index) from the median over repetitions.

No model or network call is made. Results are exploratory descriptions of one
machine and say nothing about other hardware. The run is refused while another
benchmark holds the lock, because concurrent runs distort timings.

    python experiments/run_research.py latency --repetitions 10 --warmup 2
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
for _p in (ROOT, BACKEND):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from database.environments import environment_scope  # noqa: E402
from experiments.study.env import ENV_ID, build  # noqa: E402
from experiments.study.run_benchmark import (  # noqa: E402
    RESULT_DIR, SCENARIO_FILE, BenchmarkLock, _environment, _load, sha256,
)
from experiments.study.stats import percentile  # noqa: E402
from governance.audit_chain import AuditChain  # noqa: E402
from governance.gateway import CONFIGURATIONS, Gateway  # noqa: E402
from governance.rate_limiter import set_limit  # noqa: E402
from sandbox.agent import ScriptedAgent  # noqa: E402
from sandbox.runtime import ProtectedRuntime  # noqa: E402
from sandbox.world import SandboxWorld  # noqa: E402

PRIMARY = ("baseline", "rbac_only", "policy_only", "full")


def _one_block(config_name: str, scenarios: List[dict], chain_dir: Path) -> Dict[Tuple[str, int], Tuple[float, float, float]]:
    """Run every scenario once under one configuration; return {(scenario, call index): (gateway_ms, decision_plus_audit_ms, wall_ms)}.

    Only the first attempt of each call is timed (approval retries are excluded),
    matching the manuscript's definition.
    """
    env = build()
    timings: Dict[Tuple[str, int], Tuple[float, float, float]] = {}
    scripted = ScriptedAgent()
    try:
        chain = AuditChain(str(chain_dir / f"{uuid.uuid4().hex[:8]}_{config_name}.jsonl"))
        gateway = Gateway(configuration=config_name, chain=chain)
        for scenario in scenarios:
            env.reset_runtime_state()
            setup = scenario.get("setup") or {}
            if setup.get("tool") and setup.get("limit"):
                set_limit(setup["tool"], int(setup["limit"]), ENV_ID)
            world = SandboxWorld.fresh()
            runtime = ProtectedRuntime(gateway=gateway, world=world, approved_approvers={"sandbox_test_approver"})
            for index, call in enumerate(scripted.propose(scenario), start=1):
                agent_id = env.agent_ids[call.get("agent", scenario["agent"])]
                with environment_scope(ENV_ID):
                    t_wall = time.perf_counter()
                    rec = runtime.call(
                        agent_id, call.get("tool", ""), call.get("arguments", {}),
                        scenario_id=scenario["scenario_id"], seq=index, context=scenario.get("context"),
                        run_id="latency", correlation_id=f"latency:{scenario['scenario_id']}:{index}",
                    )
                    wall_ms = (time.perf_counter() - t_wall) * 1000.0
                    if rec.decision == "REQUIRE_APPROVAL" and scenario.get("approve_after_require"):
                        runtime.approve(rec.correlation_id, "sandbox_test_approver", agent_id=agent_id,
                                        tool=call.get("tool", ""), arguments=call.get("arguments", {}))
                        runtime.call(
                            agent_id, call.get("tool", ""), call.get("arguments", {}),
                            scenario_id=scenario["scenario_id"], seq=index, context=scenario.get("context"),
                            run_id="latency", correlation_id=f"latency:{scenario['scenario_id']}:{index}",
                        )
                timings[(scenario["scenario_id"], index)] = (rec.gateway_latency_ms, rec.total_latency_ms, wall_ms)
                advance_after = setup.get("advance_after_call")
                if advance_after == index:
                    env.clock.advance(float(setup.get("advance_seconds", 0)))
    finally:
        env.close()
    return timings


def _summary(values: List[float]) -> Dict[str, float]:
    return {
        "n": len(values), "median": percentile(values, 50), "mean": statistics.fmean(values),
        "p95": percentile(values, 95), "p99": percentile(values, 99),
        "min": min(values), "max": max(values),
    }


def run(split: str, configurations: List[str], warmup: int, repetitions: int, seed: int) -> Path:
    scenarios, manifest, _review = _load(split)
    rng = random.Random(seed)
    run_id = f"latency_{split}_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}_{uuid.uuid4().hex[:8]}"
    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="aegis_latency_") as tmp:
        chain_dir = Path(tmp)
        for w in range(warmup):                       # discarded
            order = list(configurations)
            rng.shuffle(order)
            for name in order:
                _one_block(name, scenarios, chain_dir)
            print(f"  warm-up {w + 1}/{warmup} done")

        raw: Dict[str, Dict[str, List[Dict[str, Any]]]] = {c: {} for c in configurations}
        orders: List[List[str]] = []
        for r in range(repetitions):
            order = list(configurations)
            rng.shuffle(order)
            orders.append(order)
            for name in order:
                block = _one_block(name, scenarios, chain_dir)
                for (sid, idx), (gw_ms, audit_ms, wall_ms) in block.items():
                    raw[name].setdefault(f"{sid}#{idx}", []).append(
                        {"rep": r, "gateway_decision_ms": gw_ms, "decision_plus_audit_ms": audit_ms,
                         "runtime_call_wall_ms": wall_ms})
            print(f"  repetition {r + 1}/{repetitions} order={order}")

    summary: Dict[str, Any] = {}
    per_call_median: Dict[str, Dict[str, float]] = {}
    for name in configurations:
        spans = {"gateway_decision_ms": "gateway_decision_ms", "decision_plus_audit_ms": "decision_plus_audit_ms",
                 "runtime_call_wall_ms": "runtime_call_wall_ms"}
        summary[name] = {out: _summary([x[key] for calls in raw[name].values() for x in calls])
                         for out, key in spans.items()}
        summary[name]["calls_per_repetition"] = len(raw[name])
        per_call_median[name] = {k: statistics.median(x["runtime_call_wall_ms"] for x in v)
                                 for k, v in raw[name].items()}

    paired: Dict[str, Any] = {}
    if "baseline" in configurations:
        base = per_call_median["baseline"]
        for name in configurations:
            if name == "baseline":
                continue
            diffs = [per_call_median[name][k] - base[k] for k in base if k in per_call_median[name]]
            paired[name] = {"vs": "baseline", "metric": "per-call median over repetitions, runtime_call_wall_ms",
                            "n_calls": len(diffs), "median_diff_ms": percentile(diffs, 50),
                            "p95_diff_ms": percentile(diffs, 95), "mean_diff_ms": statistics.fmean(diffs)}

    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                                  check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True,
                                    check=True).stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        revision, dirty = None, None

    result = {
        "study": "PromptAegis latency protocol (exploratory)", "run_id": run_id,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "split": split, "scenario_sha256": sha256(SCENARIO_FILE), "git_revision": revision,
        "git_worktree_dirty": dirty, "environment": _environment(),
        "protocol": {"warmup_passes": warmup, "repetitions": repetitions, "seed": seed,
                     "configuration_order_per_repetition": orders,
                     "fresh_database_per_block": True, "timed": "first-attempt calls only",
                     "model_or_network_time_included": False},
        "interpretation": "Exploratory timings from one machine; not a claim about other hardware or a performance guarantee.",
        "summary": summary, "paired_vs_baseline": paired, "raw_timings": raw,
    }
    out = RESULT_DIR / f"{run_id}.json"
    out.write_text(json.dumps(result, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
    shown = out.relative_to(ROOT) if ROOT in out.parents else out
    print(f"[OK] wrote {shown}")
    for name in configurations:
        t = summary[name]["runtime_call_wall_ms"]
        g = summary[name]["gateway_decision_ms"]
        print(f"  {name:>14}: call median={t['median']:.2f} ms p95={t['p95']:.2f} ms | decision median={g['median']:.2f} ms  (n={t['n']})")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--split", choices=("dev", "tune"), default="dev")
    parser.add_argument("--config", action="append", choices=tuple(CONFIGURATIONS), dest="configs",
                        help="Repeat to select configurations (default: the four primary ones).")
    parser.add_argument("--warmup", type=int, default=2, help="Discarded passes over all configurations.")
    parser.add_argument("--repetitions", type=int, default=10, help="Measured passes over all configurations.")
    parser.add_argument("--seed", type=int, default=0, help="Seed for the per-repetition configuration order.")
    args = parser.parse_args()
    if args.repetitions < 1 or args.warmup < 0:
        parser.error("repetitions must be >= 1 and warmup >= 0")
    configs = args.configs or list(PRIMARY)
    with BenchmarkLock():
        run(args.split, configs, args.warmup, args.repetitions, args.seed)


if __name__ == "__main__":
    main()
