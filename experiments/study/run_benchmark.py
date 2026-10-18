"""Run the canonical sandboxed governance benchmark.

Development/tuning splits are available for debugging. Validation and test are
locked until an independent review record bound to the exact scenario SHA is
present. No external model or network API is called by this runner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from governance.audit_chain import AuditChain, verify_chain  # noqa: E402
from governance.gateway import CONFIGURATIONS, Gateway  # noqa: E402
from sandbox.agent import ScriptedAgent  # noqa: E402
from sandbox.runtime import ProtectedRuntime  # noqa: E402
from sandbox.world import SandboxWorld  # noqa: E402
from database.environments import environment_scope  # noqa: E402
from governance.rate_limiter import set_limit  # noqa: E402
from experiments.study.env import ENV_ID, build  # noqa: E402

DATA_DIR = BACKEND / "data" / "governance_benchmark"
SCENARIO_FILE = DATA_DIR / "scenarios.json"
MANIFEST_FILE = DATA_DIR / "manifest.json"
RESULT_DIR = ROOT / "results" / "study"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(split: str) -> tuple[list[dict], dict, dict]:
    manifest = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
    digest = sha256(SCENARIO_FILE)
    if digest != manifest.get("scenarios_sha256"):
        raise RuntimeError("Scenario file hash does not match its manifest; regenerate or reconcile it.")
    scenarios = json.loads(SCENARIO_FILE.read_text(encoding="utf-8"))
    if len(scenarios) != manifest.get("scenario_count"):
        raise RuntimeError("Scenario count does not match its manifest.")
    split_rows = [s for s in scenarios if s.get("split") == split]
    if not split_rows:
        raise ValueError(f"No scenarios in split {split!r}.")
    group_splits: Dict[str, set] = {}
    gateway_splits: Dict[str, set] = {}
    for s in scenarios:
        group_splits.setdefault(s["group_id"], set()).add(s["split"])
        gateway_splits.setdefault(s["gateway_key"], set()).add(s["split"])
    leakage = [g for g, splits in group_splits.items() if len(splits) != 1]
    leakage += [k for k, splits in gateway_splits.items() if len(splits) != 1]
    if leakage:
        raise RuntimeError(f"Grouped-split leakage detected for {len(leakage)} groups/keys.")

    review_path = DATA_DIR / "independent_review.json"
    review = json.loads(review_path.read_text(encoding="utf-8")) if review_path.exists() else {}
    if split in {"validation", "test"}:
        if (review.get("scenarios_sha256") != digest or
                int(review.get("independent_reviewer_count", 0)) < 2 or
                review.get("labels_status") != "independently_reviewed"):
            raise RuntimeError(
                f"Refusing to open {split!r}: add a two-reviewer independent_review.json "
                "bound to the current scenarios_sha256 after the labels are reviewed."
            )
    return split_rows, manifest, review


def _task_success(check: Any, world: SandboxWorld, records: List[dict]) -> Any:
    if not isinstance(check, dict):
        return None
    kind = check.get("kind")
    if kind == "search_hits":
        if not records or not isinstance(records[-1], dict):
            return False
        rows = records[-1].get("rows")
        minimum = check.get("min_rows", 1)
        # Non-search, denied, malformed, or failed calls have no row count.
        # Treat those as failed task checks rather than crashing the whole run.
        if type(rows) is not int or type(minimum) is not int:
            return False
        return rows >= minimum
    if kind == "executed_ok":
        return bool(records and isinstance(records[-1], dict) and records[-1].get("executed")
                    and not records[-1].get("tool_error"))
    if kind == "customer_field":
        row = world.customers.get(check.get("customer_id"), {})
        return row.get(check.get("field")) == check.get("value")
    if kind == "email_sent_to":
        return any(m.get("to") == check.get("to") for m in world.outbox)
    if kind == "customer_deleted":
        return check.get("customer_id") not in world.customers
    if kind == "data_exported":
        return any(x.get("customer_id") == check.get("customer_id") for x in world.exports)
    return None


def run(split: str, configurations: List[str]) -> Path:
    scenarios, manifest, review = _load(split)
    run_id = f"governance_{split}_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}_{uuid.uuid4().hex[:8]}"
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    audit_dir = RESULT_DIR / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    env = build()
    run_records: Dict[str, Any] = {}
    scripted = ScriptedAgent()
    try:
        for config_name in configurations:
            if config_name not in CONFIGURATIONS:
                raise ValueError(f"Unknown gateway configuration {config_name!r}.")
            chain_path = audit_dir / f"{run_id}_{config_name}.jsonl"
            chain = AuditChain(str(chain_path))
            gateway = Gateway(configuration=config_name, chain=chain)
            config_records: List[dict] = []
            for scenario in scenarios:
                # Rate-limit sequences are self-contained; reset the DB counter
                # and virtual clock between scenarios, but not within each one.
                env.reset_runtime_state()
                setup = scenario.get("setup") or {}
                if setup.get("tool") and setup.get("limit"):
                    set_limit(setup["tool"], int(setup["limit"]), ENV_ID)
                world = SandboxWorld.fresh()
                runtime = ProtectedRuntime(
                    gateway=gateway, world=world,
                    approved_approvers={"sandbox_test_approver"},
                )
                calls = scripted.propose(scenario)
                expected = scenario.get("expected_decisions", [])
                if len(calls) != len(expected):
                    raise ValueError(f"Scenario {scenario['scenario_id']} has a calls/labels length mismatch.")
                records: List[dict] = []
                start_hash = world.state_hash()
                for index, (call, expected_decision) in enumerate(zip(calls, expected), start=1):
                    principal = call.get("agent", scenario["agent"])
                    agent_id = env.agent_ids.get(principal)
                    if not agent_id:
                        raise ValueError(f"Unknown scenario principal {principal!r}.")
                    corr = f"{run_id}:{scenario['scenario_id']}:{index}"
                    with environment_scope(ENV_ID):
                        rec = runtime.call(
                            agent_id, call.get("tool", ""), call.get("arguments", {}),
                            scenario_id=scenario["scenario_id"], seq=index,
                            context=scenario.get("context"), run_id=run_id,
                            correlation_id=corr,
                        )
                        first_decision = rec.decision
                        approval_retry = None
                        if first_decision == "REQUIRE_APPROVAL" and scenario.get("approve_after_require"):
                            runtime.approve(
                                rec.correlation_id, "sandbox_test_approver", agent_id=agent_id,
                                tool=call.get("tool", ""), arguments=call.get("arguments", {}),
                            )
                            approval_retry = runtime.call(
                                agent_id, call.get("tool", ""), call.get("arguments", {}),
                                scenario_id=scenario["scenario_id"], seq=index,
                                context=scenario.get("context"), run_id=run_id,
                                correlation_id=corr,
                            ).as_dict()
                    record = rec.as_dict()
                    record["expected_decision"] = expected_decision
                    record["decision_correct"] = first_decision == expected_decision
                    record["approval_retry"] = approval_retry
                    records.append(record)
                    advance_after = setup.get("advance_after_call")
                    if advance_after == index:
                        env.clock.advance(float(setup.get("advance_seconds", 0)))

                task_success = _task_success(scenario.get("task_check"), world, records)
                in_scope = scenario.get("scope", "in_scope") == "in_scope"
                unsafe_types = sorted({e for r in records for e in r["unsafe_effect_types"]})
                config_records.append({
                    "scenario_id": scenario["scenario_id"], "group_id": scenario["group_id"],
                    "gateway_key": scenario["gateway_key"], "category": scenario["category"],
                    "subcategory": scenario["subcategory"], "split": split, "scope": scenario.get("scope"),
                    "label_status": scenario.get("label_status"),
                    "expected_decisions": expected, "records": records,
                    "decision_exact_match": all(r["decision_correct"] for r in records),
                    "task_check": scenario.get("task_check"), "task_success": task_success,
                    "task_check_applicable": scenario.get("task_check") is not None,
                    "unsafe_effect_types": unsafe_types, "unsafe_effect": bool(unsafe_types),
                    "state_changed": world.state_hash() != start_hash,
                    "audit_complete": all(
                        r["audited"] and (r["approval_retry"] is None or r["approval_retry"]["audited"])
                        for r in records
                    ),
                    "in_scope": in_scope,
                })

            included = [r for r in config_records if r["in_scope"]]
            calls = []
            for scenario_record in included:
                for call_record in scenario_record["records"]:
                    calls.append(call_record)
                    if call_record["approval_retry"] is not None:
                        calls.append(call_record["approval_retry"])
            applicable_tasks = [r for r in included if r["task_check_applicable"]]
            run_records[config_name] = {
                "scenario_count": len(config_records),
                "in_scope_scenario_count": len(included),
                "out_of_scope_scenario_count": len(config_records) - len(included),
                "call_count": len(calls),
                "decision_exact_accuracy": sum(r["decision_exact_match"] for r in included) / len(included),
                "unsafe_effect_scenarios": sum(r["unsafe_effect"] for r in included),
                "task_success_rate": (sum(r["task_success"] is True for r in applicable_tasks) / len(applicable_tasks)
                                      if applicable_tasks else None),
                "task_check_count": len(applicable_tasks),
                "audit_complete_scenarios": sum(r["audit_complete"] for r in included),
                "audit_coverage": (sum(r["audit_complete"] for r in included) / len(included) if included else None),
                "decision_counts": dict(Counter(c["decision"] for c in calls)),
                "unsafe_effect_types": dict(Counter(e for r in included for e in r["unsafe_effect_types"])),
                "scenarios": config_records,
                "audit_chain": str(chain_path.relative_to(ROOT)).replace("\\", "/"),
                "audit_chain_entries": len(chain),
                "audit_chain_valid": verify_chain(chain.entries())[0],
                "audit_chain_head_sha256": chain.head,
            }
    finally:
        env.close()

    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                  text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True,
                                    text=True, check=True).stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        revision, dirty = None, None
    result = {
        "study": "PromptAegis sandboxed tool-governance evaluation",
        "run_id": run_id, "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "split": split, "confirmatory": split in {"validation", "test"},
        "label_status": manifest.get("label_status"), "review_record": review or None,
        "scenario_count": len(scenarios), "scenario_sha256": sha256(SCENARIO_FILE),
        "manifest_sha256": sha256(MANIFEST_FILE), "runner_sha256": sha256(Path(__file__)),
        "gateway_sha256": sha256(BACKEND / "governance" / "gateway.py"),
        "validator_sha256": sha256(BACKEND / "governance" / "param_validator.py"),
        "sandbox_runtime_sha256": sha256(BACKEND / "sandbox" / "runtime.py"),
        "git_revision": revision, "git_worktree_dirty": dirty,
        "execution_mode": "scripted deterministic proposals; isolated in-memory business world; no network or live model",
        "interpretation": "Development/tuning split only. Labels are author-authored pending independent review; no confirmatory security or utility claims.",
        "configurations": run_records,
    }
    out = RESULT_DIR / f"{run_id}.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"[OK] {split}: {len(scenarios)} scenarios; output={out.relative_to(ROOT)}")
    for cfg, data in run_records.items():
        print(f"  {cfg}: in_scope={data['in_scope_scenario_count']} calls={data['call_count']} "
              f"exact={data['decision_exact_accuracy']:.3f} unsafe_effects={data['unsafe_effect_scenarios']} "
              f"task_checks={data['task_check_count']} audit={data['audit_coverage']:.3f}")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "tune", "validation", "test"), default="dev")
    parser.add_argument("--config", action="append", choices=tuple(CONFIGURATIONS), dest="configs",
                        help="Repeat to select configurations; defaults to all four mechanism comparisons.")
    args = parser.parse_args()
    run(args.split, args.configs or ["baseline", "rbac_only", "policy_only", "full"])


if __name__ == "__main__":
    main()
