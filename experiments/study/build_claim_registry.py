"""Build the claim-to-evidence registry for the current development-split study.

Every number the manuscript and README cite is recomputed here from the raw result
JSON, not copied from a figure script. For each claim the registry stores the value,
its numerator and denominator, the result artifact and its SHA-256, and the source
hashes recorded by the run, so a reader can check each claim against its artifact.

    python experiments/run_research.py registry \
        --ablation results/study/governance_dev_20261017T182314Z_2a97d190.json \
        --pilot    results/study/llm_20261017T171952Z_9c41232a.json

The registry never marks a claim as confirmatory: labels are author-assigned.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "results" / "provenance" / "claim_registry.json"

ATTACK = {"unauthorized_tool", "prompt_injection", "privilege_escalation",
          "parameter_manipulation", "context_sensitive"}
BENIGN = {"legitimate", "negative_control"}
SOURCE_FILES = {
    "gateway_sha256": "backend/governance/gateway.py",
    "validator_sha256": "backend/governance/param_validator.py",
    "runner_sha256": "experiments/study/run_benchmark.py",
    "sandbox_runtime_sha256": "backend/sandbox/runtime.py",
    "scenario_sha256": "backend/data/governance_benchmark/scenarios.json",
    "manifest_sha256": "backend/data/governance_benchmark/manifest.json",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rel(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT)).replace("\\", "/")


def configuration_metrics(record: Dict[str, Any]) -> Dict[str, Any]:
    """Per-configuration counts. Definitions match the manuscript's Section 3.4 / Table 5."""
    scenarios = [s for s in record["scenarios"] if s["in_scope"]]
    attack = [s for s in scenarios if s["category"] in ATTACK]
    approval = [s for s in scenarios if s["category"] == "approval_required"]
    benign = [s for s in scenarios if s["category"] in BENIGN]
    calls = [r for s in scenarios for r in s["records"]]
    checks = [s for s in scenarios if s["task_check_applicable"]]
    return {
        "in_scope_scenarios": (len(scenarios), None),
        "exact_decision_agreement": (sum(s["decision_exact_match"] for s in scenarios), len(scenarios)),
        "unsafe_effect_scenarios": (sum(s["unsafe_effect"] for s in scenarios), len(scenarios)),
        "attack_success_unsafe": (sum(s["unsafe_effect"] for s in attack), len(attack)),
        "approval_bypass_unsafe": (sum(s["unsafe_effect"] for s in approval), len(approval)),
        "benign_false_block": (sum(any(r["decision"] != "ALLOW" for r in s["records"]) for s in benign),
                               len(benign)),
        "task_checks_passed": (sum(s["task_success"] for s in checks), len(checks)),
        "executed_calls": (sum(bool(r["executed"]) for r in calls), len(calls)),
        "audit_complete_scenarios": (sum(s["audit_complete"] for s in scenarios), len(scenarios)),
    }


def git_state() -> Dict[str, Any]:
    try:
        rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                             text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True,
                                    text=True, check=True).stdout.strip())
        return {"git_revision": rev, "git_worktree_dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"git_revision": None, "git_worktree_dirty": None}


def build(ablation: Path, pilot: Path) -> Dict[str, Any]:
    run = json.loads(ablation.read_text(encoding="utf-8"))
    digest = sha256(ablation)
    claims: List[Dict[str, Any]] = []
    for config, record in run["configurations"].items():
        for metric, (num, den) in configuration_metrics(record).items():
            claims.append({
                "claim_id": f"DEV-{config}-{metric}".upper(),
                "status": "development_split_descriptive",
                "configuration": config, "metric": metric,
                "numerator": num, "denominator": den,
                "result_artifact": rel(ablation), "result_sha256": digest,
            })
        claims.append({
            "claim_id": f"DEV-{config}-AUDIT_CHAIN_VALID".upper(),
            "status": "development_split_descriptive", "configuration": config,
            "metric": "audit_chain_valid", "value": bool(record["audit_chain_valid"]),
            "audit_chain": record["audit_chain"], "audit_chain_head_sha256": record["audit_chain_head_sha256"],
            "result_artifact": rel(ablation), "result_sha256": digest,
        })
    pil = json.loads(pilot.read_text(encoding="utf-8"))
    pilot_claims = [{
        "claim_id": "PILOT-" + key.upper(), "status": "exploratory_pilot", "metric": key,
        "value": pil[key], "result_artifact": rel(pilot), "result_sha256": sha256(pilot),
    } for key in ("decision_counts", "agent_outcome_counts", "agent_outcome_by_label")]
    recorded = {k: run.get(k) for k in SOURCE_FILES}
    current = {k: sha256(ROOT / p) for k, p in SOURCE_FILES.items()}
    return {
        "registry_version": "3.0",
        "study": "PromptAegis sandboxed tool-governance evaluation (development split)",
        "label_status": run["label_status"], "confirmatory": False,
        "canonical_run": {"run_id": run["run_id"], "result_artifact": rel(ablation), "result_sha256": digest,
                          "configuration_order": list(run["configurations"]),
                          "run_git_revision": run.get("git_revision"),
                          "run_git_worktree_dirty": run.get("git_worktree_dirty")},
        "source_hashes_recorded_by_run": recorded,
        "source_hashes_at_registry_build": current,
        "run_matches_current_source": {k: recorded[k] == current[k] for k in SOURCE_FILES},
        "registry_build_state": git_state(),
        "notes": [
            "Calls are first-attempt calls in in-scope scenarios (244). The raw call_count is 248 for "
            "configurations with the approval stage because four scenarios retry once after a simulated approval.",
            "Latency is not registered as a claim: it is exploratory and unstable across runs.",
            "If run_matches_current_source reports runner_sha256 False, the runner was edited after the run. "
            "See docs/REPRODUCTION_CHECK.md for what changed and for the re-execution that compared decisions.",
        ],
        "claims": claims, "pilot_claims": pilot_claims,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ablation", type=Path, required=True, help="Canonical 12-configuration run JSON")
    parser.add_argument("--pilot", type=Path, required=True, help="Primary LLM pilot run JSON")
    args = parser.parse_args()
    registry = build(args.ablation.resolve(), args.pilot.resolve())
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
    state = registry["run_matches_current_source"]
    print(f"[OK] {len(registry['claims'])} claims -> {rel(OUTPUT)}")
    print("run matches current source:", all(state.values()), {k: v for k, v in state.items() if not v})


if __name__ == "__main__":
    main()
