"""Adversarial parameter robustness probe.
Evaluates the 500-instance clustered adversarial perturbation testbed
(adversarial_extension.json: 5 perturbation classes x 100 base instances)
across two distinct evaluation regimes:

A. MECHANISM-ISOLATED POLICY EVALUATION (Rate-Limiter Isolated):
   - Standard Policy (configuration='policy_only'): evaluates regexes on raw input
   - Hardened Policy (configuration='policy_hardened_isolated'): evaluates regexes on keyword-agnostic canonicalized input

B. COMPOUND FULL-GOVERNANCE BURST EVALUATION (Full Stack):
   - Standard Gateway (configuration='full'): rate limiting, RBAC, policy, risk
   - Hardened Gateway (configuration='hardened'): full stack with pre-execution canonicalization

Measures real runtime latencies (time.perf_counter).
Outputs per-perturbation-class non-ALLOW decision rates and mechanism attribution.
This interceptor study has no sandbox-effect oracle; it does not estimate
attack success, evasion rate, or harm.
Saves each run under ``results/adversarial_runs/``.
"""
import csv
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List
import numpy as np

# Ensure project root in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from experiments.common.config import (
    AUDITED_COMMIT,
    BENCHMARK_DIR,
    DERIVED_DIR,
    EXPERIMENT_VERSION,
    RAW_DIR,
)
from experiments.common.clock import ResearchExperimentClock, reset_to_production_clock, set_clock
from experiments.common.runner import determine_blocking_stage, ensure_initialized
from governance.legacy_interceptor import intercept
from governance.rate_limiter import reset_rate_limits


PERTURBATION_CLASSES = [
    "case_alternation",
    "comment_fragmentation",
    "advanced_sql",
    "url_encoding",
    "base64_obfuscation",
]


def main():
    print("================================================================")
    print("PromptAegis adversarial parameter probe (N=500)")
    print("================================================================")

    role_map = ensure_initialized()
    adv_file = os.path.join(BENCHMARK_DIR, "adversarial_extension.json")
    if not os.path.exists(adv_file):
        raise FileNotFoundError(f"Adversarial dataset not found: {adv_file}")

    with open(adv_file, "r", encoding="utf-8") as fp:
        scenarios = json.load(fp)

    manifest_file = os.path.join(BENCHMARK_DIR, "adversarial_extension_manifest.json")
    if not os.path.exists(manifest_file):
        raise FileNotFoundError(
            "Adversarial corpus manifest is missing. Generate the probe corpus with "
            "python experiments/study/generate_adversarial_extension.py first."
        )
    with open(manifest_file, "r", encoding="utf-8") as fp:
        corpus_manifest = json.load(fp)
    with open(adv_file, "rb") as fp:
        corpus_sha256 = hashlib.sha256(fp.read()).hexdigest()
    if corpus_sha256 != corpus_manifest.get("generated_file_sha256"):
        raise RuntimeError("Adversarial corpus hash differs from its manifest; regenerate and review it.")

    print(f"Loaded {len(scenarios)} adversarial mutation scenarios (5 classes x 100 base instances).")
    clock = ResearchExperimentClock(start_time=1790000000.0, step_seconds=0.05)
    set_clock(clock)

    all_events = []
    regimes = {
        "isolated_standard": "policy_only",
        "isolated_hardened": "policy_hardened_isolated",
        "compound_standard": "full",
        "compound_hardened": "hardened",
    }
    outcomes_by_regime = {}

    try:
        for regime_name, cfg in regimes.items():
            reset_rate_limits()
            clock.reset(1790000000.0)

            cfg_events = []
            latencies = []

            for sc in scenarios:
                sid = sc.get("mutated_scenario_id") or sc.get("scenario_id")
                orig_id = sc.get("original_scenario_id", "")
                mtype = sc.get("mutation_type", "unknown")
                tool = sc.get("expected_tool", "")
                args = sc.get("arguments", {})
                role = sc.get("agent_role", "support")
                agent_id = role_map.get(role, role_map.get("support", ""))

                clock.step()
                t0 = time.perf_counter()
                res = intercept(
                    agent_id=agent_id,
                    tool_name=tool,
                    arguments=args,
                    configuration=cfg,
                    experiment_run_id=f"adv_{regime_name}",
                )
                lat_ms = (time.perf_counter() - t0) * 1000.0

                actual = res["decision"]
                reason = res["reason"]
                blocked = (actual != "ALLOW")
                stage = res.get("first_blocking_stage") or determine_blocking_stage(actual, reason)
                stage_evals = res.get("stage_evaluations", {})

                rec = {
                    "scenario_id": sid,
                    "original_id": orig_id,
                    "mutation_type": mtype,
                    "regime": regime_name,
                    "configuration": cfg,
                    "tool": tool,
                    "actual_decision": actual,
                    "reason": reason,
                    "is_blocked": 1 if blocked else 0,
                    "first_blocking_stage": stage,
                    "blocking_mechanism": stage,
                    "rate_limit_state": stage_evals.get("rate_limiter", {}),
                    "policy_result": stage_evals.get("policy_engine", {}),
                    "latency_ms": lat_ms,
                }
                cfg_events.append(rec)
                latencies.append(lat_ms)

            all_events.extend(cfg_events)
            outcomes_by_regime[regime_name] = {
                "events": cfg_events,
                "latencies": latencies,
            }

    finally:
        reset_to_production_clock()

    # Compute detailed metrics for isolated and compound regimes
    iso_std_ev = outcomes_by_regime["isolated_standard"]["events"]
    iso_hrd_ev = outcomes_by_regime["isolated_hardened"]["events"]
    cmp_std_ev = outcomes_by_regime["compound_standard"]["events"]
    cmp_hrd_ev = outcomes_by_regime["compound_hardened"]["events"]

    print("\n--- A. MECHANISM-ISOLATED POLICY EVALUATION (No Rate-Limiter Interference) ---")
    print(f"{'Perturbation Class':25} | {'Isolated Std':14} | {'Isolated Hrd':14} | {'Delta':8} | {'Std non-ALLOW':14}")
    print("-" * 85)

    isolated_by_class = []
    for pclass in PERTURBATION_CLASSES:
        std_sub = [e for e in iso_std_ev if e["mutation_type"] == pclass]
        hrd_sub = [e for e in iso_hrd_ev if e["mutation_type"] == pclass]
        n = len(std_sub)
        sb = sum(e["is_blocked"] for e in std_sub)
        hb = sum(e["is_blocked"] for e in hrd_sub)
        sr = sb / n if n else 0.0
        hr = hb / n if n else 0.0
        delta = hr - sr
        not_allowed = 1.0 - sr
        isolated_by_class.append({
            "perturbation_class": pclass,
            "sample_size": n,
            "standard_blocked": sb,
            "standard_recall": round(sr, 4),
            "hardened_blocked": hb,
            "hardened_recall": round(hr, 4),
            "improvement_delta": round(delta, 4),
            "standard_not_allowed_rate": round(not_allowed, 4),
        })
        print(f"{pclass:25} | {sr*100:5.1f}% ({sb:2d}/{n:2d}) | {hr*100:5.1f}% ({hb:2d}/{n:2d}) | {delta*100:+5.1f}% | {not_allowed*100:5.1f}%")

    tot_n = len(iso_std_ev)
    tot_iso_sb = sum(e["is_blocked"] for e in iso_std_ev)
    tot_iso_hb = sum(e["is_blocked"] for e in iso_hrd_ev)
    tot_iso_sr = tot_iso_sb / tot_n
    tot_iso_hr = tot_iso_hb / tot_n
    tot_iso_delta = tot_iso_hr - tot_iso_sr
    tot_iso_not_allowed = 1.0 - tot_iso_sr
    print("-" * 85)
    print(f"{'Overall Aggregate':25} | {tot_iso_sr*100:5.1f}% ({tot_iso_sb:2d}/{tot_n:2d}) | {tot_iso_hr*100:5.1f}% ({tot_iso_hb:2d}/{tot_n:2d}) | {tot_iso_delta*100:+5.1f}% | {tot_iso_not_allowed*100:5.1f}%")

    print("\n--- B. COMPOUND FULL-GOVERNANCE BURST EVALUATION (With Burst Rate Limiting) ---")
    print(f"{'Perturbation Class':25} | {'Compound Std':14} | {'Compound Hrd':14} | {'Delta':8} | {'Mechanism Attribution (Std)'}")
    print("-" * 95)

    compound_by_class = []
    for pclass in PERTURBATION_CLASSES:
        std_sub = [e for e in cmp_std_ev if e["mutation_type"] == pclass]
        hrd_sub = [e for e in cmp_hrd_ev if e["mutation_type"] == pclass]
        n = len(std_sub)
        sb = sum(e["is_blocked"] for e in std_sub)
        hb = sum(e["is_blocked"] for e in hrd_sub)
        sr = sb / n if n else 0.0
        hr = hb / n if n else 0.0
        delta = hr - sr
        
        # Attribution
        stages_std = {}
        for e in std_sub:
            st = e["first_blocking_stage"]
            stages_std[st] = stages_std.get(st, 0) + 1

        compound_by_class.append({
            "perturbation_class": pclass,
            "sample_size": n,
            "standard_blocked": sb,
            "standard_recall": round(sr, 4),
            "hardened_blocked": hb,
            "hardened_recall": round(hr, 4),
            "improvement_delta": round(delta, 4),
            "standard_not_allowed_rate": round(1.0 - sr, 4),
            "mechanism_stages_standard": stages_std,
        })
        attr_str = ", ".join(f"{k}:{v}" for k, v in stages_std.items())
        print(f"{pclass:25} | {sr*100:5.1f}% ({sb:2d}/{n:2d}) | {hr*100:5.1f}% ({hb:2d}/{n:2d}) | {delta*100:+5.1f}% | {attr_str}")

    tot_cmp_sb = sum(e["is_blocked"] for e in cmp_std_ev)
    tot_cmp_hb = sum(e["is_blocked"] for e in cmp_hrd_ev)
    tot_cmp_sr = tot_cmp_sb / tot_n
    tot_cmp_hr = tot_cmp_hb / tot_n
    tot_cmp_delta = tot_cmp_hr - tot_cmp_sr
    print("-" * 95)
    print(f"{'Overall Aggregate':25} | {tot_cmp_sr*100:5.1f}% ({tot_cmp_sb:2d}/{tot_n:2d}) | {tot_cmp_hr*100:5.1f}% ({tot_cmp_hb:2d}/{tot_n:2d}) | {tot_cmp_delta*100:+5.1f}% | Total blocked: {tot_cmp_sb}/{tot_n}")

    run_id = datetime.now(timezone.utc).strftime("adversarial_%Y%m%dT%H%M%SZ")
    payload = {
        "run_id": run_id,
        "corpus_manifest": corpus_manifest,
        "corpus_sha256": corpus_sha256,
        "interpretation_limit": (
            "Project-authored mutation suite. These are gateway decision/interception outcomes; "
            "non-ALLOW rate is not an effect-based attack-success or evasion metric."
        ),
        "commit": AUDITED_COMMIT,
        "sample_size": tot_n,
        "mutation_structure": "5 perturbation classes x 100 base instances (clustered design)",
        "mechanism_isolated_evaluation": {
            "description": "Rate-limiter isolated policy evaluation measuring pure canonicalization efficacy",
            "overall_standard_recall": round(tot_iso_sr, 4),
            "overall_hardened_recall": round(tot_iso_hr, 4),
            "overall_delta": round(tot_iso_delta, 4),
            "overall_standard_not_allowed_rate": round(tot_iso_not_allowed, 4),
            "by_perturbation": isolated_by_class,
        },
        "compound_burst_evaluation": {
            "description": "Compound full-stack runtime gateway under high-frequency arrival",
            "overall_standard_recall": round(tot_cmp_sr, 4),
            "overall_hardened_recall": round(tot_cmp_hr, 4),
            "overall_delta": round(tot_cmp_delta, 4),
            "overall_standard_not_allowed_rate": round(1.0 - tot_cmp_sr, 4),
            "by_perturbation": compound_by_class,
        },
        "by_perturbation": compound_by_class + [{
            "perturbation_class": "overall_aggregate",
            "sample_size": tot_n,
            "standard_blocked": tot_cmp_sb,
            "standard_recall": round(tot_cmp_sr, 4),
            "standard_not_allowed_rate": round(1.0 - tot_cmp_sr, 4),
            "hardened_blocked": tot_cmp_hb,
            "hardened_recall": round(tot_cmp_hr, 4),
            "improvement_delta": round(tot_cmp_delta, 4),
        }],
        "overall_standard_recall": round(tot_cmp_sr, 4),
        "overall_hardened_recall": round(tot_cmp_hr, 4),
        "overall_delta": round(tot_cmp_delta, 4),
        "overall_standard_not_allowed_rate": round(1.0 - tot_cmp_sr, 4),
    }

    # Save raw and derived JSON
    run_dir = os.path.join(os.path.dirname(RAW_DIR), "adversarial_runs", run_id)
    raw_dir = os.path.join(run_dir, "raw")
    derived_dir = os.path.join(run_dir, "derived")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(derived_dir, exist_ok=True)
    raw_path = os.path.join(raw_dir, "adversarial_events.json")
    with open(raw_path, "w", encoding="utf-8") as fp:
        json.dump({"events": all_events}, fp, indent=2)

    derived_json_path = os.path.join(derived_dir, "adversarial_metrics.json")
    with open(derived_json_path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2)

    # Save CSV
    derived_csv_path = os.path.join(derived_dir, "adversarial_metrics.csv")
    with open(derived_csv_path, "w", newline="", encoding="utf-8") as fp:
        fieldnames = ["perturbation_class", "sample_size", "standard_recall", "hardened_recall", "improvement_delta", "standard_not_allowed_rate"]
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for r in isolated_by_class:
            writer.writerow({
                "perturbation_class": r["perturbation_class"],
                "sample_size": r["sample_size"],
                "standard_recall": r["standard_recall"],
                "hardened_recall": r["hardened_recall"],
                "improvement_delta": r["improvement_delta"],
                "standard_not_allowed_rate": r["standard_not_allowed_rate"],
            })

    print(f"\n[OK] Adversarial metrics saved to {derived_json_path} and {derived_csv_path}")


if __name__ == "__main__":
    main()
