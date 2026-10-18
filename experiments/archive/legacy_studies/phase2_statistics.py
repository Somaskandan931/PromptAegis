"""
Phase 2: Canonical Statistical Pipeline.
Reads canonical raw observations from results/raw/canonical_benchmark_events.json,
and computes:
1. McNemar Chi-Square tests (Edwards continuity-corrected and uncorrected)
2. Paired Wilcoxon signed-rank tests for latency distributions
3. 95% Bootstrap Confidence Intervals (10,000 resamples) for ASR and LTCR
4. Full summary tables stored in results/derived/ and results/statistical/.

NEVER hardcodes empirical values. All outputs are derived mathematically.
"""
import csv
import json
import os
import sys
import numpy as np
from scipy import stats

# Ensure project root in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from experiments.common.config import DERIVED_DIR, RAW_DIR, STATISTICAL_DIR


def compute_mcnemar(events_ref, events_target):
    """
    Compute McNemar 2x2 contingency table and chi-square test with Edwards correction.
    """
    ref_map = {e["scenario_id"]: e["is_correct"] for e in events_ref}
    target_map = {e["scenario_id"]: e["is_correct"] for e in events_target}

    common_ids = sorted(set(ref_map.keys()) & set(target_map.keys()))
    a = b = c = d = 0

    for sid in common_ids:
        r = ref_map[sid]
        t = target_map[sid]
        if r == 1 and t == 1:
            a += 1
        elif r == 1 and t == 0:
            b += 1  # ref correct, target incorrect (e.g. false positive on legit)
        elif r == 0 and t == 1:
            c += 1  # ref incorrect, target correct (e.g. intercepted attack)
        elif r == 0 and t == 0:
            d += 1

    discordant = b + c
    if discordant == 0:
        return {
            "n": len(common_ids),
            "table": {"a": a, "b": b, "c": c, "d": d},
            "chi2_edwards": 0.0,
            "p_value_edwards": 1.0,
            "chi2_uncorrected": 0.0,
            "p_value_uncorrected": 1.0,
        }

    # Edwards continuity-corrected: (|b - c| - 1)^2 / (b + c)
    chi2_edwards = float((abs(b - c) - 1.0) ** 2 / discordant)
    p_val_edwards = float(stats.chi2.sf(chi2_edwards, df=1))

    # Uncorrected: (b - c)^2 / (b + c)
    chi2_uncorr = float((b - c) ** 2 / discordant)
    p_val_uncorr = float(stats.chi2.sf(chi2_uncorr, df=1))

    return {
        "n": len(common_ids),
        "table": {"a": a, "b": b, "c": c, "d": d},
        "chi2_edwards": round(chi2_edwards, 5),
        "p_value_edwards": p_val_edwards,
        "chi2_uncorrected": round(chi2_uncorr, 5),
        "p_value_uncorrected": p_val_uncorr,
        "discordant_pairs": discordant,
    }


def compute_paired_latency(events_ref, events_target):
    """
    Compute paired latency statistics and Wilcoxon signed-rank test.
    """
    ref_map = {e["scenario_id"]: e["latency_ms"] for e in events_ref}
    target_map = {e["scenario_id"]: e["latency_ms"] for e in events_target}

    common_ids = sorted(set(ref_map.keys()) & set(target_map.keys()))
    ref_lats = np.array([ref_map[sid] for sid in common_ids])
    tgt_lats = np.array([target_map[sid] for sid in common_ids])
    diffs = tgt_lats - ref_lats

    # Wilcoxon signed-rank test
    # If all differences are zero, p=1.0
    if np.all(diffs == 0):
        stat, p_val = 0.0, 1.0
    else:
        try:
            w_res = stats.wilcoxon(tgt_lats, ref_lats)
            stat, p_val = float(w_res.statistic), float(w_res.pvalue)
        except Exception as e:
            stat, p_val = 0.0, 1.0

    return {
        "n": len(common_ids),
        "ref_median_ms": round(float(np.median(ref_lats)), 3),
        "target_median_ms": round(float(np.median(tgt_lats)), 3),
        "median_paired_diff_ms": round(float(np.median(diffs)), 3),
        "mean_paired_diff_ms": round(float(np.mean(diffs)), 3),
        "std_paired_diff_ms": round(float(np.std(diffs)), 3),
        "wilcoxon_stat": round(stat, 2),
        "wilcoxon_p_value": p_val,
        "p50_overhead_ms": round(float(np.percentile(diffs, 50)), 3),
        "p95_overhead_ms": round(float(np.percentile(diffs, 95)), 3),
        "p99_overhead_ms": round(float(np.percentile(diffs, 99)), 3),
    }


def bootstrap_ci(values, n_resamples=10000, alpha=0.05, seed=42):
    """
    Compute non-parametric bootstrap confidence interval (percentile method).
    """
    if len(values) == 0:
        return 0.0, 0.0
    rng = np.random.default_rng(seed)
    n = len(values)
    boot_indices = rng.integers(0, n, size=(n_resamples, n))
    boot_samples = values[boot_indices]
    boot_means = np.mean(boot_samples, axis=1)

    low_pct = (alpha / 2.0) * 100.0
    high_pct = (1.0 - alpha / 2.0) * 100.0
    ci_lower = float(np.percentile(boot_means, low_pct))
    ci_upper = float(np.percentile(boot_means, high_pct))
    return round(ci_lower, 4), round(ci_upper, 4)


def run_phase2():
    print("================================================================")
    print("PromptAegis Phase 2: Canonical Statistical Analysis")
    print("================================================================")

    raw_path = os.path.join(RAW_DIR, "canonical_benchmark_events.json")
    if not os.path.exists(raw_path):
        raise FileNotFoundError(f"Raw benchmark file not found: {raw_path}. Run phase 1 first.")

    with open(raw_path, "r", encoding="utf-8") as fp:
        raw_data = json.load(fp)

    events = raw_data["events"]
    configs = raw_data["configurations"]
    print(f"Loaded {len(events)} events across configurations: {configs}")

    events_by_cfg = {cfg: [e for e in events if e["configuration"] == cfg] for cfg in configs}

    # 1. Compute Bootstrap Confidence Intervals for ASR and LTCR
    print("\n--- 1. Bootstrap Confidence Intervals (N=10,000 resamples) ---")
    bootstrap_results = {}
    bootstrap_csv_rows = []

    for cfg in configs:
        cfg_events = events_by_cfg[cfg]
        attack_events = [e for e in cfg_events if e["category"] != "legitimate"]
        legit_events = [e for e in cfg_events if e["category"] == "legitimate"]

        # ASR array: 1 if attack succeeded (actual == ALLOW), 0 otherwise
        attack_success = np.array([1 if e["actual_decision"] == "ALLOW" else 0 for e in attack_events])
        asr_mean = float(np.mean(attack_success)) if len(attack_success) > 0 else 0.0
        asr_low, asr_high = bootstrap_ci(attack_success, n_resamples=10000, seed=42)

        # LTCR array: 1 if legit succeeded (actual == ALLOW), 0 otherwise
        legit_success = np.array([1 if e["actual_decision"] == "ALLOW" else 0 for e in legit_events])
        ltcr_mean = float(np.mean(legit_success)) if len(legit_success) > 0 else 0.0
        ltcr_low, ltcr_high = bootstrap_ci(legit_success, n_resamples=10000, seed=42)

        bootstrap_results[cfg] = {
            "asr": round(asr_mean, 4),
            "asr_ci_95": [asr_low, asr_high],
            "ltcr": round(ltcr_mean, 4),
            "ltcr_ci_95": [ltcr_low, ltcr_high],
        }
        bootstrap_csv_rows.append({
            "configuration": cfg,
            "asr": asr_mean,
            "asr_ci_lower": asr_low,
            "asr_ci_upper": asr_high,
            "ltcr": ltcr_mean,
            "ltcr_ci_lower": ltcr_low,
            "ltcr_ci_upper": ltcr_high,
        })
        print(f"[{cfg.upper():10}] ASR: {asr_mean*100:.1f}% [{asr_low*100:.1f}%, {asr_high*100:.1f}%] | LTCR: {ltcr_mean*100:.1f}% [{ltcr_low*100:.1f}%, {ltcr_high*100:.1f}%]")

    # Save Bootstrap CIs
    boot_json_path = os.path.join(STATISTICAL_DIR, "bootstrap_confidence_intervals.json")
    with open(boot_json_path, "w", encoding="utf-8") as fp:
        json.dump(bootstrap_results, fp, indent=2)

    boot_csv_path = os.path.join(STATISTICAL_DIR, "bootstrap_confidence_intervals.csv")
    with open(boot_csv_path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=["configuration", "asr", "asr_ci_lower", "asr_ci_upper", "ltcr", "ltcr_ci_lower", "ltcr_ci_upper"])
        writer.writeheader()
        for r in bootstrap_csv_rows:
            writer.writerow(r)

    # 2. McNemar Tests (vs Baseline reference)
    print("\n--- 2. McNemar Chi-Square Tests (Baseline Reference) ---")
    mcnemar_results = {}
    mcnemar_csv_rows = []
    baseline_events = events_by_cfg.get("baseline", [])

    for cfg in configs:
        if cfg == "baseline":
            continue
        cfg_events = events_by_cfg[cfg]
        res = compute_mcnemar(baseline_events, cfg_events)
        mcnemar_results[f"baseline_vs_{cfg}"] = res
        mcnemar_csv_rows.append({
            "comparison": f"baseline_vs_{cfg}",
            "n": res["n"],
            "a_both_correct": res["table"]["a"],
            "b_base_correct_only": res["table"]["b"],
            "c_target_correct_only": res["table"]["c"],
            "d_both_incorrect": res["table"]["d"],
            "chi2_edwards": res["chi2_edwards"],
            "p_value_edwards": res["p_value_edwards"],
            "chi2_uncorrected": res["chi2_uncorrected"],
            "p_value_uncorrected": res["p_value_uncorrected"],
        })
        print(f"[Baseline vs {cfg.upper():10}] Edwards Chi2: {res['chi2_edwards']:.2f}, p-val: {res['p_value_edwards']:.3e} (b={res['table']['b']}, c={res['table']['c']})")

    mcnemar_json_path = os.path.join(STATISTICAL_DIR, "mcnemar_tests.json")
    with open(mcnemar_json_path, "w", encoding="utf-8") as fp:
        json.dump(mcnemar_results, fp, indent=2)

    mcnemar_csv_path = os.path.join(STATISTICAL_DIR, "mcnemar_tests.csv")
    with open(mcnemar_csv_path, "w", newline="", encoding="utf-8") as fp:
        fieldnames = ["comparison", "n", "a_both_correct", "b_base_correct_only", "c_target_correct_only", "d_both_incorrect", "chi2_edwards", "p_value_edwards", "chi2_uncorrected", "p_value_uncorrected"]
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for r in mcnemar_csv_rows:
            writer.writerow(r)

    # 3. Paired Latency Analysis & Wilcoxon Test
    print("\n--- 3. Paired Latency Analysis (Wilcoxon Signed-Rank) ---")
    latency_results = {}
    latency_csv_rows = []

    for cfg in configs:
        if cfg == "baseline":
            continue
        cfg_events = events_by_cfg[cfg]
        res = compute_paired_latency(baseline_events, cfg_events)
        latency_results[f"baseline_vs_{cfg}"] = res
        latency_csv_rows.append({
            "comparison": f"baseline_vs_{cfg}",
            "n": res["n"],
            "baseline_median_ms": res["ref_median_ms"],
            "target_median_ms": res["target_median_ms"],
            "median_paired_diff_ms": res["median_paired_diff_ms"],
            "mean_paired_diff_ms": res["mean_paired_diff_ms"],
            "std_paired_diff_ms": res["std_paired_diff_ms"],
            "wilcoxon_stat": res["wilcoxon_stat"],
            "wilcoxon_p_value": res["wilcoxon_p_value"],
        })
        print(f"[Baseline vs {cfg.upper():10}] Median Paired Overhead: {res['median_paired_diff_ms']:+.2f}ms | Wilcoxon W: {res['wilcoxon_stat']}, p-val: {res['wilcoxon_p_value']:.3e}")

    lat_json_path = os.path.join(STATISTICAL_DIR, "latency_analysis.json")
    with open(lat_json_path, "w", encoding="utf-8") as fp:
        json.dump(latency_results, fp, indent=2)

    lat_csv_path = os.path.join(STATISTICAL_DIR, "latency_analysis.csv")
    with open(lat_csv_path, "w", newline="", encoding="utf-8") as fp:
        fieldnames = ["comparison", "n", "baseline_median_ms", "target_median_ms", "median_paired_diff_ms", "mean_paired_diff_ms", "std_paired_diff_ms", "wilcoxon_stat", "wilcoxon_p_value"]
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for r in latency_csv_rows:
            writer.writerow(r)

    # 4. Save Comprehensive Derived Metrics
    derived_summary = {
        "configurations": raw_data["summary"],
        "bootstrap_confidence_intervals": bootstrap_results,
        "mcnemar_tests": mcnemar_results,
        "latency_analysis": latency_results,
    }
    derived_json_path = os.path.join(DERIVED_DIR, "benchmark_metrics.json")
    with open(derived_json_path, "w", encoding="utf-8") as fp:
        json.dump(derived_summary, fp, indent=2)
    print(f"\n[OK] Comprehensive derived metrics saved to: {derived_json_path}")


if __name__ == "__main__":
    run_phase2()
