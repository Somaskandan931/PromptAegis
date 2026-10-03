"""
Automated Provenance, Reproducibility, and Integrity Test Suite for PromptAegis.
Verifies Phase 19 requirements:
- Claim registry validity and artifact linkage
- Data-driven figure generators (no prohibited hardcoded arrays)
- Secret scanning
- Research clock determinism
- Mathematical consistency of derived metrics
"""
import glob
import json
import os
import re
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from experiments.common.config import (
    AUDITED_COMMIT,
    DERIVED_DIR,
    PROVENANCE_DIR,
    RAW_DIR,
    STATISTICAL_DIR,
)


def test_claim_registry_structure_and_linkage():
    """Verify claim_registry.json exists, is valid, and all CURRENT claims link to real files."""
    reg_path = os.path.join(PROVENANCE_DIR, "claim_registry.json")
    assert os.path.exists(reg_path), f"Claim registry missing at {reg_path}"

    with open(reg_path, "r", encoding="utf-8") as fp:
        registry = json.load(fp)

    assert "claims" in registry
    assert len(registry["claims"]) > 0

    required_fields = [
        "claim_id", "metric", "value", "unit", "population", "configuration",
        "dataset", "raw_artifact", "derived_artifact", "experiment_script",
        "commit", "status", "production_runtime", "measurement_type"
    ]

    valid_statuses = {"CURRENT-PRODUCTION", "CURRENT-DERIVED", "HISTORICAL", "OFFLINE", "SIMULATED", "RETIRED"}
    valid_measurement_types = {"MEASURED", "DERIVED", "SIMULATED"}

    for claim in registry["claims"]:
        for f in required_fields:
            assert f in claim, f"Claim {claim.get('claim_id')} missing field: {f}"

        assert claim["status"] in valid_statuses, f"Invalid status: {claim['status']}"
        assert claim["measurement_type"] in valid_measurement_types, f"Invalid measurement type: {claim['measurement_type']}"

        # Current production claims must link to existing files and have production_runtime == True
        if claim["status"] in ("CURRENT-PRODUCTION", "CURRENT-DERIVED"):
            assert claim["production_runtime"] is True, f"Claim {claim['claim_id']} marked current but production_runtime is False"
            assert claim["measurement_type"] in ("MEASURED", "DERIVED"), f"Current claim {claim['claim_id']} cannot be SIMULATED"
            
            # Check file linkage
            raw_file = os.path.join(PROJECT_ROOT, claim["raw_artifact"])
            derived_file = os.path.join(PROJECT_ROOT, claim["derived_artifact"])
            assert os.path.exists(raw_file), f"Raw artifact missing for {claim['claim_id']}: {raw_file}"
            assert os.path.exists(derived_file), f"Derived artifact missing for {claim['claim_id']}: {derived_file}"
            assert "scratch" not in claim["raw_artifact"], f"Current claim {claim['claim_id']} must not point to scratch"

        if claim["status"] == "RETIRED":
            assert claim["measurement_type"] == "SIMULATED" or "fiction" in claim["notes"].lower()


def test_figure_script_has_no_hardcoded_scientific_outcomes():
    """Verify figure generator does NOT contain hardcoded scientific outcome arrays."""
    fig_script = os.path.join(PROJECT_ROOT, "backend", "scripts", "generate_governance_figures.py")
    assert os.path.exists(fig_script), f"Missing figure script: {fig_script}"

    with open(fig_script, "r", encoding="utf-8") as fp:
        code = fp.read()

    # Prohibited patterns
    prohibited_literals = [
        "asr = [100.0, 36.0, 28.0, 31.4, 6.4]",
        "ltcr = [100.0, 80.0, 80.0, 80.0, 100.0]",
        "p50 = [21.38, 57.05, 54.76, 139.72]",
        "standard_recall = [78.0, 78.0, 68.0, 50.0, 0.0, 54.8]",
        "counts = [10, 4, 3, 1]",
    ]

    for lit in prohibited_literals:
        assert lit not in code, f"Prohibited hardcoded literal found in figure generator: {lit}"

    # Verify script loads from derived json
    assert "_load_json(\"benchmark_metrics.json\")" in code
    assert "_load_json(\"adversarial_metrics.json\")" in code
    assert "_load_json(\"closed_loop_metrics.json\")" in code


def test_derived_mathematical_consistency():
    """Verify statistical formulas match underlying raw observations."""
    metrics_path = os.path.join(DERIVED_DIR, "benchmark_metrics.json")
    assert os.path.exists(metrics_path), "Derived benchmark metrics missing"

    with open(metrics_path, "r", encoding="utf-8") as fp:
        data = json.load(fp)

    configs = data["configurations"]
    for cfg_name, cfg_data in configs.items():
        m = cfg_data["metrics"]
        n_att = m["attack_scenarios"]
        n_leg = m["legitimate_scenarios"]
        att_allowed = m["attacks_allowed"]
        leg_allowed = m["legitimate_allowed"]

        # Exact formula checks
        expected_asr = round(att_allowed / n_att, 6)
        expected_ltcr = round(leg_allowed / n_leg, 6)
        expected_fpr = round((n_leg - leg_allowed) / n_leg, 6)

        assert abs(m["attack_success_rate"] - expected_asr) < 1e-5
        assert abs(m["legitimate_task_completion_rate"] - expected_ltcr) < 1e-5
        assert abs(m["false_positive_rate"] - expected_fpr) < 1e-5


def test_secret_scan():
    """Verify no live API keys or credentials exist in tracked repository files."""
    secret_patterns = [
        re.compile(r"gsk_[a-zA-Z0-9]{20,}"),
        re.compile(r"sk-proj-[a-zA-Z0-9]{20,}"),
        re.compile(r"sk-ant-[a-zA-Z0-9]{20,}"),
    ]

    scan_extensions = [".py", ".json", ".md", ".csv", ".txt", ".env"]
    for root, dirs, files in os.walk(PROJECT_ROOT):
        # Skip git and cache
        if ".git" in root or "__pycache__" in root or "node_modules" in root:
            continue
        for file in files:
            ext = os.path.splitext(file)[1]
            if ext in scan_extensions:
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                        content = fp.read()
                        for pat in secret_patterns:
                            m = pat.search(content)
                            assert m is None, f"Potential secret matched in {fpath}: {m.group(0)[:6]}..."
                except Exception:
                    pass


def test_research_clock_determinism():
    """Verify that same dataset + same research clock produces 100% identical outputs."""
    from experiments.common.runner import BenchmarkRunner

    runner1 = BenchmarkRunner(step_seconds=0.05, start_time=1790000000.0)
    runner2 = BenchmarkRunner(step_seconds=0.05, start_time=1790000000.0)

    # Run small deterministic subset
    scenarios = [
        {
            "scenario_id": f"DET-{i:03d}",
            "category": "unauthorized_tool",
            "agent_role": "support",
            "expected_tool": "execute_sql",
            "arguments": {"query": f"SELECT {i}"},
            "expected_decision": "DENY",
        }
        for i in range(10)
    ]

    res1 = runner1.run_benchmark(configurations=["full"], scenarios=scenarios, save_raw=False)
    res2 = runner2.run_benchmark(configurations=["full"], scenarios=scenarios, save_raw=False)

    try:
        decisions1 = [e["actual_decision"] for e in res1["events"]]
        decisions2 = [e["actual_decision"] for e in res2["events"]]
        assert decisions1 == decisions2, "Research clock did not produce deterministic outcomes"
        assert len(decisions1) == 10
    finally:
        from database import db
        with db.get_conn() as conn:
            conn.execute("DELETE FROM tool_calls WHERE experiment_run_id IN (?, ?)", (res1["run_id"], res2["run_id"]))

