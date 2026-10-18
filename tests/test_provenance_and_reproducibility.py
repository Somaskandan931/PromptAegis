"""Integrity checks for the current PromptAegis evidence chain."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


CANONICAL_RUN = "governance_dev_20261018T072638Z_13a891ae"
PILOT_RUN = "llm_20261017T171952Z_9c41232a"
PRIMARY_CONFIGS = ["baseline", "rbac_only", "policy_only", "full"]
TWELVE = ["baseline", "rbac_only", "policy_only", "schema_only", "rbac_schema", "rbac_policy", "full",
          "full_minus_rbac", "full_minus_schema", "full_minus_policy", "full_minus_rate", "full_minus_approval"]


def _canonical():
    path = ROOT / "results" / "study" / f"{CANONICAL_RUN}.json"
    return path, json.loads(path.read_text(encoding="utf-8"))


def test_claim_registry_points_at_existing_canonical_run():
    registry = json.loads((ROOT / "results" / "provenance" / "claim_registry.json").read_text(encoding="utf-8"))
    path, run = _canonical()
    assert registry["registry_version"] == "3.0"
    assert registry["confirmatory"] is False
    assert registry["canonical_run"]["run_id"] == CANONICAL_RUN
    assert registry["canonical_run"]["result_artifact"] == f"results/study/{CANONICAL_RUN}.json"
    assert "\\" not in registry["canonical_run"]["result_artifact"]      # no Windows separators
    assert path.is_file()
    digest = _sha256(path)
    assert registry["canonical_run"]["result_sha256"] == digest
    assert all(c["result_sha256"] == digest for c in registry["claims"])
    assert list(run["configurations"]) == TWELVE
    for claim in registry["pilot_claims"]:
        assert (ROOT / claim["result_artifact"]).is_file()
        assert _sha256(ROOT / claim["result_artifact"]) == claim["result_sha256"]


def test_canonical_run_sources_match_current_code_except_documented_runner_edit():
    """The run's recorded hashes must match the files it claims to describe.

    run_benchmark.py gained --all-configs, a single-run lock and an environment record after this run;
    docs/REPRODUCTION_CHECK.md documents that edit and the re-execution that followed. Any other drift fails.
    """
    _, run = _canonical()
    current = {
        "gateway_sha256": "backend/governance/gateway.py",
        "validator_sha256": "backend/governance/param_validator.py",
        "sandbox_runtime_sha256": "backend/sandbox/runtime.py",
        "scenario_sha256": "backend/data/governance_benchmark/scenarios.json",
        "manifest_sha256": "backend/data/governance_benchmark/manifest.json",
    }
    for key, relative in current.items():
        assert run[key] == _sha256(ROOT / relative), f"{key} drifted from the canonical run"
    assert (ROOT / "docs" / "REPRODUCTION_CHECK.md").is_file()


def test_registry_counts_recompute_from_raw_events():
    """Registry numerators are recomputed from the raw per-scenario records, not trusted."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_claim_registry",
                                                  ROOT / "experiments" / "study" / "build_claim_registry.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _, run = _canonical()
    registry = json.loads((ROOT / "results" / "provenance" / "claim_registry.json").read_text(encoding="utf-8"))
    by_id = {c["claim_id"]: c for c in registry["claims"]}
    for config in TWELVE:
        for metric, (num, den) in module.configuration_metrics(run["configurations"][config]).items():
            claim = by_id[f"DEV-{config}-{metric}".upper()]
            assert (claim["numerator"], claim["denominator"]) == (num, den), (config, metric)


def test_headline_numbers_in_readme_and_paper_match_the_canonical_run():
    _, run = _canonical()
    expected = {"baseline": (0.39, 29), "rbac_only": (0.51, 17), "policy_only": (0.53, 14), "full": (1.0, 0)}
    for config, (agreement, unsafe) in expected.items():
        record = run["configurations"][config]
        assert round(record["decision_exact_accuracy"], 2) == agreement
        assert record["unsafe_effect_scenarios"] == unsafe
        assert record["task_check_count"] == 43 and record["audit_chain_valid"] is True
    leave_one_out = {"full_minus_schema": (0.74, 10), "full_minus_approval": (0.94, 4),
                     "full_minus_policy": (0.92, 0), "full_minus_rate": (0.94, 0), "full_minus_rbac": (1.0, 0)}
    for config, (agreement, unsafe) in leave_one_out.items():
        record = run["configurations"][config]
        assert round(record["decision_exact_accuracy"], 2) == agreement
        assert record["unsafe_effect_scenarios"] == unsafe
    assert run["confirmatory"] is False and run["review_record"] is None
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert CANONICAL_RUN in readme            # the README must name the run it reports
    assert "--all-configs" in readme


def test_every_configuration_has_a_valid_audit_chain_file():
    _, run = _canonical()
    from governance.audit_chain import AuditChain, verify_chain  # backend is on sys.path via conftest
    for config, record in run["configurations"].items():
        chain_path = ROOT / record["audit_chain"]
        assert chain_path.is_file(), chain_path
        entries = AuditChain(str(chain_path)).entries()
        assert verify_chain(entries)[0] is True, config
        assert len(entries) == record["audit_chain_entries"]


def test_legacy_600_scenario_pipeline_is_archived_not_current():
    assert not (ROOT / "experiments" / "run_governance_benchmark.py").exists()
    assert not (ROOT / "experiments" / "build_claim_registry.py").exists()
    assert (ROOT / "results" / "provenance" / "legacy" / "README.md").is_file()


def _scannable_files():
    try:
        tracked = subprocess.run(
            ["git", "ls-files", "-co", "--exclude-standard", "-z"],
            cwd=ROOT, check=True, capture_output=True,
        ).stdout.decode("utf-8", errors="ignore").split("\0")
        return [t for t in tracked if t]
    except (OSError, subprocess.CalledProcessError):
        # No git metadata (for example an unpacked archive): walk the tree, skipping ignored paths,
        # and refuse to skip .env files, which are exactly where a key would sit.
        skip_dirs = {"node_modules", "__pycache__", ".git", "dist", "tmp"}
        found = []
        for path in ROOT.rglob("*"):
            if path.is_file() and not (skip_dirs & set(path.relative_to(ROOT).parts)):
                found.append(str(path.relative_to(ROOT)))
        return found


def test_secret_scan():
    patterns = [
        re.compile(r"gsk_[a-zA-Z0-9]{20,}"),
        re.compile(r"sk-proj-[a-zA-Z0-9]{20,}"),
        re.compile(r"sk-ant-[a-zA-Z0-9]{20,}"),
    ]
    scan_extensions = {".py", ".json", ".md", ".txt", ".env", ".ps1", ".yml", ".yaml"}
    excluded_roots = {"backend/data", "results/external", "frontend/node_modules"}
    for relative in _scannable_files():
        normalized = relative.replace("\\", "/")
        if any(normalized == item or normalized.startswith(item + "/") for item in excluded_roots):
            continue
        path = ROOT / relative
        # `.env` has suffix "" in pathlib, so match the file name too.
        is_env = path.name == ".env" or path.name.startswith(".env.")
        if not path.is_file() or (path.suffix.lower() not in scan_extensions and not is_env):
            continue
        if path.name == ".env.example":
            continue
        content = path.read_text(encoding="utf-8", errors="ignore")
        assert not any(pattern.search(content) for pattern in patterns), f"Potential API key in {path}"
