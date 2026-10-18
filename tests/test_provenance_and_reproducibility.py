"""Integrity checks for the current PromptAegis evidence chain."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_claim_registry_links_corrected_run_and_historical_pilot():
    registry_path = ROOT / "results" / "provenance" / "claim_registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    current = registry["claims"]
    historical = registry["historical_claims"]
    assert len(current) == 24
    assert len(historical) == 6
    assert all(claim["status"] == "current_corrected_replay" for claim in current)
    assert all(claim["status"] == "historical_exploratory_pilot" for claim in historical)

    result_path = ROOT / current[0]["result_artifact"]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    digest = _sha256(result_path)
    assert registry["git_worktree_dirty"] is True
    assert all(claim["result_sha256"] == digest for claim in current)
    assert all(claim["result_artifact"] == current[0]["result_artifact"] for claim in current)

    for configuration, record in result["configurations"].items():
        events = record["events"]
        assert all(event["agent_name"] == "CustomerSupportAgent" for event in events)
        assert record["actual_agent_counts"] == {"CustomerSupportAgent": 600}
        expected_unsafe = [e for e in events if e["expected_decision"] != "ALLOW"]
        expected_allow = [e for e in events if e["expected_decision"] == "ALLOW"]
        m = record["metrics"]
        assert round(sum(e["actual_decision"] == "ALLOW" for e in expected_unsafe) / len(expected_unsafe), 4) == m["unsafe_tool_call_allow_rate"]
        assert round(sum(e["actual_decision"] == "ALLOW" for e in expected_allow) / len(expected_allow), 4) == m["legitimate_request_allow_rate"]
        assert round(sum(e["actual_decision"] != "ALLOW" for e in expected_allow) / len(expected_allow), 4) == m["false_positive_rate"]
        assert m["audit_events"] == len(events)
        assert m["audit_coverage"] == 1.0

    for claim in historical:
        archived = subprocess.run(
            ["git", "show", f"{claim['source_commit']}:{claim['source_artifact']}"],
            cwd=ROOT, check=True, capture_output=True,
        ).stdout
        assert hashlib.sha256(archived).hexdigest() == claim["source_artifact_sha256"]


def test_scenario_principals_and_expected_burst_labels_are_explicit():
    scenario_dir = ROOT / "backend" / "data" / "benchmark"
    files = sorted(scenario_dir.glob("*.json"))
    assert len(files) == 6
    all_ids = set()
    for path in files:
        rows = json.loads(path.read_text(encoding="utf-8"))
        assert len(rows) == 100
        assert all(row["agent_name"] == "CustomerSupportAgent" for row in rows)
        assert all(row["scenario_id"] not in all_ids for row in rows)
        all_ids.update(row["scenario_id"] for row in rows)

    burst = json.loads((scenario_dir / "excessive_calls.json").read_text(encoding="utf-8"))
    labels_by_tool = {}
    for tool in {row["expected_tool"] for row in burst}:
        tool_rows = [row for row in burst if row["expected_tool"] == tool]
        positions = [row["burst_sequence_position"] for row in tool_rows]
        assert positions == list(range(1, len(tool_rows) + 1))
        labels_by_tool[tool] = Counter(row["expected_decision"] for row in tool_rows)
        assert labels_by_tool[tool]["ALLOW"] == 10
        assert labels_by_tool[tool]["RATE_LIMIT"] == len(tool_rows) - 10


def test_figure_generator_is_result_driven():
    script = (ROOT / "experiments" / "generate_paper_figures.py").read_text(encoding="utf-8")
    assert "json.loads(path.read_text" in script
    assert "records[c][\"metrics\"]" in script
    assert "governance_allow_rates.png" in script
    assert "governance_latency.png" in script
    assert "parameter_manipulation_misses.png" in script
    assert (ROOT / "paper" / "figures" / "governance_allow_rates.png").is_file()
    assert (ROOT / "paper" / "figures" / "governance_latency.png").is_file()
    assert (ROOT / "paper" / "figures" / "parameter_manipulation_misses.png").is_file()


def test_secret_scan():
    patterns = [
        re.compile(r"gsk_[a-zA-Z0-9]{20,}"),
        re.compile(r"sk-proj-[a-zA-Z0-9]{20,}"),
        re.compile(r"sk-ant-[a-zA-Z0-9]{20,}"),
    ]
    tracked = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"],
        cwd=ROOT, check=True, capture_output=True,
    ).stdout.decode("utf-8", errors="ignore").split("\0")
    scan_extensions = {".py", ".json", ".md", ".txt", ".env"}
    excluded_roots = {"backend/data", "results/external", "frontend/node_modules"}
    for relative in tracked:
        if not relative:
            continue
        normalized = relative.replace("\\", "/")
        if any(normalized == item or normalized.startswith(item + "/") for item in excluded_roots):
            continue
        path = ROOT / relative
        if not path.is_file() or path.suffix.lower() not in scan_extensions:
            continue
        content = path.read_text(encoding="utf-8", errors="ignore")
        assert not any(pattern.search(content) for pattern in patterns), f"Potential API key in {path}"
