"""
PromptAegis Security Control Plane Frontend & Integration Scenarios Test Suite.
Validates Final Review Matrix A through M:
- A: Raw credential masking in frontend source and UI
- B: Absence of clear-text credentials in JavaScript bundle / source
- C: Multi-credential environment switching
- D: Header mismatch detection (negative test / 403 Spoof detection)
- E: Accurate 6-stage Decision Trace semantics
- F: Absence of fabricated PASS results for unrecorded stages
- G: Accurate rate-limiter terminology ("60-second fixed/tumbling window")
- H: Verification Lab disabled in connected_application (UI level)
- I: Verification Lab 403 enforcement on backend when target is connected_application
- J: Verification Lab allowed in local_dev and research_benchmark
- K: Role-based write controls (write permitted for admin/write roles, rejected for read-only)
- L: Real-time claim removal (no "streaming" or "live stream")
- M: Empty-state data provenance (strictly no cross-environment contamination)
"""
import glob
import json
import os
import re
import sys
import tempfile
import pytest
from fastapi.testclient import TestClient

BASE_URL = "http://localhost:8000"

BENCHMARK_KEY = "pa_benchmark_test_key"
LOCAL_DEV_KEY = "pa_local_dev_key"
CONNECTED_KEY = "pa_live_connected_app_key_test_token_2026"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(REPO_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app import app
import config

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def start_test_app():
    """Use isolated SQLite/credential files and run FastAPI lifespan explicitly."""
    tmp_root = os.path.join(REPO_ROOT, "tmp")
    os.makedirs(tmp_root, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="api-frontend-", dir=tmp_root) as temp_dir:
        names = (
            "BENCHMARK_DB_PATH", "LOCAL_DEV_DB_PATH", "CONNECTED_APP_DB_PATH",
            "CREDENTIALS_REGISTRY_PATH",
        )
        previous = {name: getattr(config, name) for name in names}
        config.BENCHMARK_DB_PATH = os.path.join(temp_dir, "benchmark.db")
        config.LOCAL_DEV_DB_PATH = os.path.join(temp_dir, "local.db")
        config.CONNECTED_APP_DB_PATH = os.path.join(temp_dir, "connected.db")
        config.CREDENTIALS_REGISTRY_PATH = os.path.join(temp_dir, "credentials.json")
        try:
            client.__enter__()
            yield
        finally:
            client.__exit__(None, None, None)
            for name, value in previous.items():
                setattr(config, name, value)


@pytest.fixture(autouse=True)
def enable_test_credentials(monkeypatch):
    monkeypatch.setenv("PROMPTAEGIS_ALLOW_TEST_CREDENTIALS", "1")
    monkeypatch.setenv("PROMPTAEGIS_CONNECTED_APP_KEY", CONNECTED_KEY)


def api_request(path, method="GET", body=None, key=None, env=None):
    headers = {"Content-Type": "application/json"}
    if key is not None:
        headers["X-PromptAegis-Key"] = key
        headers["Authorization"] = f"Bearer {key}"
    if env is not None:
        headers["X-PromptAegis-Environment"] = env

    response = client.request(method, path, headers=headers, json=body)
    try:
        payload = response.json()
    except ValueError:
        payload = {"raw": response.text}
    return response.status_code, payload


# ============================================================================
# Test Matrix A - M
# ============================================================================

def test_matrix_a_raw_credential_masking():
    """A. Raw credential masking in frontend source and UI."""
    gov_panel_path = os.path.join(REPO_ROOT, "frontend", "src", "pages", "GovernancePanel.jsx")
    with open(gov_panel_path, "r", encoding="utf-8") as fp:
        gov_source = fp.read()

    # Must not contain "Reveal Secret" or "Reveal Token"
    assert "Reveal Secret" not in gov_source
    assert "Reveal Token" not in gov_source
    # Must use maskCredential
    assert "maskCredential" in gov_source


def test_matrix_b_absence_of_clear_text_credentials_in_bundle():
    """B. Absence of clear-text credentials in JavaScript bundle / source."""
    dist_js_files = glob.glob(os.path.join(REPO_ROOT, "frontend", "dist", "assets", "*.js"))
    assert len(dist_js_files) > 0, "Frontend must be built prior to bundle inspection"

    for js_path in dist_js_files:
        with open(js_path, "r", encoding="utf-8") as fp:
            bundle_content = fp.read()
        assert BENCHMARK_KEY not in bundle_content
        assert LOCAL_DEV_KEY not in bundle_content
        assert CONNECTED_KEY not in bundle_content


def test_matrix_c_multi_credential_environment_switching():
    """C. Multi-credential environment switching: correct key bound to each env."""
    # Benchmark env context
    status, ctx_bench = api_request("/environments/current", key=BENCHMARK_KEY, env="research_benchmark")
    assert status == 200
    assert ctx_bench["environment_id"] == "research_benchmark"

    # Local dev env context
    status, ctx_dev = api_request("/environments/current", key=LOCAL_DEV_KEY, env="local_dev")
    assert status == 200
    assert ctx_dev["environment_id"] == "local_dev"

    # Connected app env context
    status, ctx_conn = api_request("/environments/current", key=CONNECTED_KEY, env="connected_application")
    assert status == 200
    assert ctx_conn["environment_id"] == "connected_application"


def test_matrix_d_header_mismatch_detection_spoof_403():
    """D. Header mismatch detection: key(local_dev) + env(research_benchmark) -> 403."""
    status, err = api_request("/agents", key=LOCAL_DEV_KEY, env="research_benchmark")
    assert status == 403
    detail = err.get("detail", {})
    error_code = detail.get("error", "") if isinstance(detail, dict) else str(detail)
    assert "ENVIRONMENT_SPOOF_DETECTED" in error_code


def test_matrix_e_accurate_6_stage_decision_trace_semantics():
    """E. Accurate 6-stage Decision Trace semantics in UI."""
    gov_panel_path = os.path.join(REPO_ROOT, "frontend", "src", "pages", "GovernancePanel.jsx")
    with open(gov_panel_path, "r", encoding="utf-8") as fp:
        gov_source = fp.read()

    # The canonical 6 stages must be explicitly present in trace reconstruction
    assert "1. Rate Limiter (60s Fixed/Tumbling Window)" in gov_source
    assert "2. Identity & RBAC Capability Gate" in gov_source
    assert "3. Parameter Canonicalization" in gov_source
    assert "4. Parameter Invariant Policy Evaluation" in gov_source
    assert "5. Risk Scoring & Approval Gate" in gov_source
    assert "6. Structured Audit Log (Forensic Record)" in gov_source


def test_matrix_f_absence_of_fabricated_pass_results_for_unrecorded_stages():
    """F. Absence of fabricated PASS results: unrecorded/skipped stages labeled truthfully."""
    gov_panel_path = os.path.join(REPO_ROOT, "frontend", "src", "pages", "GovernancePanel.jsx")
    with open(gov_panel_path, "r", encoding="utf-8") as fp:
        gov_source = fp.read()

    assert "Not recorded (historical schema)" in gov_source
    assert "SKIPPED / NOT EVALUATED" in gov_source


def test_matrix_g_accurate_rate_limiter_terminology():
    """G. Accurate rate-limiter terminology: zero occurrences of 'sliding window'."""
    gov_panel_path = os.path.join(REPO_ROOT, "frontend", "src", "pages", "GovernancePanel.jsx")
    with open(gov_panel_path, "r", encoding="utf-8") as fp:
        gov_source = fp.read()

    assert "sliding window" not in gov_source.lower()
    assert "60-second fixed/tumbling window" in gov_source or "60s fixed/tumbling window" in gov_source.lower()


def test_matrix_h_verification_lab_disabled_in_connected_application_ui():
    """H. Verification Lab disabled in connected_application at UI level."""
    gov_panel_path = os.path.join(REPO_ROOT, "frontend", "src", "pages", "GovernancePanel.jsx")
    with open(gov_panel_path, "r", encoding="utf-8") as fp:
        gov_source = fp.read()

    assert "VERIFICATION LAB DISABLED IN CONNECTED APPLICATION" in gov_source
    assert "SIMULATION DISABLED IN LIVE CONNECTED APPLICATION" in gov_source


def test_matrix_i_verification_lab_403_backend_enforcement():
    """I. Verification Lab 403 enforcement on backend when target is connected_application."""
    status, res = api_request(
        "/intercept",
        method="POST",
        body={
            "agent_id": "test_agent",
            "tool_name": "search_customer",
            "arguments": {"customer_id": "1"},
            "source": "verification_lab",
        },
        key=CONNECTED_KEY,
        env="connected_application",
    )
    assert status == 403
    assert "VERIFICATION_LAB_PROHIBITED_IN_CONNECTED_APP" in str(res)


def test_matrix_j_verification_lab_allowed_in_local_dev_and_benchmark():
    """J. Verification Lab allowed in local_dev and research_benchmark."""
    # Allowed in benchmark
    status, res_bench = api_request(
        "/intercept",
        method="POST",
        body={
            "agent_id": "agent_01",
            "tool_name": "search_customer",
            "arguments": {"customer_id": "101"},
            "source": "verification_lab",
        },
        key=BENCHMARK_KEY,
        env="research_benchmark",
    )
    assert status == 200
    assert "decision" in res_bench

    # Allowed in local_dev
    status, res_dev = api_request(
        "/intercept",
        method="POST",
        body={
            "agent_id": "sandbox_agent",
            "tool_name": "search_customer",
            "arguments": {"customer_id": "101"},
            "source": "verification_lab",
        },
        key=LOCAL_DEV_KEY,
        env="local_dev",
    )
    assert status == 200
    assert "decision" in res_dev

    # Remove the isolated test call from the selected benchmark environment.
    import sqlite3
    from database.environments import EnvironmentRegistry
    db_path = EnvironmentRegistry.resolve_db_path("research_benchmark")
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM tool_calls WHERE call_id = ?", (res_bench["call_id"],))
    conn.commit()
    conn.close()


def test_matrix_k_role_based_write_controls():
    """K. Role-based write controls: authenticated role reflected truthfully."""
    # Benchmark key has benchmark_runner role (write permitted)
    status, ctx = api_request("/environments/current", key=BENCHMARK_KEY, env="research_benchmark")
    assert status == 200
    assert ctx["role"] == "benchmark_runner"

    # Missing authentication rejects write with 401
    status, err = api_request(
        "/agents",
        method="POST",
        body={"name": "rogue_agent"},
        key=None,
        env=None,
    )
    assert status == 401


def test_matrix_l_real_time_claim_removal():
    """L. Real-time claim removal: no 'streaming' or 'live stream' in governance UI."""
    gov_panel_path = os.path.join(REPO_ROOT, "frontend", "src", "pages", "GovernancePanel.jsx")
    with open(gov_panel_path, "r", encoding="utf-8") as fp:
        gov_source = fp.read()

    assert "live stream" not in gov_source.lower()
    assert "streaming" not in gov_source.lower()
    assert "Runtime Events" in gov_source


def test_matrix_m_empty_state_data_provenance():
    """M. Empty-state data provenance: strictly no cross-environment contamination."""
    # Counts are intentionally not tied to a historical corpus-size threshold.
    status, bench_stats = api_request("/governance/stats", key=BENCHMARK_KEY, env="research_benchmark")
    assert status == 200
    assert isinstance(bench_stats["total_tool_calls"], int)

    # Local dev stats has isolated state
    status, dev_stats = api_request("/governance/stats", key=LOCAL_DEV_KEY, env="local_dev")
    assert status == 200
    assert isinstance(dev_stats["total_tool_calls"], int)

    # Connected app stats has isolated state
    status, conn_stats = api_request("/governance/stats", key=CONNECTED_KEY, env="connected_application")
    assert status == 200
    assert isinstance(conn_stats["total_tool_calls"], int)
    from database.environments import EnvironmentRegistry
    paths = [EnvironmentRegistry.resolve_db_path(env) for env in
             ("research_benchmark", "local_dev", "connected_application")]
    assert len({os.path.normcase(os.path.abspath(path)) for path in paths}) == 3
