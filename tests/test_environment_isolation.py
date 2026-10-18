"""
Security and Integrity Test Matrix for PromptAegis Multi-Environment Isolation.

Covers Security Hardening Pass:
1. ContextVar Request Isolation & Token/Reset Semantics (Tests A-C, O)
2. Elimination of Unsafe Default Environment Fallbacks (Test P)
3. Authoritative Credential Routing & Environment Header Security Matrix (Tests G, H, Q)
4. Credential Storage, Secret Management, & Entropy (Test S)
5. Environment Registry Disclosure Sanitization (Test R)
6. Cross-Environment Negative Access Matrix (Test T)
7. Physical Rate Limit Isolation & Independent Reset (Tests J, U)
8. Physical Audit Log Isolation (Tests I, K)
9. Scientific Benchmark Integrity & Reproducibility (Tests C, F, M, N)
"""
import os
import tempfile
import sqlite3
import sys
import uuid
import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app import app
import config
from database import db
from database.environments import (
    CredentialManager,
    EnvironmentRegistry,
    environment_scope,
    get_current_environment,
    set_current_environment,
)
from governance.rate_limiter import get_limit, set_limit, reset_rate_limits

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def start_test_app():
    """Use isolated SQLite/credential files and run FastAPI lifespan explicitly."""
    tmp_root = os.path.join(PROJECT_ROOT, "tmp")
    os.makedirs(tmp_root, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="api-isolation-", dir=tmp_root) as temp_dir:
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

BENCHMARK_KEY = "pa_benchmark_test_key"
LOCAL_DEV_KEY = "pa_local_dev_key"
CONNECTED_APP_KEY = "pa_live_connected_app_key_test_token_2026"


@pytest.fixture(autouse=True)
def enable_test_credentials(monkeypatch):
    monkeypatch.setenv("PROMPTAEGIS_ALLOW_TEST_CREDENTIALS", "1")
    monkeypatch.setenv("PROMPTAEGIS_CONNECTED_APP_KEY", CONNECTED_APP_KEY)


# ============================================================================
# Core Environment Isolation Tests (A through N)
# ============================================================================

def test_a_local_dev_isolation():
    """Test A: Mutating local_dev does not leak into research_benchmark or connected_application."""
    unique_agent_name = f"DevAgent_{uuid.uuid4().hex[:6]}"
    resp = client.post(
        "/agents",
        headers={"X-PromptAegis-Key": LOCAL_DEV_KEY},
        json={"name": unique_agent_name, "description": "Local dev test agent", "role": "dev"},
    )
    assert resp.status_code == 201, resp.text
    agent_id = resp.json()["agent_id"]

    # Verify agent exists in local_dev
    dev_agents = client.get("/agents", headers={"X-PromptAegis-Key": LOCAL_DEV_KEY}).json()
    assert any(a["agent_id"] == agent_id for a in dev_agents)

    # Verify agent DOES NOT exist in research_benchmark
    bench_agents = client.get("/agents", headers={"X-PromptAegis-Key": BENCHMARK_KEY}).json()
    assert not any(a["agent_id"] == agent_id for a in bench_agents)

    # Verify agent DOES NOT exist in connected_application
    conn_agents = client.get("/agents", headers={"X-PromptAegis-Key": CONNECTED_APP_KEY}).json()
    assert not any(a["agent_id"] == agent_id for a in conn_agents)


def test_b_connected_application_isolation():
    """Test B: Mutating connected_application does not touch local_dev or research_benchmark."""
    unique_tool_name = f"live_stripe_charge_{uuid.uuid4().hex[:6]}"
    resp = client.post(
        "/tools",
        headers={"X-PromptAegis-Key": CONNECTED_APP_KEY},
        json={
            "name": unique_tool_name,
            "category": "finance",
            "risk_level": "high",
            "requires_approval": True,
            "description": "Live external payment processor",
        },
    )
    assert resp.status_code == 201, resp.text
    tool_id = resp.json()["tool_id"]

    # Verify tool exists in connected_application
    conn_tools = client.get("/tools", headers={"X-PromptAegis-Key": CONNECTED_APP_KEY}).json()
    assert any(t["tool_id"] == tool_id for t in conn_tools)

    # Verify tool DOES NOT exist in local_dev
    dev_tools = client.get("/tools", headers={"X-PromptAegis-Key": LOCAL_DEV_KEY}).json()
    assert not any(t["tool_id"] == tool_id for t in dev_tools)

    # Verify tool DOES NOT exist in research_benchmark
    bench_tools = client.get("/tools", headers={"X-PromptAegis-Key": BENCHMARK_KEY}).json()
    assert not any(t["tool_id"] == tool_id for t in bench_tools)


def test_c_research_benchmark_isolation():
    """Test C: Benchmark state resides in gateway_benchmark.db, completely separated."""
    bench_db_path = EnvironmentRegistry.resolve_db_path("research_benchmark")
    local_db_path = EnvironmentRegistry.resolve_db_path("local_dev")

    assert os.path.exists(bench_db_path)
    assert os.path.exists(local_db_path)
    assert bench_db_path != local_db_path


def test_d_seed_protection_connected_application():
    """Test D: Seeding connected_application returns HTTP 403 Forbidden."""
    resp = client.post(
        "/governance/seed",
        headers={"X-PromptAegis-Key": CONNECTED_APP_KEY},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "SEEDING_FORBIDDEN"
    assert "strictly restricted to the 'research_benchmark' environment" in resp.json()["detail"]["message"]


def test_e_seed_protection_local_dev():
    """Test E: Seeding local_dev returns HTTP 403 Forbidden."""
    resp = client.post(
        "/governance/seed",
        headers={"X-PromptAegis-Key": LOCAL_DEV_KEY},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "SEEDING_FORBIDDEN"


def test_f_seed_success_research_benchmark():
    """Test F: Seeding research_benchmark succeeds (HTTP 200) idempotently."""
    resp = client.post(
        "/governance/seed",
        headers={"X-PromptAegis-Key": BENCHMARK_KEY},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "seeded"


def test_g_missing_auth_on_intercept():
    """Test G: Missing API key on /intercept returns HTTP 401 Unauthorized."""
    resp = client.post(
        "/intercept",
        json={"agent_id": "agent_123", "tool_name": "send_email", "arguments": {}},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "AUTHENTICATION_REQUIRED"


def test_h_environment_spoofing_detection():
    """Test H: Mismatch between credential bound environment and X-PromptAegis-Environment returns HTTP 403."""
    resp = client.post(
        "/intercept",
        headers={
            "X-PromptAegis-Key": CONNECTED_APP_KEY,
            "X-PromptAegis-Environment": "research_benchmark",
        },
        json={"agent_id": "agent_123", "tool_name": "send_email", "arguments": {}},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "ENVIRONMENT_SPOOF_DETECTED"
    assert resp.json()["detail"]["bound_environment"] == "connected_application"
    assert resp.json()["detail"]["asserted_environment"] == "research_benchmark"

    # Matching environment header should be accepted without spoofing error
    resp_valid = client.get(
        "/environments/current",
        headers={
            "X-PromptAegis-Key": CONNECTED_APP_KEY,
            "X-PromptAegis-Environment": "connected_application",
        },
    )
    assert resp_valid.status_code == 200
    assert resp_valid.json()["environment_id"] == "connected_application"


def test_i_intercept_execution_physical_db_scoping():
    """Test I: Intercept execution in connected_application writes tool call ONLY to gateway_connected.db."""
    c_agent = client.post(
        "/agents",
        headers={"X-PromptAegis-Key": CONNECTED_APP_KEY},
        json={"name": f"AppAgent_{uuid.uuid4().hex[:6]}", "role": "service"},
    ).json()
    c_tool = client.post(
        "/tools",
        headers={"X-PromptAegis-Key": CONNECTED_APP_KEY},
        json={"name": f"app_service_call_{uuid.uuid4().hex[:6]}", "category": "read", "risk_level": "low"},
    ).json()

    client.post(
        "/permissions",
        headers={"X-PromptAegis-Key": CONNECTED_APP_KEY},
        json={"agent_id": c_agent["agent_id"], "tool_id": c_tool["tool_id"], "allowed": True},
    )

    intercept_resp = client.post(
        "/intercept",
        headers={"X-PromptAegis-Key": CONNECTED_APP_KEY},
        json={
            "agent_id": c_agent["agent_id"],
            "tool_name": c_tool["name"],
            "arguments": {"payload": "secure_data"},
            "user_id": "usr_99",
        },
    )
    assert intercept_resp.status_code == 200
    call_id = intercept_resp.json()["call_id"]
    assert intercept_resp.json()["environment_id"] == "connected_application"

    # Verify physical storage in gateway_connected.db
    connected_db_path = EnvironmentRegistry.resolve_db_path("connected_application")
    conn_c = sqlite3.connect(connected_db_path)
    cur_c = conn_c.cursor()
    cur_c.execute("SELECT call_id, agent_id, tool_name FROM tool_calls WHERE call_id=?", (call_id,))
    row_c = cur_c.fetchone()
    conn_c.close()
    assert row_c is not None
    assert row_c[0] == call_id

    # Verify record DOES NOT exist in gateway_benchmark.db
    bench_db_path = EnvironmentRegistry.resolve_db_path("research_benchmark")
    conn_b = sqlite3.connect(bench_db_path)
    cur_b = conn_b.cursor()
    cur_b.execute("SELECT call_id FROM tool_calls WHERE call_id=?", (call_id,))
    row_b = cur_b.fetchone()
    conn_b.close()
    assert row_b is None, "Physical leak: tool call appeared in gateway_benchmark.db!"


def test_j_rate_limit_scoping():
    """Test J: Rate limit override and counters are strictly scoped to the active environment."""
    test_tool = f"api_sync_{uuid.uuid4().hex[:6]}"

    resp_dev = client.post(
        f"/rate-limits/{test_tool}",
        headers={"X-PromptAegis-Key": LOCAL_DEV_KEY},
        json={"limit": 2},
    )
    assert resp_dev.status_code == 200
    assert resp_dev.json()["limit"] == 2
    assert resp_dev.json()["environment_id"] == "local_dev"

    assert get_limit(test_tool, env_id="local_dev") == 2
    assert get_limit(test_tool, env_id="research_benchmark") == 50
    assert get_limit(test_tool, env_id="connected_application") == 50


def test_k_audit_log_isolation():
    """Test K: Tool calls in research_benchmark are not visible in connected_application audit query."""
    seed = client.post("/governance/seed", headers={"X-PromptAegis-Key": BENCHMARK_KEY})
    assert seed.status_code == 200, seed.text
    agent = client.post(
        "/agents",
        headers={"X-PromptAegis-Key": BENCHMARK_KEY},
        json={"name": f"AuditIsolation_{uuid.uuid4().hex[:8]}", "role": "benchmark_runner"},
    )
    tool = client.post(
        "/tools",
        headers={"X-PromptAegis-Key": BENCHMARK_KEY},
        json={"name": f"audit_probe_{uuid.uuid4().hex[:8]}", "category": "read", "risk_level": "low"},
    )
    assert agent.status_code == 201, agent.text
    assert tool.status_code == 201, tool.text
    permission = client.post(
        "/permissions",
        headers={"X-PromptAegis-Key": BENCHMARK_KEY},
        json={"agent_id": agent.json()["agent_id"], "tool_id": tool.json()["tool_id"], "allowed": True},
    )
    assert permission.status_code in (200, 201), permission.text
    created = client.post(
        "/intercept",
        headers={"X-PromptAegis-Key": BENCHMARK_KEY},
        json={"agent_id": agent.json()["agent_id"], "tool_name": tool.json()["name"], "arguments": {"payload": "audit-isolation"}},
    )
    assert created.status_code == 200, created.text

    bench_calls = client.get("/tool-calls", headers={"X-PromptAegis-Key": BENCHMARK_KEY}, params={"limit": 5}).json()
    assert len(bench_calls) > 0, "Benchmark audit log should contain evaluation records"
    bench_call_ids = {c["call_id"] for c in bench_calls}

    conn_calls = client.get("/tool-calls", headers={"X-PromptAegis-Key": CONNECTED_APP_KEY}, params={"limit": 100}).json()
    conn_call_ids = {c["call_id"] for c in conn_calls}

    intersection = bench_call_ids.intersection(conn_call_ids)
    assert len(intersection) == 0, f"Cross-environment data leakage detected in audit logs! Shared IDs: {intersection}"


def test_l_get_environments_registry():
    """Test L: GET /environments lists registered environments and access rules."""
    resp = client.get("/environments")
    assert resp.status_code == 200
    envs = resp.json()
    env_ids = [e["id"] for e in envs]
    assert "research_benchmark" in env_ids
    assert "local_dev" in env_ids
    assert "connected_application" in env_ids

    benchmark_env = next(e for e in envs if e["id"] == "research_benchmark")
    assert benchmark_env["allow_seed"] is True

    local_dev_env = next(e for e in envs if e["id"] == "local_dev")
    assert local_dev_env["allow_seed"] is False

    connected_env = next(e for e in envs if e["id"] == "connected_application")
    assert connected_env["allow_seed"] is False


def test_m_research_benchmark_data_integrity():
    """Test M: Research benchmark schema exists without asserting stale historical row counts."""
    bench_db = EnvironmentRegistry.resolve_db_path("research_benchmark")
    local_db = EnvironmentRegistry.resolve_db_path("local_dev")
    connected_db = EnvironmentRegistry.resolve_db_path("connected_application")
    assert len({os.path.normcase(os.path.abspath(p)) for p in (bench_db, local_db, connected_db)}) == 3
    conn = sqlite3.connect(bench_db)
    cur = conn.cursor()
    tables = {row[0] for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert {"tool_calls", "experiment_runs", "experiment_events"}.issubset(tables)


def test_n_inprocess_python_context_default():
    """Test N: In-process direct python execution defaults to research_benchmark."""
    assert get_current_environment() == "research_benchmark"
    with db.get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) c FROM tool_calls").fetchone()
        assert isinstance(row["c"], int) and row["c"] >= 0


# ============================================================================
# Security Hardening Pass Tests (O through U)
# ============================================================================

def test_o_contextvar_request_isolation_and_alternation():
    """
    Test O: Guarantee request context is strictly request-scoped and cannot survive.
    Tests sequence: Request A (connected) -> Request B (local) -> Request C (unauthenticated)
    Tests repeated alternating requests across worker threads: connected -> local -> benchmark -> connected -> local
    """
    # Request A: authenticated as connected_application
    resp_a = client.get("/environments/current", headers={"X-PromptAegis-Key": CONNECTED_APP_KEY})
    assert resp_a.status_code == 200
    assert resp_a.json()["environment_id"] == "connected_application"

    # Request B: authenticated as local_dev
    resp_b = client.get("/environments/current", headers={"X-PromptAegis-Key": LOCAL_DEV_KEY})
    assert resp_b.status_code == 200
    assert resp_b.json()["environment_id"] == "local_dev"

    # Request C: unauthenticated caller
    resp_c = client.get("/environments/current")
    assert resp_c.status_code == 401
    assert resp_c.json()["detail"]["error"] == "AUTHENTICATION_REQUIRED"

    # Verify that local thread state did not leak into C, and verify alternating sequence
    sequence = [
        (CONNECTED_APP_KEY, "connected_application"),
        (LOCAL_DEV_KEY, "local_dev"),
        (BENCHMARK_KEY, "research_benchmark"),
        (CONNECTED_APP_KEY, "connected_application"),
        (LOCAL_DEV_KEY, "local_dev"),
    ]
    for key, expected_env in sequence:
        resp = client.get("/environments/current", headers={"X-PromptAegis-Key": key})
        assert resp.status_code == 200
        assert resp.json()["environment_id"] == expected_env

    # Final check: unauthenticated call must still be rejected immediately
    resp_c_final = client.get("/agents")
    assert resp_c_final.status_code == 401


def test_p_elimination_of_unsafe_default_fallbacks():
    """
    Test P: Complete zero-trust enforcement across all sensitive environment-scoped endpoints.
    No credential MUST yield 401 AUTHENTICATION_REQUIRED (no silent fallback).
    Public endpoints (/health, /readiness, GET /environments) remain open.
    """
    endpoints_to_test = [
        ("GET", "/agents"),
        ("POST", "/agents"),
        ("GET", "/tools"),
        ("POST", "/tools"),
        ("POST", "/permissions"),
        ("GET", "/policies"),
        ("POST", "/policies"),
        ("POST", "/intercept"),
        ("GET", "/tool-calls"),
        ("GET", "/governance/stats"),
        ("POST", "/rate-limits/test_tool"),
        ("POST", "/governance/seed"),
        ("POST", "/governance/credentials"),
        ("POST", "/environments"),
        ("GET", "/environments/current"),
    ]

    for method, path in endpoints_to_test:
        if method == "GET":
            resp = client.get(path)
        else:
            resp = client.post(path, json={})
        assert resp.status_code == 401, f"Endpoint {method} {path} unexpectedly returned {resp.status_code} without auth!"
        assert resp.json()["detail"]["error"] == "AUTHENTICATION_REQUIRED"

    # Confirm public endpoints remain open and functional
    assert client.get("/health").status_code == 200
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/readiness").status_code == 200
    assert client.get("/readiness").json()["status"] == "ready"


def test_q_environment_header_security_matrix():
    """
    Test Q: Validate exhaustive 5-part header security matrix.
    Authoritative identity MUST come strictly from the credential.
    """
    # 1. Valid credential + matching header -> 200 OK
    resp1 = client.get(
        "/environments/current",
        headers={"X-PromptAegis-Key": CONNECTED_APP_KEY, "X-PromptAegis-Environment": "connected_application"},
    )
    assert resp1.status_code == 200
    assert resp1.json()["environment_id"] == "connected_application"

    # 2. Valid credential + omitted header -> 200 OK (credential is authority)
    resp2 = client.get(
        "/environments/current",
        headers={"X-PromptAegis-Key": CONNECTED_APP_KEY},
    )
    assert resp2.status_code == 200
    assert resp2.json()["environment_id"] == "connected_application"

    # 3. Valid credential + mismatched header -> 403 ENVIRONMENT_SPOOF_DETECTED
    resp3 = client.get(
        "/environments/current",
        headers={"X-PromptAegis-Key": CONNECTED_APP_KEY, "X-PromptAegis-Environment": "local_dev"},
    )
    assert resp3.status_code == 403
    assert resp3.json()["detail"]["error"] == "ENVIRONMENT_SPOOF_DETECTED"

    # 4. Invalid credential + arbitrary header -> 401 INVALID_CREDENTIAL
    resp4 = client.get(
        "/environments/current",
        headers={"X-PromptAegis-Key": "pa_invalid_attacker_key", "X-PromptAegis-Environment": "connected_application"},
    )
    assert resp4.status_code == 401
    assert resp4.json()["detail"]["error"] == "INVALID_CREDENTIAL"

    # 5. Missing credential + arbitrary header -> 401 AUTHENTICATION_REQUIRED
    resp5 = client.get(
        "/environments/current",
        headers={"X-PromptAegis-Environment": "connected_application"},
    )
    assert resp5.status_code == 401
    assert resp5.json()["detail"]["error"] == "AUTHENTICATION_REQUIRED"


def test_r_environment_registry_disclosure_sanitization():
    """
    Test R: GET /environments must NOT disclose database filenames, paths, or secrets.
    """
    resp = client.get("/environments")
    assert resp.status_code == 200
    envs = resp.json()
    assert len(envs) >= 3

    for e in envs:
        # Must not contain db_filename or filesystem paths
        assert "db_filename" not in e, f"Leaked internal db_filename in environment {e.get('id')}"
        assert "path" not in e
        assert "db_path" not in e
        assert "credentials" not in e
        # Must contain safe metadata only
        assert "id" in e
        assert "name" in e
        assert "type" in e
        assert "description" in e
        assert "allow_seed" in e


def test_s_secrets_management_and_env_var_override():
    """
    Test S: Support dynamic environment variable credential loading, entropy, and zero leakage in errors.
    """
    # 1. Test environment variable injection
    custom_secret = f"pa_live_env_test_{uuid.uuid4().hex}"
    os.environ["PROMPTAEGIS_CONNECTED_APP_KEY"] = custom_secret

    resp_env = client.get(
        "/environments/current",
        headers={"X-PromptAegis-Key": custom_secret},
    )
    assert resp_env.status_code == 200
    assert resp_env.json()["environment_id"] == "connected_application"

    # Clean up environment variable
    del os.environ["PROMPTAEGIS_CONNECTED_APP_KEY"]

    # 2. Test token entropy on credential creation
    admin_key = BENCHMARK_KEY
    resp_create = client.post(
        "/governance/credentials",
        headers={"X-PromptAegis-Key": admin_key},
        json={"environment_id": "connected_application", "name": "Dynamic Production Key"},
    )
    assert resp_create.status_code == 201
    new_token = resp_create.json()["token"]
    assert new_token.startswith("pa_live_")
    # Entropy check: minimum 48 hex characters after prefix
    token_hex = new_token[len("pa_live_"):]
    assert len(token_hex) >= 48

    # 3. Test that error messages do NOT echo secret tokens
    malformed_key = "secret_attempt_forbidden_xyz123"
    resp_err = client.get(
        "/environments/current",
        headers={"X-PromptAegis-Key": malformed_key},
    )
    assert resp_err.status_code == 401
    assert malformed_key not in resp_err.text, "Secret key was echoed in error response!"


def test_t_cross_environment_negative_access_matrix():
    """
    Test T: Explicit cross-environment data access denial.
    Every credential must operate exclusively against its bound environment.
    """
    # 1. Register a private agent in local_dev
    private_local_agent = f"LocalPriv_{uuid.uuid4().hex[:6]}"
    client.post(
        "/agents",
        headers={"X-PromptAegis-Key": LOCAL_DEV_KEY},
        json={"name": private_local_agent, "role": "dev"},
    )

    # 2. Connected credential attempting to query agents must NOT see private_local_agent
    conn_agents = client.get("/agents", headers={"X-PromptAegis-Key": CONNECTED_APP_KEY}).json()
    assert not any(a["name"] == private_local_agent for a in conn_agents)

    # 3. Benchmark credential attempting to query agents must NOT see private_local_agent
    bench_agents = client.get("/agents", headers={"X-PromptAegis-Key": BENCHMARK_KEY}).json()
    assert not any(a["name"] == private_local_agent for a in bench_agents)

    # 4. Connected credential attempting to query benchmark policies must NOT see benchmark policies
    conn_policies = client.get("/policies", headers={"X-PromptAegis-Key": CONNECTED_APP_KEY}).json()
    bench_policies = client.get("/policies", headers={"X-PromptAegis-Key": BENCHMARK_KEY}).json()
    bench_policy_names = {p["name"] for p in bench_policies}
    conn_policy_names = {p["name"] for p in conn_policies}
    # Benchmark has "Block support agents from delete_customer"
    assert "Block support agents from delete_customer" in bench_policy_names
    assert "Block support agents from delete_customer" not in conn_policy_names

    # 5. Local credential attempting to seed benchmark must return 403
    resp_seed = client.post("/governance/seed", headers={"X-PromptAegis-Key": LOCAL_DEV_KEY})
    assert resp_seed.status_code == 403


def test_u_rate_limit_isolation_and_independent_reset():
    """
    Test U: Rate limiting counters in one environment do NOT affect other environments.
    Resetting rate limits in local_dev does not reset counters in connected_application or benchmark.
    """
    shared_tool = f"shared_calc_{uuid.uuid4().hex[:6]}"

    # Reset counters for clean baseline
    reset_rate_limits("connected_application")
    reset_rate_limits("local_dev")
    reset_rate_limits("research_benchmark")

    # In connected_application, increment 3 times
    with environment_scope("connected_application"):
        db.increment_rate_limit("agent_x", shared_tool, 1000.0)
        db.increment_rate_limit("agent_x", shared_tool, 1000.0)
        db.increment_rate_limit("agent_x", shared_tool, 1000.0)

    # In local_dev, increment 2 times
    with environment_scope("local_dev"):
        db.increment_rate_limit("agent_x", shared_tool, 1000.0)
        db.increment_rate_limit("agent_x", shared_tool, 1000.0)

    # In research_benchmark, increment 1 time
    with environment_scope("research_benchmark"):
        db.increment_rate_limit("agent_x", shared_tool, 1000.0)

    # Verify counts in each DB
    with environment_scope("connected_application"):
        assert db.get_rate_limit_count("agent_x", shared_tool, 1000.0) == 3
    with environment_scope("local_dev"):
        assert db.get_rate_limit_count("agent_x", shared_tool, 1000.0) == 2
    with environment_scope("research_benchmark"):
        assert db.get_rate_limit_count("agent_x", shared_tool, 1000.0) == 1

    # Reset ONLY local_dev
    reset_rate_limits("local_dev")

    # Verify local_dev is 0, while connected remains 3 and benchmark remains 1
    with environment_scope("local_dev"):
        assert db.get_rate_limit_count("agent_x", shared_tool, 1000.0) == 0
    with environment_scope("connected_application"):
        assert db.get_rate_limit_count("agent_x", shared_tool, 1000.0) == 3
    with environment_scope("research_benchmark"):
        assert db.get_rate_limit_count("agent_x", shared_tool, 1000.0) == 1
