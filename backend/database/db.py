"""
SQLite storage for:
  - Detection logs (prompt injection pipeline — original)
  - Governance tables (Prompt Aegis 2.0 PRD requirements):
    agents, tools, permissions, policies, tool_calls, rate_limit_counters,
    experiment_runs, experiment_events
"""
import json
import os
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    session_id TEXT,
    source TEXT NOT NULL,
    prompt TEXT NOT NULL,
    sanitized_output TEXT,
    tier TEXT NOT NULL,
    score REAL NOT NULL,
    action TEXT NOT NULL,
    explanation TEXT NOT NULL,
    rule_score REAL,
    matched_rules TEXT,
    embedding_score REAL,
    nearest_attack_cluster TEXT,
    classifier_prob REAL,
    drift_score REAL,
    drift_flagged INTEGER
);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_tier ON logs(tier);

-- ---- Governance: Agents ----
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    role TEXT DEFAULT 'default',
    created_at REAL NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_name ON agents(name);


-- ---- Governance: Tools ----
CREATE TABLE IF NOT EXISTS tools (
    tool_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,
    risk_level TEXT NOT NULL CHECK(risk_level IN ('low', 'medium', 'high')),
    requires_approval INTEGER DEFAULT 0,
    description TEXT DEFAULT '',
    created_at REAL NOT NULL
);

-- ---- Governance: Permissions (agent -> tool: allow/deny) ----
CREATE TABLE IF NOT EXISTS permissions (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    tool_id TEXT NOT NULL REFERENCES tools(tool_id) ON DELETE CASCADE,
    allowed INTEGER NOT NULL DEFAULT 1,
    UNIQUE(agent_id, tool_id)
);

-- ---- Governance: Policies ----
CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    policy_type TEXT NOT NULL,
    target_agent_id TEXT,
    target_tool_id TEXT,
    condition_json TEXT NOT NULL DEFAULT '{}',
    action TEXT NOT NULL CHECK(action IN ('ALLOW','DENY','REQUIRE_APPROVAL','RATE_LIMIT')),
    priority INTEGER DEFAULT 100,
    enabled INTEGER DEFAULT 1,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);

-- ---- Governance: Tool Calls (audit log) ----
CREATE TABLE IF NOT EXISTS tool_calls (
    call_id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    agent_id TEXT NOT NULL,
    user_id TEXT DEFAULT '',
    tool_name TEXT NOT NULL,
    arguments_json TEXT NOT NULL DEFAULT '{}',
    decision TEXT NOT NULL CHECK(decision IN ('ALLOW','DENY','REQUIRE_APPROVAL','RATE_LIMIT')),
    reason TEXT NOT NULL,
    policy_id TEXT DEFAULT '',
    risk_score REAL NOT NULL DEFAULT 0.0,
    latency_ms REAL DEFAULT 0.0,
    experiment_run_id TEXT DEFAULT '',
    configuration TEXT DEFAULT 'full'
);
CREATE INDEX IF NOT EXISTS idx_tool_calls_timestamp ON tool_calls(timestamp);
CREATE INDEX IF NOT EXISTS idx_tool_calls_agent ON tool_calls(agent_id);
CREATE INDEX IF NOT EXISTS idx_tool_calls_decision ON tool_calls(decision);

-- ---- Governance: Rate Limit Counters ----
CREATE TABLE IF NOT EXISTS rate_limit_counters (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    window_start REAL NOT NULL,
    call_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(agent_id, tool_name, window_start)
);

-- ---- Governance: Experiment Runs ----
CREATE TABLE IF NOT EXISTS experiment_runs (
    run_id TEXT PRIMARY KEY,
    configuration TEXT NOT NULL,
    description TEXT DEFAULT '',
    started_at REAL NOT NULL,
    completed_at REAL,
    status TEXT DEFAULT 'running',
    total_scenarios INTEGER DEFAULT 0,
    metrics_json TEXT DEFAULT '{}'
);

-- ---- Governance: Experiment Events (per-scenario outcomes) ----
CREATE TABLE IF NOT EXISTS experiment_events (
    event_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES experiment_runs(run_id),
    scenario_id TEXT NOT NULL,
    category TEXT NOT NULL,
    expected_decision TEXT NOT NULL,
    actual_decision TEXT NOT NULL,
    latency_ms REAL DEFAULT 0.0,
    correct INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_exp_events_run ON experiment_events(run_id);
"""


def init_db(env: Optional[str] = None):
    """Initialize database schemas for one or all registered environments with WAL mode enabled."""
    from database.environments import EnvironmentRegistry
    envs_to_init = [env] if env else [e["id"] for e in EnvironmentRegistry.list_environments()]
    for e_id in envs_to_init:
        db_path = EnvironmentRegistry.resolve_db_path(e_id)
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.executescript(_SCHEMA)
        conn.commit()
        conn.close()


@contextmanager
def get_conn(env: Optional[str] = None):
    """Authoritative connection provider routing to the current or specified environment DB."""
    from database.environments import EnvironmentRegistry, get_current_environment
    target_env = env or get_current_environment()
    db_path = EnvironmentRegistry.resolve_db_path(target_env)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()



def insert_log(result) -> None:
    """result: core.pipeline.DetectionResult"""
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO logs (
                id, timestamp, session_id, source, prompt, sanitized_output,
                tier, score, action, explanation, rule_score, matched_rules,
                embedding_score, nearest_attack_cluster, classifier_prob,
                drift_score, drift_flagged
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                result.id,
                result.timestamp,
                result.session_id,
                result.source,
                result.original_prompt,
                result.sanitized_output,
                result.tier,
                result.score,
                result.action,
                result.explanation,
                result.rule_score,
                json.dumps(result.matched_rules),
                result.embedding_score,
                result.nearest_attack_cluster,
                result.classifier_prob,
                result.drift_score,
                int(result.drift_flagged),
            ),
        )


def fetch_logs(tier: Optional[str] = None, limit: int = 200) -> List[dict]:
    query = "SELECT * FROM logs"
    params = []
    if tier:
        query += " WHERE tier = ?"
        params.append(tier.upper())
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def fetch_statistics() -> dict:
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
        by_tier = conn.execute(
            "SELECT tier, COUNT(*) c FROM logs GROUP BY tier"
        ).fetchall()
        by_action = conn.execute(
            "SELECT action, COUNT(*) c FROM logs GROUP BY action"
        ).fetchall()
        avg_score = conn.execute("SELECT AVG(score) a FROM logs").fetchone()["a"] or 0.0

    return {
        "total_requests": total,
        "by_tier": {r["tier"]: r["c"] for r in by_tier},
        "by_action": {r["action"]: r["c"] for r in by_action},
        "average_risk_score": round(avg_score, 4),
    }


def clear_logs():
    with get_conn() as conn:
        conn.execute("DELETE FROM logs")


# ============================================================================
# Governance CRUD — Agents (FR-01)
# ============================================================================

def create_agent(agent_id: str, name: str, description: str = "", role: str = "default") -> Dict[str, Any]:
    import time
    ts = time.time()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO agents (agent_id, name, description, role, created_at) VALUES (?,?,?,?,?)",
            (agent_id, name, description, role, ts)
        )
    return {"agent_id": agent_id, "name": name, "description": description, "role": role, "created_at": ts}


def list_agents() -> List[Dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM agents ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def get_agent(agent_id: str) -> Optional[Dict]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        return dict(row) if row else None


def delete_agent(agent_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM agents WHERE agent_id=?", (agent_id,))
        return cur.rowcount > 0


# ============================================================================
# Governance CRUD — Tools (FR-02)
# ============================================================================

_RISK_SCORES = {"low": 1.0, "medium": 4.0, "high": 8.0}


def create_tool(tool_id: str, name: str, category: str, risk_level: str,
                requires_approval: bool = False, description: str = "") -> Dict[str, Any]:
    import time
    ts = time.time()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO tools (tool_id, name, category, risk_level, requires_approval, description, created_at) VALUES (?,?,?,?,?,?,?)",
            (tool_id, name, category, risk_level, int(requires_approval), description, ts)
        )
    return {"tool_id": tool_id, "name": name, "category": category, "risk_level": risk_level,
            "requires_approval": requires_approval, "description": description, "created_at": ts}


def list_tools() -> List[Dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM tools ORDER BY risk_level").fetchall()
        return [dict(r) for r in rows]


def get_tool(tool_id: str) -> Optional[Dict]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM tools WHERE tool_id=?", (tool_id,)).fetchone()
        return dict(row) if row else None


def get_tool_by_name(name: str) -> Optional[Dict]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM tools WHERE name=?", (name,)).fetchone()
        return dict(row) if row else None


def delete_tool(tool_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM tools WHERE tool_id=?", (tool_id,))
        return cur.rowcount > 0


# ============================================================================
# Governance CRUD — Permissions (FR-03)
# ============================================================================

def set_permission(perm_id: str, agent_id: str, tool_id: str, allowed: bool) -> Dict[str, Any]:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO permissions (id, agent_id, tool_id, allowed) VALUES (?,?,?,?)
               ON CONFLICT(agent_id, tool_id) DO UPDATE SET allowed=excluded.allowed""",
            (perm_id, agent_id, tool_id, int(allowed))
        )
    return {"id": perm_id, "agent_id": agent_id, "tool_id": tool_id, "allowed": allowed}


def get_agent_permissions(agent_id: str) -> List[Dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT p.*, t.name as tool_name, t.risk_level, t.category
               FROM permissions p JOIN tools t ON p.tool_id=t.tool_id
               WHERE p.agent_id=?""",
            (agent_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def is_tool_allowed_for_agent(agent_id: str, tool_name: str) -> Optional[bool]:
    """Returns None if no permission record (default deny), True/False otherwise."""
    with get_conn() as conn:
        row = conn.execute(
            """SELECT p.allowed FROM permissions p
               JOIN tools t ON p.tool_id=t.tool_id
               WHERE p.agent_id=? AND t.name=?""",
            (agent_id, tool_name)
        ).fetchone()
        return bool(row["allowed"]) if row else None


# ============================================================================
# Governance CRUD — Policies (FR-04)
# ============================================================================

def create_policy(policy_id: str, name: str, policy_type: str, action: str,
                  description: str = "", target_agent_id: Optional[str] = None,
                  target_tool_id: Optional[str] = None, condition: Optional[dict] = None,
                  priority: int = 100) -> Dict[str, Any]:
    import time
    ts = time.time()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO policies (policy_id, name, description, policy_type, target_agent_id,
               target_tool_id, condition_json, action, priority, enabled, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,1,?)""",
            (policy_id, name, description, policy_type, target_agent_id, target_tool_id,
             json.dumps(condition or {}), action, priority, ts)
        )
    return {"policy_id": policy_id, "name": name, "policy_type": policy_type, "action": action,
            "enabled": True, "priority": priority}


def list_policies(enabled_only: bool = False) -> List[Dict]:
    with get_conn() as conn:
        q = "SELECT * FROM policies"
        if enabled_only:
            q += " WHERE enabled=1"
        q += " ORDER BY priority ASC"
        rows = conn.execute(q).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["condition"] = json.loads(d.pop("condition_json", "{}"))
            result.append(d)
        return result


def toggle_policy(policy_id: str, enabled: bool) -> bool:
    with get_conn() as conn:
        cur = conn.execute("UPDATE policies SET enabled=? WHERE policy_id=?", (int(enabled), policy_id))
        return cur.rowcount > 0


def delete_policy(policy_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM policies WHERE policy_id=?", (policy_id,))
        return cur.rowcount > 0


# ============================================================================
# Governance CRUD — Tool Calls Audit Log (FR-08)
# ============================================================================

def insert_tool_call(call_id: str, agent_id: str, tool_name: str, arguments: dict,
                     decision: str, reason: str, risk_score: float, policy_id: str = "",
                     user_id: str = "", latency_ms: float = 0.0,
                     experiment_run_id: str = "", configuration: str = "full") -> None:
    import time
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO tool_calls (call_id, timestamp, agent_id, user_id, tool_name,
               arguments_json, decision, reason, policy_id, risk_score, latency_ms,
               experiment_run_id, configuration)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (call_id, time.time(), agent_id, user_id, tool_name,
             json.dumps(arguments), decision, reason, policy_id, risk_score,
             latency_ms, experiment_run_id, configuration)
        )


def fetch_tool_calls(agent_id: Optional[str] = None, decision: Optional[str] = None,
                     run_id: Optional[str] = None, limit: int = 200) -> List[Dict]:
    q = "SELECT * FROM tool_calls WHERE 1=1"
    params: list = []
    if agent_id:
        q += " AND agent_id=?"
        params.append(agent_id)
    if decision:
        q += " AND decision=?"
        params.append(decision.upper())
    if run_id:
        q += " AND experiment_run_id=?"
        params.append(run_id)
    q += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    with get_conn() as conn:
        rows = conn.execute(q, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["arguments"] = json.loads(d.pop("arguments_json", "{}"))
            result.append(d)
        return result


def fetch_governance_stats() -> Dict[str, Any]:
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM tool_calls").fetchone()["c"]
        by_decision = conn.execute(
            "SELECT decision, COUNT(*) c FROM tool_calls GROUP BY decision"
        ).fetchall()
        total_agents = conn.execute("SELECT COUNT(*) c FROM agents").fetchone()["c"]
        total_tools = conn.execute("SELECT COUNT(*) c FROM tools").fetchone()["c"]
        total_policies = conn.execute("SELECT COUNT(*) c FROM policies WHERE enabled=1").fetchone()["c"]
        avg_risk = conn.execute("SELECT AVG(risk_score) a FROM tool_calls").fetchone()["a"] or 0.0
    return {
        "total_tool_calls": total,
        "by_decision": {r["decision"]: r["c"] for r in by_decision},
        "total_agents": total_agents,
        "total_tools": total_tools,
        "active_policies": total_policies,
        "average_risk_score": round(avg_risk, 3),
    }


# ============================================================================
# Governance CRUD — Rate Limits (FR-09)
# ============================================================================

def get_rate_limit_count(agent_id: str, tool_name: str, window_start: float) -> int:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT call_count FROM rate_limit_counters WHERE agent_id=? AND tool_name=? AND window_start=?",
            (agent_id, tool_name, window_start)
        ).fetchone()
        return row["call_count"] if row else 0


def increment_rate_limit(agent_id: str, tool_name: str, window_start: float) -> int:
    rid = f"{agent_id}::{tool_name}::{window_start}"
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO rate_limit_counters (id, agent_id, tool_name, window_start, call_count)
               VALUES (?,?,?,?,1)
               ON CONFLICT(agent_id, tool_name, window_start) DO UPDATE SET call_count=call_count+1""",
            (rid, agent_id, tool_name, window_start)
        )
        row = conn.execute(
            "SELECT call_count FROM rate_limit_counters WHERE agent_id=? AND tool_name=? AND window_start=?",
            (agent_id, tool_name, window_start)
        ).fetchone()
        return row["call_count"] if row else 1


# ============================================================================
# Governance CRUD — Experiment Runs (FR-10, FR-12)
# ============================================================================

def create_experiment_run(run_id: str, configuration: str, description: str = "") -> Dict[str, Any]:
    import time
    ts = time.time()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO experiment_runs (run_id, configuration, description, started_at, status)
               VALUES (?,?,?,?,'running')""",
            (run_id, configuration, description, ts)
        )
    return {"run_id": run_id, "configuration": configuration, "description": description,
            "started_at": ts, "status": "running"}


def complete_experiment_run(run_id: str, total_scenarios: int, metrics: dict) -> None:
    import time
    with get_conn() as conn:
        conn.execute(
            """UPDATE experiment_runs SET completed_at=?, status='completed',
               total_scenarios=?, metrics_json=? WHERE run_id=?""",
            (time.time(), total_scenarios, json.dumps(metrics), run_id)
        )


def insert_experiment_event(event_id: str, run_id: str, scenario_id: str, category: str,
                            expected: str, actual: str, latency_ms: float, correct: bool) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO experiment_events (event_id, run_id, scenario_id, category,
               expected_decision, actual_decision, latency_ms, correct)
               VALUES (?,?,?,?,?,?,?,?)""",
            (event_id, run_id, scenario_id, category, expected, actual, latency_ms, int(correct))
        )


def list_experiment_runs() -> List[Dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM experiment_runs ORDER BY started_at DESC").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["metrics"] = json.loads(d.pop("metrics_json", "{}"))
            result.append(d)
        return result


def get_experiment_run(run_id: str) -> Optional[Dict]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM experiment_runs WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["metrics"] = json.loads(d.pop("metrics_json", "{}"))
        events = conn.execute(
            "SELECT * FROM experiment_events WHERE run_id=? ORDER BY scenario_id", (run_id,)
        ).fetchall()
        d["events"] = [dict(e) for e in events]
        return d

