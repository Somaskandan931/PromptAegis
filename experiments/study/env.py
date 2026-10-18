"""Build an isolated, reproducible governance environment for experiments.

* Uses a throw-away SQLite file (never the shipped benchmark DB).
* Installs a deterministic virtual clock so rate-limit windows do not depend on
  machine speed (see docs/REPOSITORY_AUDIT.md for historical limitations).
* Registers tools / agents / permissions / policies directly (no HTTP, no seed
  endpoint) and returns identifiers for use by the runner.
"""
from __future__ import annotations

import os
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import config  # noqa: E402
from database import db  # noqa: E402
from database.environments import environment_scope  # noqa: E402
from governance import rate_limiter  # noqa: E402
from governance.clock import ResearchExperimentClock, reset_to_production_clock, set_clock  # noqa: E402

ENV_ID = "research_benchmark"
CLOCK_START = 1790000000.0  # window-aligned (divisible by 60)

TOOLS = [
    # name, category, risk, requires_approval
    ("search_customer", "read", "low", False),
    ("search_order", "read", "low", False),
    ("send_email", "communication", "medium", False),
    ("update_customer", "write", "medium", False),
    ("delete_customer", "destructive", "high", True),
    ("export_customer_data", "destructive", "high", True),
    ("execute_sql", "database", "high", True),
    ("file_delete", "filesystem", "high", True),
]
AGENTS = [
    ("CustomerSupportAgent", "support"),
    ("AdminAgent", "admin"),
]
SUPPORT_ALLOWED = {"search_customer", "search_order", "send_email", "update_customer"}

# The policy-only ablation uses the configured policy set below.
POLICIES = [
    dict(name="Block support from delete_customer", policy_type="role_based", action="DENY",
         condition={"role": "support", "blocked_tool": "delete_customer"}, priority=10),
    dict(name="Block support from export_customer_data", policy_type="role_based", action="DENY",
         condition={"role": "support", "blocked_tool": "export_customer_data"}, priority=11),
    dict(name="Block listed attacker domains (legacy denylist)", policy_type="parameter_based", action="DENY",
         condition={"param_key": "recipient", "forbidden_domains": ["attacker.com", "evil.com", "hacker.io"]},
         priority=20),
    dict(name="Require approval for SQL execution", policy_type="tool_based", action="REQUIRE_APPROVAL",
         condition={"tool_name": "execute_sql"}, priority=30),
    dict(name="update_customer only while ticket is open", policy_type="context_based", action="DENY",
         condition={"required": {"ticket_status": "open"}}, priority=40, _tool="update_customer"),
]


@dataclass
class Env:
    db_path: str
    clock: ResearchExperimentClock
    agent_ids: Dict[str, str]
    tool_ids: Dict[str, str]
    previous_db_path: str
    previous_rate_limits: Dict
    owned_temp_dir: Optional[str] = None

    def reset_runtime_state(self) -> None:
        """Clear rate counters and rewind the virtual clock between runs."""
        with environment_scope(ENV_ID):
            rate_limiter.reset_rate_limits(ENV_ID)
        self.clock.reset(CLOCK_START)

    def close(self) -> None:
        reset_to_production_clock()
        rate_limiter._overrides.clear()
        rate_limiter._overrides.update(self.previous_rate_limits)
        config.BENCHMARK_DB_PATH = self.previous_db_path
        if self.owned_temp_dir:
            import shutil
            shutil.rmtree(self.owned_temp_dir, ignore_errors=True)


def build(db_path: Optional[str] = None) -> Env:
    previous_db_path = config.BENCHMARK_DB_PATH
    previous_rate_limits = dict(rate_limiter._overrides)
    owned_temp_dir = None
    if db_path is None:
        local_tmp = ROOT / "tmp"
        local_tmp.mkdir(parents=True, exist_ok=True)
        owned_temp_dir = tempfile.mkdtemp(prefix="aegis_study_", dir=str(local_tmp))
        path = os.path.join(owned_temp_dir, "gateway_study.db")
    else:
        path = os.path.abspath(db_path)
        if os.path.exists(path):
            raise FileExistsError(f"Refusing to overwrite an existing experiment database: {path}")
        os.makedirs(os.path.dirname(path), exist_ok=True)
    config.BENCHMARK_DB_PATH = path
    clock = ResearchExperimentClock(start_time=CLOCK_START)
    set_clock(clock)
    rate_limiter._overrides.clear()
    db.init_db(env=ENV_ID)
    tool_ids, agent_ids = {}, {}
    with environment_scope(ENV_ID):
        for name, cat, risk, appr in TOOLS:
            tid = f"tool_{uuid.uuid4().hex[:8]}"
            db.create_tool(tid, name, cat, risk, appr, name)
            tool_ids[name] = tid
        for name, role in AGENTS:
            aid = f"agent_{uuid.uuid4().hex[:8]}"
            db.create_agent(aid, name, name, role)
            agent_ids[name] = aid
        for tname, tid in tool_ids.items():
            db.set_permission(f"perm_{uuid.uuid4().hex[:8]}", agent_ids["CustomerSupportAgent"], tid,
                              tname in SUPPORT_ALLOWED)
            db.set_permission(f"perm_{uuid.uuid4().hex[:8]}", agent_ids["AdminAgent"], tid, True)
        for p in POLICIES:
            p = dict(p)
            tool = p.pop("_tool", None)
            db.create_policy(policy_id=f"pol_{uuid.uuid4().hex[:8]}", description=p["name"],
                             target_tool_id=tool_ids.get(tool) if tool else None, **p)
        # Generous default limits; rate-limit scenarios set their own limit.
        for tname in tool_ids:
            rate_limiter.set_limit(tname, 10_000, ENV_ID)
    return Env(path, clock, agent_ids, tool_ids, previous_db_path, previous_rate_limits, owned_temp_dir)
