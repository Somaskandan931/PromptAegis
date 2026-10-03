"""
Rate limiting for tool calls (PRD Section 19).
Uses a 60-second tumbling-window counter stored in SQLite.
Default: 10 requests per 60-second window per (agent, tool).
"""
import math
import time
from typing import Dict, Tuple

from database import db
from governance.clock import get_clock

# Default limits (tool_name -> requests_per_minute)
# Search tools: higher limit (100/min) — legitimate agents may query frequently
# Destructive tools: strict limit (5/min) — prevents abuse
_DEFAULT_LIMITS: Dict[str, int] = {
    "search_customer": 100,
    "search_order": 100,
    "send_email": 20,
    "update_customer": 20,
    "delete_customer": 5,
    "export_customer_data": 2,
    "execute_sql": 5,
    "file_delete": 5,
}
_GLOBAL_DEFAULT = 50
_WINDOW_SECONDS = 60.0


from database.environments import get_current_environment

# In-memory overrides scoped by (environment_id, tool_name)
_overrides: Dict[Tuple[str, str], int] = {}


def get_limit(tool_name: str, env_id: str = None) -> int:
    """Return configured call limit per window for this tool in the target or current environment."""
    env = env_id or get_current_environment()
    if (env, tool_name) in _overrides:
        return _overrides[(env, tool_name)]
    return _DEFAULT_LIMITS.get(tool_name, _GLOBAL_DEFAULT)


def set_limit(tool_name: str, limit: int, env_id: str = None) -> None:
    """Override rate limit for a tool at runtime in the target or current environment."""
    env = env_id or get_current_environment()
    _overrides[(env, tool_name)] = limit


def reset_rate_limits(env_id: str = None) -> None:
    """Clear all rate limit counters from DB for the target or current environment."""
    env = env_id or get_current_environment()
    with db.get_conn(env=env) as conn:
        conn.execute("DELETE FROM rate_limit_counters")


def _window_start(ts: float = None) -> float:
    """Floor timestamp to window boundary."""
    if ts is None:
        ts = get_clock().time()
    return math.floor(ts / _WINDOW_SECONDS) * _WINDOW_SECONDS


def check_and_increment(agent_id: str, tool_name: str, timestamp: float = None) -> Tuple[bool, int, int]:
    """
    Check rate limit, increment counter if not exceeded.

    Returns:
        (allowed, current_count, limit)
    """
    limit = get_limit(tool_name)
    window = _window_start(timestamp)
    current = db.get_rate_limit_count(agent_id, tool_name, window)
    if current >= limit:
        return False, current, limit
    new_count = db.increment_rate_limit(agent_id, tool_name, window)
    return True, new_count, limit
