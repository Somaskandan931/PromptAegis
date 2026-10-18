"""
Policy engine (PRD Sections 15-16, FR-04, FR-06).
Evaluates enabled policies in priority order and returns the first matching action.
Supports policy types:
  - tool_based: block agent from using specific tool
  - parameter_based: block based on argument values
  - role_based: block based on agent role
  - context_based: block based on session context
  - rate_based: additional rate control beyond rate_limiter
"""
import base64
import re
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse

from database import db


def _string_values(value: Any):
    """Yield scalar values nested anywhere in a structured tool argument."""
    if isinstance(value, dict):
        for nested in value.values():
            yield from _string_values(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            yield from _string_values(nested)
    elif isinstance(value, (str, int, float)):
        yield str(value)


def _safe_b64_decode(raw_token: str) -> str:
    """Safely decode a base64 token if it yields printable text without domain keywords."""
    try:
        decoded_bytes = base64.b64decode(raw_token.strip())
        decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
        if decoded_text and any(c.isprintable() for c in decoded_text):
            return decoded_text
    except Exception:
        pass
    return raw_token


def _normalize_value(val: str) -> str:
    """
    Keyword-agnostic parameter canonicalization:
    - Bounded URL percent-decoding (up to 2 passes to handle nested encoding)
    - Base64 payload decoding only for explicit markers (base64:...)
    - SQL inline comment fragmentation stripping (/* ... */)
    Does NOT use target-leaked SQL keyword sniffing.
    """
    s = str(val)

    # 1. URL percent-decoding (up to 2 passes)
    for _ in range(2):
        if "%" in s:
            try:
                unquoted = urllib.parse.unquote(s)
                if unquoted == s:
                    break
                s = unquoted
            except Exception:
                break

    # 2. Base64 payload decoding (keyword-agnostic)
    if "base64:" in s:
        s = re.sub(r"base64:([A-Za-z0-9+/=]+)", lambda m: _safe_b64_decode(m.group(1)), s)

    # 3. Strip SQL comment fragmentation (e.g. /**/ or /*...*/)
    s = re.sub(r"/\*.*?\*/", " ", s)
    return s.strip()


def evaluate_policies(
    agent_id: str,
    tool_name: str,
    arguments: Dict[str, Any],
    agent_role: str = "default",
    hardened: bool = False,
    context: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str, str]:
    """
    Evaluate all enabled policies in priority order.

    Args:
        agent_id: Identifier of the agent
        tool_name: Name of the invoked tool
        arguments: Tool invocation arguments
        agent_role: Role of the agent
        hardened: If True, applies pre-inspection normalization (URL/Base64/SQL comments)
        context: Trusted runtime attributes, such as session state or environment label.

    Returns:
        (action, reason, policy_id)
        action: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'RATE_LIMIT' | 'PASS'
        'PASS' means no policy matched -> caller uses permission engine result.
    """
    policies = db.list_policies(enabled_only=True)
    agent = db.get_agent(agent_id)
    runtime_context = context or {}

    for policy in policies:
        pid = policy["policy_id"]
        ptype = policy["policy_type"]
        action = policy["action"]
        cond = policy.get("condition", {})
        ta = policy.get("target_agent_id")
        tt = policy.get("target_tool_id")

        # Agent filter
        if ta and ta != agent_id:
            continue
        # Tool filter
        if tt:
            tool_row = db.get_tool(tt)
            if tool_row and tool_row["name"] != tool_name:
                continue

        if ptype == "tool_based":
            # Policy targets a specific tool by name
            target_tool_name = cond.get("tool_name", "")
            if not target_tool_name:
                # No tool specified — skip (malformed policy)
                continue
            if target_tool_name != tool_name:
                continue
            return action, f"POLICY_{ptype.upper()}:{target_tool_name}", pid

        elif ptype == "parameter_based":
            # Block if a specific argument key has a forbidden value
            param_key = cond.get("param_key", "")
            forbidden_values = cond.get("forbidden_values", [])
            forbidden_domains = cond.get("forbidden_domains", [])
            regex_pattern = cond.get("regex_pattern", "")

            # Resolve parameter value (support aliased keys like recipient <-> to)
            raw_val = arguments.get(param_key)
            if raw_val is None:
                if param_key == "recipient":
                    raw_val = arguments.get("to")
                elif param_key == "to":
                    raw_val = arguments.get("recipient")

            if raw_val is None:
                if not param_key:
                    # If no specific param_key was required, inspect all string args
                    arg_strings = list(_string_values(arguments))
                else:
                    # Specific param_key was required by policy but is absent from tool arguments
                    continue
            else:
                arg_strings = list(_string_values(raw_val))

            for val_str in arg_strings:
                inspect_str = _normalize_value(val_str) if hardened else val_str
                inspect_lower = inspect_str.lower()

                if forbidden_values:
                    if any(fv.lower() in inspect_lower for fv in forbidden_values):
                        return action, f"PARAMETER_VIOLATION:{param_key or 'argument'}", pid

                if forbidden_domains:
                    if any(fd.lower() in inspect_lower for fd in forbidden_domains):
                        return action, f"DOMAIN_VIOLATION:{param_key or 'argument'}", pid

                if regex_pattern:
                    if re.search(regex_pattern, inspect_str, re.IGNORECASE):
                        return action, f"REGEX_VIOLATION:{param_key or 'argument'}", pid

            continue

        elif ptype == "role_based":
            # Apply action only if agent's role matches
            target_role = cond.get("role", "")
            blocked_tool = cond.get("blocked_tool", "")
            if agent and agent.get("role") == target_role:
                if blocked_tool and blocked_tool != tool_name:
                    continue
                return action, f"ROLE_RESTRICTION:{target_role}", pid
            continue

        elif ptype == "context_based":
            # Example: {"required": {"session_state": "approved"},
            # "allowed_values": {"environment": ["research_benchmark"]}}
            required = cond.get("required", {})
            allowed_values = cond.get("allowed_values", {})
            if not isinstance(required, dict) or not isinstance(allowed_values, dict):
                continue
            for key, expected in required.items():
                if runtime_context.get(key) != expected:
                    return action, f"CONTEXT_REQUIREMENT_FAILED:{key}", pid
            for key, permitted in allowed_values.items():
                permitted_values = permitted if isinstance(permitted, list) else [permitted]
                if runtime_context.get(key) not in permitted_values:
                    return action, f"CONTEXT_NOT_ALLOWED:{key}", pid
            continue

        elif ptype == "rate_based":
            # Handled by rate_limiter.py — skip here
            continue

    return "PASS", "NO_POLICY_MATCHED", ""
