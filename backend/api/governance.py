"""
Governance API — Prompt Aegis 2.0
Exposes all governance management and tool interception endpoints (PRD FR-01 to FR-09).

Routes:
  POST   /agents                   - Register agent (FR-01)
  GET    /agents                   - List agents
  DELETE /agents/{agent_id}        - Remove agent
  POST   /tools                    - Register tool (FR-02)
  GET    /tools                    - List tools
  DELETE /tools/{tool_id}          - Remove tool
  POST   /permissions              - Assign permission (FR-03)
  GET    /permissions/{agent_id}   - Get agent permissions
  POST   /policies                 - Create policy (FR-04)
  GET    /policies                 - List policies
  PATCH  /policies/{policy_id}     - Toggle enable/disable
  DELETE /policies/{policy_id}     - Remove policy
  POST   /intercept                - Intercept tool call (FR-05, FR-06, FR-07)
  GET    /tool-calls               - Tool call audit log (FR-08)
  GET    /governance/stats         - Summary statistics
  POST   /rate-limits/{tool_name}  - Set rate limit for tool (FR-09)
  POST   /governance/seed          - Seed default agents/tools/policies for demo
"""
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.auth import (
    EnvironmentContext,
    get_authenticated_environment,
)
from database import db
from database.environments import (
    CredentialManager,
    EnvironmentRegistry,
    environment_scope,
    get_current_environment,
    set_current_environment,
)
from governance.interceptor import intercept

router = APIRouter()


# ============================================================================
# Schemas
# ============================================================================

class EnvironmentCreate(BaseModel):
    id: str
    name: str
    type: str = "custom"
    description: str = ""

class CredentialCreate(BaseModel):
    environment_id: str
    name: str
    allowed_roles: List[str] = ["application_gateway"]

class AgentCreate(BaseModel):
    name: str
    description: str = ""
    role: str = "default"

class ToolCreate(BaseModel):
    name: str
    category: str
    risk_level: str = Field(..., pattern="^(low|medium|high)$")
    requires_approval: bool = False
    description: str = ""

class PermissionCreate(BaseModel):
    agent_id: str
    tool_id: str
    allowed: bool = True

class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    policy_type: str
    action: str = Field(..., pattern="^(ALLOW|DENY|REQUIRE_APPROVAL|RATE_LIMIT)$")
    target_agent_id: Optional[str] = None
    target_tool_id: Optional[str] = None
    condition: Dict[str, Any] = {}
    priority: int = 100

class PolicyToggle(BaseModel):
    enabled: bool

class InterceptRequest(BaseModel):
    agent_id: str
    tool_name: str
    arguments: Dict[str, Any] = {}
    user_id: str = ""
    configuration: str = "full"
    experiment_run_id: str = ""
    source: str = "runtime"

class RateLimitSet(BaseModel):
    limit: int = Field(..., gt=0)


# ============================================================================
# Environments Management (Architecture Layer)
# ============================================================================

@router.get("/environments", tags=["governance"])
def list_environments():
    """List registered environments with sanitized public metadata only."""
    return EnvironmentRegistry.list_environments(sanitize=True)


@router.post("/environments", status_code=201, tags=["governance"])
def register_environment(
    body: EnvironmentCreate,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Register a new isolated environment (requires admin credential)."""
    roles = env_ctx.credential_info.get("allowed_roles", []) if env_ctx.credential_info else []
    if "admin" not in roles:
        raise HTTPException(403, "Admin privileges required to register new environments.")
    try:
        new_env = EnvironmentRegistry.register_environment(
            env_id=body.id,
            name=body.name,
            env_type=body.type,
            description=body.description,
        )
        db.init_db(env=body.id)
        return EnvironmentRegistry.get_environment(body.id, sanitize=True)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/environments/current", tags=["governance"])
def get_current_environment_context(
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Return currently active authenticated environment context."""
    return {
        "environment_id": env_ctx.environment_id,
        "environment_info": env_ctx.environment_info,
        "credential_info": env_ctx.credential_info,
        "role": env_ctx.role,
        "authenticated": True,
    }


@router.post("/governance/credentials", status_code=201, tags=["governance"])
def create_environment_credential(
    body: CredentialCreate,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Issue a new environment-bound credential (requires admin)."""
    roles = env_ctx.credential_info.get("allowed_roles", []) if env_ctx.credential_info else []
    if "admin" not in roles:
        raise HTTPException(403, "Admin privileges required to issue environment credentials.")
    if not EnvironmentRegistry.get_environment(body.environment_id):
        raise HTTPException(404, f"Environment '{body.environment_id}' not found.")
    return CredentialManager.create_credential(
        environment_id=body.environment_id,
        name=body.name,
        allowed_roles=body.allowed_roles,
    )


def _resolve_env_context(env_ctx: Any) -> EnvironmentContext:
    if isinstance(env_ctx, EnvironmentContext):
        return env_ctx
    target_env = get_current_environment()
    return EnvironmentContext(
        environment_id=target_env,
        environment_info=EnvironmentRegistry.get_environment(target_env, sanitize=True) or {},
        credential_info=None,
        role="benchmark_runner",
    )


WRITE_ROLES = {"admin", "developer", "benchmark_runner"}

def _require_write_access(env_ctx: EnvironmentContext) -> None:
    roles = set(env_ctx.credential_info.get("allowed_roles", [])) if env_ctx.credential_info else {env_ctx.role}
    if not (roles & WRITE_ROLES):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "INSUFFICIENT_ROLE_PERMISSIONS",
                "message": f"Role '{env_ctx.role}' has READ-ONLY access. Governance write mutations require one of: {sorted(list(WRITE_ROLES))}.",
            },
        )


# ============================================================================
# Agents (FR-01)
# ============================================================================

@router.post("/agents", status_code=201, tags=["governance"])
def register_agent(
    body: AgentCreate,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Register a new AI agent with the governance system."""
    _require_write_access(env_ctx)
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        agent_id = f"agent_{uuid.uuid4().hex[:8]}"
        try:
            agent = db.create_agent(agent_id, body.name, body.description, body.role)
            return agent
        except Exception as e:
            if "UNIQUE constraint" in str(e):
                raise HTTPException(400, f"Agent name '{body.name}' already exists.")
            raise HTTPException(500, str(e))


@router.get("/agents", tags=["governance"])
def list_agents(env_ctx: EnvironmentContext = Depends(get_authenticated_environment)):
    """List all registered agents in the active environment."""
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        return db.list_agents()


@router.delete("/agents/{agent_id}", tags=["governance"])
def remove_agent(
    agent_id: str,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Remove an agent and all its permissions in the active environment."""
    _require_write_access(env_ctx)
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        if not db.delete_agent(agent_id):
            raise HTTPException(404, f"Agent '{agent_id}' not found.")
        return {"deleted": True, "agent_id": agent_id}


# ============================================================================
# Tools (FR-02)
# ============================================================================

@router.post("/tools", status_code=201, tags=["governance"])
def register_tool(
    body: ToolCreate,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Register a tool in the active environment tool registry."""
    _require_write_access(env_ctx)
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        tool_id = f"tool_{uuid.uuid4().hex[:8]}"
        try:
            tool = db.create_tool(tool_id, body.name, body.category, body.risk_level,
                                  body.requires_approval, body.description)
            return tool
        except Exception as e:
            if "UNIQUE constraint" in str(e):
                raise HTTPException(400, f"Tool '{body.name}' already registered.")
            raise HTTPException(500, str(e))


@router.get("/tools", tags=["governance"])
def list_tools(env_ctx: EnvironmentContext = Depends(get_authenticated_environment)):
    """List all registered tools with metadata in the active environment."""
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        return db.list_tools()


@router.delete("/tools/{tool_id}", tags=["governance"])
def remove_tool(
    tool_id: str,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Remove a tool from the active environment registry."""
    _require_write_access(env_ctx)
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        if not db.delete_tool(tool_id):
            raise HTTPException(404, f"Tool '{tool_id}' not found.")
        return {"deleted": True, "tool_id": tool_id}


# ============================================================================
# Permissions (FR-03)
# ============================================================================

@router.post("/permissions", status_code=201, tags=["governance"])
def set_permission(
    body: PermissionCreate,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Assign or update a permission record in the active environment."""
    _require_write_access(env_ctx)
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        if not db.get_agent(body.agent_id):
            raise HTTPException(404, f"Agent '{body.agent_id}' not found.")
        if not db.get_tool(body.tool_id):
            raise HTTPException(404, f"Tool '{body.tool_id}' not found.")
        perm_id = f"perm_{uuid.uuid4().hex[:8]}"
        result = db.set_permission(perm_id, body.agent_id, body.tool_id, body.allowed)
        return result


@router.get("/permissions/{agent_id}", tags=["governance"])
def get_permissions(
    agent_id: str,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Get all permission records for an agent in the active environment."""
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        if not db.get_agent(agent_id):
            raise HTTPException(404, f"Agent '{agent_id}' not found.")
        return db.get_agent_permissions(agent_id)


# ============================================================================
# Policies (FR-04)
# ============================================================================

@router.post("/policies", status_code=201, tags=["governance"])
def create_policy(
    body: PolicyCreate,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Create a new governance policy in the active environment."""
    _require_write_access(env_ctx)
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        policy_id = f"pol_{uuid.uuid4().hex[:8]}"
        try:
            result = db.create_policy(
                policy_id=policy_id,
                name=body.name,
                policy_type=body.policy_type,
                action=body.action,
                description=body.description,
                target_agent_id=body.target_agent_id,
                target_tool_id=body.target_tool_id,
                condition=body.condition,
                priority=body.priority,
            )
            return result
        except Exception as e:
            raise HTTPException(500, str(e))


@router.get("/policies", tags=["governance"])
def list_policies(
    enabled_only: bool = Query(False),
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """List all policies in the active environment."""
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        return db.list_policies(enabled_only=enabled_only)


@router.patch("/policies/{policy_id}", tags=["governance"])
def toggle_policy(
    policy_id: str,
    body: PolicyToggle,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Enable or disable a policy in the active environment."""
    _require_write_access(env_ctx)
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        if not db.toggle_policy(policy_id, body.enabled):
            raise HTTPException(404, f"Policy '{policy_id}' not found.")
        return {"policy_id": policy_id, "enabled": body.enabled}


@router.delete("/policies/{policy_id}", tags=["governance"])
def remove_policy(
    policy_id: str,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Delete a policy in the active environment."""
    _require_write_access(env_ctx)
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        if not db.delete_policy(policy_id):
            raise HTTPException(404, f"Policy '{policy_id}' not found.")
        return {"deleted": True, "policy_id": policy_id}


# ============================================================================
# Tool Interception — Core Gateway (FR-05, FR-06, FR-07)
# ============================================================================

@router.post("/intercept", tags=["governance"])
def intercept_tool_call(
    body: InterceptRequest,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """
    Main governance gateway endpoint.
    Evaluates tool invocation proposal strictly inside the authenticated environment.
    """
    env = _resolve_env_context(env_ctx)
    if (body.source == "verification_lab" or body.experiment_run_id.startswith("lab_")) and env.environment_id == "connected_application":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "VERIFICATION_LAB_PROHIBITED_IN_CONNECTED_APP",
                "message": "Verification Lab simulation is prohibited in the live connected_application environment. Switch to local_dev or research_benchmark.",
            },
        )
    with environment_scope(env.environment_id):
        result = intercept(
            agent_id=body.agent_id,
            tool_name=body.tool_name,
            arguments=body.arguments,
            user_id=body.user_id,
            configuration=body.configuration,
            experiment_run_id=body.experiment_run_id,
        )
        if isinstance(result, dict):
            result["environment_id"] = env.environment_id
        return result


# ============================================================================
# Tool Calls Audit Log (FR-08)
# ============================================================================

@router.get("/tool-calls", tags=["governance"])
def get_tool_calls(
    agent_id: Optional[str] = Query(None),
    decision: Optional[str] = Query(None),
    run_id: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Retrieve tool call audit log from the active environment."""
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        return db.fetch_tool_calls(agent_id=agent_id, decision=decision, run_id=run_id, limit=limit)


# ============================================================================
# Statistics
# ============================================================================

@router.get("/governance/stats", tags=["governance"])
def governance_stats(env_ctx: EnvironmentContext = Depends(get_authenticated_environment)):
    """Return summary governance metrics for the active environment."""
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        stats = db.fetch_governance_stats()
        stats["environment_id"] = env.environment_id
        return stats


# ============================================================================
# Rate Limits (FR-09)
# ============================================================================

@router.post("/rate-limits/{tool_name}", tags=["governance"])
def set_rate_limit(
    tool_name: str,
    body: RateLimitSet,
    env_ctx: EnvironmentContext = Depends(get_authenticated_environment),
):
    """Override the per-window rate limit for a tool in the active environment."""
    _require_write_access(env_ctx)
    env = _resolve_env_context(env_ctx)
    with environment_scope(env.environment_id):
        from governance.rate_limiter import set_limit
        set_limit(tool_name, body.limit, env_id=env.environment_id)
        return {
            "tool_name": tool_name,
            "limit": body.limit,
            "window_seconds": 60,
            "environment_id": env.environment_id,
        }


# ============================================================================
# Seed defaults (for demo / research reproducibility)
# ============================================================================

_SEED_TOOLS = [
    {"name": "search_customer", "category": "read", "risk_level": "low", "requires_approval": False,
     "description": "Search customer records by ID or name"},
    {"name": "search_order", "category": "read", "risk_level": "low", "requires_approval": False,
     "description": "Search order records"},
    {"name": "send_email", "category": "communication", "risk_level": "medium", "requires_approval": False,
     "description": "Send email to a recipient"},
    {"name": "update_customer", "category": "write", "risk_level": "medium", "requires_approval": False,
     "description": "Update customer record fields"},
    {"name": "delete_customer", "category": "destructive", "risk_level": "high", "requires_approval": True,
     "description": "Permanently delete a customer record"},
    {"name": "export_customer_data", "category": "destructive", "risk_level": "high", "requires_approval": True,
     "description": "Export all customer data to external location"},
    {"name": "execute_sql", "category": "database", "risk_level": "high", "requires_approval": True,
     "description": "Execute arbitrary SQL against the database"},
    {"name": "file_delete", "category": "filesystem", "risk_level": "high", "requires_approval": True,
     "description": "Delete a file from the filesystem"},
]

_SEED_AGENTS = [
    {"name": "CustomerSupportAgent", "description": "Handles customer support tasks", "role": "support"},
    {"name": "AdminAgent", "description": "Administrative agent with elevated privileges", "role": "admin"},
    {"name": "EmailAssistant", "description": "Handles email communication tasks", "role": "support"},
    {"name": "UnrestrictedAgent", "description": "Baseline agent with no governance (for experiments)", "role": "baseline"},
]

_SEED_POLICIES = [
    {
        "name": "Block support agents from delete_customer",
        "policy_type": "role_based",
        "action": "DENY",
        "description": "Support agents cannot delete customers (privilege escalation prevention)",
        "condition": {"role": "support", "blocked_tool": "delete_customer"},
        "priority": 10,
    },
    {
        "name": "Block support agents from export_customer_data",
        "policy_type": "role_based",
        "action": "DENY",
        "description": "Support agents cannot export customer data",
        "condition": {"role": "support", "blocked_tool": "export_customer_data"},
        "priority": 11,
    },
    {
        "name": "Block external email domains",
        "policy_type": "parameter_based",
        "action": "DENY",
        "description": "Email can only be sent to company.com domain",
        "condition": {"param_key": "recipient", "forbidden_domains": ["attacker.com", "evil.com", "hacker.io"]},
        "priority": 20,
    },
    {
        "name": "Require approval for SQL execution",
        "policy_type": "tool_based",
        "action": "REQUIRE_APPROVAL",
        "description": "SQL execution always requires human approval",
        "condition": {"tool_name": "execute_sql"},
        "priority": 30,
    },
    {
        "name": "Rate limit excessive search calls",
        "policy_type": "rate_based",
        "action": "RATE_LIMIT",
        "description": "Prevent automated abuse of search tools",
        "condition": {"tool_name": "search_customer", "limit": 10},
        "priority": 50,
    },
]


@router.post("/governance/seed", tags=["governance"])
def seed_defaults(env_ctx: EnvironmentContext = Depends(get_authenticated_environment)):
    """
    Seed the governance system with default tools, agents, permissions and policies.
    Idempotent — safe to call multiple times.
    RESTRICTED: Strictly forbidden on non-benchmark environments (HTTP 403).
    """
    env = _resolve_env_context(env_ctx)
    if env.environment_id != "research_benchmark":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "SEEDING_FORBIDDEN",
                "message": (
                    f"Seeding synthetic benchmark artifacts is strictly restricted to the 'research_benchmark' environment. "
                    f"Target environment '{env.environment_id}' prohibits synthetic benchmark seeding."
                ),
                "target_environment": env.environment_id,
            },
        )

    with environment_scope(env.environment_id):
        seeded = {"tools": [], "agents": [], "permissions": [], "policies": []}

        # Seed tools
        tool_id_map = {}
        for t in _SEED_TOOLS:
            existing = db.get_tool_by_name(t["name"])
            if existing:
                tool_id_map[t["name"]] = existing["tool_id"]
                continue
            tid = f"tool_{uuid.uuid4().hex[:8]}"
            db.create_tool(tid, t["name"], t["category"], t["risk_level"],
                           t["requires_approval"], t["description"])
            tool_id_map[t["name"]] = tid
            seeded["tools"].append(t["name"])

        # Seed agents
        agent_id_map = {}
        existing_agents = {a["name"]: a["agent_id"] for a in db.list_agents()}
        for a in _SEED_AGENTS:
            if a["name"] in existing_agents:
                agent_id_map[a["name"]] = existing_agents[a["name"]]
                continue
            aid = f"agent_{uuid.uuid4().hex[:8]}"
            db.create_agent(aid, a["name"], a["description"], a["role"])
            agent_id_map[a["name"]] = aid
            seeded["agents"].append(a["name"])

        # Seed permissions: CustomerSupportAgent → allow read tools, deny destructive
        support_id = agent_id_map.get("CustomerSupportAgent", "")
        support_perms = {
            "search_customer": True, "search_order": True, "send_email": True,
            "update_customer": True, "delete_customer": False,
            "export_customer_data": False, "execute_sql": False, "file_delete": False,
        }
        for tool_name, allowed in support_perms.items():
            tid = tool_id_map.get(tool_name)
            if support_id and tid:
                pid = f"perm_{uuid.uuid4().hex[:8]}"
                db.set_permission(pid, support_id, tid, allowed)
                seeded["permissions"].append(f"CustomerSupportAgent->{tool_name}:{allowed}")

        # Admin gets all tools
        admin_id = agent_id_map.get("AdminAgent", "")
        for tool_name, tid in tool_id_map.items():
            if admin_id:
                pid = f"perm_{uuid.uuid4().hex[:8]}"
                db.set_permission(pid, admin_id, tid, True)

        # EmailAssistant gets send_email + search_customer
        email_id = agent_id_map.get("EmailAssistant", "")
        for tool_name in ["send_email", "search_customer", "search_order"]:
            tid = tool_id_map.get(tool_name)
            if email_id and tid:
                pid = f"perm_{uuid.uuid4().hex[:8]}"
                db.set_permission(pid, email_id, tid, True)

        # Unrestricted agent gets all tools (for baseline experiments)
        unrest_id = agent_id_map.get("UnrestrictedAgent", "")
        for tool_name, tid in tool_id_map.items():
            if unrest_id:
                pid = f"perm_{uuid.uuid4().hex[:8]}"
                db.set_permission(pid, unrest_id, tid, True)

        # Seed policies
        existing_policy_names = {p["name"] for p in db.list_policies()}
        for p in _SEED_POLICIES:
            if p["name"] in existing_policy_names:
                continue
            pol_id = f"pol_{uuid.uuid4().hex[:8]}"
            db.create_policy(
                policy_id=pol_id, name=p["name"], policy_type=p["policy_type"],
                action=p["action"], description=p["description"],
                condition=p["condition"], priority=p["priority"],
            )
            seeded["policies"].append(p["name"])

        return {"status": "seeded", "seeded": seeded,
                "totals": {"tools": len(tool_id_map), "agents": len(agent_id_map)}}
