"""Compatibility API for the canonical PromptAegis governance gateway.

The REST API and ``AgentAdapter`` historically consumed a dictionary-returning
``intercept`` function. This module preserves that contract while routing every
request through :class:`governance.gateway.Gateway`, which is also used by the
research sandbox. The retired implementation is kept separately for exact
replay of historical decision-only experiments; new code must not import it.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from governance.audit_chain import AuditChain
from governance.gateway import CONFIGURATIONS, Gateway


_CONFIGURATION_ALIASES = {
    "baseline": "baseline",
    "permission": "rbac_only",
    "rbac_only": "rbac_only",
    "policy": "policy_only",
    "policy_only": "policy_only",
    "full": "full",
    "hardened": "full",
    "full_burst": "full",
    "full_normalized": "full",
    "full_governance": "full",
}


def intercept(
    agent_id: str,
    tool_name: str,
    arguments: Dict[str, Any],
    user_id: str = "",
    configuration: str = "full",
    experiment_run_id: str = "",
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Evaluate a call through the canonical gateway, returning the API shape.

    Configuration aliases are accepted for compatibility with saved UI/API
    requests. All aliases resolve to the same explicit gateway ablations.
    Unknown configurations fail closed rather than silently selecting a mode.
    """
    mapped = _CONFIGURATION_ALIASES.get(configuration)
    if mapped not in CONFIGURATIONS:
        raise ValueError(f"Unknown governance configuration {configuration!r}.")

    gateway = Gateway(configuration=mapped, chain=AuditChain())
    decision = gateway.evaluate(
        agent_id=agent_id,
        tool_name=tool_name,
        arguments=arguments,
        user_id=user_id,
        context=context or {},
        experiment_run_id=experiment_run_id,
    )
    executed = set(decision.stages_executed)
    block_to_api_stage = {
        "rbac": "permission_engine",
        "schema": "policy_engine",
        "policy": "policy_engine",
        "rate": "rate_limiter",
        "approval": "risk_scorer",
        "audit": "audit",
        "request": "permission_engine",
    }
    blocking_stage = block_to_api_stage.get(decision.first_blocking_stage, "none")
    stage_evaluations = {
        "rate_limiter": {
            "executed": "rate" in executed,
            "allowed": decision.first_blocking_stage != "rate",
        },
        "permission_engine": {
            "executed": "rbac" in executed,
            "allowed": decision.first_blocking_stage not in {"request", "rbac"},
            "reason": decision.internal_reason if blocking_stage == "permission_engine" else "Permission check passed",
        },
        "policy_engine": {
            "executed": bool(executed.intersection({"schema", "policy"})),
            "action": decision.decision if blocking_stage == "policy_engine" else "PASS",
            "reason": decision.internal_reason if blocking_stage == "policy_engine" else "No policy violations detected",
            "policy_id": decision.policy_id,
        },
        "risk_scorer": {
            "executed": "approval" in executed,
            "score": decision.risk_score,
            "requires_approval": decision.decision == "REQUIRE_APPROVAL",
        },
    }
    return {
        "decision": decision.decision,
        "reason": decision.internal_reason,
        "reason_code": decision.reason_code,
        "public_message": decision.public_message,
        "policy_id": decision.policy_id,
        "risk_score": decision.risk_score,
        "call_id": decision.call_id,
        "correlation_id": decision.correlation_id,
        "latency_ms": decision.latency_ms,
        "first_blocking_stage": blocking_stage,
        "stage_evaluations": stage_evaluations,
        "audited": decision.audited,
    }
