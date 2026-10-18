"""
Tool interception pipeline (PRD FR-05, FR-06, FR-07).
Orchestrates the full configuration as: Rate Limit → Permission Check →
Policy Evaluation → Risk Gate → Audit Log. Isolated baseline, RBAC-only, and
policy-only modes bypass the stages described in their branch comments below.

Decision priority:
  1. RATE_LIMIT (if rate limit exceeded)
  2. Permission engine DENY (no permission)
  3. Policy engine DENY/REQUIRE_APPROVAL (explicit policy match)
  4. Risk score threshold gate (high-risk tool requires explicit ALLOW)
  5. ALLOW
"""
import time
import uuid
from typing import Any, Dict, Optional, Tuple

from database import db
from governance.permission_engine import check_permission
from governance.policy_engine import evaluate_policies
from governance.rate_limiter import check_and_increment
from governance.risk_scorer import compute_risk_score


def intercept(
    agent_id: str,
    tool_name: str,
    arguments: Dict[str, Any],
    user_id: str = "",
    configuration: str = "full",  # 'baseline' | 'permission' | 'policy' | 'full' | 'hardened'
    experiment_run_id: str = "",
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Main interception entry point.

    Args:
        agent_id: Registered agent identifier
        tool_name: Name of the tool being invoked
        arguments: Tool call arguments dict
        user_id: Optional user identifier for audit
        configuration: Which governance controls are active ('baseline' | 'permission' | 'policy' | 'full' | 'hardened')
        experiment_run_id: Optional experiment run ID for benchmark tracking
        context: Trusted runtime attributes used by context-based policies

    Returns dict with keys:
        decision: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'RATE_LIMIT'
        reason: human-readable reason string
        policy_id: matched policy ID (if any)
        risk_score: computed risk score
        call_id: audit log UUID
        latency_ms: processing time
    """
    t0 = time.perf_counter()
    call_id = str(uuid.uuid4())
    hardened_mode = (configuration == "hardened")

    # Fetch tool metadata
    tool_row = db.get_tool_by_name(tool_name)
    if tool_row is None:
        # Unknown tool — DENY (secure by default)
        decision = "DENY"
        reason = "UNKNOWN_TOOL"
        policy_id = ""
        risk_score = 10.0
        latency_ms = (time.perf_counter() - t0) * 1000
        _audit(call_id, agent_id, user_id, tool_name, arguments, decision,
               reason, policy_id, risk_score, latency_ms, experiment_run_id, configuration, context)
        return _result(decision, reason, policy_id, risk_score, call_id, latency_ms)

    tool_risk = tool_row["risk_level"]
    requires_approval = bool(tool_row["requires_approval"])

    # Baseline: no governance — just execute (always ALLOW)
    if configuration == "baseline":
        decision, reason, policy_id = "ALLOW", "BASELINE_NO_GOVERNANCE", ""
        risk_score = compute_risk_score(tool_risk, True, arguments, 0, 10, requires_approval)
        latency_ms = (time.perf_counter() - t0) * 1000
        stage_evals = {
            "rate_limiter": {"executed": False, "allowed": True},
            "permission_engine": {"executed": False, "allowed": True},
            "policy_engine": {"executed": False, "action": "ALLOW"},
            "risk_scorer": {"executed": False, "score": risk_score}
        }
        _audit(call_id, agent_id, user_id, tool_name, arguments, decision,
               reason, policy_id, risk_score, latency_ms, experiment_run_id, configuration, context)
        return _result(decision, reason, policy_id, risk_score, call_id, latency_ms,
                       first_blocking_stage="none", stage_evaluations=stage_evals)

    # -------------------------------------------------------------------------
    # Mode A: MECHANISM-ISOLATED RBAC EXPERIMENT (rbac_only / permission)
    # Rate limiting and policy evaluation are explicitly bypassed to isolate RBAC.
    # -------------------------------------------------------------------------
    if configuration in ("rbac_only", "permission"):
        perm_ok, perm_reason = check_permission(agent_id, tool_name)
        risk_score = compute_risk_score(tool_risk, perm_ok, arguments, 0, 10, requires_approval)
        latency_ms = (time.perf_counter() - t0) * 1000
        stage_evals = {
            "rate_limiter": {"executed": False, "allowed": True},
            "permission_engine": {"executed": True, "allowed": perm_ok, "reason": perm_reason},
            "policy_engine": {"executed": False, "action": "PASS"},
            "risk_scorer": {"executed": False, "score": risk_score}
        }
        if not perm_ok:
            decision = "DENY"
            reason = perm_reason
            first_stage = "permission_engine"
        else:
            decision = "ALLOW"
            reason = "RBAC_CHECK_PASSED"
            first_stage = "none"
        _audit(call_id, agent_id, user_id, tool_name, arguments, decision,
               reason, "", risk_score, latency_ms, experiment_run_id, configuration, context)
        return _result(decision, reason, "", risk_score, call_id, latency_ms,
                       first_blocking_stage=first_stage, stage_evaluations=stage_evals)

    # -------------------------------------------------------------------------
    # Mode B: MECHANISM-ISOLATED POLICY EXPERIMENT (policy_only / policy / policy_hardened_isolated)
    # Rate limiting and RBAC are explicitly bypassed to isolate parameter policy detection.
    # -------------------------------------------------------------------------
    if configuration in ("policy_only", "policy", "policy_hardened_isolated"):
        agent_row = db.get_agent(agent_id)
        agent_role = agent_row["role"] if agent_row else "default"
        is_hardened = (configuration == "policy_hardened_isolated" or hardened_mode)
        pol_action, pol_reason, pol_id = evaluate_policies(
            agent_id, tool_name, arguments, agent_role, hardened=is_hardened, context=context
        )
        risk_score = compute_risk_score(tool_risk, True, arguments, 0, 10, requires_approval)
        latency_ms = (time.perf_counter() - t0) * 1000
        stage_evals = {
            "rate_limiter": {"executed": False, "allowed": True},
            "permission_engine": {"executed": False, "allowed": True},
            "policy_engine": {"executed": True, "action": pol_action, "reason": pol_reason, "policy_id": pol_id},
            "risk_scorer": {"executed": False, "score": risk_score}
        }
        if pol_action not in ("PASS", "ALLOW"):
            decision = pol_action
            reason = pol_reason
            first_stage = "policy_engine"
            policy_id = pol_id
        else:
            decision = "ALLOW"
            reason = "NO_POLICY_VIOLATIONS"
            first_stage = "none"
            policy_id = ""
        _audit(call_id, agent_id, user_id, tool_name, arguments, decision,
               reason, policy_id, risk_score, latency_ms, experiment_run_id, configuration, context)
        return _result(decision, reason, policy_id, risk_score, call_id, latency_ms,
                       first_blocking_stage=first_stage, stage_evaluations=stage_evals)

    # -------------------------------------------------------------------------
    # Mode C: COMPOUND FULL-STACK RUNTIME GATEWAY (full / hardened / full_burst)
    # Complete 4-stage pipeline execution: RateLimit -> RBAC -> Policy -> Risk
    # Includes shadow instrumentation to answer counterfactual mechanism questions.
    # -------------------------------------------------------------------------
    # Step 1: Rate limiting
    rate_ok, call_count, limit = check_and_increment(agent_id, tool_name)
    
    # Shadow evaluation for causal attribution
    perm_ok, perm_reason = check_permission(agent_id, tool_name)
    agent_row = db.get_agent(agent_id)
    agent_role = agent_row["role"] if agent_row else "default"
    pol_action, pol_reason, pol_id = evaluate_policies(
        agent_id, tool_name, arguments, agent_role, hardened=hardened_mode, context=context
    )

    stage_evals = {
        "rate_limiter": {"executed": True, "allowed": rate_ok, "count": call_count, "limit": limit},
        "permission_engine": {"executed": True, "allowed": perm_ok, "reason": perm_reason},
        "policy_engine": {"executed": True, "action": pol_action, "reason": pol_reason, "policy_id": pol_id},
    }

    if not rate_ok:
        decision = "RATE_LIMIT"
        reason = f"RATE_LIMIT_EXCEEDED:{call_count}/{limit}_per_60s"
        policy_id = ""
        risk_score = compute_risk_score(tool_risk, None, arguments, call_count, limit, requires_approval)
        stage_evals["risk_scorer"] = {"executed": False, "score": risk_score}
        latency_ms = (time.perf_counter() - t0) * 1000
        _audit(call_id, agent_id, user_id, tool_name, arguments, decision,
               reason, policy_id, risk_score, latency_ms, experiment_run_id, configuration, context)
        return _result(decision, reason, policy_id, risk_score, call_id, latency_ms,
                       first_blocking_stage="rate_limiter", stage_evaluations=stage_evals)

    # Step 2: Permission check
    if not perm_ok:
        risk_score = compute_risk_score(tool_risk, False, arguments, call_count, limit, requires_approval)
        stage_evals["risk_scorer"] = {"executed": False, "score": risk_score}
        decision = "DENY"
        reason = perm_reason
        first_stage = "permission_engine"
        policy_id = ""
        latency_ms = (time.perf_counter() - t0) * 1000
        _audit(call_id, agent_id, user_id, tool_name, arguments, decision,
               reason, policy_id, risk_score, latency_ms, experiment_run_id, configuration, context)
        return _result(decision, reason, policy_id, risk_score, call_id, latency_ms,
                       first_blocking_stage=first_stage, stage_evaluations=stage_evals)

    # Step 3: Policy evaluation
    if pol_action not in ("PASS", "ALLOW"):
        risk_score = compute_risk_score(tool_risk, perm_ok, arguments, call_count, limit, requires_approval)
        stage_evals["risk_scorer"] = {"executed": False, "score": risk_score}
        decision = pol_action
        reason = pol_reason
        latency_ms = (time.perf_counter() - t0) * 1000
        _audit(call_id, agent_id, user_id, tool_name, arguments, decision,
               reason, pol_id, risk_score, latency_ms, experiment_run_id, configuration, context)
        return _result(decision, reason, pol_id, risk_score, call_id, latency_ms,
                       first_blocking_stage="policy_engine", stage_evaluations=stage_evals)

    # Step 4: Risk-based gate
    risk_score = compute_risk_score(tool_risk, perm_ok, arguments, call_count, limit, requires_approval)
    stage_evals["risk_scorer"] = {"executed": True, "score": risk_score, "requires_approval": requires_approval}
    if requires_approval or risk_score >= 7.0:
        decision = "REQUIRE_APPROVAL"
        reason = f"HIGH_RISK_REQUIRES_APPROVAL:score={risk_score}"
        latency_ms = (time.perf_counter() - t0) * 1000
        _audit(call_id, agent_id, user_id, tool_name, arguments, decision,
               reason, "", risk_score, latency_ms, experiment_run_id, configuration, context)
        return _result(decision, reason, "", risk_score, call_id, latency_ms,
                       first_blocking_stage="risk_scorer", stage_evaluations=stage_evals)

    # Step 5: ALLOW
    decision = "ALLOW"
    reason = "ALL_CHECKS_PASSED"
    latency_ms = (time.perf_counter() - t0) * 1000
    _audit(call_id, agent_id, user_id, tool_name, arguments, decision,
           reason, "", risk_score, latency_ms, experiment_run_id, configuration, context)
    return _result(decision, reason, "", risk_score, call_id, latency_ms,
                   first_blocking_stage="none", stage_evaluations=stage_evals)


def _audit(call_id, agent_id, user_id, tool_name, arguments, decision,
           reason, policy_id, risk_score, latency_ms, experiment_run_id, configuration, context):
    db.insert_tool_call(
        call_id=call_id, agent_id=agent_id, tool_name=tool_name,
        arguments=arguments, decision=decision, reason=reason,
        risk_score=risk_score, policy_id=policy_id, user_id=user_id,
        latency_ms=latency_ms, experiment_run_id=experiment_run_id,
        configuration=configuration, context=context
    )


def _result(decision, reason, policy_id, risk_score, call_id, latency_ms,
            first_blocking_stage="none", stage_evaluations=None) -> Dict[str, Any]:
    return {
        "decision": decision,
        "reason": reason,
        "policy_id": policy_id,
        "risk_score": risk_score,
        "call_id": call_id,
        "latency_ms": round(latency_ms, 3),
        "first_blocking_stage": first_blocking_stage,
        "stage_evaluations": stage_evaluations or {},
    }
