"""PromptAegis enforcement gateway.

Deterministic precedence (first stage that blocks wins; stages never "upgrade"
a stricter earlier outcome)
-------------------------------------------------------------------------
 0. request well-formedness / identity          -> DENY   (mandatory)
 1. tool is registered                          -> DENY   (mandatory)
 2. RBAC permission (least privilege)           -> DENY   (mandatory)
 3. parameter contract (allowlist schemas)      -> DENY   (mandatory)
 4. policy engine (tool/role/context/regex ...) -> DENY | REQUIRE_APPROVAL
 5. rate limit                                  -> RATE_LIMIT
 6. approval metadata / risk gate               -> REQUIRE_APPROVAL
 7. otherwise                                   -> ALLOW

Design decisions
----------------
* The rate limiter is consulted only for requests that passed stages 0-4.
  This prevents rejected calls from consuming a caller's rate budget.
* The risk score is advisory: it can raise ALLOW to REQUIRE_APPROVAL above a
  threshold but can never override a DENY.
* Any exception inside a stage, and any audit-write failure, produces a DENY
  (fail closed).  An unaudited ALLOW is never returned for a protected tool.
* Denial responses carry a stable ``reason_code`` and a generic
  ``public_message``; internal rule names stay in the audit record only.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Optional

from database import db
from governance.audit_chain import AuditChain, args_digest, redact
from governance.param_validator import CONTRACT_VERSION, validate_arguments
from governance.permission_engine import check_permission
from governance.policy_engine import evaluate_policies
from governance.rate_limiter import check_and_increment
from governance.risk_scorer import compute_risk_score

POLICY_VERSION = "gateway+" + CONTRACT_VERSION
RISK_APPROVAL_THRESHOLD = 7.0

PUBLIC_MESSAGES = {
    "ALLOW": "Request permitted.",
    "DENY": "Request denied by governance policy.",
    "REQUIRE_APPROVAL": "Request requires explicit approval before execution.",
    "RATE_LIMIT": "Too many requests; try again later.",
}

ALL_STAGES: FrozenSet[str] = frozenset({"rbac", "schema", "policy", "rate", "approval"})

# Named configurations used by the research experiments. Baseline = no controls, but
# identical sandbox + instrumentation (the gateway still records everything).
CONFIGURATIONS: Dict[str, FrozenSet[str]] = {
    "baseline": frozenset(),
    "rbac_only": frozenset({"rbac"}),
    "policy_only": frozenset({"policy"}),
    "schema_only": frozenset({"schema"}),
    "rbac_schema": frozenset({"rbac", "schema"}),
    "rbac_policy": frozenset({"rbac", "policy"}),
    "full": ALL_STAGES,
    # leave-one-out ablations of the full gateway
    "full_minus_rbac": ALL_STAGES - {"rbac"},
    "full_minus_schema": ALL_STAGES - {"schema"},
    "full_minus_policy": ALL_STAGES - {"policy"},
    "full_minus_rate": ALL_STAGES - {"rate"},
    "full_minus_approval": ALL_STAGES - {"approval"},
}


@dataclass
class Decision:
    decision: str                 # ALLOW | DENY | REQUIRE_APPROVAL | RATE_LIMIT
    reason_code: str              # stable machine code
    internal_reason: str          # detail for the audit log only
    public_message: str
    call_id: str
    correlation_id: str
    first_blocking_stage: str
    risk_score: float
    latency_ms: float
    policy_version: str = POLICY_VERSION
    policy_id: str = ""
    stages_executed: tuple = ()
    audited: bool = True

    def public(self) -> Dict[str, Any]:
        """What a caller (the agent) is allowed to see."""
        return {
            "decision": self.decision,
            "reason_code": self.reason_code,
            "message": self.public_message,
            "correlation_id": self.correlation_id,
        }


@dataclass
class Gateway:
    configuration: str = "full"
    enabled: Optional[FrozenSet[str]] = None
    chain: Optional[AuditChain] = None
    # test hooks for fault injection (never set in production use)
    _fault: Optional[str] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.enabled is None:
            if self.configuration not in CONFIGURATIONS:
                raise ValueError(f"unknown configuration {self.configuration!r}")
            self.enabled = CONFIGURATIONS[self.configuration]
        if self.chain is None:
            self.chain = AuditChain()

    # ------------------------------------------------------------------
    def evaluate(self, agent_id: Any, tool_name: Any, arguments: Any, *,
                 user_id: str = "", context: Optional[Dict[str, Any]] = None,
                 experiment_run_id: str = "", correlation_id: str = "") -> Decision:
        t0 = time.perf_counter()
        call_id = str(uuid.uuid4())
        corr = correlation_id or call_id
        executed: list = []
        tool_risk, requires_approval, risk_score = "medium", False, 0.0
        try:
            decision, code, internal, stage, policy_id, risk_score = self._decide(
                agent_id, tool_name, arguments, context or {}, executed)
        except Exception as exc:  # fail closed on ANY engine error
            decision, code, stage, policy_id = "DENY", "GATEWAY_ERROR", "gateway", ""
            internal = f"{type(exc).__name__}: {exc}"
        latency_ms = (time.perf_counter() - t0) * 1000.0
        result = Decision(
            decision=decision, reason_code=code, internal_reason=internal,
            public_message=PUBLIC_MESSAGES[decision], call_id=call_id,
            correlation_id=corr, first_blocking_stage=stage, risk_score=risk_score,
            latency_ms=round(latency_ms, 3), policy_id=policy_id,
            stages_executed=tuple(executed),
        )
        return self._audit(result, agent_id, user_id, tool_name, arguments, context or {}, experiment_run_id)

    # ------------------------------------------------------------------
    def _decide(self, agent_id, tool_name, arguments, context, executed):
        en = self.enabled
        if self._fault == "engine":
            raise RuntimeError("injected policy-engine failure")

        # Stage 0: well-formedness / identity (always on: not a "control" under test)
        if not isinstance(agent_id, str) or not agent_id or not isinstance(tool_name, str) or not tool_name:
            return "DENY", "INVALID_REQUEST", "missing agent or tool identifier", "request", "", 10.0
        if not isinstance(arguments, dict):
            return "DENY", "INVALID_REQUEST", "arguments is not an object", "request", "", 10.0
        if db.get_agent(agent_id) is None:
            return "DENY", "UNKNOWN_AGENT", "agent not registered", "request", "", 10.0
        tool_row = db.get_tool_by_name(tool_name)
        if tool_row is None:
            return "DENY", "UNKNOWN_TOOL", "tool not registered", "request", "", 10.0
        tool_risk = tool_row["risk_level"]
        requires_approval = bool(tool_row["requires_approval"])

        perm_ok: Optional[bool] = None
        if "rbac" in en:
            executed.append("rbac")
            perm_ok, perm_reason = check_permission(agent_id, tool_name)
            if not perm_ok:
                score = compute_risk_score(tool_risk, False, arguments, 0, 10, requires_approval)
                return "DENY", "RBAC_DENIED", perm_reason, "rbac", "", score

        if "schema" in en:
            executed.append("schema")
            res = validate_arguments(tool_name, arguments,
                                     custom_contract=tool_row.get("argument_contract"))
            if not res.valid:
                v = res.first
                score = compute_risk_score(tool_risk, perm_ok, arguments, 0, 10, requires_approval)
                return "DENY", v.code, f"{v.argument}: {v.detail}", "schema", "", score

        if "policy" in en:
            executed.append("policy")
            agent_row = db.get_agent(agent_id)
            role = agent_row["role"] if agent_row else "default"
            # A legacy "ALLOW" policy would short-circuit later DENY policies in
            # evaluate_policies (first match wins).  Refuse to run in that state.
            if any(p.get("action") == "ALLOW" for p in db.list_policies(enabled_only=True)):
                return "DENY", "POLICY_CONFIG_INVALID", "ALLOW-action policies are not supported", "policy", "", 10.0
            action, reason, pid = evaluate_policies(agent_id, tool_name, arguments, role,
                                                    hardened=True, context=context)
            if action not in ("PASS", "ALLOW"):
                score = compute_risk_score(tool_risk, perm_ok, arguments, 0, 10, requires_approval)
                code = {"DENY": "POLICY_DENIED", "REQUIRE_APPROVAL": "POLICY_REQUIRES_APPROVAL",
                        "RATE_LIMIT": "POLICY_RATE_LIMIT"}.get(action, "POLICY_DENIED")
                return action, code, reason, "policy", pid, score

        count, limit = 0, 10
        if "rate" in en:
            executed.append("rate")
            ok, count, limit = check_and_increment(agent_id, tool_name)
            if not ok:
                score = compute_risk_score(tool_risk, perm_ok, arguments, count, limit, requires_approval)
                return "RATE_LIMIT", "RATE_LIMIT_EXCEEDED", f"{count}/{limit} per 60s", "rate", "", score

        score = compute_risk_score(tool_risk, perm_ok, arguments, count, limit, requires_approval)
        if "approval" in en:
            executed.append("approval")
            if requires_approval:
                return "REQUIRE_APPROVAL", "APPROVAL_REQUIRED", "tool metadata requires approval", "approval", "", score
            if score >= RISK_APPROVAL_THRESHOLD:
                return "REQUIRE_APPROVAL", "RISK_THRESHOLD", f"score={score}", "approval", "", score
        return "ALLOW", "ALLOWED", "all enabled controls passed", "none", "", score

    # ------------------------------------------------------------------
    def _audit(self, result: Decision, agent_id, user_id, tool_name, arguments, context,
               run_id) -> Decision:
        safe_args = redact(arguments) if isinstance(arguments, dict) else {"_non_object": True}
        ctx = dict(context) if isinstance(context, dict) else {}
        ctx.update({"_policy_version": result.policy_version,
                    "_correlation_id": result.correlation_id,
                    "_reason_code": result.reason_code,
                    "_stage": result.first_blocking_stage,
                    "_args_sha256": args_digest(arguments)})
        try:
            if self._fault == "audit":
                raise OSError("injected audit-store failure")
            db.insert_tool_call(
                call_id=result.call_id, agent_id=str(agent_id), tool_name=str(tool_name),
                arguments=safe_args, decision=result.decision,
                reason=f"{result.reason_code}|{result.internal_reason}"[:500],
                risk_score=result.risk_score, policy_id=result.policy_id, user_id=user_id,
                latency_ms=result.latency_ms, experiment_run_id=run_id,
                configuration=self.configuration, context=redact(ctx))
            self.chain.append({
                "call_id": result.call_id, "correlation_id": result.correlation_id,
                "agent_id": str(agent_id), "tool": str(tool_name),
                "decision": result.decision, "reason_code": result.reason_code,
                "policy_version": result.policy_version,
                "args_sha256": ctx["_args_sha256"], "run_id": run_id,
            })
        except Exception as exc:
            result.audited = False
            if result.decision != "DENY":
                # An action we cannot record must not be permitted.
                result.internal_reason = f"audit failure ({type(exc).__name__}); original={result.decision}"
                result.decision = "DENY"
                result.reason_code = "AUDIT_UNAVAILABLE"
                result.public_message = PUBLIC_MESSAGES["DENY"]
                result.first_blocking_stage = "audit"
                try:
                    db.update_tool_call_outcome(
                        result.call_id, "DENY", "AUDIT_UNAVAILABLE|audit-chain write failed"
                    )
                except Exception:
                    # The caller still receives DENY; runtime must never execute
                    # a request after any part of the audit operation fails.
                    pass
        return result
