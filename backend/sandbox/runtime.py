"""Gateway-mediated execution of sandbox tools (Phase 6).

``ProtectedRuntime.call`` is the *only* path from an agent to a tool.  It
records, separately and for every proposed call:

  proposed call -> gateway decision -> whether the tool actually executed ->
  state change (hash before/after) -> effects -> tool error (if any)

Execution rules
---------------
* ALLOW                      -> execute.
* REQUIRE_APPROVAL           -> execute only if an explicit approval exists for
                                that call's correlation id (``approve``).
* DENY / RATE_LIMIT          -> never execute.
* Gateway exception/timeout  -> treated as DENY by ``Gateway`` (fail closed).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from governance.audit_chain import args_digest
from governance.gateway import Decision, Gateway
from sandbox.world import Effect, SandboxWorld, unsafe_effects


@dataclass
class CallRecord:
    scenario_id: str
    seq: int
    tool: str
    arguments: Dict[str, Any]
    decision: str
    reason_code: str
    first_blocking_stage: str
    call_id: str
    correlation_id: str
    gateway_latency_ms: float
    total_latency_ms: float
    executed: bool
    state_changed: bool
    effect_types: List[str]
    unsafe_effect_types: List[str]
    tool_error: Optional[str]
    audited: bool
    approved: bool = False
    rows: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class ProtectedRuntime:
    gateway: Gateway
    world: SandboxWorld
    approved_approvers: Set[str] = field(default_factory=set)
    approvals: Dict[str, str] = field(default_factory=dict)

    def approve(self, correlation_id: str, approver: str, *, agent_id: str, tool: str,
                arguments: Dict[str, Any]) -> None:
        """Bind a single-use approval to an authorized approver and exact request.

        The allowlist is a harness control, not an identity provider. Production
        integrations must call this only after authenticating a human approver.
        """
        if not correlation_id or approver not in self.approved_approvers:
            raise PermissionError("approver is not authorized for this runtime")
        self.approvals[correlation_id] = self._approval_binding(agent_id, tool, arguments)

    @staticmethod
    def _approval_binding(agent_id: str, tool: str, arguments: Dict[str, Any]) -> str:
        return args_digest({"agent_id": agent_id, "tool": tool, "arguments": arguments})

    def call(self, agent_id: str, tool: str, arguments: Dict[str, Any], *, scenario_id: str = "",
             seq: int = 0, user_id: str = "", context: Optional[Dict[str, Any]] = None,
             run_id: str = "", correlation_id: str = "") -> CallRecord:
        t_start = time.perf_counter()
        decision: Decision = self.gateway.evaluate(
            agent_id, tool, arguments, user_id=user_id, context=context,
            experiment_run_id=run_id, correlation_id=correlation_id)
        total_ms = (time.perf_counter() - t_start) * 1000.0
        binding = self._approval_binding(agent_id, tool, arguments)
        approved = (decision.decision == "REQUIRE_APPROVAL" and
                    self.approvals.get(decision.correlation_id) == binding)
        if approved:
            # Approval is single-use so a retry cannot replay a destructive action.
            del self.approvals[decision.correlation_id]
        permitted = decision.decision == "ALLOW" or approved
        before_hash = self.world.state_hash()
        n_before = len(self.world.effects)
        error: Optional[str] = None
        executed = False
        rows: Optional[int] = None
        if permitted:
            fn = getattr(self.world, tool, None)
            if fn is None or tool not in SandboxWorld.TOOLS:
                error = "tool has no sandbox implementation"
            else:
                try:
                    ret = fn(**arguments)
                    executed = True
                    if isinstance(ret, dict) and isinstance(ret.get("rows"), list):
                        rows = len(ret["rows"])
                except Exception as exc:  # malformed call that passed the gateway (e.g. baseline)
                    error = f"{type(exc).__name__}"
        new_effects: List[Effect] = self.world.effects[n_before:]
        return CallRecord(
            scenario_id=scenario_id, seq=seq, tool=tool, arguments=arguments,
            decision=decision.decision, reason_code=decision.reason_code,
            first_blocking_stage=decision.first_blocking_stage, call_id=decision.call_id,
            correlation_id=decision.correlation_id, gateway_latency_ms=decision.latency_ms, total_latency_ms=round(total_ms, 3),
            executed=executed, state_changed=self.world.state_hash() != before_hash,
            effect_types=[e.effect_type for e in new_effects],
            unsafe_effect_types=[e.effect_type for e in unsafe_effects(new_effects)
                                 if not (approved and e.effect_type in {"customer_deleted", "data_exported", "sql_executed", "file_deleted"})],
            tool_error=error, audited=decision.audited, approved=approved, rows=rows)
