"""Failure-mode, attribution and concurrency tests for the enforcement gateway.

These back the implementation claims in the manuscript (fail-closed behaviour, stage order, rate-limit
atomicity). They test the in-process prototype only; they are not an adversarial security evaluation.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
for path in (ROOT, BACKEND):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from database.environments import environment_scope  # noqa: E402
from experiments.study.env import ENV_ID, build  # noqa: E402
from governance import gateway as gateway_module  # noqa: E402
from governance.gateway import Gateway  # noqa: E402
from governance.rate_limiter import set_limit  # noqa: E402
from sandbox.runtime import ProtectedRuntime  # noqa: E402
from sandbox.world import SandboxWorld  # noqa: E402

VALID_DELETE = {"customer_id": "cust-10042", "reason": "customer requested deletion"}
VALID_EXPORT = {"customer_id": "cust-10017", "destination": "audit@company.com"}
VALID_UPDATE = {"customer_id": "cust-10019", "fields": {"phone": "+1-555-6439"}}


@pytest.fixture
def env():
    built = build()
    try:
        with environment_scope(ENV_ID):
            yield built
    finally:
        built.close()


def _runtime(configuration: str = "full") -> ProtectedRuntime:
    return ProtectedRuntime(Gateway(configuration), SandboxWorld.fresh(),
                            approved_approvers={"sandbox-reviewer"})


# ---------------------------------------------------------------- exception in each stage
@pytest.mark.parametrize("attribute", ["check_permission", "validate_arguments",
                                       "evaluate_policies", "check_and_increment",
                                       "compute_risk_score"])
def test_exception_in_any_stage_denies_and_does_not_execute(env, monkeypatch, attribute):
    def boom(*args, **kwargs):
        raise RuntimeError(f"injected failure in {attribute}")

    monkeypatch.setattr(gateway_module, attribute, boom)
    agent = env.agent_ids["CustomerSupportAgent"]
    runtime = _runtime()
    record = runtime.call(agent, "search_customer", {"query": "cust-10042"})
    assert record.decision == "DENY"
    assert record.reason_code == "GATEWAY_ERROR"
    assert not record.executed and not record.state_changed
    assert record.audited, "a failed stage must still leave an audit record"


# ---------------------------------------------------------------- malformed identity / arguments
@pytest.mark.parametrize("agent,tool,arguments,code", [
    ("", "search_customer", {}, "INVALID_REQUEST"),
    (None, "search_customer", {}, "INVALID_REQUEST"),
    ("__agent__", "", {}, "INVALID_REQUEST"),
    ("__agent__", 7, {}, "INVALID_REQUEST"),
    ("__agent__", "search_customer", ["not", "an", "object"], "INVALID_REQUEST"),
    ("__agent__", "search_customer", None, "INVALID_REQUEST"),
    ("no-such-agent", "search_customer", {"query": "x"}, "UNKNOWN_AGENT"),
    ("__agent__", "no_such_tool", {"query": "x"}, "UNKNOWN_TOOL"),
])
def test_invalid_or_unknown_identifiers_are_denied_before_any_control(env, agent, tool, arguments, code):
    agent_id = env.agent_ids["CustomerSupportAgent"] if agent == "__agent__" else agent
    decision = Gateway("baseline").evaluate(agent_id, tool, arguments)   # baseline = no optional controls
    assert decision.decision == "DENY" and decision.reason_code == code
    assert decision.first_blocking_stage == "request"
    assert decision.audited


def test_unknown_argument_names_are_rejected_by_the_contract(env):
    agent = env.agent_ids["CustomerSupportAgent"]
    decision = Gateway("full").evaluate(agent, "search_customer", {"query": "cust-10042", "admin": True})
    assert decision.decision == "DENY" and decision.first_blocking_stage == "schema"


# ---------------------------------------------------------------- schema-valid but unauthorized
def test_schema_valid_call_outside_the_role_is_stopped_by_rbac_not_by_the_contract(env):
    agent = env.agent_ids["CustomerSupportAgent"]
    # The arguments satisfy the delete_customer contract: only authorization can stop this call.
    assert Gateway("schema_only").evaluate(agent, "delete_customer", VALID_DELETE).decision == "ALLOW"
    full = Gateway("full").evaluate(agent, "delete_customer", VALID_DELETE)
    assert full.decision == "DENY" and full.first_blocking_stage == "rbac"


def test_schema_valid_call_violating_trusted_context_is_stopped_by_policy(env):
    agent = env.agent_ids["CustomerSupportAgent"]
    closed = {"ticket_status": "closed"}
    assert Gateway("rbac_schema").evaluate(agent, "update_customer", VALID_UPDATE,
                                           context=closed).decision == "ALLOW"
    full = Gateway("full").evaluate(agent, "update_customer", VALID_UPDATE, context=closed)
    assert full.decision == "DENY" and full.first_blocking_stage == "policy"


def test_stage_order_decides_attribution_when_several_controls_would_block(env):
    """Support role + delete_customer is blocked by RBAC and by a policy rule. Attribution follows the order."""
    agent = env.agent_ids["CustomerSupportAgent"]
    assert Gateway("full").evaluate(agent, "delete_customer", VALID_DELETE).first_blocking_stage == "rbac"
    without_rbac = Gateway("full_minus_rbac").evaluate(agent, "delete_customer", VALID_DELETE)
    assert without_rbac.decision == "DENY" and without_rbac.first_blocking_stage == "policy"
    assert Gateway("policy_only").evaluate(agent, "delete_customer", VALID_DELETE).first_blocking_stage == "policy"


def test_stages_run_in_the_documented_order(env):
    agent = env.agent_ids["AdminAgent"]
    decision = Gateway("full").evaluate(agent, "export_customer_data", VALID_EXPORT)
    assert decision.decision == "REQUIRE_APPROVAL" and decision.first_blocking_stage == "approval"
    assert decision.stages_executed == ("rbac", "schema", "policy", "rate", "approval")


def test_rejected_calls_do_not_consume_the_rate_budget(env):
    agent = env.agent_ids["CustomerSupportAgent"]
    set_limit("search_customer", 2, ENV_ID)
    gateway = Gateway("full")
    for _ in range(5):   # schema-invalid calls are blocked before the rate stage
        assert gateway.evaluate(agent, "search_customer", {"query": "x' OR '1'='1"}).decision == "DENY"
    outcomes = [gateway.evaluate(agent, "search_customer", {"query": "cust-10042"}).decision for _ in range(3)]
    assert outcomes == ["ALLOW", "ALLOW", "RATE_LIMIT"]


# ---------------------------------------------------------------- rate-limit boundary and concurrency
def test_rate_limit_boundary_is_exact(env):
    agent = env.agent_ids["CustomerSupportAgent"]
    set_limit("search_customer", 5, ENV_ID)
    gateway = Gateway("full")
    outcomes = [gateway.evaluate(agent, "search_customer", {"query": "cust-10042"}).decision
                for _ in range(8)]
    assert outcomes == ["ALLOW"] * 5 + ["RATE_LIMIT"] * 3


def test_concurrent_calls_cannot_exceed_the_rate_limit(env):
    agent = env.agent_ids["CustomerSupportAgent"]
    limit, workers, per_worker = 6, 8, 5
    set_limit("search_customer", limit, ENV_ID)
    gateway = Gateway("rbac_schema")  # no rate stage in the gateway; test the limiter itself below
    from governance.rate_limiter import check_and_increment
    results, errors = [], []
    start = threading.Barrier(workers)

    def worker():
        try:
            with environment_scope(ENV_ID):   # context variables do not cross threads
                start.wait()
                for _ in range(per_worker):
                    results.append(check_and_increment(agent, "search_customer")[0])
        except Exception as exc:  # pragma: no cover - surfaced by the assertion below
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(results) == workers * per_worker
    assert sum(results) == limit, "the atomic counter must admit exactly `limit` calls per window"
    assert gateway is not None


# ---------------------------------------------------------------- adapter: nothing runs without permission
def test_runtime_never_executes_a_non_allowed_call(env):
    agent = env.agent_ids["CustomerSupportAgent"]
    runtime = _runtime()
    for tool, args in (("delete_customer", VALID_DELETE), ("export_customer_data", VALID_EXPORT),
                       ("execute_sql", {"query": "SELECT 1"})):
        record = runtime.call(agent, tool, args)
        assert record.decision != "ALLOW"
        assert not record.executed and not record.state_changed
