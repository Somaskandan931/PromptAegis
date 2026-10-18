from __future__ import annotations

import json
import sys
import shutil
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database.environments import environment_scope
from database import db
from experiments.study.env import ENV_ID, build
from experiments.study.run_benchmark import _task_success
from governance.audit_chain import AuditChain, verify_chain
from governance.gateway import Gateway
from governance.interceptor import intercept
from governance.param_validator import validate_arguments, validate_contract_definition
from governance.policy_engine import _normalize_value
from sandbox.runtime import ProtectedRuntime
from sandbox.world import SandboxWorld


@pytest.fixture
def isolated_env():
    env = build()
    try:
        with environment_scope(ENV_ID):
            yield env
    finally:
        env.close()


def test_contract_accepts_valid_request_and_rejects_sql_injection():
    assert validate_arguments("search_customer", {"query": "cust-10042"}).valid
    result = validate_arguments("search_customer", {"query": "x' OR '1'='1"})
    assert not result.valid
    assert result.first.code == "PARAM_QUERY_NOT_IN_CONTRACT"


def test_registered_custom_tool_contract_is_persistent_and_enforced(isolated_env):
    contract = {
        "type": "object",
        "properties": {"record_id": {"type": "string", "minLength": 1, "maxLength": 12},
                       "count": {"type": "integer", "minimum": 1, "maximum": 5}},
        "required": ["record_id"],
        "additionalProperties": False,
    }
    agent_id = isolated_env.agent_ids["CustomerSupportAgent"]
    tool_id = "tool_custom_contract_test"
    with environment_scope(ENV_ID):
        db.create_tool(tool_id, "custom_lookup", "read", "low", argument_contract=contract)
        db.set_permission("perm_custom_contract_test", agent_id, tool_id, True)
        stored = db.get_tool_by_name("custom_lookup")
        assert stored["argument_contract"] == contract
        gateway = Gateway("full")
        assert gateway.evaluate(agent_id, "custom_lookup", {"record_id": "abc", "count": 2}).decision == "ALLOW"
        rejected = gateway.evaluate(agent_id, "custom_lookup", {"record_id": "abc", "count": 9})
        assert rejected.decision == "DENY"
        assert rejected.reason_code == "PARAM_CUSTOM_MAXIMUM"
        extra = gateway.evaluate(agent_id, "custom_lookup", {"record_id": "abc", "admin": True})
        assert extra.decision == "DENY"
        assert extra.reason_code == "PARAM_CUSTOM_UNEXPECTED"


def test_custom_contract_validation_fails_closed_when_missing_or_invalid():
    assert validate_arguments("not_builtin", {"x": 1}).first.code == "PARAM_NO_CONTRACT"
    assert validate_arguments("not_builtin", {"x": 1}, {"type": "object", "properties": {"x": {"type": "nonsense"}}}).first.code == "PARAM_INVALID_CONTRACT"
    assert validate_arguments("not_builtin", {"x": 1}, {"type": ["object"]}).first.code == "PARAM_INVALID_CONTRACT"
    with pytest.raises(ValueError):
        validate_contract_definition({"type": "array"})


def test_search_task_check_treats_missing_rows_as_failure_not_exception():
    world = SandboxWorld.fresh()
    check = {"kind": "search_hits", "min_rows": 1}
    assert _task_success(check, world, [{"rows": 1}]) is True
    assert _task_success(check, world, [{"rows": None}]) is False
    assert _task_success(check, world, [{"decision": "DENY"}]) is False
    assert _task_success(check, world, []) is False


def test_api_compatibility_interceptor_uses_canonical_gateway(isolated_env):
    agent = isolated_env.agent_ids["CustomerSupportAgent"]
    with environment_scope(ENV_ID):
        result = intercept(agent, "search_customer", {"query": "cust-10042"}, configuration="full")
    assert result["decision"] == "ALLOW"
    assert result["audited"] is True
    assert result["stage_evaluations"]["permission_engine"]["executed"] is True
    assert result["stage_evaluations"]["policy_engine"]["executed"] is True


def test_hardening_does_not_decode_ordinary_words_as_base64():
    email = "steal@attacker.com"
    assert _normalize_value(email) == email
    assert _normalize_value("base64:c2VsZWN0") == "select"


def test_denied_request_does_not_reach_sandbox(isolated_env):
    agent = isolated_env.agent_ids["CustomerSupportAgent"]
    world = SandboxWorld.fresh()
    runtime = ProtectedRuntime(Gateway("full"), world, approved_approvers={"sandbox-reviewer"})
    with environment_scope(ENV_ID):
        record = runtime.call(agent, "search_customer", {"query": "x' OR '1'='1"})
    assert record.decision == "DENY"
    assert record.first_blocking_stage == "schema"
    assert not record.executed
    assert not record.state_changed
    assert record.audited


def test_approval_is_required_then_only_explicitly_approved_retry_executes(isolated_env):
    agent = isolated_env.agent_ids["AdminAgent"]
    world = SandboxWorld.fresh()
    runtime = ProtectedRuntime(Gateway("full"), world, approved_approvers={"sandbox-reviewer"})
    args = {"customer_id": "cust-10042", "reason": "approved test deletion"}
    with environment_scope(ENV_ID):
        pending = runtime.call(agent, "delete_customer", args, correlation_id="approval-test")
        assert pending.decision == "REQUIRE_APPROVAL"
        assert not pending.executed
        assert "cust-10042" in world.customers

        with pytest.raises(PermissionError):
            runtime.approve(pending.correlation_id, "untrusted-agent", agent_id=agent,
                            tool="delete_customer", arguments=args)
        runtime.approve(pending.correlation_id, "sandbox-reviewer", agent_id=agent,
                        tool="delete_customer", arguments={"customer_id": "cust-20087", "reason": "other"})
        mismatch = runtime.call(agent, "delete_customer", args, correlation_id="approval-test")
        assert not mismatch.executed
        assert not mismatch.approved
        runtime.approve(pending.correlation_id, "sandbox-reviewer", agent_id=agent,
                        tool="delete_customer", arguments=args)
        approved = runtime.call(agent, "delete_customer", args, correlation_id="approval-test")
        replay = runtime.call(agent, "delete_customer", args, correlation_id="approval-test")
    assert approved.decision == "REQUIRE_APPROVAL"
    assert approved.approved and approved.executed
    assert approved.state_changed
    assert not approved.unsafe_effect_types
    assert "cust-10042" not in world.customers
    assert not replay.executed
    assert not replay.approved


def test_audit_failure_fails_closed_before_tool_execution(isolated_env):
    agent = isolated_env.agent_ids["CustomerSupportAgent"]
    world = SandboxWorld.fresh()
    gateway = Gateway("full", _fault="audit")
    runtime = ProtectedRuntime(gateway, world)
    with environment_scope(ENV_ID):
        record = runtime.call(agent, "search_customer", {"query": "cust-10042"})
    assert record.decision == "DENY"
    assert record.reason_code == "AUDIT_UNAVAILABLE"
    assert not record.audited
    assert not record.executed
    assert not record.state_changed


def test_audit_chain_failure_corrects_database_decision_and_fails_closed(isolated_env):
    agent = isolated_env.agent_ids["CustomerSupportAgent"]
    world = SandboxWorld.fresh()
    gateway = Gateway("full")

    def fail_append(_entry):
        raise OSError("simulated chain disk failure")

    gateway.chain.append = fail_append
    runtime = ProtectedRuntime(gateway, world)
    with environment_scope(ENV_ID):
        record = runtime.call(agent, "search_customer", {"query": "cust-10042"})

    assert record.decision == "DENY"
    assert record.reason_code == "AUDIT_UNAVAILABLE"
    assert not record.audited
    assert not record.executed
    rows = db.fetch_tool_calls()
    stored = next(row for row in rows if row["call_id"] == record.call_id)
    assert stored["decision"] == "DENY"


def test_cyclic_arguments_are_denied_and_still_audited(isolated_env):
    agent = isolated_env.agent_ids["CustomerSupportAgent"]
    world = SandboxWorld.fresh()
    runtime = ProtectedRuntime(Gateway("full"), world)
    cyclic = []
    cyclic.append(cyclic)
    with environment_scope(ENV_ID):
        record = runtime.call(agent, "search_customer", {"query": cyclic})
    assert record.decision == "DENY"
    assert record.audited
    assert not record.executed


def _workspace_temp_dir():
    path = ROOT / "tmp" / f"test-study-{uuid.uuid4().hex}"
    path.mkdir(parents=True)
    return path


def test_audit_chain_detects_tampering_and_refuses_to_resume():
    folder = _workspace_temp_dir()
    try:
        path = folder / "audit.jsonl"
        chain = AuditChain(str(path))
        chain.append({"call_id": "1", "decision": "ALLOW"})
        assert verify_chain(chain.entries()) == (True, None)
        entry = json.loads(path.read_text(encoding="utf-8"))
        entry["body"]["decision"] = "DENY"
        path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match="audit chain is invalid"):
            AuditChain(str(path))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_environment_builder_refuses_to_overwrite_user_database():
    folder = _workspace_temp_dir()
    try:
        existing = folder / "must-survive.db"
        existing.write_bytes(b"important existing file")
        with pytest.raises(FileExistsError):
            build(str(existing))
        assert existing.read_bytes() == b"important existing file"
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_holdout_split_is_locked_without_independent_review():
    from experiments.study.run_benchmark import _load

    with pytest.raises(RuntimeError, match="Refusing to open 'test'"):
        _load("test")
