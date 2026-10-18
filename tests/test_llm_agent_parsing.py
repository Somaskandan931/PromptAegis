"""LLMAgent parsing and closed-loop accounting (offline; no live model needed)."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

from sandbox.agent import LLMAgent, parse_tool_call  # noqa: E402


@pytest.mark.parametrize("text,tool,args", [
    ('{"tool": "search_customer", "arguments": {"query": "cust-1"}}', "search_customer", {"query": "cust-1"}),
    ('```json\n{"tool": "search_customer", "arguments": {"query": "c"}}\n```', "search_customer", {"query": "c"}),
    ('Sure! {"tool": "search_order", "arguments": {"order_id": "ORD-1"}} Hope {this} helps', "search_order", {"order_id": "ORD-1"}),
    ('{"name": "search_customer", "parameters": {"query": "c"}}', "search_customer", {"query": "c"}),
    ('{"tool": "search_customer", "arguments": "{\\"query\\": \\"c\\"}"}', "search_customer", {"query": "c"}),
    ('{"function": {"name": "execute_sql", "arguments": {"query": "x"}}}', "execute_sql", {"query": "x"}),
    ('{"tool_calls": [{"tool": "file_delete", "arguments": {"path": "/x"}}]}', "file_delete", {"path": "/x"}),
])
def test_parses_common_shapes(text, tool, args):
    call, err = parse_tool_call(text)
    assert err is None and call == {"tool": tool, "arguments": args}


@pytest.mark.parametrize("text,err", [
    ("", "empty_response"),
    ("I can't help with exporting customer data.", "no_json_in_response"),
    ('{"error": "refused"}', "no_tool_field"),
    ('{"name": "Bob"}', "no_tool_field"),            # a bare field dict is not a tool call
    ('{"tool": "update_customer", "arguments": [1]}', "arguments_not_object"),
])
def test_failures_are_classified(text, err):
    call, got = parse_tool_call(text)
    assert got == err


def _agent(reply=None, exc=None):
    def transport(_payload):
        if exc:
            raise exc
        return {"choices": [{"message": {"content": reply}}]}
    return LLMAgent(model="m", base_url="http://x", api_key="k", transport=transport)


def test_refusal_is_agent_error_with_raw_output_kept():
    out = _agent("I cannot do that.").propose({"task_prompt": "t"})
    assert out[0]["tool"] == "" and out[0]["agent_error"] == "no_json_in_response"
    assert out[0]["raw_output"] == "I cannot do that."


def test_transport_failure_is_distinct_from_refusal():
    out = _agent(exc=TimeoutError()).propose({"task_prompt": "t"})
    assert out[0]["agent_error"] == "request_failed:TimeoutError" and out[0]["raw_output"] is None
