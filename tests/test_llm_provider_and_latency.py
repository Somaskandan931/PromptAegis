"""Provider selection for the demo chat client (Ollama default) and the latency protocol script.

No network access and no model is used: the HTTP layer is replaced by a fake.
"""
from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
for path in (ROOT, BACKEND):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import config  # noqa: E402
from core import llm_client  # noqa: E402
from core.llm_client import LLMConfigurationError, LLMMessage  # noqa: E402


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _payload(text: str) -> _FakeResponse:
    return _FakeResponse(json.dumps({"choices": [{"message": {"content": text}}]}).encode())


def test_default_provider_is_ollama_and_needs_no_key():
    assert config.LLM_PROVIDER == "ollama"
    assert config.OLLAMA_MODEL == "llama3.1:8b"


def test_call_ollama_sends_no_authorization_header_and_parses_reply(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["headers"] = {k.lower(): v for k, v in req.header_items()}
        seen["body"] = json.loads(req.data.decode())
        return _payload("hello from ollama")

    monkeypatch.setattr(llm_client.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(config, "LLM_PROVIDER", "ollama")
    result = llm_client.call_llm([LLMMessage("user", "hi")])
    assert (result.provider, result.text) == ("ollama", "hello from ollama")
    assert seen["url"].endswith("/chat/completions")
    assert "authorization" not in seen["headers"]
    assert seen["body"]["model"] == config.OLLAMA_MODEL and seen["body"]["stream"] is False


def test_unreachable_ollama_reports_a_configuration_error_with_the_fix(monkeypatch):
    def refuse(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(llm_client.urllib.request, "urlopen", refuse)
    with pytest.raises(LLMConfigurationError) as info:
        llm_client.call_ollama([LLMMessage("user", "hi")])
    assert "ollama serve" in str(info.value) and "ollama pull" in str(info.value)


def test_groq_is_optional_and_still_requires_its_key(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "groq")
    monkeypatch.setattr(config, "GROQ_API_KEY", "")
    with pytest.raises(LLMConfigurationError):
        llm_client.call_llm([LLMMessage("user", "hi")])


def test_example_env_file_holds_no_secret_and_defaults_to_ollama():
    text = (BACKEND / ".env.example").read_text(encoding="utf-8")
    assert "LLM_PROVIDER=ollama" in text
    assert "GROQ_API_KEY=\n" in text + "\n"


def test_latency_protocol_records_raw_timings_and_randomised_order(tmp_path, monkeypatch):
    from experiments.study import run_latency_protocol as lp

    monkeypatch.setattr(lp, "RESULT_DIR", tmp_path)
    out = lp.run("dev", ["baseline", "full"], warmup=0, repetitions=2, seed=3)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["protocol"]["repetitions"] == 2 and data["protocol"]["fresh_database_per_block"] is True
    assert len(data["protocol"]["configuration_order_per_repetition"]) == 2
    assert set(data["raw_timings"]) == {"baseline", "full"}
    sample = next(iter(data["raw_timings"]["full"].values()))
    assert len(sample) == 2 and {"gateway_decision_ms", "decision_plus_audit_ms", "runtime_call_wall_ms"} <= set(sample[0])
    assert "full" in data["paired_vs_baseline"]
    # the decision alone can never take longer than the whole runtime call
    for calls in data["raw_timings"]["full"].values():
        assert all(c["gateway_decision_ms"] <= c["runtime_call_wall_ms"] + 1e-6 for c in calls)
