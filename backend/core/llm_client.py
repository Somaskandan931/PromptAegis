"""
Downstream LLM client used by the Aegis chat surface.

The gateway decision happens before this module is called. This client is
deliberately small and stdlib-only so the demo does not need another SDK
install. The default provider is a local Ollama server (LLM_PROVIDER=ollama,
OLLAMA_MODEL, OLLAMA_BASE_URL); set LLM_PROVIDER=groq plus GROQ_API_KEY to use Groq.
"""
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import List

import config


class LLMConfigurationError(RuntimeError):
    pass


class LLMProviderError(RuntimeError):
    pass


@dataclass
class LLMMessage:
    role: str
    content: str


@dataclass
class LLMResult:
    provider: str
    model: str
    text: str


def _extract_text(payload: dict) -> str:
    choices = payload.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    return str(message.get("content") or "").strip()


def call_groq(messages: List[LLMMessage]) -> LLMResult:
    if not config.GROQ_API_KEY:
        raise LLMConfigurationError("GROQ_API_KEY is not configured.")

    url = config.GROQ_BASE_URL.rstrip("/") + "/chat/completions"
    body = {
        "model": config.GROQ_MODEL,
        "messages": [{"role": message.role, "content": message.content} for message in messages],
        "temperature": 0.4,
        "max_completion_tokens": 700,
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {config.GROQ_API_KEY}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Aegis-Gateway/0.1",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=config.LLM_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise LLMProviderError(f"Groq request failed ({exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise LLMProviderError(f"Groq request failed: {exc.reason}") from exc

    text = _extract_text(payload)
    if not text:
        raise LLMProviderError("Groq response did not contain output text.")

    return LLMResult(provider="groq", model=config.GROQ_MODEL, text=text)


def call_ollama(messages: List[LLMMessage]) -> LLMResult:
    """Call a local Ollama server through its OpenAI-compatible endpoint (no API key)."""
    url = config.OLLAMA_BASE_URL.rstrip("/") + "/chat/completions"
    body = {
        "model": config.OLLAMA_MODEL,
        "messages": [{"role": message.role, "content": message.content} for message in messages],
        "temperature": 0.4,
        "max_tokens": 700,
        "stream": False,
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "User-Agent": "Aegis-Gateway/0.1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=config.LLM_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise LLMProviderError(f"Ollama request failed ({exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise LLMConfigurationError(
            f"Ollama is not reachable at {config.OLLAMA_BASE_URL} ({exc.reason}). "
            f"Run `ollama serve` and `ollama pull {config.OLLAMA_MODEL}`."
        ) from exc

    text = _extract_text(payload)
    if not text:
        raise LLMProviderError("Ollama response did not contain output text.")
    return LLMResult(provider="ollama", model=config.OLLAMA_MODEL, text=text)


def call_llm(messages: List[LLMMessage]) -> LLMResult:
    """Dispatch to the configured provider (default: Ollama)."""
    if config.LLM_PROVIDER == "groq":
        return call_groq(messages)
    return call_ollama(messages)
