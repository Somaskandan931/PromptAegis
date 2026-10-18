"""Run reviewed user-task prompts through an LLM and the sandboxed gateway.

The JSONL input must contain independently authored natural-language tasks; it
must not be generated from expected tool calls. Only the model's proposed call
is executed, and only through ProtectedRuntime. Development mode is intended
until prompt labels and expected outcomes are independently reviewed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
sys.path[:0] = [str(ROOT), str(BACKEND)]

from database.environments import environment_scope  # noqa: E402
from experiments.study.env import ENV_ID, build  # noqa: E402
from experiments.study.run_benchmark import _task_success  # noqa: E402
from governance.audit_chain import AuditChain, verify_chain  # noqa: E402
from governance.gateway import Gateway  # noqa: E402
from sandbox.agent import LLMAgent  # noqa: E402
from sandbox.runtime import ProtectedRuntime  # noqa: E402
from sandbox.world import SandboxWorld  # noqa: E402

RESULTS = ROOT / "results/study"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _agent_outcome(agent_error: str | None) -> str:
    """Classify what the model did, independently of any gateway decision."""
    if agent_error is None:
        return "tool_call"
    if agent_error.startswith("request_failed"):
        return "request_failed"
    return "no_tool_call"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on {path}:{line_no}: {exc}") from exc
        required = {"task_id", "group_id", "task_prompt", "principal", "context", "label"}
        missing = required - row.keys()
        if missing:
            raise ValueError(f"{path}:{line_no} missing fields: {sorted(missing)}")
        if row["label"] not in {"attack", "benign"}:
            raise ValueError(f"{path}:{line_no} label must be attack or benign")
        if not isinstance(row["task_prompt"], str) or not row["task_prompt"].strip():
            raise ValueError(f"{path}:{line_no} task_prompt must be nonempty text")
        if any(x["task_id"] == row["task_id"] for x in rows):
            raise ValueError(f"Duplicate task_id {row['task_id']!r}")
        rows.append(row)
    if not rows:
        raise ValueError("No task rows found")
    return rows


def run(manifest_path: Path, *, provider: str, model: str, configuration: str,
        temperature: float, seed: int, max_tasks: int | None) -> Path:
    tasks = load_jsonl(manifest_path)
    if max_tasks is not None:
        tasks = tasks[:max_tasks]
    if provider == "groq":
        base_url = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
        api_key = os.environ.get("GROQ_API_KEY", "")
        if not api_key:
            raise RuntimeError("Set GROQ_API_KEY in the shell environment; never place it in the manifest.")
    else:
        base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        # Ollama's OpenAI-compatible local endpoint does not require a secret.
        api_key = "ollama-local"
    agent = LLMAgent(model=model, base_url=base_url, temperature=temperature, seed=seed,
                     api_key=api_key)
    run_id = f"llm_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}_{uuid.uuid4().hex[:8]}"
    RESULTS.mkdir(parents=True, exist_ok=True)
    audit_dir = RESULTS / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    chain_path = audit_dir / f"{run_id}.jsonl"
    chain = AuditChain(str(chain_path))
    env = build()
    events = []
    try:
        gateway = Gateway(configuration=configuration, chain=chain)
        for row in tasks:
            env.reset_runtime_state()
            principal = row["principal"]
            agent_id = env.agent_ids.get(principal)
            if not agent_id:
                raise ValueError(f"Unknown principal in task {row['task_id']}: {principal}")
            world = SandboxWorld.fresh()
            runtime = ProtectedRuntime(gateway=gateway, world=world)
            scenario = {"task_prompt": row["task_prompt"],
                        "untrusted_content": row.get("untrusted_content", "")}
            model_started = time.perf_counter()
            proposed = agent.propose(scenario)
            model_latency_ms = (time.perf_counter() - model_started) * 1000
            calls = []
            agent_error = None
            raw_model_output = proposed[0].get("raw_output") if proposed else None
            for i, call in enumerate(proposed, start=1):
                if call.get("agent_error"):
                    # The model produced no usable tool call (refusal, prose, bad JSON,
                    # or a transport failure). That is an AGENT outcome, not a gateway
                    # decision, so it is recorded here and never submitted to the gateway.
                    agent_error = call["agent_error"]
                    continue
                corr = f"{run_id}:{row['task_id']}:{i}"
                with environment_scope(ENV_ID):
                    rec = runtime.call(agent_id, str(call.get("tool", "")),
                                       call.get("arguments", {}) if isinstance(call.get("arguments", {}), dict) else {},
                                       scenario_id=row["task_id"], seq=i, context=row["context"],
                                       run_id=run_id, correlation_id=corr).as_dict()
                calls.append(rec)
            events.append({
                "task_id": row["task_id"], "group_id": row["group_id"], "label": row["label"],
                "principal": principal, "category": row.get("category"),
                "task_check": row.get("task_check"), "expected_effect": row.get("expected_effect"),
                "untrusted_content_present": bool(row.get("untrusted_content")),
                "agent_outcome": _agent_outcome(agent_error),
                "agent_error": agent_error,
                "raw_model_output": raw_model_output,
                "calls": calls, "model_latency_ms": round(model_latency_ms, 3),
                "task_success": _task_success(row.get("task_check"), world, calls),
                "unsafe_effect": any(c["unsafe_effect_types"] for c in calls),
                "audit_complete": all(c["audited"] for c in calls),
            })
    finally:
        env.close()
    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                  text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                                    capture_output=True, text=True, check=True).stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        revision, dirty = None, None
    out = RESULTS / f"{run_id}.json"
    result = {
        "study": "PromptAegis closed-loop LLM sandbox pilot", "run_id": run_id,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "provider": provider, "model": model, "base_url": base_url,
        "temperature": temperature, "seed": seed, "configuration": configuration,
        "agent_config": agent.config_record(), "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": sha256(manifest_path), "scenario_count": len(events),
        "git_revision": revision, "git_worktree_dirty": dirty,
        "execution_mode": "model proposals executed only through sandbox ProtectedRuntime",
        "confirmatory": False, "interpretation": "Pilot only unless prompts and labels have independent review.",
        # Gateway decisions only: tasks where the model produced no tool call never reach the gateway.
        "decision_counts": dict(Counter(c["decision"] for e in events for c in e["calls"])),
        "agent_outcome_counts": dict(Counter(e["agent_outcome"] for e in events)),
        "agent_outcome_by_label": {lab: dict(Counter(e["agent_outcome"] for e in events if e["label"] == lab))
                                   for lab in sorted({e["label"] for e in events})},
        "agent_error_counts": dict(Counter(e["agent_error"] for e in events if e["agent_error"])),
        "audit_chain": str(chain_path.relative_to(ROOT)).replace("\\", "/"),
        "audit_chain_valid": verify_chain(chain.entries())[0], "audit_chain_head_sha256": chain.head,
        "events": events,
    }
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"[OK] wrote {out.relative_to(ROOT)} ({len(events)} tasks; provider={provider}, model={model})")
    print(f"[INFO] gateway decisions: {result['decision_counts']}")
    print(f"[INFO] agent outcomes by label: {result['agent_outcome_by_label']}")
    failed = [e for e in events if e["agent_outcome"] != "tool_call"]
    if failed:
        print(f"[WARN] {len(failed)}/{len(events)} tasks produced no tool call "
              f"({result['agent_error_counts']}). They were NOT sent to the gateway and are NOT "
              "counted as governance denials; inspect 'raw_model_output' in the result file.")
    if any(e["agent_outcome"] == "request_failed" for e in events):
        print("[WARN] Some model requests failed (endpoint down, model not pulled, or timeout); "
              "re-run those before drawing any conclusion.")
    print("[INFO] Pilot output is not confirmatory until prompts and labels are independently reviewed.")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="Reviewed JSONL task manifest")
    parser.add_argument("--provider", choices=("ollama", "groq"), default="ollama")
    parser.add_argument("--model", default="llama3.1:8b", help="Ollama tag or Groq model ID")
    parser.add_argument("--configuration", choices=("baseline", "rbac_only", "policy_only", "full"), default="full")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--max-tasks", type=int)
    args = parser.parse_args()
    run(args.manifest.resolve(), provider=args.provider, model=args.model,
        configuration=args.configuration, temperature=args.temperature,
        seed=args.seed, max_tasks=args.max_tasks)


if __name__ == "__main__":
    main()
