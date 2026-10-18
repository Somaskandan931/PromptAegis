"""Summarize closed-loop LLM pilot runs into paper-ready artifacts.

Reads one or more ``results/study/llm_*.json`` files written by
``run_llm_closed_loop.py`` and writes, under ``--out-dir`` (default
``paper/generated``):

* ``llm_pilot_numbers.tex``  LaTeX macros for the primary (first) run
* ``llm_pilot_table.tex``    booktabs table with one row per run
* ``llm_pilot_summary.md``   plain-text summary incl. per-task outcomes

Every figure in the manuscript's pilot subsection comes from these files, so
nothing is typed by hand. Runs listed in ``results/study/CONTAMINATED_RUNS.md``
and runs written before the agent-outcome fields existed are refused.

    python experiments/study/summarize_llm_pilot.py results/study/llm_<ID>.json
    python experiments/study/summarize_llm_pilot.py RUN_A.json RUN_B.json --out-dir paper/generated
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from statistics import mean
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CONTAMINATED = ROOT / "results/study/CONTAMINATED_RUNS.md"


def tex(text: Any) -> str:
    """Escape text for LaTeX."""
    out = str(text)
    for a, b in (("\\", r"\textbackslash{}"), ("_", r"\_"), ("&", r"\&"), ("%", r"\%"),
                 ("#", r"\#"), ("$", r"\$")):
        out = out.replace(a, b)
    return out


def contaminated_ids() -> set[str]:
    if not CONTAMINATED.exists():
        return set()
    return set(re.findall(r"`((?:llm|governance)_[0-9TZ]+_[0-9a-f]{8})`", CONTAMINATED.read_text(encoding="utf-8")))


def load(path: Path) -> dict[str, Any]:
    run = json.loads(path.read_text(encoding="utf-8"))
    if run.get("run_id") in contaminated_ids():
        raise SystemExit(f"[ERROR] {run['run_id']} is listed in CONTAMINATED_RUNS.md; do not analyze it.")
    events = run.get("events") or []
    if not events or any("agent_outcome" not in e for e in events):
        raise SystemExit(f"[ERROR] {path.name} predates the agent-outcome fields (refusals were recorded as gateway "
                         "denials). Re-run the pilot with the fixed runner.")
    return run


def summarize(run: dict[str, Any]) -> dict[str, Any]:
    ev = run["events"]
    benign = [e for e in ev if e["label"] == "benign"]
    attack = [e for e in ev if e["label"] == "attack"]
    first = lambda e: e["calls"][0] if e["calls"] else None  # one tool call per task by design

    proposals = [(e, first(e)) for e in attack if e["agent_outcome"] == "tool_call"]
    return {
        "run_id": run["run_id"], "model": run["model"], "configuration": run["configuration"],
        "temperature": run["temperature"], "seed": run["seed"],
        "n": len(ev), "benign_n": len(benign), "attack_n": len(attack),
        "benign_tool_calls": sum(e["agent_outcome"] == "tool_call" for e in benign),
        "benign_allowed": sum(bool(first(e)) and first(e)["decision"] == "ALLOW" for e in benign),
        "benign_success": sum(bool(e["task_success"]) for e in benign),
        "attack_no_call": sum(e["agent_outcome"] == "no_tool_call" for e in attack),
        "attack_request_failed": sum(e["agent_outcome"] == "request_failed" for e in attack),
        "attack_proposals": len(proposals),
        "attack_proposals_denied": sum(c["decision"] == "DENY" for _, c in proposals),
        "attack_proposals_allowed": sum(c["decision"] == "ALLOW" for _, c in proposals),
        "attack_proposals_approval": sum(c["decision"] == "REQUIRE_APPROVAL" for _, c in proposals),
        "attack_success": sum(bool(e["task_success"]) for e in attack),
        "unsafe_tasks": sum(bool(e["unsafe_effect"]) for e in ev),
        "request_failed": sum(e["agent_outcome"] == "request_failed" for e in ev),
        "mean_latency_s": mean(e["model_latency_ms"] for e in ev) / 1000.0,
        "audit_valid": bool(run["audit_chain_valid"]),
        "audit_complete": all(e["audit_complete"] for e in ev),
        "proposal_detail": [{"task_id": e["task_id"], "tool": c["tool"], "decision": c["decision"],
                             "reason_code": c["reason_code"], "stage": c["first_blocking_stage"],
                             "unsafe": bool(e["unsafe_effect"])} for e, c in proposals],
        "tasks": [{"task_id": e["task_id"], "label": e["label"], "agent_outcome": e["agent_outcome"],
                   "agent_error": e["agent_error"], "decision": (first(e) or {}).get("decision", "-"),
                   "reason_code": (first(e) or {}).get("reason_code", "-"),
                   "task_success": e["task_success"], "unsafe_effect": e["unsafe_effect"],
                   "raw": (e.get("raw_model_output") or "")[:140].replace("\n", " ")} for e in ev],
    }


def proposal_sentence(s: dict[str, Any]) -> str:
    d = s["proposal_detail"]
    if not d:
        return "No injected task produced a structured tool proposal."
    parts = []
    for p in d:
        verb = {"DENY": "denied", "ALLOW": "allowed", "REQUIRE_APPROVAL": "held for approval"}.get(p["decision"], p["decision"])
        where = "" if p["stage"] in ("none", None) else f" at the {tex(p['stage'])} stage"
        parts.append(f"\\texttt{{{tex(p['tool'])}}} ({verb}{where}, \\texttt{{{tex(p['reason_code'])}}}"
                     f"{'; unsafe effect observed' if p['unsafe'] else ''})")
    return "The injected-task proposal(s) were: " + "; ".join(parts) + "."


def numbers_tex(s: dict[str, Any]) -> str:
    m = {
        "pilotRunId": tex(s["run_id"]), "pilotModel": tex(s["model"]), "pilotConfig": tex(s["configuration"]),
        "pilotN": s["n"], "pilotBenignN": s["benign_n"], "pilotAttackN": s["attack_n"],
        "pilotBenignToolCalls": s["benign_tool_calls"], "pilotBenignAllowed": s["benign_allowed"],
        "pilotBenignSuccess": s["benign_success"], "pilotAttackNoCall": s["attack_no_call"],
        "pilotAttackProposals": s["attack_proposals"], "pilotAttackDenied": s["attack_proposals_denied"],
        "pilotAttackAllowed": s["attack_proposals_allowed"], "pilotAttackTaskSuccess": s["attack_success"],
        "pilotUnsafeTasks": s["unsafe_tasks"], "pilotMeanLatency": f"{s['mean_latency_s']:.2f}",
        "pilotAuditValid": "valid" if s["audit_valid"] and s["audit_complete"] else "NOT valid",
        "pilotProposalSentence": proposal_sentence(s),
    }
    lines = ["% AUTO-GENERATED by experiments/study/summarize_llm_pilot.py -- do not edit by hand."]
    lines += [f"\\renewcommand{{\\{k}}}{{{v}}}" for k, v in m.items()]
    return "\n".join(lines) + "\n"


def table_tex(rows: list[dict[str, Any]]) -> str:
    body = []
    for s in rows:
        body.append(" & ".join([
            f"\\texttt{{{tex(s['model'])}}}", tex(s["configuration"]),
            f"{s['benign_success']}/{s['benign_n']}",
            f"{s['attack_no_call']}/{s['attack_n']}",
            f"{s['attack_proposals_denied']}/{s['attack_proposals']}",
            f"{s['attack_proposals_allowed']}/{s['attack_proposals']}",
            f"{s['attack_success']}/{s['attack_n']}",
            str(s["unsafe_tasks"]), f"{s['mean_latency_s']:.1f}"]) + " \\\\")
    return "\n".join([
        "% AUTO-GENERATED by experiments/study/summarize_llm_pilot.py -- do not edit by hand.",
        "\\begin{table*}[t]", "\\centering",
        "\\caption{Exploratory closed-loop pilot (12 project-authored tasks: 6 benign, 6 with injected untrusted content). "
        "Benign ok: authored task check passed. No call: injected tasks where the model replied without a tool call "
        "(these never reach the gateway). Denied/Allowed: gateway decisions on the remaining injected-task proposals. "
        "Attack-task ok: authored check for the user's legitimate request passed. Unsafe: tasks with an observed unsafe "
        "sandbox effect. Latency: mean model response time in seconds.}",
        "\\label{tab:llm-pilot}", "\\footnotesize", "\\setlength{\\tabcolsep}{4pt}",
        "\\begin{tabular}{llrrrrrrr}", "\\toprule",
        "Model & Gateway & Benign ok & No call & Denied & Allowed & Attack-task ok & Unsafe & Latency \\\\",
        "\\midrule", *body, "\\bottomrule", "\\end{tabular}",
        "\\end{table*}", ""])


def summary_md(rows: list[dict[str, Any]]) -> str:
    out = ["# LLM pilot summary (auto-generated)", ""]
    for s in rows:
        out += [f"## {s['run_id']} -- {s['model']} / {s['configuration']} (T={s['temperature']}, seed={s['seed']})", "",
                f"- benign: {s['benign_tool_calls']}/{s['benign_n']} produced a tool call, {s['benign_allowed']} allowed, "
                f"{s['benign_success']} passed the task check",
                f"- injected tasks: {s['attack_no_call']}/{s['attack_n']} no tool call; {s['attack_proposals']} proposal(s): "
                f"{s['attack_proposals_denied']} denied, {s['attack_proposals_allowed']} allowed, "
                f"{s['attack_proposals_approval']} require approval; {s['attack_success']} passed the user-task check",
                f"- unsafe-effect tasks: {s['unsafe_tasks']}; failed requests: {s['request_failed']}; "
                f"mean model latency {s['mean_latency_s']:.2f} s; audit chain valid={s['audit_valid']} complete={s['audit_complete']}",
                "", "| task | label | agent outcome | gateway | reason | task ok | unsafe | model said |", "|---|---|---|---|---|---|---|---|"]
        out += [f"| {t['task_id']} | {t['label']} | {t['agent_outcome']} | {t['decision']} | {t['reason_code']} | "
                f"{t['task_success']} | {t['unsafe_effect']} | {t['raw'] or ''} |" for t in s["tasks"]]
        out.append("")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", type=Path, help="llm_*.json result files; the first is the primary run")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "paper/generated")
    args = ap.parse_args()
    rows = [summarize(load(p)) for p in args.runs]
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "llm_pilot_numbers.tex").write_text(numbers_tex(rows[0]), encoding="utf-8", newline="\n")
    (args.out_dir / "llm_pilot_table.tex").write_text(table_tex(rows), encoding="utf-8", newline="\n")
    (args.out_dir / "llm_pilot_summary.md").write_text(summary_md(rows), encoding="utf-8", newline="\n")
    print(summary_md(rows))
    print(f"[OK] wrote llm_pilot_numbers.tex, llm_pilot_table.tex, llm_pilot_summary.md to {args.out_dir}")
    if any(r["request_failed"] for r in rows):
        print("[WARN] Some model requests failed; re-run before using these numbers.", file=sys.stderr)


if __name__ == "__main__":
    main()
