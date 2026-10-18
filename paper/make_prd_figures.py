"""Figures and metrics that the research proposal (PRD sections 6, 19, 24, 28) asks for.

Usage (from the paper/ directory):
    python make_prd_figures.py <ablation_run.json> <original_4config_run.json>

  ablation_run.json   12-configuration re-execution (run 2a97d190)
  original_run.json   4-configuration run cited for latency (run 056a4792)

Writes
  figures/fig_security_utility.pdf   ASR, benign false-block and executed-call count
  figures/fig_stage_attribution.pdf  first blocking stage per category (full gateway)
  figures/fig_rate_limit.pdf         per-call ALLOW fraction in rate-limit sequences
  figures/fig_latency.pdf            per-call latency distributions, two runs
  generated/prd_metrics.json         every number plotted or tabulated
  generated/prd_metrics_table.tex    LaTeX table of the PRD metrics

Every number is computed from the stored result JSON; nothing is typed in.
"""
import json
import os
import sys
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

abl = json.load(open(sys.argv[1]))
orig = json.load(open(sys.argv[2]))
os.makedirs("figures", exist_ok=True)
os.makedirs("generated", exist_ok=True)
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8,
                     "axes.spines.top": False, "axes.spines.right": False})

ORDER = ["baseline", "rbac_only", "policy_only", "schema_only", "rbac_schema", "rbac_policy",
         "full", "full_minus_rbac", "full_minus_schema", "full_minus_policy",
         "full_minus_rate", "full_minus_approval"]
LABEL = {"baseline": "Baseline", "rbac_only": "RBAC", "policy_only": "Policy", "schema_only": "Schema",
         "rbac_schema": "RBAC+Schema", "rbac_policy": "RBAC+Policy", "full": "Full",
         "full_minus_rbac": "Full\u2212RBAC", "full_minus_schema": "Full\u2212Schema",
         "full_minus_policy": "Full\u2212Policy", "full_minus_rate": "Full\u2212Rate",
         "full_minus_approval": "Full\u2212Approval"}
COL = ["#8c8c8c"] + ["#4c78a8"] * 5 + ["#2a9d8f"] + ["#e9a23b"] * 5
BENIGN = {"legitimate", "negative_control"}
ATTACK = {"unauthorized_tool", "prompt_injection", "privilege_escalation",
          "parameter_manipulation", "context_sensitive"}
C = abl["configurations"]


def in_scope(cfg):
    return [s for s in cfg["scenarios"] if s["scope"] == "in_scope"]


# ------------------------------------------------------------------ metrics
M = {}
for k in ORDER:
    sc = in_scope(C[k])
    calls = [r for s in sc for r in s["records"]]
    atk = [s for s in sc if s["category"] in ATTACK]
    apr = [s for s in sc if s["category"] == "approval_required"]
    ben = [s for s in sc if s["category"] in BENIGN]
    lat = np.array([r["total_latency_ms"] for r in calls])
    M[k] = {
        "attack_scenarios": len(atk),
        "asr_unsafe": sum(s["unsafe_effect"] for s in atk),
        "approval_scenarios": len(apr),
        "approval_bypass_unsafe": sum(s["unsafe_effect"] for s in apr),
        "benign_scenarios": len(ben),
        "benign_false_block": sum(any(r["decision"] != "ALLOW" for r in s["records"]) for s in ben),
        "task_checks": sum(1 for s in sc if s["task_check_applicable"]),
        "task_checks_passed": sum(1 for s in sc if s["task_check_applicable"] and s["task_success"]),
        "calls": len(calls),
        "executed_calls": sum(r["executed"] for r in calls),
        "latency_ms": {"median": float(np.percentile(lat, 50)), "p95": float(np.percentile(lat, 95)),
                       "p99": float(np.percentile(lat, 99)), "mean": float(lat.mean())},
    }
orig_lat = {}
for k in ["baseline", "rbac_only", "policy_only", "full"]:
    calls = [r for s in in_scope(orig["configurations"][k]) for r in s["records"]]
    orig_lat[k] = np.array([r["total_latency_ms"] for r in calls])
    M[k]["latency_original_run_ms"] = {"median": float(np.percentile(orig_lat[k], 50)),
                                       "p95": float(np.percentile(orig_lat[k], 95)),
                                       "p99": float(np.percentile(orig_lat[k], 99)),
                                       "mean": float(orig_lat[k].mean()), "n": int(len(orig_lat[k]))}
json.dump(M, open("generated/prd_metrics.json", "w"), indent=1)

# ---------------------------------------------------- Fig A: security vs utility
fig, ax = plt.subplots(1, 3, figsize=(7.2, 3.1), sharey=True)
y = np.arange(len(ORDER))[::-1]
asr = [100 * M[k]["asr_unsafe"] / M[k]["attack_scenarios"] for k in ORDER]
ax[0].barh(y, asr, color=COL)
ax[0].set_xlim(0, 70)
ax[0].set_xlabel("Attack-labelled scenarios with an unsafe\neffect, % (label: count; n=49)")
for yi, v, k in zip(y, asr, ORDER):
    ax[0].text(v + 1, yi, f"{M[k]['asr_unsafe']}", va="center", fontsize=7)
fb = [M[k]["benign_false_block"] for k in ORDER]
tp = [100 * M[k]["task_checks_passed"] / M[k]["task_checks"] for k in ORDER]
ax[1].barh(y, [100 - 0 * v for v in tp], color="#d9d9d9", height=0.62)
ax[1].barh(y, tp, color="#2a9d8f", height=0.62)
ax[1].set_xlim(0, 150)
ax[1].set_xlabel("Task checks passed (%; n=43);\nlabel: benign scenarios blocked (of 39)")
for yi, v, f in zip(y, tp, fb):
    ax[1].text(103, yi, f"{v:.0f}%;  {f}/39 blocked", va="center", fontsize=6.5)
ex = [M[k]["executed_calls"] for k in ORDER]
tot = M["baseline"]["calls"]
ax[2].barh(y, ex, color=COL)
ax[2].set_xlim(0, 300)
ax[2].set_xlabel(f"Calls reaching a sandbox tool\n(of {tot} proposed)")
for yi, v in zip(y, ex):
    ax[2].text(v + 4, yi, str(v), va="center", fontsize=7)
ax[0].set_yticks(y)
ax[0].set_yticklabels([LABEL[k] for k in ORDER])
fig.tight_layout()
fig.savefig("figures/fig_security_utility.pdf")
plt.close(fig)

# ---------------------------------------- Fig B: first blocking stage (full)
cats = ["legitimate", "negative_control", "unauthorized_tool", "prompt_injection",
        "privilege_escalation", "parameter_manipulation", "context_sensitive",
        "approval_required", "rate_limit"]
CL = {"legitimate": "Legitimate", "negative_control": "Negative control",
      "unauthorized_tool": "Unauthorized tool", "prompt_injection": "Injection-labelled",
      "privilege_escalation": "Privilege escalation", "parameter_manipulation": "Parameter manipulation",
      "context_sensitive": "Context-sensitive", "approval_required": "Approval-required",
      "rate_limit": "Rate-limit sequences"}
STAGES = ["none", "rbac", "schema", "policy", "rate", "approval"]
SL = {"none": "Passed (ALLOW)", "rbac": "RBAC", "schema": "Schema", "policy": "Policy",
      "rate": "Rate limit", "approval": "Approval"}
SC = {"none": "#cfe3d4", "rbac": "#4c78a8", "schema": "#e9a23b", "policy": "#b07aa1",
      "rate": "#e15759", "approval": "#76b7b2"}
tab = defaultdict(Counter)
for s in in_scope(C["full"]):
    for r in s["records"]:
        tab[s["category"]][r["first_blocking_stage"]] += 1
fig, ax = plt.subplots(figsize=(7.2, 3.0))
yy = np.arange(len(cats))[::-1]
left = np.zeros(len(cats))
for st in STAGES:
    vals = np.array([tab[c][st] for c in cats], dtype=float)
    ax.barh(yy, vals, left=left, color=SC[st], label=SL[st], edgecolor="white", lw=0.5)
    for yi, l, v in zip(yy, left, vals):
        if v >= 6:
            ax.text(l + v / 2, yi, f"{int(v)}", ha="center", va="center", fontsize=6.5)
    left += vals
ax.set_yticks(yy)
ax.set_yticklabels([CL[c] for c in cats])
ax.set_xlabel("Proposed calls (full gateway, in-scope development scenarios)")
ax.legend(frameon=False, ncol=6, fontsize=6.5, loc="lower center", bbox_to_anchor=(0.45, 1.0), columnspacing=1.0, handlelength=1.2)
fig.tight_layout()
fig.savefig("figures/fig_stage_attribution.pdf")
plt.close(fig)
M["_stage_attribution_full"] = {c: dict(tab[c]) for c in cats}

# ------------------------------------------------- Fig C: rate-limit effect
def cum_executed(cfg, group_suffix):
    """Cumulative calls reaching the tool along one burst sequence (all scenarios in the group agree)."""
    for s in in_scope(cfg):
        if s["category"] == "rate_limit" and s["group_id"].endswith(group_suffix):
            return np.cumsum([1 if r["executed"] else 0 for r in s["records"]]), s["scenario_id"]
    raise KeyError(group_suffix)


fig, ax = plt.subplots(1, 2, figsize=(7.2, 2.4))
for a, (suf, lim) in zip(ax, ((".L5", 5), (".L20", 20))):
    for k, c, ls in (("full", "#2a9d8f", "-"), ("full_minus_rate", "#e9a23b", "--")):
        cum, sid = cum_executed(C[k], suf)
        a.step(np.arange(1, len(cum) + 1), cum, where="post", color=c, ls=ls, lw=1.6, label=LABEL[k])
    a.axhline(lim, color="#999", lw=0.7, ls=":")
    a.set_title(f"Burst of {len(cum)} calls, limit {lim} per 60 s", fontsize=8)
    a.set_xlabel("Calls proposed in the window")
    a.set_ylabel("Cumulative calls executed")
ax[0].legend(frameon=False, fontsize=7, loc="upper left")
fig.tight_layout()
fig.savefig("figures/fig_rate_limit.pdf")
plt.close(fig)
M["_rate_limit_executed"] = {
    suf: {k: int(cum_executed(C[k], suf)[0][-1]) for k in ("full", "full_minus_rate")}
    for suf in (".L5", ".L20")}

# ---------------------------------------------------- Fig D: latency
prim = ["baseline", "rbac_only", "policy_only", "full"]
fig, ax = plt.subplots(1, 2, figsize=(7.2, 2.5), sharey=False)
ax[0].boxplot([orig_lat[k] for k in prim], tick_labels=[LABEL[k] for k in prim], showfliers=False,
              whis=(5, 95), patch_artist=True, boxprops=dict(facecolor="#dbe9f6"),
              medianprops=dict(color="#c0392b"))
ax[0].set_title("Original run (cited in the latency table)", fontsize=8)
ax[0].set_ylabel("Per-call time, gateway + tool (ms)")
re_lat = {k: np.array([r["total_latency_ms"] for s in in_scope(C[k]) for r in s["records"]]) for k in prim}
ax[1].boxplot([re_lat[k] for k in prim], tick_labels=[LABEL[k] for k in prim], showfliers=False,
              whis=(5, 95), patch_artist=True, boxprops=dict(facecolor="#fde8d0"),
              medianprops=dict(color="#c0392b"))
ax[1].set_title("Re-execution (12-configuration run)", fontsize=8)
for a in ax:
    a.grid(axis="y", alpha=0.25)
fig.tight_layout()
fig.savefig("figures/fig_latency.pdf")
plt.close(fig)

# ---------------------------------------------------- LaTeX table
rows = []
for k in ORDER:
    m = M[k]
    rows.append(f"{LABEL[k].replace(chr(0x2212), '$-$')} & {m['asr_unsafe']}/{m['attack_scenarios']} & "
                f"{m['approval_bypass_unsafe']}/{m['approval_scenarios']} & "
                f"{m['benign_false_block']}/{m['benign_scenarios']} & "
                f"{m['task_checks_passed']}/{m['task_checks']} & {m['executed_calls']} \\\\")
tex = ("\\begin{tabular}{lrrrrr}\n\\toprule\n"
       "Configuration & ASR & Appr.\\ bypass & False block & Tasks & Executed \\\\\n\\midrule\n"
       + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")
open("generated/prd_metrics_table.tex", "w").write(tex)
json.dump(M, open("generated/prd_metrics.json", "w"), indent=1)
print("PRD figures and metrics written")
