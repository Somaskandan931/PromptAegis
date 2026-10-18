"""Regenerates every figure of the manuscript from the result JSON files.
Usage:  python make_figures.py  <ablation_run.json>  <pilot_full.json>
"""
import json, sys, collections
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

abl = json.load(open(sys.argv[1]))
pilot = json.load(open(sys.argv[2]))
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.spines.top": False, "axes.spines.right": False})

ORDER = ["baseline","rbac_only","policy_only","schema_only","rbac_schema","rbac_policy",
         "full","full_minus_rbac","full_minus_schema","full_minus_policy","full_minus_rate","full_minus_approval"]
LABEL = {"baseline":"Baseline","rbac_only":"RBAC","policy_only":"Policy","schema_only":"Schema",
         "rbac_schema":"RBAC+Schema","rbac_policy":"RBAC+Policy","full":"Full",
         "full_minus_rbac":"Full\u2212RBAC","full_minus_schema":"Full\u2212Schema",
         "full_minus_policy":"Full\u2212Policy","full_minus_rate":"Full\u2212Rate","full_minus_approval":"Full\u2212Approval"}
C = abl["configurations"]

# ---------- Figure 2: ablation ----------
fig, ax = plt.subplots(1, 2, figsize=(7.2, 2.9), sharey=True)
y = np.arange(len(ORDER))[::-1]
acc = [C[k]["decision_exact_accuracy"]*100 for k in ORDER]
uns = [C[k]["unsafe_effect_scenarios"] for k in ORDER]
col = ["#8c8c8c"]*1 + ["#4c78a8"]*5 + ["#2a9d8f"] + ["#e9a23b"]*5
ax[0].barh(y, acc, color=col); ax[0].set_xlim(0,112); ax[0].set_xlabel("Exact decision agreement (%)")
ax[1].barh(y, uns, color=col); ax[1].set_xlim(0,34); ax[1].set_xlabel("Unsafe-effect scenarios (of 100)")
for a,vals,fmt in ((ax[0],acc,"{:.0f}"),(ax[1],uns,"{:d}")):
    for yi,v in zip(y,vals): a.text(v+(1 if a is ax[0] else .4), yi, fmt.format(v), va="center", fontsize=7)
ax[0].set_yticks(y); ax[0].set_yticklabels([LABEL[k] for k in ORDER])
fig.tight_layout(); fig.savefig("figures/fig_ablation.pdf"); plt.close(fig)

# ---------- Figure 3: per-category heatmap ----------
cats = ["legitimate","negative_control","unauthorized_tool","prompt_injection","privilege_escalation",
        "parameter_manipulation","context_sensitive","approval_required","rate_limit"]
CL = {"legitimate":"Legitimate (30)","negative_control":"Negative control (9)","unauthorized_tool":"Unauthorized tool (6)",
      "prompt_injection":"Injection-labelled (6)","privilege_escalation":"Privilege escalation (6)",
      "parameter_manipulation":"Parameter manipulation (23)","context_sensitive":"Context-sensitive (8)",
      "approval_required":"Approval-required (6)","rate_limit":"Rate-limit (6)"}
M = np.zeros((len(cats), len(ORDER)))
for j,k in enumerate(ORDER):
    t = collections.defaultdict(lambda:[0,0])
    for s in C[k]["scenarios"]:
        if s["scope"]!="in_scope": continue
        t[s["category"]][0]+=1; t[s["category"]][1]+=s["decision_exact_match"]
    for i,c in enumerate(cats): M[i,j] = 100*t[c][1]/t[c][0]
fig, ax = plt.subplots(figsize=(7.2, 3.3))
im = ax.imshow(M, cmap="YlGnBu", vmin=0, vmax=100, aspect="auto")
ax.set_xticks(range(len(ORDER))); ax.set_xticklabels([LABEL[k] for k in ORDER], rotation=40, ha="right")
ax.set_yticks(range(len(cats))); ax.set_yticklabels([CL[c] for c in cats])
for i in range(len(cats)):
    for j in range(len(ORDER)):
        ax.text(j,i,f"{M[i,j]:.0f}",ha="center",va="center",fontsize=6.5,color="white" if M[i,j]>60 else "black")
for s in ax.spines.values(): s.set_visible(False)
cb = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.01); cb.set_label("Exact agreement (%)")
fig.tight_layout(); fig.savefig("figures/fig_category_heatmap.pdf"); plt.close(fig)

# Figure 1 (architecture) is produced by make_architecture_figure.py

# ---------- Figure 4: pilot flow ----------
ev = pilot["events"]; ben=[e for e in ev if e["label"]=="benign"]; att=[e for e in ev if e["label"]!="benign"]
nb=len(ben); na=len(att)
b_call=sum(e["agent_outcome"]=="tool_call" for e in ben)
a_call=sum(e["agent_outcome"]=="tool_call" for e in att); a_nocall=na-a_call
fig, ax = plt.subplots(figsize=(7.2, 2.6)); ax.set_xlim(0,100); ax.set_ylim(-2,32); ax.axis("off")
def b2(x,y,w,h,t,fc): 
    ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle="round,pad=0.25,rounding_size=1",fc=fc,ec="#444",lw=0.9)); ax.text(x+w/2,y+h/2,t,ha="center",va="center",fontsize=6.8)
b2(1,12,14,8,f"{nb+na} pilot tasks\n(llama3.1:8b, T=0)","#f2f2f2")
b2(21,22,16,8,f"{nb} benign","#dbe9f6"); b2(21,2,16,8,f"{na} injected-content","#fde8d0")
b2(44,22,16,8,f"{b_call}/{nb} tool call\n(gateway reached)","#dbe9f6")
b2(44,10.5,17,8,f"{a_call}/{na} tool call\n(gateway reached)","#fde8d0"); b2(44,-0.5,17,8,f"{a_nocall}/{na} prose reply\n(gateway NOT reached)","#e8e8e8")
ben_allowed=sum(e["calls"][0]["decision"]=="ALLOW" for e in ben if e["calls"])
b2(70,22,27,8,f"{ben_allowed} ALLOW; {sum(bool(e['task_success']) for e in ben)}/{nb} task checks pass","#d9f0e3")
den=sum(e["calls"][0]["decision"]!="ALLOW" for e in att if e["calls"])
b2(70,10.5,27,8,f"{den} Denied at schema stage\n(invalid ID format)\n0 unsafe effects","#d9f0e3")
b2(70,-0.5,27,8,"No action; user task also\nleft uncompleted (0/6 ok)","#f7f0d4")
for (x1,y1,x2,y2) in [(15.3,17,20.7,24),(15.3,15,20.7,8),(37.3,26,43.7,26),(37.3,8,43.7,13.5),(37.3,6,43.7,3.5),(60.3,26,69.7,26),(61.3,14.5,69.7,14.5),(61.3,3.5,69.7,3.5)]:
    ax.add_patch(FancyArrowPatch((x1,y1),(x2,y2),arrowstyle="-|>",mutation_scale=7,lw=0.8,color="#444"))
fig.tight_layout(); fig.savefig("figures/fig_pilot_flow.pdf"); plt.close(fig)
print("figures written")
