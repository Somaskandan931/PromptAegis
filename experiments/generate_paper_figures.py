"""Generate manuscript figures directly from a saved governance run."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = ROOT / "results" / "governance"
FIGURE_DIR = ROOT / "paper" / "figures"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, help="Result JSON; defaults to newest governance run")
    args = parser.parse_args()
    candidates = sorted(RESULT_DIR.glob("governance_benchmark_*.json"), key=lambda p: p.stat().st_mtime)
    path = args.result or (candidates[-1] if candidates else None)
    if path is None or not path.is_file():
        raise SystemExit("No governance result JSON found.")
    data = json.loads(path.read_text(encoding="utf-8"))
    order = ["baseline", "rbac_only", "policy_only", "full"]
    labels = ["Baseline", "RBAC-only", "Policy-only", "Full"]
    colors = ["#777777", "#4472C4", "#70AD47", "#C00000"]
    records = data["configurations"]
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.spines.top": False,
                         "axes.spines.right": False, "figure.dpi": 150})

    fig, ax = plt.subplots(figsize=(7.0, 3.6))
    x = np.arange(len(order))
    width = 0.34
    unsafe = [100 * records[c]["metrics"]["unsafe_tool_call_allow_rate"] for c in order]
    legitimate = [100 * records[c]["metrics"]["legitimate_request_allow_rate"] for c in order]
    ax.bar(x - width / 2, unsafe, width, label="Expected-unsafe calls allowed", color="#C00000")
    ax.bar(x + width / 2, legitimate, width, label="Expected-legitimate calls allowed", color="#4472C4")
    ax.set_ylabel("Calls receiving ALLOW (%)")
    ax.set_ylim(0, 112)
    ax.set_xticks(x, labels)
    ax.grid(axis="y", alpha=.22)
    ax.legend(frameon=False, ncols=1, loc="upper right")
    ax.set_title("Gateway decisions on the 600-case controlled replay")
    fig.tight_layout()
    fig.savefig(FIGURE_DIR / "governance_allow_rates.png", dpi=300, bbox_inches="tight")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7.0, 3.6))
    med = [records[c]["metrics"]["latency_median_ms"] for c in order]
    p95 = [records[c]["metrics"]["latency_p95_ms"] for c in order]
    ax.bar(x - width / 2, med, width, label="Median", color="#4472C4")
    ax.bar(x + width / 2, p95, width, label="95th percentile", color="#ED7D31")
    ax.set_ylabel("Gateway decision latency (ms)")
    ax.set_xticks(x, labels)
    ax.grid(axis="y", alpha=.22)
    ax.legend(frameon=False)
    ax.set_title("Local gateway latency; one replay per configuration")
    fig.tight_layout()
    fig.savefig(FIGURE_DIR / "governance_latency.png", dpi=300, bbox_inches="tight")
    plt.close(fig)

    full_events = records["full"]["events"]
    counts = {"SQL-like search query": 0, "Customer update": 0, "Other parameter case": 0}
    for event in full_events:
        if event["category"] != "parameter_manipulation" or event["expected_decision"] == "ALLOW" or event["actual_decision"] != "ALLOW":
            continue
        if event["tool_name"] == "search_customer":
            counts["SQL-like search query"] += 1
        elif event["tool_name"] == "update_customer":
            counts["Customer update"] += 1
        else:
            counts["Other parameter case"] += 1
    fig, ax = plt.subplots(figsize=(6.2, 3.4))
    bars = ax.bar(list(counts), list(counts.values()), color=["#C00000", "#ED7D31", "#A5A5A5"])
    ax.bar_label(bars, padding=3)
    ax.set_ylabel("Unsafe parameter cases receiving ALLOW (n)")
    ax.set_ylim(0, max(5, max(counts.values(), default=0) + 8))
    ax.grid(axis="y", alpha=.22)
    ax.set_title("Full-gateway parameter-manipulation misses")
    ax.tick_params(axis="x", labelrotation=12)
    fig.tight_layout()
    fig.savefig(FIGURE_DIR / "parameter_manipulation_misses.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"[OK] Generated three figures from {path}")


if __name__ == "__main__":
    main()
