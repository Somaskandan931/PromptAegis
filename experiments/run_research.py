"""Canonical command-line entry point for the PromptAegis research project.

Examples (from the repository root)::

    python experiments/run_research.py benchmark --split dev
    python experiments/run_research.py analyze results/study/<RUN_ID>.json
    python experiments/run_research.py latency --repetitions 10 --warmup 2
    python experiments/run_research.py corpora --batch-size 256
    python experiments/run_research.py registry --ablation results/study/<RUN_ID>.json --pilot results/study/<LLM_RUN_ID>.json
    python experiments/run_research.py adversarial

The deterministic sandbox benchmark and prompt-corpus study are separate
protocols. There is no supported AgentDojo run path.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


COMMANDS = {
    "benchmark": Path("experiments/study/run_benchmark.py"),
    "analyze": Path("experiments/study/analyze_run.py"),
    "llm": Path("experiments/study/run_llm_closed_loop.py"),
    "latency": Path("experiments/study/run_latency_protocol.py"),
    "adversarial": Path("experiments/run_adversarial_probe.py"),
    "generate-probe": Path("experiments/study/generate_adversarial_extension.py"),
    "corpora": Path("experiments/evaluate_prompt_corpora.py"),
    "registry": Path("experiments/study/build_claim_registry.py"),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("arguments", nargs=argparse.REMAINDER,
                        help="Arguments forwarded to the selected experiment command.")
    args = parser.parse_args()
    script = ROOT / COMMANDS[args.command]
    return subprocess.run([sys.executable, str(script), *args.arguments], cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
