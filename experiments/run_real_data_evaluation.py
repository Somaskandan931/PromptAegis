"""Prepare, train, and evaluate PromptAegis on real prompt datasets only."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
DATA = BACKEND / "data" / "intermediate"
MODELS = BACKEND / "models"
RESULTS = ROOT / "results" / "external"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    print("[RUN] " + " ".join(command), flush=True)
    result = subprocess.run(command, cwd=cwd, env=env)
    if result.returncode:
        raise SystemExit(result.returncode)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the complete real-data prompt-screening research pipeline.")
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--sample-size", type=int, default=10000, help="Maximum attack and benign training rows per class.")
    parser.add_argument("--skip-prepare", action="store_true", help="Reuse prepared split files and their manifest.")
    parser.add_argument("--skip-training", action="store_true", help="Reuse a model only if its real-data provenance hashes match.")
    args = parser.parse_args()
    if args.batch_size < 1 or args.sample_size < 1:
        parser.error("batch-size and sample-size must be positive")

    base_env = os.environ.copy()
    if not args.skip_prepare:
        run([sys.executable, "scripts/prepare_real_research_data.py"], cwd=BACKEND, env=base_env)

    required = [
        DATA / "hackaprompt_train.csv", DATA / "hackaprompt_train_sample.csv", DATA / "hackaprompt_test.csv",
        DATA / "toxicchat_train.csv", DATA / "toxicchat_trigger_train.csv",
        DATA / "toxicchat_test.csv", DATA / "real_research_data_manifest.json",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError("Missing prepared real-data files: " + ", ".join(missing))

    train_env = base_env.copy()
    train_env.update({
        "PROMPTAEGIS_ATTACK_CORPUS_PATH": str(DATA / "hackaprompt_train_sample.csv"),
        "PROMPTAEGIS_BENIGN_CORPUS_PATH": str(DATA / "toxicchat_train.csv"),
        "PROMPTAEGIS_TRIGGER_BENIGN_CORPUS_PATH": str(DATA / "toxicchat_trigger_train.csv"),
    })
    provenance_path = MODELS / "real_training_manifest.json"
    if args.skip_training:
        if not provenance_path.exists():
            raise RuntimeError("No real-data training provenance exists; run without --skip-training first.")
        old = json.loads(provenance_path.read_text(encoding="utf-8"))
        for name, path in (("hackaprompt_train_sample.csv", required[1]), ("toxicchat_train.csv", required[3]),
                           ("toxicchat_trigger_train.csv", required[4])):
            if old.get("training_data", {}).get(name) != sha256(path):
                raise RuntimeError(f"Trained model provenance does not match {name}; retrain before evaluation.")
    else:
        run([sys.executable, "-m", "models.train", "--sample-size", str(args.sample_size)], cwd=BACKEND, env=train_env)
        trained = {
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "training_data": {
                "hackaprompt_train_sample.csv": sha256(required[1]),
                "toxicchat_train.csv": sha256(required[3]),
                "toxicchat_trigger_train.csv": sha256(required[4]),
            },
            "training_sample_size_per_class": args.sample_size,
            "classifier_sha256": sha256(MODELS / "detector.pkl"),
            "threshold_sha256": sha256(MODELS / "threshold.json"),
            "note": "Model trained only on up to 10,000 real HackAPrompt training prompts and ToxicChat non-toxic/non-jailbreak training prompts.",
        }
        provenance_path.write_text(json.dumps(trained, indent=2), encoding="utf-8")

    run([sys.executable, "experiments/evaluate_prompt_corpora.py", "--batch-size", str(args.batch_size)],
        cwd=ROOT, env=train_env)
    print(f"[OK] Real-data run complete. Evaluation JSON is in {RESULTS}")


if __name__ == "__main__":
    main()
