"""Prepare non-synthetic train/test CSVs from HackAPrompt and ToxicChat.

HackAPrompt is partitioned 80/20 with a fixed seed, stratified by source level.
ToxicChat keeps its upstream train/test split; only human-labelled non-toxic,
non-jailbreak user prompts are retained as benign proxies. Derived files are
written to data/intermediate/, which is excluded from Git.
"""
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
OUT = DATA / "intermediate"
HACKAPROMPT = DATA / "hackaprompt_attacks.csv"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_zero(value) -> bool:
    if value is None:
        return False
    try:
        return float(value) == 0.0
    except (TypeError, ValueError):
        return str(value).strip().lower() in {"false", "no", "non-toxic", "unharmful"}


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def download_hackaprompt() -> None:
    """Fetch the gated official source after the user accepts its terms."""
    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise RuntimeError("Install optional requirements: python -m pip install datasets huggingface_hub") from exc
    print("[INFO] Downloading the gated HackAPrompt source (accept terms and authenticate first)...", flush=True)
    try:
        dataset = load_dataset("hackaprompt/hackaprompt-dataset", split="train", streaming=True)
    except Exception as exc:
        raise RuntimeError(
            "HackAPrompt download failed. Accept its Hugging Face terms and run "
            "'huggingface-cli login', then rerun this command."
        ) from exc
    seen: set[str] = set()
    count = 0
    with HACKAPROMPT.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("text", "cluster_id", "cluster_name"))
        writer.writeheader()
        for row in dataset:
            text = (row.get("user_input") or "").strip()
            if len(text) < 8 or text in seen:
                continue
            seen.add(text)
            level = str(row.get("level", "unlabeled"))
            writer.writerow({"text": text, "cluster_id": level, "cluster_name": f"HackAPrompt level {level}"})
            count += 1
            if count % 50000 == 0:
                print(f"[PROGRESS] Downloaded {count} unique prompts", flush=True)
    print(f"[OK] Downloaded {count} unique HackAPrompt rows to {HACKAPROMPT}", flush=True)


def main() -> None:
    if not HACKAPROMPT.exists():
        download_hackaprompt()
    OUT.mkdir(parents=True, exist_ok=True)

    attacks = pd.read_csv(HACKAPROMPT, low_memory=False)
    if "text" not in attacks.columns:
        raise ValueError("hackaprompt_attacks.csv must contain a text column")
    attacks["text"] = attacks["text"].fillna("").astype(str).str.strip()
    attacks = attacks[attacks["text"].str.len() > 0].drop_duplicates(subset=["text"])
    stratify = attacks["cluster_id"] if "cluster_id" in attacks.columns else None
    train_attacks, test_attacks = train_test_split(
        attacks, test_size=0.20, random_state=42, stratify=stratify
    )
    train_attacks.to_csv(OUT / "hackaprompt_train.csv", index=False)
    test_attacks.to_csv(OUT / "hackaprompt_test.csv", index=False)
    if len(train_attacks) > 10000:
        sample_strata = train_attacks["cluster_id"] if "cluster_id" in train_attacks.columns else None
        attack_train_sample, _ = train_test_split(
            train_attacks, train_size=10000, random_state=43, stratify=sample_strata
        )
    else:
        attack_train_sample = train_attacks
    attack_train_sample.to_csv(OUT / "hackaprompt_train_sample.csv", index=False)

    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise RuntimeError("Install optional requirements: python -m pip install datasets huggingface_hub") from exc
    print("[INFO] Loading ToxicChat 0124 and its native train/test splits...", flush=True)
    toxicchat = load_dataset("lmsys/toxic-chat", "toxicchat0124")
    toxicchat_counts = {}
    for split_name in ("train", "test"):
        source_rows = toxicchat[split_name]
        safe_rows = []
        for row in source_rows:
            prompt = (row.get("user_input") or "").strip()
            if prompt and is_zero(row.get("toxicity")) and is_zero(row.get("jailbreaking")):
                safe_rows.append({"text": prompt})
        if split_name == "train":
            trigger_terms = ("ignore", "instruction", "system prompt", "jailbreak", "forget", "override")
            trigger_rows = [r for r in safe_rows if any(term in r["text"].lower() for term in trigger_terms)]
            trigger_texts = {r["text"] for r in trigger_rows}
            general_rows = [r for r in safe_rows if r["text"] not in trigger_texts]
            write_csv(OUT / "toxicchat_train.csv", general_rows, ("text",))
            write_csv(OUT / "toxicchat_trigger_train.csv", trigger_rows, ("text",))
            toxicchat_counts[split_name] = {
                "source_rows": len(source_rows), "safe_proxy_rows": len(safe_rows),
                "general_train_rows": len(general_rows), "trigger_train_rows": len(trigger_rows),
            }
            print(f"[OK] ToxicChat train: {len(general_rows)} general + {len(trigger_rows)} trigger-rich safe prompts", flush=True)
        else:
            write_csv(OUT / "toxicchat_test.csv", safe_rows, ("text",))
            toxicchat_counts[split_name] = {"source_rows": len(source_rows), "benign_proxy_rows": len(safe_rows)}
            print(f"[OK] ToxicChat test: {len(safe_rows)} safe-proxy prompts", flush=True)

    files = [
        "hackaprompt_train.csv", "hackaprompt_train_sample.csv", "hackaprompt_test.csv",
        "toxicchat_train.csv", "toxicchat_trigger_train.csv", "toxicchat_test.csv",
    ]
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hackaprompt": {
            "source_file": HACKAPROMPT.name,
            "source_sha256": sha256(HACKAPROMPT),
            "source_rows": int(len(attacks)),
            "train_rows": int(len(train_attacks)),
            "sampled_train_rows": int(len(attack_train_sample)),
            "test_rows": int(len(test_attacks)),
            "split": "80/20 row-level stratified by source cluster_id; random_state=42",
            "training_sample": "up to 10,000 rows sampled from the training partition; random_state=43",
        },
        "toxicchat": {
            "dataset": "lmsys/toxic-chat",
            "config": "toxicchat0124",
            "revision": "Hugging Face main at preparation time; freeze derived CSV hashes below",
        "filter": "toxicity == 0 and jailbreaking == 0; user_input only; trigger subset selected by fixed lexical terms",
            "splits": toxicchat_counts,
        },
        "derived_files": {name: {"sha256": sha256(OUT / name), "bytes": (OUT / name).stat().st_size} for name in files},
        "interpretation": "ToxicChat non-toxic/non-jailbreak prompts are benign proxies, not ground-truth labels for prompt-injection absence.",
    }
    (OUT / "real_research_data_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[OK] HackAPrompt train pool/sample/test: {len(train_attacks)}/{len(attack_train_sample)}/{len(test_attacks)}")
    print(f"[OK] Prepared real research data under {OUT}")


if __name__ == "__main__":
    main()
