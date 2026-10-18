"""Evaluate every checked-out prompt corpus with the frozen PromptAegis detector.

This is a prompt-corpus screening evaluation. It does not call a hosted LLM:
the CSV rows are screened locally and do not represent complete agent tasks.

The evaluation uses the prepared held-out HackAPrompt attack partition and
the native ToxicChat test split filtered to non-toxic, non-jailbreak prompts.
The latter is a benign proxy, not a prompt-injection-free ground-truth set.
"""
import argparse
import csv
import hashlib
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Iterator


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import config
from core.classifier import Classifier
from core import rule_engine, severity
from core.semantic_engine import SemanticEngine
from utils.preprocess import preprocess


DATA_DIR = BACKEND_DIR / "data" / "intermediate"
RESULTS_DIR = PROJECT_ROOT / "results" / "external"

# The evaluation uses only real-data holdouts. Legacy toy/template corpora
# are deliberately excluded from the active research path.
SOURCES = (
    {"file": "hackaprompt_test.csv", "label": "attack", "role": "heldout_real_attack"},
    {"file": "toxicchat_test.csv", "label": "benign", "role": "heldout_real_benign_proxy"},
)


def _text_batches(path: Path, batch_size: int) -> Iterator[list[str]]:
    """Stream CSV data so the 393k-row HackAPrompt corpus stays bounded."""
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "text" not in reader.fieldnames:
            raise ValueError(f"{path} must contain a text column")
        batch: list[str] = []
        for row in reader:
            text = (row.get("text") or "").strip()
            if text:
                batch.append(text)
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evaluate_source(source: dict[str, str], engine: SemanticEngine, classifier: Classifier, batch_size: int) -> dict:
    path = DATA_DIR / source["file"]
    if not path.exists():
        return {**source, "status": "missing", "total": 0}

    actions: Counter[str] = Counter()
    tiers: Counter[str] = Counter()
    total = 0
    for raw_texts in _text_batches(path, batch_size):
        texts = [preprocess(text) for text in raw_texts]
        semantic_results = engine.analyze_batch(texts)
        for text, semantic_result in zip(texts, semantic_results):
            rules = rule_engine.match_rules(text)
            prediction = classifier.predict(text, rules.score, semantic_result.context_anchored_score)
            decision = severity.evaluate(
                rule_score=rules.score,
                embed_score=semantic_result.context_anchored_score,
                classifier_prob=prediction.probability,
                drift_score=0.0,
                matched_rules=rules.matched,
            )
            actions[decision.action] += 1
            tiers[decision.tier] += 1
            total += 1
        if total and total % (batch_size * 20) == 0:
            print(f"[PROGRESS] {source['file']}: {total} rows screened", flush=True)

    flagged = total - actions["pass"]
    metric_name = "intervention_rate" if source["label"] == "attack" else "false_positive_rate"
    return {
        **source,
        "status": "complete",
        "sha256": _sha256(path),
        "total": total,
        "actions": dict(actions),
        "tiers": dict(tiers),
        "flagged": flagged,
        metric_name: flagged / total if total else None,
    }


def main() -> Path:
    parser = argparse.ArgumentParser(description="Evaluate all local prompt corpora with the frozen detector.")
    parser.add_argument("--batch-size", type=int, default=256)
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error("--batch-size must be positive")

    print("[INFO] Building the frozen detector's semantic index from its configured development corpora.")
    engine = SemanticEngine.instance()
    classifier = Classifier.instance()
    print("[INFO] Evaluating the real-data holdouts; no hosted LLM request is made.")
    reports = []
    for source in SOURCES:
        print(f"[INFO] {source['file']} ({source['role']})")
        report = _evaluate_source(source, engine, classifier, args.batch_size)
        reports.append(report)
        print(f"[OK] {source['file']}: {report['total']} rows")

    headline = {item["file"]: item for item in reports}
    payload = {
        "dataset_family": "real prompt holdouts",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "detector_mode": "frozen persisted detector and configured semantic index",
        "detector_artifacts": {
            "classifier_backend": type(classifier.model).__name__ if classifier.model is not None else "heuristic_fallback",
            "classifier_sha256": _sha256(Path(config.MODEL_DIR) / "detector.pkl")
            if (Path(config.MODEL_DIR) / "detector.pkl").exists() else None,
            "threshold_sha256": _sha256(Path(config.MODEL_DIR) / "threshold.json")
            if (Path(config.MODEL_DIR) / "threshold.json").exists() else None,
            "embedding_model": config.EMBEDDING_MODEL_NAME,
        },
        "prepared_data_manifest_sha256": _sha256(DATA_DIR / "real_research_data_manifest.json")
        if (DATA_DIR / "real_research_data_manifest.json").exists() else None,
        "method_note": (
            "Only the held-out HackAPrompt attack split and the native ToxicChat test split "
            "are screened. ToxicChat rows are filtered to non-toxic and non-jailbreak user prompts; "
            "they are benign proxies, not labels proving the absence of prompt injection."
        ),
        "sources": reports,
        "external_transfer_headline": {
            "attack_source": "hackaprompt_test.csv",
            "benign_proxy_source": "toxicchat_test.csv",
            "intervention_rate": headline.get("hackaprompt_test.csv", {}).get("intervention_rate"),
            "benign_proxy_intervention_rate": headline.get("toxicchat_test.csv", {}).get("false_positive_rate"),
        },
        "interpretation_boundary": (
            "Standalone prompt screening only. HackAPrompt rows are a row-level held-out split; "
            "ToxicChat is a native held-out split of consented user prompts. "
            "These rates do not measure tool-call authorization or task completion."
        ),
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output = RESULTS_DIR / f"prompt_corpora_all_{int(time.time())}.json"
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[OK] Wrote prompt-corpus results to {output}")
    return output


if __name__ == "__main__":
    main()
