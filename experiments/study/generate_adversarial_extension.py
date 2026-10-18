"""Create a deterministic 500-case normalization probe from the seed set.

This is a project-authored perturbation study, not an external/real-world
benchmark. It produces five transformations for each of the 100
parameter_manipulation seed scenarios. Results must be reported separately from
the sandbox effect-oracle benchmark and cannot reproduce historical metrics unless
the generated corpus hash matches the historical source manifest.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "backend/data/benchmark/parameter_manipulation.json"
OUT = ROOT / "backend/data/benchmark/adversarial_extension.json"
MANIFEST = ROOT / "backend/data/benchmark/adversarial_extension_manifest.json"
MUTATIONS = ("case_alternation", "comment_fragmentation", "advanced_sql", "url_encoding", "base64_obfuscation")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def transform(value: Any, kind: str) -> Any:
    if isinstance(value, dict):
        return {k: transform(v, kind) for k, v in value.items()}
    if isinstance(value, list):
        return [transform(v, kind) for v in value]
    if not isinstance(value, str):
        return value
    if kind == "case_alternation":
        chars = [c.upper() if i % 2 else c.lower() for i, c in enumerate(value)]
        return "".join(chars)
    if kind == "comment_fragmentation":
        return re.sub(r"(?i)(select|union|where|or|and|drop|insert|update|delete)",
                      lambda m: "/**/".join(m.group(0)), value)
    if kind == "advanced_sql":
        return value + "' OR '1'='1' /* controlled benchmark payload */"
    if kind == "url_encoding":
        from urllib.parse import quote
        return quote(value, safe="")
    if kind == "base64_obfuscation":
        return "base64:" + base64.b64encode(value.encode("utf-8")).decode("ascii")
    raise ValueError(f"Unknown mutation {kind}")


def generate() -> Path:
    raw = SOURCE.read_bytes()
    base = json.loads(raw)
    if len(base) != 100:
        raise ValueError(f"Expected exactly 100 seed scenarios; found {len(base)} in {SOURCE}")
    seen = set()
    output = []
    for seed in base:
        for mutation in MUTATIONS:
            row = {k: v for k, v in seed.items()}
            row["arguments"] = transform(seed.get("arguments", {}), mutation)
            row["mutated_scenario_id"] = f"{seed['scenario_id']}::{mutation}"
            row["original_scenario_id"] = seed["scenario_id"]
            row["mutation_type"] = mutation
            row["source_label"] = seed.get("expected_decision")
            key = json.dumps([row["original_scenario_id"], mutation, row["arguments"]], sort_keys=True)
            if key in seen:
                raise ValueError(f"Duplicate generated mutation for {row['mutated_scenario_id']}")
            seen.add(key)
            output.append(row)
    if len(output) != 500:
        raise AssertionError(f"Expected 500 rows, generated {len(output)}")
    payload = (json.dumps(output, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    OUT.write_bytes(payload)
    manifest = {
        "dataset": "PromptAegis project-authored adversarial normalization probe",
        "purpose": "decision-level normalization sensitivity; not an external benchmark",
        "seed_file": str(SOURCE.relative_to(ROOT)).replace("\\", "/"),
        "seed_file_sha256": digest(raw), "generator": str(Path(__file__).resolve().relative_to(ROOT)).replace("\\", "/"),
        "generator_sha256": digest(Path(__file__).read_bytes()), "generated_file_sha256": digest(payload),
        "seed_scenarios": len(base), "mutation_classes": list(MUTATIONS),
        "cases_per_mutation": len(base), "scenario_count": len(output),
        "label_status": "inherited_from_project_authored_seed_labels; not independently reviewed",
        "limitations": ["synthetic transformations", "decision-only legacy runner", "not evidence of real attack prevalence"],
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"[OK] generated {len(output)} project-authored variants: {OUT.relative_to(ROOT)}")
    print(f"[OK] source and output hashes recorded: {MANIFEST.relative_to(ROOT)}")
    return OUT


if __name__ == "__main__":
    generate()
