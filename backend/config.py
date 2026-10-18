"""
Central configuration for the Prompt Injection Detection Gateway.
All tunable thresholds live here so they can be calibrated in one place
(see PRD Section 5.4 / 9 - false positive calibration).
"""
import os


def _load_dotenv(path: str) -> None:
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_load_dotenv(os.path.join(BASE_DIR, ".env"))
DATA_DIR = os.path.join(BASE_DIR, "data")
DATABASE_DIR = os.path.join(BASE_DIR, "database")

# Environment Database Paths (Physical Isolation)
BENCHMARK_DB_PATH = os.path.join(DATABASE_DIR, "gateway_benchmark.db")
LOCAL_DEV_DB_PATH = os.path.join(DATABASE_DIR, "gateway_local_dev.db")
CONNECTED_APP_DB_PATH = os.path.join(DATABASE_DIR, "gateway_connected.db")
ENVIRONMENTS_REGISTRY_PATH = os.path.join(DATABASE_DIR, "environments.json")
CREDENTIALS_REGISTRY_PATH = os.path.join(DATABASE_DIR, "credentials.json")

# Authoritative default path (resolves to benchmark DB for research reproducibility)
DB_PATH = BENCHMARK_DB_PATH
MODEL_DIR = os.path.join(BASE_DIR, "models")

REAL_SPLIT_DIR = os.path.join(DATA_DIR, "intermediate")
ATTACK_CORPUS_PATH = os.environ.get(
    "PROMPTAEGIS_ATTACK_CORPUS_PATH", os.path.join(REAL_SPLIT_DIR, "hackaprompt_train_sample.csv")
)
BENIGN_CORPUS_PATH = os.environ.get(
    "PROMPTAEGIS_BENIGN_CORPUS_PATH", os.path.join(REAL_SPLIT_DIR, "toxicchat_train.csv")
)
TRIGGER_BENIGN_CORPUS_PATH = os.environ.get(
    "PROMPTAEGIS_TRIGGER_BENIGN_CORPUS_PATH", os.path.join(REAL_SPLIT_DIR, "toxicchat_trigger_train.csv")
)

# ---------------------------------------------------------------------------
# Embedding model
# ---------------------------------------------------------------------------
EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIM = 384

# ---------------------------------------------------------------------------
# Layer weights (risk score combination — PRD 5.4)
# ---------------------------------------------------------------------------
WEIGHT_RULE = 0.25
WEIGHT_EMBEDDING = 0.30
WEIGHT_CLASSIFIER = 0.30
WEIGHT_DRIFT = 0.15

# ---------------------------------------------------------------------------
# Tier thresholds
# ---------------------------------------------------------------------------
HIGH_EMBED_THRESHOLD = 0.70
HIGH_CLASSIFIER_THRESHOLD = 0.70

MEDIUM_SCORE_THRESHOLD = 0.55
LOW_SCORE_THRESHOLD = 0.25

MEDIUM_EMBED_THRESHOLD = 0.50
MEDIUM_CLASSIFIER_THRESHOLD = 0.50

# ---------------------------------------------------------------------------
# Classifier decision threshold (auto-calibrated)
# ---------------------------------------------------------------------------
# models/train.py sweeps the precision-recall curve on the held-out test
# split and writes the recall-optimal cutoff to models/threshold.json (see
# train.py::_select_threshold). If that file exists we use it to override
# MEDIUM_CLASSIFIER_THRESHOLD / HIGH_CLASSIFIER_THRESHOLD above, so a
# retrain automatically recalibrates how much weight a given classifier
# probability carries in severity.get_tier() -- without editing this file
# by hand. Falls back to the static defaults above if train.py hasn't been
# run yet (or the file is missing/corrupt).
_THRESHOLD_FILE = os.path.join(MODEL_DIR, "threshold.json")
if os.path.exists(_THRESHOLD_FILE):
    try:
        import json as _json
        with open(_THRESHOLD_FILE) as _f:
            _tuned = _json.load(_f)
        # The tuned cutoff replaces MEDIUM_CLASSIFIER_THRESHOLD (the "is this
        # classifier probability elevated enough to matter" gate). HIGH stays
        # a fixed margin above it so the HIGH tier still requires a
        # meaningfully more confident prediction than MEDIUM.
        MEDIUM_CLASSIFIER_THRESHOLD = float(_tuned["medium_classifier_threshold"])
        HIGH_CLASSIFIER_THRESHOLD = float(_tuned["high_classifier_threshold"])
    except Exception:
        pass  # keep static defaults if the file is missing a key or malformed

# Stricter thresholds applied to tool_output (indirect injection — Layer F)
TOOL_OUTPUT_EMBED_DELTA = -0.10       # subtract from HIGH threshold, i.e. easier to trigger
TOOL_OUTPUT_CLASSIFIER_DELTA = -0.10

# ---------------------------------------------------------------------------
# Multi-turn drift (Layer D)
# ---------------------------------------------------------------------------
DRIFT_WINDOW = 5                # last N turns considered
DRIFT_ALERT_THRESHOLD = 0.45    # cosine distance from session-intent(0)

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
CORS_ORIGINS = ["http://localhost:5173", "http://localhost:3000"]

# ---------------------------------------------------------------------------
# Downstream LLM provider
# ---------------------------------------------------------------------------
# Groq model IDs that have been shut down, mapped to the replacement Groq
# recommends (https://console.groq.com/docs/deprecations). A stale value in
# backend/.env or the shell (e.g. GROQ_MODEL=llama-3.3-70b-versatile) would
# otherwise fail every request with HTTP 404 "model_not_found".
RETIRED_GROQ_MODELS = {
    "llama-3.3-70b-versatile": "openai/gpt-oss-120b",   # shut down 2026-08-16
    "llama-3.1-8b-instant": "openai/gpt-oss-20b",       # shut down 2026-08-16
    "qwen/qwen3.6-27b": "qwen/qwen3.8-27b",             # shut down 2026-09-14
    "qwen/qwen3-32b": "openai/gpt-oss-120b",            # shut down 2026-07-17
    "meta-llama/llama-4-scout-17b-16e-instruct": "openai/gpt-oss-120b",  # 2026-07-17
}
DEFAULT_GROQ_MODEL = "openai/gpt-oss-120b"


def resolve_groq_model(model: str) -> str:
    """Return a live Groq model ID, remapping retired IDs with a warning."""
    model = (model or "").strip() or DEFAULT_GROQ_MODEL
    replacement = RETIRED_GROQ_MODELS.get(model)
    if replacement:
        import warnings
        warnings.warn(
            f"Groq model '{model}' has been retired; using '{replacement}' instead. "
            f"Update GROQ_MODEL in backend/.env or your shell to silence this.",
            RuntimeWarning, stacklevel=2,
        )
        return replacement
    return model


# Provider selection: Ollama (local, keyless) is the default; Groq is optional.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama").strip().lower()
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = resolve_groq_model(os.getenv("GROQ_MODEL", DEFAULT_GROQ_MODEL))
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
LLM_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "120" if LLM_PROVIDER == "ollama" else "45"))
