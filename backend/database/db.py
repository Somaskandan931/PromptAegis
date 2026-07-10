"""
SQLite storage for detection logs. One table is enough for the MVP
(PRD Section 7 — no need for a production DB for the hackathon).
"""
import json
import os
import sqlite3
from contextlib import contextmanager
from typing import List, Optional

import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    session_id TEXT,
    source TEXT NOT NULL,
    prompt TEXT NOT NULL,
    sanitized_output TEXT,
    tier TEXT NOT NULL,
    score REAL NOT NULL,
    action TEXT NOT NULL,
    explanation TEXT NOT NULL,
    rule_score REAL,
    matched_rules TEXT,
    embedding_score REAL,
    nearest_attack_cluster TEXT,
    classifier_prob REAL,
    drift_score REAL,
    drift_flagged INTEGER
);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_tier ON logs(tier);
"""


def init_db():
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    with get_conn() as conn:
        conn.executescript(_SCHEMA)


@contextmanager
def get_conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def insert_log(result) -> None:
    """result: core.pipeline.DetectionResult"""
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO logs (
                id, timestamp, session_id, source, prompt, sanitized_output,
                tier, score, action, explanation, rule_score, matched_rules,
                embedding_score, nearest_attack_cluster, classifier_prob,
                drift_score, drift_flagged
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                result.id,
                result.timestamp,
                result.session_id,
                result.source,
                result.original_prompt,
                result.sanitized_output,
                result.tier,
                result.score,
                result.action,
                result.explanation,
                result.rule_score,
                json.dumps(result.matched_rules),
                result.embedding_score,
                result.nearest_attack_cluster,
                result.classifier_prob,
                result.drift_score,
                int(result.drift_flagged),
            ),
        )


def fetch_logs(tier: Optional[str] = None, limit: int = 200) -> List[dict]:
    query = "SELECT * FROM logs"
    params = []
    if tier:
        query += " WHERE tier = ?"
        params.append(tier.upper())
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def fetch_statistics() -> dict:
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
        by_tier = conn.execute(
            "SELECT tier, COUNT(*) c FROM logs GROUP BY tier"
        ).fetchall()
        by_action = conn.execute(
            "SELECT action, COUNT(*) c FROM logs GROUP BY action"
        ).fetchall()
        avg_score = conn.execute("SELECT AVG(score) a FROM logs").fetchone()["a"] or 0.0

    return {
        "total_requests": total,
        "by_tier": {r["tier"]: r["c"] for r in by_tier},
        "by_action": {r["action"]: r["c"] for r in by_action},
        "average_risk_score": round(avg_score, 4),
    }


def clear_logs():
    with get_conn() as conn:
        conn.execute("DELETE FROM logs")
