"""Audit helpers for the governance gateway: argument redaction and a hash chain.

The SQLite ``tool_calls`` table remains the primary audit store.  The hash
chain is an *additional*, append-only JSON-lines record in which every entry
commits to the previous entry's hash.  Editing, deleting or re-ordering any
earlier entry changes every later hash, so ``verify_chain`` detects it.

Limits (documented in docs/research/KNOWN_LIMITATIONS.md): a hash chain stored next
to the data it protects is *tamper-evident*, not tamper-proof.  An attacker who
can rewrite the whole file can recompute the chain.  Anchoring the head hash
in an external system would be required for stronger guarantees.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from typing import Any, Dict, List, Optional, Tuple

_SENSITIVE_KEY = re.compile(r"(pass(word)?|secret|token|api[_-]?key|authorization|credential|ssn|card)", re.I)
GENESIS = "0" * 64


def redact(value: Any, _seen: Optional[set] = None) -> Any:
    """Return a copy of ``value`` with sensitive-looking keys masked."""
    if _seen is None:
        _seen = set()
    if isinstance(value, dict):
        ident = id(value)
        if ident in _seen:
            return "[CIRCULAR]"
        _seen.add(ident)
        try:
            return {k: ("[REDACTED]" if _SENSITIVE_KEY.search(str(k)) else redact(v, _seen))
                    for k, v in value.items()}
        finally:
            _seen.remove(ident)
    if isinstance(value, (list, tuple)):
        ident = id(value)
        if ident in _seen:
            return "[CIRCULAR]"
        _seen.add(ident)
        try:
            return [redact(v, _seen) for v in value]
        finally:
            _seen.remove(ident)
    return value


def args_digest(arguments: Any) -> str:
    """Stable SHA-256 of the *unredacted* arguments (lets a reviewer prove which
    request was evaluated without storing sensitive content)."""
    try:
        canonical = json.dumps(arguments, sort_keys=True, default=str, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        # Direct Python callers can supply objects that cannot occur in JSON
        # requests (including cyclic containers). Keep the audit path total.
        try:
            canonical = f"non-json:{type(arguments).__name__}:{repr(arguments)}"
        except Exception:
            canonical = f"non-json:{type(arguments).__name__}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _entry_hash(body: Dict[str, Any], prev_hash: str) -> str:
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


class AuditChain:
    """Append-only hash-chained log (in memory, optionally mirrored to a file)."""

    def __init__(self, path: Optional[str] = None):
        self._path = path
        self._lock = threading.Lock()
        self._entries: List[Dict[str, Any]] = []
        self._head = GENESIS
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        self._entries.append(entry)
                        self._head = entry["hash"]
            ok, bad_index = verify_chain(self._entries)
            if not ok:
                raise ValueError(f"audit chain is invalid at entry {bad_index}; refusing to append")

    @property
    def head(self) -> str:
        return self._head

    def __len__(self) -> int:
        return len(self._entries)

    def append(self, body: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            digest = _entry_hash(body, self._head)
            entry = {"body": body, "prev": self._head, "hash": digest}
            if self._path:
                os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
            self._entries.append(entry)
            self._head = digest
            return entry

    def entries(self) -> List[Dict[str, Any]]:
        return list(self._entries)


def verify_chain(entries: List[Dict[str, Any]]) -> Tuple[bool, Optional[int]]:
    """Return (ok, index_of_first_bad_entry)."""
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.get("prev") != prev or _entry_hash(e["body"], prev) != e.get("hash"):
            return False, i
        prev = e["hash"]
    return True, None
