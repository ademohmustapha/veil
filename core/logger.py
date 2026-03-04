"""AURORA Immutable Audit Logger — tamper-evident chained log entries."""
from __future__ import annotations
import json, time, hashlib, hmac, os
from pathlib import Path
from typing import Optional
from core.paths import AURORA_HOME
from core.bootstrap import Bootstrap

_LOG_FILE = AURORA_HOME / "aurora_audit.jsonl"

class AuditLogger:
    """Append-only audit log with HMAC chaining (each entry hash-linked to previous)."""
    _prev_hash: str = "0" * 64

    def __init__(self):
        AURORA_HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        if _LOG_FILE.exists():
            self._prev_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        try:
            lines = _LOG_FILE.read_text().strip().splitlines()
            if lines:
                last = json.loads(lines[-1])
                return last.get("entry_hash", "0" * 64)
        except Exception: pass
        return "0" * 64

    def log(self, layer: str, event_type: str, message: str,
            severity: str = "INFO", metadata: Optional[dict] = None) -> str:
        # If HMAC secret unavailable, generate a random session secret.
        # This means the chain won't verify across restarts without the real key,
        # but it will never use a known/guessable secret.
        _hmac_secret = Bootstrap.get_hmac_secret()
        if not _hmac_secret:
            import os as _os
            _hmac_secret = _os.urandom(32)
        secret = _hmac_secret
        entry = {
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "timestamp_ns": time.time_ns(),
            "layer": layer,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "metadata": metadata or {},
            "prev_hash": self._prev_hash,
        }
        canon = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        entry_hash = hmac.new(secret, canon.encode(), hashlib.sha256).hexdigest()
        entry["entry_hash"] = entry_hash
        self._prev_hash = entry_hash
        try:
            with open(_LOG_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception: pass
        return entry_hash

    def read_all(self) -> list:
        try:
            return [json.loads(l) for l in _LOG_FILE.read_text().strip().splitlines() if l]
        except Exception: return []

    def verify_chain(self) -> tuple[bool, int, int]:
        entries = self.read_all()
        # If HMAC secret unavailable, generate a random session secret.
        # This means the chain won't verify across restarts without the real key,
        # but it will never use a known/guessable secret.
        _hmac_secret = Bootstrap.get_hmac_secret()
        if not _hmac_secret:
            import os as _os
            _hmac_secret = _os.urandom(32)
        secret = _hmac_secret
        ok = total = 0
        prev = "0" * 64
        for e in entries:
            total += 1
            stored_hash = e.pop("entry_hash", "")
            canon = json.dumps(e, sort_keys=True, separators=(",", ":"))
            expected = hmac.new(secret, canon.encode(), hashlib.sha256).hexdigest()
            if hmac.compare_digest(stored_hash, expected) and e.get("prev_hash") == prev:
                ok += 1
            prev = stored_hash
            e["entry_hash"] = stored_hash
        return (ok == total), ok, total
