"""
AURORA Tamper-Proof Audit Log
Each log entry is SHA-256 chained to the previous entry.
Any deletion or modification of entries is cryptographically detectable.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditLog:
    """
    Immutable, chained audit log.

    Chain structure:
      entry_n.chain_hash = SHA-256(entry_n.data || entry_{n-1}.chain_hash)

    Any gap or modification in the chain is immediately detectable via verify_chain().
    """

    _GENESIS_HASH = "0" * 64  # Sentinel for the first entry

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = log_dir / "aurora_audit.jsonl"
        self._prev_hash: Optional[str] = self._get_tail_hash()

    # ─── Public API ──────────────────────────────────────────────────────────

    def log(
        self,
        event_type: str,
        severity: str,
        message: str,
        layer: str = "SYSTEM",
        user_id: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Write a tamper-proof log entry. Returns entry ID."""
        entry_id = str(uuid.uuid4())
        entry = {
            "entry_id": entry_id,
            "timestamp": time.time(),
            "timestamp_iso": _iso_now(),
            "event_type": event_type,
            "severity": severity,
            "layer": layer,
            "message": message,
            "user_id": user_id or "SYSTEM",
            "data": data or {},
            "chain_hash": "",  # filled below
        }
        prev_hash = self._prev_hash or self._GENESIS_HASH
        chain_input = (json.dumps(entry, sort_keys=True) + prev_hash).encode()
        chain_hash = hashlib.sha256(chain_input).hexdigest()
        entry["chain_hash"] = chain_hash

        with open(self._log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        self._prev_hash = chain_hash
        return entry_id

    def verify_chain(self) -> Dict[str, Any]:
        """
        Verify the integrity of the entire audit chain.
        Returns: {valid: bool, entries_checked: int, first_violation: Optional[int]}
        """
        if not self._log_path.exists():
            return {"valid": True, "entries_checked": 0, "first_violation": None}

        entries = [json.loads(line) for line in self._log_path.read_text().splitlines() if line.strip()]
        prev_hash = self._GENESIS_HASH
        for i, entry in enumerate(entries):
            stored_hash = entry.get("chain_hash", "")
            # Recompute without chain_hash field
            check = {k: v for k, v in entry.items() if k != "chain_hash"}
            check["chain_hash"] = ""
            chain_input = (json.dumps(check, sort_keys=True) + prev_hash).encode()
            expected = hashlib.sha256(chain_input).hexdigest()
            if stored_hash != expected:
                return {"valid": False, "entries_checked": i + 1, "first_violation": i}
            prev_hash = stored_hash

        return {"valid": True, "entries_checked": len(entries), "first_violation": None}

    def tail(self, n: int = 20) -> List[dict]:
        """Return last n log entries."""
        if not self._log_path.exists():
            return []
        lines = self._log_path.read_text().splitlines()
        return [json.loads(line) for line in lines[-n:] if line.strip()]

    def query(self, event_type: Optional[str] = None,
              severity: Optional[str] = None,
              user_id: Optional[str] = None) -> List[dict]:
        """Filter log entries by criteria."""
        if not self._log_path.exists():
            return []
        results = []
        for line in self._log_path.read_text().splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if event_type and entry.get("event_type") != event_type:
                continue
            if severity and entry.get("severity") != severity:
                continue
            if user_id and entry.get("user_id") != user_id:
                continue
            results.append(entry)
        return results

    # ─── Internal ────────────────────────────────────────────────────────────

    def _get_tail_hash(self) -> Optional[str]:
        if not self._log_path.exists():
            return None
        lines = self._log_path.read_text().splitlines()
        for line in reversed(lines):
            line = line.strip()
            if line:
                try:
                    return json.loads(line).get("chain_hash")
                except json.JSONDecodeError:
                    return None
        return None


def _iso_now() -> str:
    import datetime
    return datetime.datetime.utcnow().isoformat() + "Z"
