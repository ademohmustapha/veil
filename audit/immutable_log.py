"""
AURORA – Immutable Audit Log
============================
Every event is written as a HMAC-linked JSON-Lines block.
Tampering with any record breaks the chain — detectable on verify().

Chain structure:
  block_n.hmac = HMAC-SHA256( block_n.data || block_{n-1}.hmac )

On startup AURORA verifies the entire chain. Any gap or broken HMAC
triggers a CRITICAL alert and halts the audit subsystem until resolved
by a human operator with the master HMAC secret.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from core.crypto import CryptoPrimitive

from core.paths import AURORA_HOME as _AURORA_HOME
_AUDIT_FILE = _AURORA_HOME / "aurora_audit.jsonl"
_GENESIS_HMAC = "0" * 64   # genesis sentinel
_MAX_LOG_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB
_MAX_ROTATED_FILES = 10


@dataclass
class AuditEvent:
    event_id:   str
    timestamp:  float
    event_type: str        # IDENTITY | RISK | CONTAINMENT | ALIGNMENT | EVOLUTION | SYSTEM | AUTH
    severity:   str        # INFO | WARN | HIGH | CRITICAL
    actor_id:   Optional[str]
    org_id:     Optional[str]
    summary:    str
    detail:     Dict[str, Any]
    prev_hmac:  str
    hmac:       str = ""   # computed on seal()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def seal(self, secret: bytes) -> "AuditEvent":
        payload = json.dumps({
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "actor_id": self.actor_id,
            "org_id": self.org_id,
            "summary": self.summary,
            "detail": self.detail,
            "prev_hmac": self.prev_hmac,
        }, sort_keys=True).encode()
        self.hmac = CryptoPrimitive.hmac_sign(payload, secret)
        return self

    def verify(self, secret: bytes) -> bool:
        payload = json.dumps({
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "actor_id": self.actor_id,
            "org_id": self.org_id,
            "summary": self.summary,
            "detail": self.detail,
            "prev_hmac": self.prev_hmac,
        }, sort_keys=True).encode()
        return CryptoPrimitive.hmac_verify(payload, self.hmac, secret)


class ImmutableAuditLog:
    """
    Append-only, tamper-evident audit log.
    Thread-safety: protected by file-level append semantics on POSIX.
    """

    # Minimum HMAC secret length — protects against empty-secret forgery
    _MIN_SECRET_LEN = 32

    def __init__(self, secret: bytes) -> None:
        if len(secret) < self._MIN_SECRET_LEN:
            raise ValueError(
                f"AURORA audit log secret must be at least {self._MIN_SECRET_LEN} bytes. "
                f"Got {len(secret)}. Use Bootstrap.get_hmac_secret() which generates 64 bytes."
            )
        self._secret = secret
        self._last_hmac: str = self._read_last_hmac()

    def _read_last_hmac(self) -> str:
        if not _AUDIT_FILE.exists():
            return _GENESIS_HMAC
        last_line = ""
        with open(_AUDIT_FILE, "rb") as fh:
            # Read last non-empty line efficiently
            fh.seek(0, 2)
            size = fh.tell()
            if size == 0:
                return _GENESIS_HMAC
            pos = size - 1
            buf: List[bytes] = []
            while pos >= 0:
                fh.seek(pos)
                ch = fh.read(1)
                if ch == b"\n" and buf:
                    break
                buf.append(ch)
                pos -= 1
            last_line = b"".join(reversed(buf)).decode("utf-8", errors="replace").strip()
        if not last_line:
            return _GENESIS_HMAC
        try:
            data = json.loads(last_line)
            return data.get("hmac", _GENESIS_HMAC)
        except json.JSONDecodeError:
            return _GENESIS_HMAC

    def log(
        self,
        event_type: str,
        severity: str,
        summary: str,
        detail: Optional[Dict[str, Any]] = None,
        actor_id: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=CryptoPrimitive.generate_id("EVT"),
            timestamp=time.time(),
            event_type=event_type,
            severity=severity,
            actor_id=actor_id,
            org_id=org_id,
            summary=summary,
            detail=detail or {},
            prev_hmac=self._last_hmac,
        )
        event.seal(self._secret)
        self._last_hmac = event.hmac
        # Rotate if needed before appending
        self._rotate_if_needed()
        # Append to JSONL file
        with open(_AUDIT_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event.to_dict()) + "\n")
        # ── Push alert for HIGH and CRITICAL events ───────────────────────
        if severity in ("HIGH", "CRITICAL"):
            self._push_alert(event)
        return event

    @staticmethod
    def _push_alert(event: "AuditEvent") -> None:
        """
        Non-blocking push notification for HIGH/CRITICAL audit events.
        Import is deferred to avoid circular imports and to make the
        notifications module fully optional.
        """
        try:
            from notifications.dispatcher import get_dispatcher
            get_dispatcher().alert(
                severity=event.severity,
                event_type=event.event_type,
                summary=event.summary,
                detail={
                    **event.detail,
                    "event_id": event.event_id,
                    "actor_id": event.actor_id,
                    "org_id":   event.org_id,
                },
            )
        except Exception:
            pass  # Never let notification failures block audit logging

    def _rotate_if_needed(self) -> None:
        """Rotate the audit log if it exceeds the maximum size."""
        try:
            if not _AUDIT_FILE.exists() or _AUDIT_FILE.stat().st_size < _MAX_LOG_SIZE_BYTES:
                return
            import shutil
            # Shift existing rotated files
            for i in range(_MAX_ROTATED_FILES - 1, 0, -1):
                src = _AUDIT_FILE.with_suffix(f".jsonl.{i}")
                dst = _AUDIT_FILE.with_suffix(f".jsonl.{i + 1}")
                if src.exists():
                    if i + 1 > _MAX_ROTATED_FILES:
                        src.unlink()  # Delete oldest
                    else:
                        shutil.move(str(src), str(dst))
            # Move current log to .1
            shutil.move(str(_AUDIT_FILE), str(_AUDIT_FILE.with_suffix(".jsonl.1")))
            # Reset last HMAC for new log file
            self._last_hmac = _GENESIS_HMAC
        except Exception:
            pass  # Never let rotation failures block audit logging

    def verify_chain(self) -> Dict[str, Any]:
        """
        Walk the entire chain and verify every HMAC link.
        Returns a report: {valid: bool, total: int, broken_at: list}
        """
        if not _AUDIT_FILE.exists():
            return {"valid": True, "total": 0, "broken_at": []}

        broken: List[str] = []
        total = 0
        prev_hmac = _GENESIS_HMAC

        with open(_AUDIT_FILE, "r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    d = json.loads(line)
                    event = AuditEvent(**d)
                    if event.prev_hmac != prev_hmac:
                        broken.append(f"Line {line_no}: chain break (prev_hmac mismatch)")
                    if not event.verify(self._secret):
                        broken.append(f"Line {line_no}: HMAC invalid (event_id={event.event_id})")
                    prev_hmac = event.hmac
                except Exception as exc:
                    broken.append(f"Line {line_no}: parse error ({exc})")

        return {
            "valid": len(broken) == 0,
            "total": total,
            "broken_at": broken,
        }

    def tail(self, n: int = 50) -> List[Dict[str, Any]]:
        """Return the last n audit events."""
        if not _AUDIT_FILE.exists():
            return []
        events: List[Dict[str, Any]] = []
        with open(_AUDIT_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return events[-n:]

    def search(self, event_type: Optional[str] = None, severity: Optional[str] = None,
               actor_id: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        if not _AUDIT_FILE.exists():
            return []
        results: List[Dict[str, Any]] = []
        with open(_AUDIT_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    if event_type and d.get("event_type") != event_type:
                        continue
                    if severity and d.get("severity") != severity:
                        continue
                    if actor_id and d.get("actor_id") != actor_id:
                        continue
                    results.append(d)
                    if len(results) >= limit:
                        break
                except json.JSONDecodeError:
                    pass
        return results
