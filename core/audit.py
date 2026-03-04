"""
AURORA Immutable Audit Chain
Cryptographically sealed, append-only event log.
Each block: SHA3-256 of (prev_hash + timestamp_ns + event_json)
HMAC-signed with per-install secret. Ed25519-sealed at checkpoints.
"""
from __future__ import annotations
import json, time, hashlib, hmac, os
from dataclasses import dataclass, asdict
from typing import Optional
from core.crypto import CryptoPrimitive

@dataclass
class AuditBlock:
    index: int
    timestamp_ns: int
    event_type: str
    actor: str
    resource: str
    action: str
    outcome: str
    severity: str          # INFO | LOW | MEDIUM | HIGH | CRITICAL
    metadata: dict
    prev_hash: str
    block_hash: str
    hmac_tag: str
    signature: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

class AuroraAuditChain:
    """
    Tamper-proof audit trail. Any modification to any block
    invalidates all subsequent block_hash values — detectable instantly.
    """
    SEVERITY_LEVELS = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    def __init__(self, chain_path: str, hmac_key: bytes, priv_pem: bytes = None):
        self._path = chain_path
        self._key = hmac_key
        self._priv_pem = priv_pem
        self._crypto = CryptoPrimitive()
        self._blocks: list[AuditBlock] = []
        self._load()

    def _load(self):
        if os.path.exists(self._path):
            try:
                with open(self._path) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            d = json.loads(line)
                            self._blocks.append(AuditBlock(**d))
            except Exception:
                pass

    def _prev_hash(self) -> str:
        if not self._blocks:
            return "0" * 64
        return self._blocks[-1].block_hash

    def log(self, event_type: str, actor: str, resource: str, action: str,
            outcome: str, severity: str = "INFO", metadata: dict = None) -> AuditBlock:
        severity = severity.upper()
        if severity not in self.SEVERITY_LEVELS:
            severity = "INFO"
        idx = len(self._blocks)
        ts = time.time_ns()
        prev_h = self._prev_hash()
        meta = metadata or {}
        payload = json.dumps({
            "index": idx, "ts": ts, "type": event_type,
            "actor": actor, "resource": resource, "action": action,
            "outcome": outcome, "severity": severity, "meta": meta,
            "prev": prev_h
        }, sort_keys=True).encode()
        block_hash = hashlib.sha3_256(payload).hexdigest()
        hmac_tag = self._crypto.hmac_sign(payload, self._key)
        sig = None
        if self._priv_pem and severity in ("HIGH", "CRITICAL"):
            sig = self._crypto.sign(payload, self._priv_pem)
        block = AuditBlock(
            index=idx, timestamp_ns=ts, event_type=event_type,
            actor=actor, resource=resource, action=action,
            outcome=outcome, severity=severity, metadata=meta,
            prev_hash=prev_h, block_hash=block_hash,
            hmac_tag=hmac_tag, signature=sig
        )
        self._blocks.append(block)
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "a") as f:
            f.write(json.dumps(block.to_dict()) + "\n")
        return block

    def verify_chain(self) -> tuple[bool, list[str]]:
        issues = []
        prev_h = "0" * 64
        for i, blk in enumerate(self._blocks):
            if blk.prev_hash != prev_h:
                issues.append(f"Block {i}: prev_hash mismatch (CHAIN BREAK)")
            payload = json.dumps({
                "index": blk.index, "ts": blk.timestamp_ns, "type": blk.event_type,
                "actor": blk.actor, "resource": blk.resource, "action": blk.action,
                "outcome": blk.outcome, "severity": blk.severity, "meta": blk.metadata,
                "prev": blk.prev_hash
            }, sort_keys=True).encode()
            expected_hash = hashlib.sha3_256(payload).hexdigest()
            if blk.block_hash != expected_hash:
                issues.append(f"Block {i}: block_hash tampered (DATA CORRUPTION)")
            if not self._crypto.hmac_verify(payload, blk.hmac_tag, self._key):
                issues.append(f"Block {i}: HMAC invalid (POSSIBLE FORGERY)")
            prev_h = blk.block_hash
        return (len(issues) == 0), issues

    def query(self, severity_min: str = "INFO", limit: int = 100) -> list[AuditBlock]:
        min_level = self.SEVERITY_LEVELS.get(severity_min.upper(), 0)
        results = [b for b in self._blocks
                   if self.SEVERITY_LEVELS.get(b.severity, 0) >= min_level]
        return results[-limit:]

    def stats(self) -> dict:
        counts = {s: 0 for s in self.SEVERITY_LEVELS}
        for b in self._blocks:
            counts[b.severity] = counts.get(b.severity, 0) + 1
        return {"total": len(self._blocks), "by_severity": counts}
