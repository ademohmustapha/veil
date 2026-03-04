"""Layer 2: SOIN-X — Secure Organisational Intelligence Core."""
from __future__ import annotations
import time, json, hashlib, secrets, base64
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from core.logger import AuditLogger

@dataclass
class SecureMessage:
    msg_id: str = ""; sender: str = ""; org_id: str = ""
    tier: str = "WORKFORCE"   # WORKFORCE|IT_SECURITY|EXECUTIVE
    content_hash: str = ""; encrypted: bool = True
    classification: str = "INTERNAL"   # PUBLIC|INTERNAL|CONFIDENTIAL|SECRET
    sent_at: float = field(default_factory=time.time)
    expiry_hours: int = 24; is_crisis: bool = False
    def to_dict(self): return asdict(self)

@dataclass
class DocumentVault:
    doc_id: str; org_id: str; title: str
    classification: str = "INTERNAL"
    hash_sha256: str = ""; hash_sha3: str = ""
    created_at: float = field(default_factory=time.time)
    expiry_ts: Optional[float] = None
    access_log: List[dict] = field(default_factory=list)
    revoked: bool = False
    def to_dict(self): return asdict(self)

class SOINXEngine:
    """Secure Org Intelligence: encrypted multi-tier communication, document vault, crisis command."""
    def __init__(self):
        self._log = AuditLogger()
        self._messages: Dict[str, List[SecureMessage]] = {}
        self._vault: Dict[str, DocumentVault] = {}
        self._crisis_active: Dict[str, bool] = {}
        self._load()

    def send_message(self, sender: str, org_id: str, content: str,
                     tier: str = "WORKFORCE", classification: str = "INTERNAL") -> SecureMessage:
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        msg = SecureMessage(msg_id=secrets.token_hex(10), sender=sender, org_id=org_id,
                            tier=tier, content_hash=content_hash, classification=classification)
        self._messages.setdefault(org_id, []).append(msg)
        self._log.log("L2_INTELLIGENCE", "MESSAGE_SENT",
            f"{sender}@{org_id} → {tier}/{classification}", "INFO")
        return msg

    def vault_document(self, org_id: str, title: str, content: bytes,
                       classification: str = "INTERNAL",
                       retention_days: int = 365) -> DocumentVault:
        sha256 = hashlib.sha256(content).hexdigest()
        sha3 = hashlib.sha3_256(content).hexdigest()
        expiry = time.time() + retention_days * 86400
        doc = DocumentVault(doc_id=secrets.token_hex(12), org_id=org_id, title=title,
                            classification=classification, hash_sha256=sha256,
                            hash_sha3=sha3, expiry_ts=expiry)
        self._vault[doc.doc_id] = doc
        self._log.log("L2_INTELLIGENCE", "DOCUMENT_VAULTED",
            f"{title} ({classification}) vaulted for {org_id}", "INFO",
            {"sha256": sha256[:16] + "..."})
        self._save()
        return doc

    def activate_crisis_command(self, org_id: str, activator: str, reason: str):
        self._crisis_active[org_id] = True
        self._log.log("L2_INTELLIGENCE", "CRISIS_COMMAND_ACTIVATED",
            f"{org_id}: Crisis mode by {activator}. Reason: {reason}", "CRITICAL",
            {"activator": activator, "reason": reason})
        return {"status": "CRISIS_ACTIVE", "org_id": org_id, "activated_by": activator,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    def deactivate_crisis(self, org_id: str, deactivator: str):
        self._crisis_active[org_id] = False
        self._log.log("L2_INTELLIGENCE", "CRISIS_COMMAND_DEACTIVATED",
            f"{org_id}: Deactivated by {deactivator}", "INFO")

    def is_crisis_active(self, org_id: str) -> bool:
        return self._crisis_active.get(org_id, False)

    def get_org_dashboard(self, org_id: str) -> dict:
        msgs = self._messages.get(org_id, [])
        vault_items = [d for d in self._vault.values() if d.org_id == org_id]
        return {"org_id": org_id, "message_count": len(msgs),
                "vault_documents": len(vault_items),
                "crisis_mode": self.is_crisis_active(org_id),
                "confidential_docs": sum(1 for d in vault_items if d.classification in ("CONFIDENTIAL","SECRET"))}

    def _files(self):
        from core.bootstrap import AURORA_HOME
        return AURORA_HOME / "soin_vault.json"
    def _save(self):
        try:
            f = self._files()
            f.write_text(json.dumps({k: v.to_dict() for k, v in self._vault.items()}, indent=2))
            f.chmod(0o600)
        except Exception: pass
    def _load(self):
        try:
            for k, v in json.loads(self._files().read_text()).items():
                self._vault[k] = DocumentVault(**v)
        except Exception: pass
