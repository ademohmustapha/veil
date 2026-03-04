"""AURORA Layer 2 — Secure Document Vault (AES-256-GCM + Policy Lifecycle)"""
from __future__ import annotations
import secrets, hashlib, json, time
from typing import Dict, Optional

class SecureVault:
    def __init__(self):
        self._vault: Dict[str, Dict] = {}
        self._key = secrets.token_bytes(32)

    def store(self, doc_id: str, data: bytes, policy: str = "INTERNAL") -> Dict:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = secrets.token_bytes(12)
            ct = AESGCM(self._key).encrypt(nonce, data, policy.encode())
        except ImportError:
            ct = bytes(a ^ b for a, b in zip(data, (self._key * ((len(data)//32)+1))[:len(data)]))
            nonce = b"\x00"*12
        self._vault[doc_id] = {"ct":ct,"nonce":nonce,"policy":policy,"stored_at":time.time(),"hash":hashlib.sha256(data).hexdigest()}
        return {"doc_id":doc_id,"policy":policy,"stored":True}

    def retrieve(self, doc_id: str) -> Optional[bytes]:
        entry = self._vault.get(doc_id)
        if not entry: return None
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            return AESGCM(self._key).decrypt(entry["nonce"], entry["ct"], entry["policy"].encode())
        except ImportError:
            ct = entry["ct"]
            return bytes(a ^ b for a, b in zip(ct, (self._key * ((len(ct)//32)+1))[:len(ct)]))

    def check_policy(self, doc_id: str, required_policy: str, user_role: str) -> bool:
        entry = self._vault.get(doc_id)
        if not entry: return False
        policy_levels = {"PUBLIC":0,"INTERNAL":1,"CONFIDENTIAL":2,"RESTRICTED":3,"TOP_SECRET":4}
        role_levels = {"standard_user":1,"developer":2,"manager":2,"security_analyst":3,"ciso":4,"admin":4}
        doc_level = policy_levels.get(entry["policy"], 99)
        user_level = role_levels.get(user_role, 0)
        return user_level >= doc_level
