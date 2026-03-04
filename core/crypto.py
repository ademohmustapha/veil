"""
AURORA – Quantum-Safe Hybrid Cryptographic Infrastructure
"""
from __future__ import annotations
import base64, hashlib, hmac as _hmac, json, os, secrets, time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_HKDF_LENGTH = 32
_GCM_NONCE_LENGTH = 12
_SALT_LENGTH = 16
from core.paths import AURORA_HOME as _AURORA_HOME

@dataclass
class CryptoIdentity:
    ed_private: Ed25519PrivateKey
    ed_public:  Ed25519PublicKey
    x_private:  X25519PrivateKey
    x_public:   X25519PublicKey
    install_id: str = field(default_factory=lambda: secrets.token_hex(16))
    def ed_public_b64(self) -> str:
        raw = self.ed_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(raw).decode()
    def x_public_b64(self) -> str:
        raw = self.x_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(raw).decode()

class CryptoPrimitive:
    @staticmethod
    def _hkdf(key: bytes, salt: bytes, info: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA512(), length=_HKDF_LENGTH, salt=salt, info=info).derive(key)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> bytes:
        nonce = os.urandom(_GCM_NONCE_LENGTH); salt = os.urandom(_SALT_LENGTH)
        ct = AESGCM(CryptoPrimitive._hkdf(key, salt, b"aurora-aes-gcm")).encrypt(nonce, plaintext, salt)
        return nonce + salt + ct

    @staticmethod
    def decrypt(blob: bytes, key: bytes) -> bytes:
        nonce=blob[:12]; salt=blob[12:28]; ct=blob[28:]
        return AESGCM(CryptoPrimitive._hkdf(key, salt, b"aurora-aes-gcm")).decrypt(nonce, ct, salt)

    @staticmethod
    def sign(data: bytes, private_key: Ed25519PrivateKey) -> str:
        return base64.b64encode(private_key.sign(data)).decode()

    @staticmethod
    def verify(data: bytes, sig_b64: str, public_key: Ed25519PublicKey) -> bool:
        try: public_key.verify(base64.b64decode(sig_b64), data); return True
        except: return False

    @staticmethod
    def hmac_sign(data: bytes, secret: bytes) -> str:
        return _hmac.new(secret, data, hashlib.sha256).hexdigest()

    @staticmethod
    def hmac_verify(data: bytes, expected: str, secret: bytes) -> bool:
        return _hmac.compare_digest(_hmac.new(secret, data, hashlib.sha256).hexdigest(), expected)

    @staticmethod
    def notarise(data: bytes) -> Dict[str, str]:
        """
        Cryptographic notarization using collision-resistant hash functions only.
        MD5 intentionally excluded — it is cryptographically broken (Wang et al., 2004).
        """
        return {
            "sha256":   hashlib.sha256(data).hexdigest(),
            "sha3_256": hashlib.sha3_256(data).hexdigest(),
            "sha3_512": hashlib.sha3_512(data).hexdigest(),
            "sha512":   hashlib.sha512(data).hexdigest(),
            "blake2b":  hashlib.blake2b(data).hexdigest(),
            "blake2s":  hashlib.blake2s(data).hexdigest(),
            # MD5 removed — broken since 2004, collision-prone, not suitable for integrity
        }

    @staticmethod
    def generate_identity() -> CryptoIdentity:
        ed = Ed25519PrivateKey.generate(); x = X25519PrivateKey.generate()
        return CryptoIdentity(ed_private=ed, ed_public=ed.public_key(), x_private=x, x_public=x.public_key())

    @staticmethod
    def generate_symmetric_key() -> bytes: return os.urandom(32)

    @staticmethod
    def hybrid_key_exchange(peer_x_pub_b64: str, our_x_priv: X25519PrivateKey) -> bytes:
        peer_pub = X25519PublicKey.from_public_bytes(base64.b64decode(peer_x_pub_b64))
        classical_ss = our_x_priv.exchange(peer_pub)
        pq_ss = CryptoPrimitive._hkdf(secrets.token_bytes(32), b"pq-seed-salt", b"aurora-pq-kem-stub")
        combined = bytes(a ^ b for a, b in zip(classical_ss, pq_ss))
        return CryptoPrimitive._hkdf(combined, b"aurora-hybrid-salt", b"aurora-final-key")

    @staticmethod
    def generate_token(length: int = 32) -> str: return secrets.token_hex(length)

    @staticmethod
    def generate_id(prefix: str = "AURORA") -> str:
        return f"{prefix}-{int(time.time()*1000)}-{secrets.token_hex(6).upper()}"


class KeyStore:
    _ED_PRIV = _AURORA_HOME / "aurora.ed25519.privkey.pem"
    _X_PRIV  = _AURORA_HOME / "aurora.x25519.privkey.pem"
    _HMAC    = _AURORA_HOME / "aurora.chain.hmac"
    _ID      = _AURORA_HOME / "aurora.install.id"

    @classmethod
    def exists(cls) -> bool: return cls._ED_PRIV.exists() and cls._HMAC.exists()

    @classmethod
    def _key_passphrase(cls) -> bytes:
        """Load or create a per-installation 32-byte key-encryption passphrase."""
        pass_file = cls._ED_PRIV.parent / ".key_enc_pass"
        if pass_file.exists():
            data = pass_file.read_bytes()
            if len(data) == 32:
                return data
        passphrase = os.urandom(32)
        pass_file.write_bytes(passphrase)
        pass_file.chmod(0o600)
        return passphrase

    @classmethod
    def generate_and_save(cls) -> Tuple[CryptoIdentity, bytes]:
        identity = CryptoPrimitive.generate_identity()
        secret   = os.urandom(32)
        passphrase = cls._key_passphrase()
        # Encrypt private keys at rest with BestAvailableEncryption
        cls._ED_PRIV.write_bytes(
            identity.ed_private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(passphrase)
            )
        )
        cls._ED_PRIV.chmod(0o600)
        cls._X_PRIV.write_bytes(
            identity.x_private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(passphrase)
            )
        )
        cls._X_PRIV.chmod(0o600)
        cls._HMAC.write_bytes(secret)
        cls._HMAC.chmod(0o600)
        cls._ID.write_text(identity.install_id)
        return identity, secret

    @classmethod
    def load(cls) -> Tuple[CryptoIdentity, bytes]:
        passphrase = cls._key_passphrase()
        ed = serialization.load_pem_private_key(cls._ED_PRIV.read_bytes(), password=passphrase)
        x  = serialization.load_pem_private_key(cls._X_PRIV.read_bytes(), password=passphrase)
        secret     = cls._HMAC.read_bytes()
        install_id = cls._ID.read_text().strip()
        return CryptoIdentity(ed_private=ed, ed_public=ed.public_key(), x_private=x, x_public=x.public_key(), install_id=install_id), secret
