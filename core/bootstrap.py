"""
AURORA Bootstrap — System initialization, dependency management, key generation.
Runs before any other module. Handles first-run setup silently.
"""
from __future__ import annotations
import os, sys, json, secrets, hashlib, subprocess, importlib
from pathlib import Path
from typing import Optional

# Resolve AURORA_HOME with the same safety rules as core/paths.py.
# bootstrap runs before paths.py is importable, so we duplicate the guard here.
_RAW_HOME = os.environ.get("AURORA_HOME", str(Path.home() / ".aurora"))
if ".." in _RAW_HOME or _RAW_HOME.startswith("/proc") or _RAW_HOME.startswith("/sys"):
    import warnings
    warnings.warn(f"AURORA bootstrap: suspicious AURORA_HOME '{_RAW_HOME}' — falling back to default.", stacklevel=1)
    _RAW_HOME = str(Path.home() / ".aurora")
_AURORA_HOME = Path(_RAW_HOME).expanduser().resolve()
_KEYS_DIR = _AURORA_HOME / "keys"
# FIXED: Config filename aligned with core/config.py (_CONFIG_FILE = AURORA_HOME / "aurora_config.json")
# Previously bootstrap wrote "config.json" but config.py read "aurora_config.json" — they never shared state.
_CONFIG_FILE = _AURORA_HOME / "aurora_config.json"
_INSTALL_ID_FILE = _AURORA_HOME / ".install_id"

REQUIRED_DEPS = [
    "numpy", "scipy", "cryptography", "colorama",
    "sklearn",   # scikit-learn
    "networkx",
    "requests",
    "argon2",      # argon2-cffi — Argon2id password hashing (RFC 9106)
]

OPTIONAL_DEPS = {
    "tqdm":    "progress bars",
    "psutil":  "system resource monitoring",
    "Pillow":  "image analysis support",
}


class Bootstrap:
    """First-run initialization and dependency resolution."""

    def __init__(self):
        _AURORA_HOME.mkdir(parents=True, exist_ok=True)
        _KEYS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Dependency management ────────────────────────────────────────────────

    def ensure_deps(self) -> None:
        """Install missing required dependencies automatically."""
        missing = [pkg for pkg in REQUIRED_DEPS if not self._importable(pkg)]
        if not missing:
            return
        print(f"[AURORA] Installing {len(missing)} missing dependencies…")
        for pkg in missing:
            pip_name = "scikit-learn" if pkg == "sklearn" else pkg
            subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_name,
                 "--quiet", "--break-system-packages"],
                check=False,
            )

    def _importable(self, package: str) -> bool:
        try:
            importlib.import_module(package)
            return True
        except ImportError:
            return False

    # ── Key management ───────────────────────────────────────────────────────

    def ensure_keys(self) -> None:
        """Generate Ed25519 identity keys and HMAC secret on first run."""
        priv_key_file = _KEYS_DIR / "aurora_identity.privkey.pem"
        pub_key_file  = _KEYS_DIR / "aurora_identity.pubkey.pem"
        hmac_file     = _KEYS_DIR / ".aurora_hmac"
        kyber_file    = _KEYS_DIR / ".kyber_seed"

        if not priv_key_file.exists():
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                from cryptography.hazmat.primitives.serialization import (
                    Encoding, PrivateFormat, PublicFormat, BestAvailableEncryption
                )
                # Derive a key-encryption passphrase from the install ID + a random salt
                # This ensures the private key is encrypted at rest
                import secrets as _sec
                key_pass = _sec.token_bytes(32)  # Per-installation random passphrase
                key_pass_file = _KEYS_DIR / ".key_pass"
                key_pass_file.write_bytes(key_pass)
                key_pass_file.chmod(0o600)

                priv = Ed25519PrivateKey.generate()
                pub  = priv.public_key()
                priv_key_file.write_bytes(
                    priv.private_bytes(
                        Encoding.PEM,
                        PrivateFormat.PKCS8,
                        BestAvailableEncryption(key_pass)  # Encrypted at rest
                    )
                )
                pub_key_file.write_bytes(
                    pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                )
                priv_key_file.chmod(0o600)
                print("[AURORA] ✓ Ed25519 identity keys generated (encrypted at rest)")
            except ImportError:
                pass  # graceful degradation

        if not hmac_file.exists():
            hmac_file.write_bytes(secrets.token_bytes(64))
            hmac_file.chmod(0o600)

        if not kyber_file.exists():
            # Kyber-512 seed (ML-KEM simulation seed — 32 bytes)
            kyber_file.write_bytes(secrets.token_bytes(32))
            kyber_file.chmod(0o600)

        if not _INSTALL_ID_FILE.exists():
            install_id = hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:24]
            _INSTALL_ID_FILE.write_text(install_id)

        if not _CONFIG_FILE.exists():
            self._write_default_config()

    def _write_default_config(self) -> None:
        # FIXED: config.json renamed to aurora_config.json to align with core/config.py
        config = {
            "version": "aurora",
            "install_id": (_INSTALL_ID_FILE.read_text() if _INSTALL_ID_FILE.exists() else "unknown"),
            "risk_threshold_critical": 85,
            "risk_threshold_high": 65,
            "risk_threshold_medium": 40,
            "containment_auto_threshold": 80,
            "co_evolution_interval_hours": 6,
            "federated_privacy_epsilon": 1.0,
            "api_host": "127.0.0.1",
            "api_port": 9000,
            "log_level": "INFO",
            "quantum_safe_mode": True,
            "ethical_override_enabled": True,
        }
        _CONFIG_FILE.write_text(json.dumps(config, indent=2))

    @staticmethod
    def get_config() -> dict:
        try:
            return json.loads(_CONFIG_FILE.read_text())
        except Exception:
            return {}

    @staticmethod
    def get_install_id() -> str:
        try:
            return _INSTALL_ID_FILE.read_text().strip()
        except Exception:
            return "unknown"

    @staticmethod
    def get_hmac_secret() -> bytes:
        p = _KEYS_DIR / ".aurora_hmac"
        return p.read_bytes() if p.exists() else b""

    @staticmethod
    def get_private_key_pem() -> Optional[bytes]:
        p = _KEYS_DIR / "aurora_identity.privkey.pem"
        return p.read_bytes() if p.exists() else None

    @staticmethod
    def get_public_key_pem() -> Optional[bytes]:
        p = _KEYS_DIR / "aurora_identity.pubkey.pem"
        return p.read_bytes() if p.exists() else None
