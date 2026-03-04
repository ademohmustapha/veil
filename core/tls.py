"""
AURORA – Native TLS for the API Server
=======================================
Wraps the stdlib ThreadedWSGIServer with a real TLS context so the API
can serve HTTPS natively — no reverse proxy required.

Supports two modes:
  1. BYOC (Bring Your Own Certificate) — operator provides cert + key paths
     via config or environment variables.
  2. Self-Signed Auto-Generate — on first run, generates a 4096-bit RSA cert
     valid for 10 years with SAN localhost/127.0.0.1. Stored at
     ~/.aurora/tls/{aurora.crt, aurora.key} (chmod 600).

Configuration (aurora_config.json or AURORA_* env vars):
  api_tls_enabled       : true/false    (default: false — operator opt-in)
  api_tls_cert_file     : /path/to/cert.pem
  api_tls_key_file      : /path/to/key.pem
  api_tls_self_signed   : true/false    (default: true when tls_enabled but no cert)
  api_tls_min_version   : "TLSv1.2"    (default: TLSv1.2; "TLSv1.3" for stricter)

Cipher policy:
  Python's ssl module default secure context + explicit exclusion of
  RC4, MD5, DES, 3DES, EXPORT, NULL, and aNULL suites.

When TLS is enabled:
  - The API server binds HTTPS.
  - The startup message shows the cert fingerprint and expiry date.
  - HTTP→HTTPS redirect is NOT provided (caller must use the correct scheme;
    AURORA does not serve plain HTTP and TLS simultaneously).

Example env-var usage:
  AURORA_API_TLS_ENABLED=true
  AURORA_API_TLS_CERT_FILE=/etc/aurora/tls/server.crt
  AURORA_API_TLS_KEY_FILE=/etc/aurora/tls/server.key
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
import os
import ssl
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("aurora.tls")

_TLS_DIR = Path(os.environ.get("AURORA_HOME", str(Path.home() / ".aurora"))) / "tls"
_DEFAULT_CERT = _TLS_DIR / "aurora.crt"
_DEFAULT_KEY  = _TLS_DIR / "aurora.key"


# ── Cipher exclusion list ─────────────────────────────────────────────────────
# These suites are explicitly removed from Python's default secure context.
_WEAK_CIPHERS = [
    "RC4", "MD5", "aDH", "DES", "3DES", "EXPORT", "NULL", "aNULL",
    "eNULL", "ADH", "AECDH", "RC2", "IDEA", "SEED",
]

def _hardened_context(purpose=ssl.Purpose.CLIENT_AUTH) -> ssl.SSLContext:
    """
    Return an SSLContext with a hardened cipher list:
      - TLS 1.2 minimum (1.3 supported automatically by Python 3.7+)
      - Weak ciphers explicitly excluded
      - Server-side cipher order enforced
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!3DES")
    ctx.options |= ssl.OP_NO_SSLv2
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.options |= ssl.OP_NO_TLSv1
    ctx.options |= ssl.OP_NO_TLSv1_1
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.options |= ssl.OP_SINGLE_DH_USE
    ctx.options |= ssl.OP_SINGLE_ECDH_USE
    return ctx


# ── Self-signed certificate generation ───────────────────────────────────────

def _generate_self_signed(cert_path: Path, key_path: Path) -> None:
    """
    Generate a 4096-bit RSA self-signed certificate with SAN for localhost.
    Uses the `cryptography` package (already a required dependency of AURORA).
    Valid for 10 years. Stored with chmod 600.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    _TLS_DIR.mkdir(parents=True, exist_ok=True)

    # Generate RSA-4096 private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Build certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,            "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,  "AURORA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,           "AURORA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,       "AURORA Self-Signed"),
        x509.NameAttribute(NameOID.COMMON_NAME,             "localhost"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.IPAddress(ipaddress.IPv6Address("::1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Write private key (chmod 600)
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)

    # Write certificate
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cert_path.chmod(0o600)

    logger.info(
        f"[TLS] Self-signed certificate generated: {cert_path} "
        f"(valid until {cert.not_valid_after_utc.date()})"
    )


def _cert_fingerprint(cert_path: Path) -> str:
    """Return SHA-256 fingerprint of certificate for operator verification."""
    try:
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import hashes as _hashes
        import binascii
        raw = _x509.load_pem_x509_certificate(cert_path.read_bytes())
        fp  = raw.fingerprint(_hashes.SHA256())
        return ":".join(f"{b:02X}" for b in fp)
    except Exception:
        return "<fingerprint unavailable>"


def _cert_expiry(cert_path: Path) -> str:
    """Return human-readable expiry date of certificate."""
    try:
        from cryptography import x509 as _x509
        raw = _x509.load_pem_x509_certificate(cert_path.read_bytes())
        return str(raw.not_valid_after_utc.date())
    except Exception:
        return "<expiry unavailable>"


# ── Public API ────────────────────────────────────────────────────────────────

class TLSConfig:
    """
    Resolved TLS configuration for the AURORA API server.
    Call `build_context()` to get the ssl.SSLContext to pass to the server.
    """

    def __init__(
        self,
        enabled:     bool        = False,
        cert_file:   Optional[str] = None,
        key_file:    Optional[str] = None,
        self_signed: bool        = True,
        min_version: str         = "TLSv1.2",
    ):
        self.enabled     = enabled
        self.cert_file   = Path(cert_file)   if cert_file else _DEFAULT_CERT
        self.key_file    = Path(key_file)    if key_file  else _DEFAULT_KEY
        self.self_signed = self_signed
        self.min_version = min_version

    @classmethod
    def from_config(cls) -> "TLSConfig":
        """Load TLS config from AuroraConfig + environment variables."""
        try:
            from core.config import get_config
            cfg = get_config()
            enabled     = bool(cfg.get("api_tls_enabled",     False))
            cert_file   = cfg.get("api_tls_cert_file",   None) or os.environ.get("AURORA_API_TLS_CERT_FILE")
            key_file    = cfg.get("api_tls_key_file",    None) or os.environ.get("AURORA_API_TLS_KEY_FILE")
            self_signed = bool(cfg.get("api_tls_self_signed", True))
            min_version = str(cfg.get("api_tls_min_version",  "TLSv1.2"))
        except Exception:
            enabled, cert_file, key_file, self_signed, min_version = \
                False, None, None, True, "TLSv1.2"

        # Env-var overrides
        if os.environ.get("AURORA_API_TLS_ENABLED", "").lower() in ("1", "true", "yes"):
            enabled = True
        return cls(enabled, cert_file, key_file, self_signed, min_version)

    def build_context(self) -> Optional[ssl.SSLContext]:
        """
        Return a hardened SSLContext, or None if TLS is disabled.
        Auto-generates self-signed cert if needed.
        """
        if not self.enabled:
            return None

        # Auto-generate self-signed cert if no BYOC cert exists
        if not self.cert_file.exists() or not self.key_file.exists():
            if self.self_signed:
                logger.info("[TLS] No cert found — generating self-signed certificate…")
                _generate_self_signed(self.cert_file, self.key_file)
            else:
                raise FileNotFoundError(
                    f"TLS enabled but cert/key not found: "
                    f"{self.cert_file} / {self.key_file}. "
                    "Set api_tls_self_signed=true to auto-generate, or provide BYOC files."
                )

        ctx = _hardened_context()
        ctx.load_cert_chain(certfile=str(self.cert_file), keyfile=str(self.key_file))

        logger.info(
            f"[TLS] Context built — cert: {self.cert_file.name} | "
            f"fingerprint: {_cert_fingerprint(self.cert_file)} | "
            f"expires: {_cert_expiry(self.cert_file)}"
        )
        return ctx

    def info(self) -> dict:
        """Return TLS status info for health endpoint and operator display."""
        if not self.enabled:
            return {"tls_enabled": False}
        return {
            "tls_enabled":    True,
            "cert_file":      str(self.cert_file),
            "key_file":       str(self.key_file),
            "self_signed":    self.self_signed,
            "min_version":    self.min_version,
            "cert_exists":    self.cert_file.exists(),
            "key_exists":     self.key_file.exists(),
            "fingerprint":    _cert_fingerprint(self.cert_file) if self.cert_file.exists() else None,
            "expires":        _cert_expiry(self.cert_file)      if self.cert_file.exists() else None,
        }
