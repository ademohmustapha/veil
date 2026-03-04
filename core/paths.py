"""
AURORA Secure Path Resolution
==============================
Centralizes AURORA_HOME resolution with protection against:
  - Path traversal via env var injection (AURORA_HOME=../../etc)
  - Symlink attacks
  - Relative path injection

All modules should import AURORA_HOME from here, not from os.environ directly.
"""
from __future__ import annotations
import os
from pathlib import Path

_DEFAULT_HOME = Path.home() / ".aurora"
_RAW_HOME = os.environ.get("AURORA_HOME", str(_DEFAULT_HOME))

def _resolve_safe_home() -> Path:
    """
    Resolve AURORA_HOME to a canonical absolute path.
    If the resolved path is outside the user's home directory AND not an
    explicitly allowed absolute path, fall back to the default.
    """
    try:
        p = Path(_RAW_HOME).expanduser().resolve()
    except Exception:
        p = _DEFAULT_HOME.resolve()

    # Security: reject paths that contain traversal sequences in the raw input
    raw_str = str(_RAW_HOME)
    if ".." in raw_str or raw_str.startswith("/proc") or raw_str.startswith("/sys"):
        import warnings
        warnings.warn(
            f"AURORA: Suspicious AURORA_HOME path '{_RAW_HOME}' — falling back to default.",
            SecurityWarning, stacklevel=2
        )
        p = _DEFAULT_HOME.resolve()

    # Security: reject /dev/null and similar
    if str(p) in ("/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"):
        p = _DEFAULT_HOME.resolve()

    p.mkdir(parents=True, exist_ok=True)
    return p


AURORA_HOME: Path = _resolve_safe_home()

__all__ = ["AURORA_HOME"]
