"""AURORA – Self-Hardening Watchdog (security guards for the tool itself)"""
from __future__ import annotations
import hashlib, os, re, time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

MAX_BODY_BYTES = 10 * 1024 * 1024
MAX_STRING_LEN = 65_536
MAX_PATH_LEN = 4096
DEFAULT_RATE_LIMIT = 120
BURST_LIMIT = 20

_PATH_TRAVERSAL_RE = re.compile(r"\.\.[/\\]")
_NULL_BYTE_RE = re.compile(r"\x00")
_HTML_INJECTION_RE = re.compile(r"[<>\"']")
_INTEGRITY_FILES = ["core/crypto.py","core/bootstrap.py","audit/immutable_log.py","engines/ethics.py","aurora.py"]

class ValidationError(Exception): pass
class RateLimitExceeded(Exception): pass

class InputSanitiser:
    @staticmethod
    def string(v: Any, max_len: int = MAX_STRING_LEN, allow_html: bool = False) -> str:
        if not isinstance(v, str):
            try: v = str(v)
            except: raise ValidationError("Cannot convert to string")
        if _NULL_BYTE_RE.search(v): raise ValidationError("Null bytes not allowed")
        if len(v) > max_len: raise ValidationError(f"Input exceeds max length {max_len}")
        if not allow_html: v = _HTML_INJECTION_RE.sub("", v)
        return v

    @staticmethod
    def path(v: Any) -> Path:
        s = str(v)
        if _NULL_BYTE_RE.search(s): raise ValidationError("Null byte in path")
        if _PATH_TRAVERSAL_RE.search(s): raise ValidationError(f"Path traversal attempt: {s!r}")
        if len(s) > MAX_PATH_LEN: raise ValidationError("Path too long")
        return Path(s)

    @staticmethod
    def numeric(v: Any, lo: float, hi: float, name: str = "value") -> float:
        try: n = float(v)
        except: raise ValidationError(f"{name} must be numeric")
        if not (lo <= n <= hi): raise ValidationError(f"{name}={n} out of range [{lo},{hi}]")
        return n

    @staticmethod
    def body_size(data: bytes) -> bytes:
        if len(data) > MAX_BODY_BYTES: raise ValidationError(f"Body too large: {len(data)}")
        return data

class RateLimiter:
    def __init__(self, max_per_min: int = DEFAULT_RATE_LIMIT, burst: int = BURST_LIMIT):
        self._max = max_per_min; self._burst = burst
        self._wins: Dict[str, deque] = defaultdict(deque)
        self._bursts: Dict[str, deque] = defaultdict(deque)

    def check(self, source: str) -> None:
        now = time.time()
        w = self._wins[source]
        while w and w[0] < now - 60: w.popleft()
        if len(w) >= self._max: raise RateLimitExceeded(f"{source!r} exceeded {self._max} req/min")
        w.append(now)
        b = self._bursts[source]
        while b and b[0] < now - 5: b.popleft()
        if len(b) >= self._burst: raise RateLimitExceeded(f"{source!r} exceeded burst limit")
        b.append(now)

    def status(self, source: str) -> Dict[str, Any]:
        now = time.time()
        w = self._wins.get(source, deque())
        recent = sum(1 for t in w if t > now - 60)
        return {"source": source, "requests_last_60s": recent, "limit_per_minute": self._max, "headroom": max(0, self._max - recent)}

class SelfIntegrityChecker:
    _BASELINE_FILE = Path(os.environ.get("AURORA_HOME", str(Path.home() / ".aurora"))) / "aurora.integrity.json"
    _ROOT = Path(__file__).parent.parent

    @classmethod
    def compute_baseline(cls) -> Dict[str, str]:
        import json
        hashes = {}
        for rel in _INTEGRITY_FILES:
            p = cls._ROOT / rel
            if p.exists(): hashes[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
        cls._BASELINE_FILE.write_text(json.dumps(hashes, indent=2))
        return hashes

    @classmethod
    def verify(cls) -> Dict[str, Any]:
        import json
        if not cls._BASELINE_FILE.exists():
            baseline = cls.compute_baseline()
            return {"status": "baseline_created", "files_checked": len(baseline), "tampered": []}
        baseline = json.loads(cls._BASELINE_FILE.read_text())
        tampered, missing, ok = [], [], []
        for rel, expected in baseline.items():
            p = cls._ROOT / rel
            if not p.exists(): missing.append(rel); continue
            current = hashlib.sha256(p.read_bytes()).hexdigest()
            (ok if current == expected else tampered).append(rel)
        return {"status": "ok" if not tampered and not missing else "TAMPERED",
                "files_ok": len(ok), "tampered": tampered, "missing": missing,
                "integrity_verified": len(tampered) == 0 and len(missing) == 0}

class HardeningMiddleware:
    def __init__(self):
        self._rl = RateLimiter()
    def process(self, source_ip: str, path: str, body: Optional[bytes] = None) -> None:
        self._rl.check(source_ip)
        InputSanitiser.path(path)
        if body: InputSanitiser.body_size(body)
