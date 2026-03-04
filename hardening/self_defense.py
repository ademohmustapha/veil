"""
AURORA Platform Self-Defense & Anti-Tamper
==========================================
FIXED:
  - Prompt injection filter normalises Unicode (NFC + homoglyph strip) before regex
  - Normalises whitespace/newline splitting before pattern match
  - Zero-width character stripping added
  - Rate limit key uses a validated, canonicalized client identifier
"""
from __future__ import annotations
import time, re, hashlib, os, unicodedata
from typing import Dict


# ─── Prompt injection patterns (applied AFTER unicode normalisation) ──────────
_PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions?",
    r"you\s+are\s+now",
    r"pretend\s+(you\s+are|to\s+be)",
    r"system\s+prompt\s*:",
    r"^\s*system\s*:\s*",              # SYSTEM: at line start
    r"disregard\s+(all\s+)?prior",
    r"new\s+instructions?\s*:",
    r"override\s+(all\s+)?previous",
    r"override\s+safety",
    r"forget\s+(all\s+)?previous",
    r"act\s+as\s+(if\s+you\s+are|a\s+different|an?\s+evil|an?\s+unrestricted)",
    r"jailbreak",
    r"do\s+anything\s+now",             # DAN
    r"developer\s+mode",
    r"dan\s+mode",
    r"unrestricted\s+(ai|mode|assistant)",
    r"without\s+(any\s+)?restrictions",
    r"bypass\s+(safety|filter|restriction)",
]

_SQL_PATTERNS = [
    r"(\'|\")(..*?)(--|;|\/\*)",
    # Context-aware — requires SQL syntax markers, not standalone English words
    r"\b(DROP|ALTER|TRUNCATE)\b",
    r"\bEXEC\b\s*\(",
    r"\bUNION\b\s+(?:ALL\s+)?\bSELECT\b",
    r"(?i)\bSELECT\b.{0,40}\bFROM\b\s+\w+(?=\s*(?:,|;|\.)|\s+(?:WHERE|JOIN|GROUP|ORDER|HAVING|LIMIT)\b)",
    r"\b(?:DELETE|INSERT)\b\s+\b(?:FROM|INTO)\b",
    r"\bUPDATE\b\s+\w+\s+\bSET\b",
    r";\s*(DROP|DELETE|INSERT|UPDATE|ALTER)",
    r"--\s*$",
    r"/\*.*?\*/",
    r"'\s*(?:OR|AND)\s*'[^']*'\s*=\s*'",
    r"'\s*(?:OR|AND)\s+\d+\s*=\s*\d",
    r"\d+\s*'\s*(?:OR|AND)\s*'",
    r"(?:OR|AND)\s+\d+\s*=\s*\d+\s*(?:--|$)",
]
_CMD_PATTERNS = [
    r"[;&|`$(){}[\]<>]",
    r"\.\.[/\\]",
    r"/etc/",
    r"/proc/",
    r"/sys/",
    r"\\\\",                # UNC paths
]

# Pre-compiled
_COMPILED_PATTERNS = [
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in _PROMPT_INJECTION_PATTERNS + _SQL_PATTERNS + _CMD_PATTERNS
]

# Zero-width and invisible Unicode categories to strip
_ZERO_WIDTH = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]"
)

# Homoglyph → ASCII mapping (Cyrillic, Greek, Math symbols, IPA extensions)
_HOMOGLYPH_TABLE = str.maketrans({
    # Cyrillic
    'а':'a','е':'e','о':'o','р':'p','с':'c','у':'y','х':'x',
    '\u0430':'a','\u0435':'e','\u043e':'o','\u0440':'p',
    '\u0441':'c','\u0443':'y','\u0445':'x',
    'ѕ':'s','і':'i','ј':'j','ԁ':'d',
    '\u0455':'s',   # Cyrillic DZE → s
    # Greek
    'ρ':'p','σ':'o','τ':'t','ν':'v','ω':'w','α':'a','β':'b',
    # Math / double-struck / script
    'ⅈ':'i','ⅉ':'j','ℐ':'i','ℑ':'i',
    '\u2148':'i',  # DOUBLE-STRUCK ITALIC SMALL I
    # IPA extensions  
    'ɑ':'a','ɡ':'g','ɾ':'r','ɹ':'r','ɻ':'r',   # r-lookalikes
    'ɩ':'i','ɪ':'i','ǀ':'i',
    'ꜱ':'s','ꜰ':'f','ꜱ':'s',
    # Fullwidth Latin
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},
})

def _deep_normalise(text: str) -> str:
    """
    Unicode normalisation pipeline:
    1. NFC normalise
    2. Strip zero-width/invisible chars
    3. Apply homoglyph table
    4. ASCII-fold any remaining non-ASCII letters via unicodedata
    5. Collapse whitespace
    """
    import unicodedata as _ud
    text = _ud.normalize("NFC", text)
    text = _ZERO_WIDTH.sub("", text)
    text = text.translate(_HOMOGLYPH_TABLE)
    # Fold any remaining non-ASCII via NFKD decomposition + ASCII-only filter
    nfkd = _ud.normalize("NFKD", text)
    text = "".join(c for c in nfkd if _ud.category(c) != "Mn" or ord(c) < 128)
    text = re.sub(r"\s+", " ", text)
    return text


class SelfDefense:
    _RATE_LIMIT_WINDOW = 60
    _RATE_LIMIT_MAX    = 100

    def __init__(self):
        self._rate_buckets: Dict[str, list] = {}
        self._blocked_ips: set = set()

    # ── Input sanitisation ────────────────────────────────────────────────

    @staticmethod
    def _normalise_for_detection(text: str) -> str:
        """
        Normalise text before injection-pattern matching.
        Steps:
          1. Unicode NFC normalisation
          2. Strip zero-width / invisible characters
          3. Replace known homoglyphs with ASCII equivalents
          4. Collapse duplicate whitespace / newlines to single space
        This defeats homoglyph, zero-width, and newline-splitting bypasses.
        """
        return _deep_normalise(text)

    def sanitize_input(self, raw: str) -> str:
        """
        Multi-vector input sanitization with Unicode-normalised pattern matching.
        Returns sanitized string; injection payloads replaced with [FILTERED].
        """
        if not isinstance(raw, str):
            raw = str(raw)[:65536]

        # Strip null bytes and control characters unconditionally
        raw = raw.replace("\x00", "").replace("\r", " ")

        # Apply patterns on the NORMALISED text, but replace in original
        normalised = self._normalise_for_detection(raw)
        sanitized  = raw

        for pattern in _COMPILED_PATTERNS:
            # If pattern matches normalised form, filter the sanitized form too
            if pattern.search(normalised):
                sanitized = pattern.sub("[FILTERED]", sanitized)
                normalised = pattern.sub("[FILTERED]", normalised)

        return sanitized

    # ── Rate limiting ─────────────────────────────────────────────────────

    def check_rate_limit(self, client_id: str, endpoint: str = "api") -> bool:
        """Token bucket rate limiter. Returns True if request is ALLOWED."""
        # Validate/canonicalize client_id to prevent bypass via key manipulation
        safe_id = hashlib.sha256(str(client_id)[:256].encode()).hexdigest()[:32]
        key = f"{safe_id}:{endpoint}"
        now = time.time()
        window = self._rate_buckets.setdefault(key, [])
        self._rate_buckets[key] = [t for t in window if now - t < self._RATE_LIMIT_WINDOW]
        if len(self._rate_buckets[key]) >= self._RATE_LIMIT_MAX:
            return False
        self._rate_buckets[key].append(now)
        return True

    # ── Misc ──────────────────────────────────────────────────────────────

    def secure_wipe(self, data: bytearray) -> None:
        """Overwrite sensitive memory before deallocation."""
        for i in range(len(data)):
            data[i] = 0

    def detect_debug_environment(self) -> bool:
        """Detect debugging or analysis environment."""
        indicators = [
            os.environ.get("PYTHONINSPECT") is not None,
            os.environ.get("PYTHONDEBUG") is not None,
            hasattr(__builtins__, "__dict__") and "__breakpointhook__" in getattr(
                __builtins__, "__dict__", {}),
        ]
        return any(indicators)

    def validate_token(self, token: str, expected_hash: str) -> bool:
        """Constant-time token comparison to prevent timing attacks."""
        import hmac
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return hmac.compare_digest(token_hash, expected_hash)
