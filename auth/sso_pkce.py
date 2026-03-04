"""
AURORA — SSO / OIDC Authentication with PKCE (RFC 7636)
=========================================================
Full Authorization Code Flow + PKCE for CLI and server contexts.

Supported IdP types:
  • Generic OIDC (Okta, Auth0, Azure AD, Keycloak, Google Workspace, …)
  • GitHub OAuth2 (code flow with state; PKCE not supported by GitHub OAuth)
  • Microsoft Entra ID (Azure AD) — tenant-path handling

PKCE (RFC 7636):
  • Method: S256 (SHA-256, mandatory for FIPS environments)
  • code_verifier: 96 bytes CSPRNG → 128-char BASE64URL (unreserved chars only)
  • code_challenge = BASE64URL(SHA256(ASCII(verifier)))
  • State: 32 URL-safe random bytes (CSRF protection)
  • Pending sessions stored in a process-level dict AND optionally in a
    file-based session store (AURORA_SSO_SESSION_STORE env var or config)
    so restarts during active flows don't silently orphan state.

Token persistence (NOC-screen friendly):
  • A short-lived signed session cookie is issued by the dashboard endpoint
    (dashboard/live_dashboard.py serves GET /dashboard/token-refresh).
  • The cookie (HttpOnly; SameSite=Strict; Secure on HTTPS) carries a
    server-side signed session ID. The actual token is stored in a
    per-session file under AURORA_HOME/sso_sessions/. The file is
    deleted on logout or expiry.
  • For non-browser contexts (CLI, API), the token is held in memory only
    and never written to disk.

SSO session cleanup:
  • Pending PKCE sessions (state → {verifier, nonce, started_at}) are stored
    in _AURORA_HOME/sso_pending.json when AURORA_SSO_PERSIST_PENDING=true.
  • Entries older than _PKCE_TTL_S (600 s) are evicted on every load.
  • On server restart, the persisted pending sessions are restored, so an
    in-flight PKCE flow can still complete.

Configuration — ~/.aurora/sso.json  OR  environment variables:
  {
    "provider":          "oidc",
    "client_id":         "${AURORA_SSO_CLIENT_ID}",
    "client_secret":     "${AURORA_SSO_CLIENT_SECRET}",
    "issuer":            "${AURORA_SSO_ISSUER}",
    "redirect_uri":      "http://localhost:9101/callback",
    "scopes":            ["openid","profile","email"],
    "pkce":              true,
    "tenant_id":         "${AURORA_SSO_TENANT_ID}",
    "persist_pending":   true,
    "session_ttl":       3600
  }
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("aurora.sso")

# ── Config ────────────────────────────────────────────────────────────────────

try:
    from core.paths import AURORA_HOME as _AURORA_HOME
except ImportError:
    _AURORA_HOME = Path.home() / ".aurora"

_CONFIG_FILE       = _AURORA_HOME / "sso.json"
_PENDING_FILE      = _AURORA_HOME / "sso_pending.json"   # persisted PKCE sessions
_SESSION_DIR       = _AURORA_HOME / "sso_sessions"        # NOC token store
_COOKIE_NAME       = "aurora_session"
_CALLBACK_PORT_DEFAULT = 9101
_CALLBACK_TIMEOUT_S    = 120
_PKCE_TTL_S            = 600   # 10 min: max time for browser to complete auth
_SESSION_TTL_DEFAULT   = 3600  # 1 h default session lifetime

# HMAC key for session cookie signing (per-process, non-persistent)
# Non-persistent is intentional: a server restart invalidates all cookies,
# forcing re-authentication — acceptable for security tools.
_COOKIE_SIGN_KEY = secrets.token_bytes(32)


def _resolve(val: Any) -> str:
    if isinstance(val, str) and val.startswith("${") and val.endswith("}"):
        key = val[2:-1]; return os.environ.get(key, "")
    return str(val) if val else ""


def _load_config() -> Dict:
    cfg: Dict = {}
    try:
        if _CONFIG_FILE.exists():
            cfg = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("[sso] config load failed: %s", exc)
    for k, env in [("client_id","AURORA_SSO_CLIENT_ID"),
                   ("client_secret","AURORA_SSO_CLIENT_SECRET"),
                   ("issuer","AURORA_SSO_ISSUER"),
                   ("redirect_uri","AURORA_SSO_REDIRECT_URI"),
                   ("tenant_id","AURORA_SSO_TENANT_ID"),
                   ("provider","AURORA_SSO_PROVIDER")]:
        if os.environ.get(env) and k not in cfg:
            cfg[k] = os.environ[env]
    if os.environ.get("AURORA_SSO_PERSIST_PENDING","").lower() in ("1","true","yes"):
        cfg.setdefault("persist_pending", True)
    return cfg


# ── PKCE (RFC 7636) ───────────────────────────────────────────────────────────

def _generate_pkce_pair() -> Tuple[str, str]:
    """
    Generate (code_verifier, code_challenge) per RFC 7636 §4.1/§4.2.
    code_verifier : 96 bytes CSPRNG → 128-char BASE64URL (unreserved chars only)
    code_challenge: BASE64URL(SHA-256(ASCII(verifier)))  [S256]
    """
    verifier_bytes = secrets.token_bytes(96)
    code_verifier  = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=").decode("ascii")
    digest         = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _generate_state() -> str:
    return secrets.token_urlsafe(32)


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _https_get(url: str, timeout: int = 10) -> Dict:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "AURORA-SSO/1",
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
        return json.loads(resp.read())


def _https_post_form(url: str, data: Dict, timeout: int = 15) -> Dict:
    ctx  = ssl.create_default_context()
    body = urllib.parse.urlencode(data).encode("utf-8")
    req  = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept":       "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        raise SSOError(f"Token exchange HTTP {exc.code}: {text[:300]}") from exc


# ── Session cookie signing ────────────────────────────────────────────────────

def _sign_session_id(session_id: str) -> str:
    """Return a signed session token: session_id.hmac_hex."""
    mac = _hmac.new(_COOKIE_SIGN_KEY, session_id.encode(), "sha256").hexdigest()
    return f"{session_id}.{mac}"


def _verify_session_id(token: str) -> Optional[str]:
    """Return session_id if signature is valid, else None."""
    if "." not in token: return None
    sid, _, mac = token.rpartition(".")
    expected = _hmac.new(_COOKIE_SIGN_KEY, sid.encode(), "sha256").hexdigest()
    if not _hmac.compare_digest(mac, expected): return None
    return sid


# ── Server-side session store (NOC cookie support) ───────────────────────────

class _SessionStore:
    """
    File-backed, in-memory-cached session store for NOC dashboard tokens.

    Each session is stored as a JSON file at:
      AURORA_HOME/sso_sessions/<session_id>.json

    The session file contains: {access_token, id_token, refresh_token,
    expires_at, user_sub, user_email, issued_at}

    Files are deleted on logout or after their expires_at timestamp.
    The directory is created with mode 0o700 (owner-only access).
    """

    def __init__(self):
        self._dir  = _SESSION_DIR
        self._lock = threading.Lock()
        try:
            self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning("[sso] session dir creation failed: %s", exc)

    def create(self, token_resp: "TokenResponse", user_info: Optional["UserInfo"] = None,
               ttl: Optional[int] = None) -> str:
        """Persist a token and return a signed session cookie value.
        ttl defaults to token_resp.expires_in when not specified."""
        if ttl is None:
            ttl = token_resp.expires_in  # use token lifetime (0 = immediate expiry)
        session_id = secrets.token_urlsafe(32)
        data = {
            "access_token":  token_resp.access_token,
            "id_token":      token_resp.id_token,
            "refresh_token": token_resp.refresh_token,
            "expires_at":    time.time() + ttl,
            "issued_at":     token_resp.issued_at,
            "user_sub":      user_info.sub   if user_info else "",
            "user_email":    user_info.email if user_info else "",
        }
        path = self._dir / f"{session_id}.json"
        try:
            path.write_text(json.dumps(data), encoding="utf-8")
            path.chmod(0o600)
        except Exception as exc:
            logger.warning("[sso] session write failed: %s", exc)
        return _sign_session_id(session_id)

    def get(self, signed_token: str) -> Optional[Dict]:
        """Return session data or None if invalid / expired."""
        session_id = _verify_session_id(signed_token)
        if not session_id: return None
        path = self._dir / f"{session_id}.json"
        try:
            if not path.exists(): return None
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception: return None
        if time.time() > data.get("expires_at", 0):
            self.delete(signed_token)
            return None
        return data

    def delete(self, signed_token: str) -> None:
        """Delete a session (logout)."""
        session_id = _verify_session_id(signed_token)
        if not session_id: return
        path = self._dir / f"{session_id}.json"
        try:
            if path.exists(): path.unlink()
        except Exception as exc:
            logger.debug("[sso] session delete: %s", exc)

    def cookie_header(self, signed_token: str, ttl: int = _SESSION_TTL_DEFAULT,
                      secure: bool = False) -> str:
        """
        Build a Set-Cookie header value.
        Flags: HttpOnly; SameSite=Strict; Secure (when secure=True for HTTPS).
        """
        flags = [f"{_COOKIE_NAME}={signed_token}",
                 f"Max-Age={ttl}", "HttpOnly", "SameSite=Strict", "Path=/"]
        if secure: flags.append("Secure")
        return "; ".join(flags)

    def prune_expired(self) -> int:
        """Delete expired session files. Returns count of pruned files."""
        now = time.time(); count = 0
        try:
            for p in self._dir.glob("*.json"):
                try:
                    data = json.loads(p.read_text())
                    if now > data.get("expires_at", 0):
                        p.unlink(); count += 1
                except Exception:
                    pass
        except Exception: pass
        return count


_SESSION_STORE = _SessionStore()


# ── Pending PKCE session persistence ─────────────────────────────────────────

class _PendingSessionStore:
    """
    Optional file-backed store for in-flight PKCE pending sessions.

    If persist_pending=True (config or AURORA_SSO_PERSIST_PENDING=true),
    pending sessions (state → {verifier, nonce, started_at}) are serialised
    to _PENDING_FILE so a server restart during the PKCE auth flow can still
    complete the token exchange.

    Entries older than _PKCE_TTL_S are evicted on every load/save.
    """

    def __init__(self, persist: bool = False):
        self._persist = persist
        self._sessions: Dict[str, Dict] = {}
        self._lock = threading.Lock()
        if persist: self._load()

    def _load(self) -> None:
        try:
            if _PENDING_FILE.exists():
                data = json.loads(_PENDING_FILE.read_text(encoding="utf-8"))
                now  = time.time()
                self._sessions = {
                    k: v for k, v in data.items()
                    if now - v.get("started_at", 0) < _PKCE_TTL_S
                }
        except Exception as exc:
            logger.debug("[sso] pending load failed: %s", exc)

    def _save(self) -> None:
        if not self._persist: return
        now = time.time()
        live = {k: v for k, v in self._sessions.items()
                if now - v.get("started_at", 0) < _PKCE_TTL_S}
        try:
            _PENDING_FILE.write_text(json.dumps(live), encoding="utf-8")
            _PENDING_FILE.chmod(0o600)
        except Exception as exc:
            logger.debug("[sso] pending save failed: %s", exc)

    def put(self, state: str, session: Dict) -> None:
        with self._lock:
            self._sessions[state] = session
            # Evict expired entries
            now = time.time()
            expired = [s for s, d in self._sessions.items()
                       if now - d.get("started_at", 0) > _PKCE_TTL_S]
            for s in expired: del self._sessions[s]
            self._save()

    def pop(self, state: str) -> Optional[Dict]:
        with self._lock:
            session = self._sessions.pop(state, None)
            if session: self._save()
            return session

    def has(self, state: str) -> bool:
        with self._lock:
            sess = self._sessions.get(state)
            if not sess: return False
            if time.time() - sess.get("started_at", 0) > _PKCE_TTL_S:
                del self._sessions[state]; return False
            return True


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class TokenResponse:
    access_token:  str
    id_token:      str   = ""
    refresh_token: str   = ""
    expires_in:    int   = 3600
    token_type:    str   = "Bearer"
    scope:         str   = ""
    issued_at:     float = field(default_factory=time.time)

    @property
    def expired(self) -> bool:
        return time.time() > self.issued_at + self.expires_in - 30

    def to_dict(self) -> Dict:
        return {k: getattr(self, k) for k in
                ("access_token","id_token","refresh_token","expires_in",
                 "token_type","scope","issued_at")}

    @classmethod
    def from_dict(cls, d: Dict) -> "TokenResponse":
        return cls(**{k: d[k] for k in d if k in cls.__dataclass_fields__})


@dataclass
class UserInfo:
    sub:     str
    email:   str = ""
    name:    str = ""
    picture: str = ""
    raw:     Dict = field(default_factory=dict)


class SSOError(Exception): pass
class SSOStateError(SSOError): pass


# ── OIDC Discovery ────────────────────────────────────────────────────────────

class OIDCDiscovery:
    _cache: Dict[str, Dict] = {}
    _lock  = threading.Lock()

    @classmethod
    def get(cls, issuer: str) -> Dict:
        issuer = issuer.rstrip("/")
        with cls._lock:
            if issuer in cls._cache: return cls._cache[issuer]
        try:
            meta = _https_get(f"{issuer}/.well-known/openid-configuration")
        except Exception as exc:
            raise SSOError(f"OIDC discovery failed for {issuer}: {exc}") from exc
        with cls._lock: cls._cache[issuer] = meta
        return meta


# ── JWT validation ────────────────────────────────────────────────────────────

class JWTValidator:
    """
    Minimal OIDC ID token validator.
    Verifies: signature (RS256/ES256 via JWKS), iss, aud, exp, iat, nonce.
    Falls back to claims-only if `cryptography` not installed.
    """

    def __init__(self, issuer: str, client_id: str):
        self._issuer    = issuer
        self._client_id = client_id

    def validate(self, id_token: str, nonce: str = "") -> UserInfo:
        if not id_token: raise SSOError("id_token is empty")
        parts = id_token.split(".")
        if len(parts) != 3: raise SSOError("id_token not a valid JWT")
        header  = json.loads(self._b64d(parts[0]))
        payload = json.loads(self._b64d(parts[1]))
        now = time.time()
        if payload.get("exp", 0) and now > payload["exp"]:
            raise SSOError(f"id_token expired (exp={payload['exp']})")
        if payload.get("iat", now) > now + 60:
            raise SSOError("id_token iat is in the future")
        iss = payload.get("iss", "")
        if iss and iss.rstrip("/") != self._issuer.rstrip("/"):
            raise SSOError(f"iss mismatch: {iss} != {self._issuer}")
        aud = payload.get("aud", "")
        if isinstance(aud, list):
            if self._client_id not in aud: raise SSOError(f"aud {aud} missing client_id")
        elif aud and aud != self._client_id:
            raise SSOError(f"aud mismatch: {aud}")
        if nonce and payload.get("nonce", "") != nonce:
            raise SSOError("nonce mismatch")
        try:
            self._verify_sig(id_token, header.get("alg",""), header.get("kid",""))
        except ImportError:
            logger.warning("[sso] cryptography not installed — signature not verified (claims only)")
        except Exception as exc:
            raise SSOError(f"Signature invalid: {exc}") from exc
        return UserInfo(sub=payload.get("sub",""), email=payload.get("email",""),
                        name=payload.get("name","") or payload.get("preferred_username",""),
                        picture=payload.get("picture",""), raw=payload)

    def _b64d(self, s: str) -> bytes:
        pad = 4 - len(s) % 4
        if pad < 4: s += "=" * pad
        return base64.urlsafe_b64decode(s)

    def _verify_sig(self, id_token: str, alg: str, kid: str) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec, padding as _pad
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        meta     = OIDCDiscovery.get(self._issuer)
        jwks     = _https_get(meta.get("jwks_uri",""))
        keys     = jwks.get("keys",[])
        if not keys: raise SSOError("JWKS is empty")
        key_data = next((k for k in keys if k.get("kid") == kid), None) or keys[0]
        kty = key_data.get("kty","")
        if kty == "RSA":
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            n   = int.from_bytes(self._b64d(key_data["n"]), "big")
            e   = int.from_bytes(self._b64d(key_data["e"]), "big")
            pub = RSAPublicNumbers(e, n).public_key(default_backend())
        elif kty == "EC":
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePublicNumbers, SECP256R1, SECP384R1, SECP521R1)
            crv_map = {"P-256": SECP256R1(), "P-384": SECP384R1(), "P-521": SECP521R1()}
            crv = crv_map.get(key_data.get("crv","P-256"), SECP256R1())
            pub = EllipticCurvePublicNumbers(
                int.from_bytes(self._b64d(key_data["x"]),"big"),
                int.from_bytes(self._b64d(key_data["y"]),"big"), crv
            ).public_key(default_backend())
        else:
            raise SSOError(f"Unsupported key type: {kty}")
        parts = id_token.split(".")
        msg   = f"{parts[0]}.{parts[1]}".encode("ascii")
        sig   = self._b64d(parts[2])
        hash_map = {"RS256":hashes.SHA256(),"RS384":hashes.SHA384(),"RS512":hashes.SHA512(),
                    "ES256":hashes.SHA256(),"ES384":hashes.SHA384(),"ES512":hashes.SHA512()}
        halg = hash_map.get(alg, hashes.SHA256())
        if kty == "RSA":
            pub.verify(sig, msg, _pad.PKCS1v15(), halg)
        elif kty == "EC":
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            half = len(sig)//2
            r, s = int.from_bytes(sig[:half],"big"), int.from_bytes(sig[half:],"big")
            pub.verify(encode_dss_signature(r,s), msg, ec.ECDSA(halg))


# ── SSO flow engine ───────────────────────────────────────────────────────────

class SSOFlow:
    """
    OIDC Authorization Code Flow + PKCE (RFC 7636).

    Session cleanup on restart:
      When persist_pending=True, in-flight PKCE pending sessions survive
      server restarts. The callback handler restores the state from
      _AURORA_HOME/sso_pending.json and completes the token exchange.

    NOC token persistence:
      authenticate_cli() / exchange_code() return a TokenResponse.
      Callers can persist it via _SESSION_STORE.create(token_resp) and
      pass the returned signed cookie value to the dashboard.
    """

    def __init__(self, cfg: Optional[Dict] = None):
        self._cfg           = cfg or _load_config()
        self._provider      = self._cfg.get("provider", "oidc").lower()
        self._client_id     = _resolve(self._cfg.get("client_id", ""))
        self._client_secret = _resolve(self._cfg.get("client_secret", ""))
        self._issuer        = _resolve(self._cfg.get("issuer", ""))
        self._redirect_uri  = _resolve(self._cfg.get("redirect_uri",
                                f"http://localhost:{_CALLBACK_PORT_DEFAULT}/callback"))
        self._scopes        = self._cfg.get("scopes", ["openid","profile","email"])
        self._use_pkce      = self._cfg.get("pkce", True)
        self._tenant_id     = _resolve(self._cfg.get("tenant_id", ""))
        self._session_ttl   = int(self._cfg.get("session_ttl", _SESSION_TTL_DEFAULT))
        persist             = bool(self._cfg.get("persist_pending", False))
        self._pending       = _PendingSessionStore(persist=persist)
        self._token_cache: Optional[TokenResponse] = None

    @property
    def _configured(self) -> bool:
        return bool(self._client_id and (self._issuer or self._provider == "github"))

    def _get_endpoints(self) -> Dict[str, str]:
        if self._provider == "github":
            return {"authorization_endpoint": "https://github.com/login/oauth/authorize",
                    "token_endpoint":          "https://github.com/login/oauth/access_token",
                    "userinfo_endpoint":       "https://api.github.com/user"}
        if self._provider == "entra" and self._tenant_id:
            base = f"https://login.microsoftonline.com/{self._tenant_id}/v2.0"
            try: return OIDCDiscovery.get(base)
            except Exception:
                return {"authorization_endpoint": f"{base}/oauth2/v2.0/authorize",
                        "token_endpoint":          f"{base}/oauth2/v2.0/token",
                        "userinfo_endpoint":       "https://graph.microsoft.com/oidc/userinfo"}
        if self._issuer:
            try: return OIDCDiscovery.get(self._issuer)
            except Exception as exc:
                logger.warning("[sso] discovery failed: %s — using manual config", exc)
        return {"authorization_endpoint": _resolve(self._cfg.get("auth_endpoint","")),
                "token_endpoint":          _resolve(self._cfg.get("token_endpoint","")),
                "userinfo_endpoint":       _resolve(self._cfg.get("userinfo_endpoint",""))}

    def begin_auth(self) -> Tuple[str, str]:
        """
        Start PKCE authorization flow.
        Returns (authorization_url, state).
        Pending session is stored (and optionally persisted to disk).
        """
        if not self._configured:
            raise SSOError("SSO not configured. Set AURORA_SSO_CLIENT_ID and AURORA_SSO_ISSUER.")
        endpoints     = self._get_endpoints()
        auth_endpoint = endpoints.get("authorization_endpoint","")
        if not auth_endpoint: raise SSOError("authorization_endpoint not available")

        state = _generate_state()
        nonce = secrets.token_urlsafe(16)
        session: Dict = {"nonce": nonce, "started_at": time.time()}

        params: Dict[str, str] = {
            "response_type": "code",
            "client_id":     self._client_id,
            "redirect_uri":  self._redirect_uri,
            "scope":         " ".join(self._scopes),
            "state":         state,
            "nonce":         nonce,
        }
        if self._use_pkce and self._provider != "github":
            verifier, challenge = _generate_pkce_pair()
            session["code_verifier"] = verifier
            params["code_challenge"]        = challenge
            params["code_challenge_method"] = "S256"

        self._pending.put(state, session)
        url = auth_endpoint + "?" + urllib.parse.urlencode(params)
        logger.info("[sso] begin_auth: provider=%s pkce=%s state=%s…",
                    self._provider, "S256" if "code_verifier" in session else "none", state[:8])
        return url, state

    def exchange_code(self, code: str, state: str, received_state: str) -> TokenResponse:
        """
        Exchange authorization code for tokens.
        CSRF-validates state, includes code_verifier (PKCE).
        Session is looked up from the persist-capable _PendingSessionStore.
        """
        if not _hmac.compare_digest(state, received_state):
            raise SSOStateError(f"state mismatch — CSRF? expected={state[:8]}…")
        session = self._pending.pop(state)
        if not session:
            raise SSOError(f"Unknown state '{state[:8]}…' — session expired or server restarted "
                           f"with persist_pending=false")

        endpoints = self._get_endpoints()
        token_ep  = endpoints.get("token_endpoint","")
        if not token_ep: raise SSOError("token_endpoint not available")

        data: Dict[str, str] = {
            "grant_type":   "authorization_code",
            "code":         code,
            "redirect_uri": self._redirect_uri,
            "client_id":    self._client_id,
        }
        if self._client_secret:   data["client_secret"]  = self._client_secret
        if "code_verifier" in session: data["code_verifier"] = session["code_verifier"]

        resp = _https_post_form(token_ep, data)
        if "error" in resp:
            raise SSOError(f"Token exchange error: {resp['error']} — {resp.get('error_description','')}")

        tr = TokenResponse(
            access_token  = resp.get("access_token",""),
            id_token      = resp.get("id_token",""),
            refresh_token = resp.get("refresh_token",""),
            expires_in    = int(resp.get("expires_in", 3600)),
            token_type    = resp.get("token_type","Bearer"),
            scope         = resp.get("scope",""),
        )
        self._token_cache = tr
        return tr

    def create_session_cookie(self, token_resp: TokenResponse,
                              user_info: Optional[UserInfo] = None) -> str:
        """
        Persist token to disk session store and return signed cookie value.
        Use this for NOC dashboard / shared-screen scenarios.
        """
        return _SESSION_STORE.create(token_resp, user_info, ttl=self._session_ttl)

    def get_session_cookie_header(self, signed_token: str, secure: bool = False) -> str:
        """Build Set-Cookie header for dashboard response."""
        return _SESSION_STORE.cookie_header(signed_token, ttl=self._session_ttl, secure=secure)

    def resolve_session_cookie(self, cookie_header: str) -> Optional[Dict]:
        """
        Parse Cookie header, validate signature, return session data or None.
        Use in dashboard request handlers.
        """
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith(f"{_COOKIE_NAME}="):
                val = part[len(f"{_COOKIE_NAME}="):]
                return _SESSION_STORE.get(val)
        return None

    def refresh_token(self, refresh_token: str) -> TokenResponse:
        endpoints = self._get_endpoints()
        token_ep  = endpoints.get("token_endpoint","")
        if not token_ep: raise SSOError("token_endpoint unavailable for refresh")
        data: Dict[str, str] = {"grant_type": "refresh_token", "refresh_token": refresh_token,
                                "client_id":   self._client_id}
        if self._client_secret: data["client_secret"] = self._client_secret
        resp = _https_post_form(token_ep, data)
        if "error" in resp:
            raise SSOError(f"Refresh error: {resp['error']}")
        tr = TokenResponse(access_token=resp.get("access_token",""),
                           id_token=resp.get("id_token",""),
                           refresh_token=resp.get("refresh_token", refresh_token),
                           expires_in=int(resp.get("expires_in", 3600)))
        self._token_cache = tr
        return tr

    def validate_id_token(self, id_token: str, nonce: str = "") -> UserInfo:
        return JWTValidator(self._issuer or "", self._client_id).validate(id_token, nonce=nonce)

    def get_userinfo(self, access_token: str) -> UserInfo:
        ep = self._get_endpoints().get("userinfo_endpoint","")
        if not ep: raise SSOError("userinfo_endpoint not configured")
        ctx = ssl.create_default_context()
        req = urllib.request.Request(ep, headers={"Authorization": f"Bearer {access_token}",
                                                  "Accept": "application/json"})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            data = json.loads(resp.read())
        return UserInfo(sub=data.get("sub",data.get("id","")), email=data.get("email",""),
                        name=data.get("name","") or data.get("login",""),
                        picture=data.get("picture",data.get("avatar_url","")), raw=data)

    def authenticate_cli(self) -> TokenResponse:
        """Full CLI flow: opens browser, runs local callback server, exchanges code."""
        auth_url, state = self.begin_auth()
        try:
            import webbrowser; webbrowser.open(auth_url)
            print(f"[AURORA SSO] Browser opened. If not: {auth_url}")
        except Exception:
            print(f"[AURORA SSO] Open: {auth_url}")

        parsed  = urllib.parse.urlparse(self._redirect_uri)
        port    = parsed.port or _CALLBACK_PORT_DEFAULT
        cb_path = parsed.path or "/callback"
        result: Dict = {}; done = threading.Event()

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                p = urllib.parse.urlparse(self.path)
                if p.path != cb_path:
                    self.send_response(404); self.end_headers(); return
                result.update(dict(urllib.parse.parse_qsl(p.query)))
                self.send_response(200)
                self.send_header("Content-Type","text/html; charset=utf-8"); self.end_headers()
                self.wfile.write(b"<html><body style='font-family:sans-serif;text-align:center;padding:40px'>"
                                 b"<h2 style='color:#0af5a0'>AURORA authentication successful</h2>"
                                 b"<p>You may close this tab.</p></body></html>")
                done.set()
            def log_message(self, *a): pass

        with HTTPServer(("127.0.0.1", port), _Handler) as server:
            server.timeout = 1
            deadline = time.time() + _CALLBACK_TIMEOUT_S
            print(f"[AURORA SSO] Waiting on port {port}…")
            while not done.is_set() and time.time() < deadline:
                server.handle_request()

        if not done.is_set():
            raise SSOError(f"Authentication timed out after {_CALLBACK_TIMEOUT_S}s")
        if "error" in result:
            raise SSOError(f"IdP error: {result['error']}")
        code = result.get("code","")
        if not code: raise SSOError("No authorization code in callback")
        return self.exchange_code(code, state, result.get("state",""))

    def status(self) -> Dict:
        return {
            "configured":        self._configured,
            "provider":          self._provider,
            "issuer":            self._issuer or None,
            "client_id":         self._client_id[:8] + "…" if self._client_id else None,
            "redirect_uri":      self._redirect_uri,
            "scopes":            self._scopes,
            "pkce":              self._use_pkce and self._provider != "github",
            "pkce_method":       "S256",
            "persist_pending":   self._pending._persist,
            "session_store":     str(_SESSION_DIR),
            "session_ttl":       self._session_ttl,
            "has_cached_token":  self._token_cache is not None and not self._token_cache.expired,
        }


# ── Singleton ─────────────────────────────────────────────────────────────────

_sso: Optional[SSOFlow] = None
_sso_lock = threading.Lock()

def get_sso() -> SSOFlow:
    global _sso
    if _sso is None:
        with _sso_lock:
            if _sso is None:
                _sso = SSOFlow()
    return _sso
