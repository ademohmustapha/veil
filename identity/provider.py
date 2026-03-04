"""
AURORA Identity Provider Integration Layer
==========================================
Resolves user_id and org_id automatically from configured identity backends
so operators never have to type them manually.

Supported backends (in priority order):
  1. SSO session token  — OAuth2 / OpenID Connect / SAML 2.0 (Okta, Azure AD, etc.)
  2. LDAP / Active Directory connector
  3. org_config.json roster  — admin-registered employee list
  4. CSV/JSON bulk import  — one-time roster feed
  5. Env-var fallback  — AURORA_USER_ID / AURORA_ORG_ID
  6. Interactive prompt (last resort — existing behaviour preserved)

Configure via ~/.aurora/identity.json  (see IDENTITY_CONFIG_SCHEMA below)
"""

from __future__ import annotations

import csv
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.paths import AURORA_HOME as _AURORA_HOME

logger = logging.getLogger("aurora.identity")

_IDENTITY_CFG_FILE = _AURORA_HOME / "identity.json"
_ORG_CFG_FILE      = _AURORA_HOME / "org_config.json"
_ROSTER_CACHE_FILE = _AURORA_HOME / "roster_cache.json"

# ── Schema documentation (written to identity.json on first run if absent) ──

IDENTITY_CONFIG_SCHEMA = {
    "_comment": "AURORA Identity Provider Configuration — edit and save to ~/.aurora/identity.json",

    "active_backend": "auto",
    # auto | sso | ldap | org_config | env | prompt

    "sso": {
        "_comment": "OAuth2 / OpenID Connect — works with Okta, Azure AD, Google Workspace, etc.",
        "provider":        "okta",
        "issuer_url":      "https://your-tenant.okta.com/oauth2/default",
        "client_id":       "${AURORA_SSO_CLIENT_ID}",
        "client_secret":   "${AURORA_SSO_CLIENT_SECRET}",
        "scopes":          ["openid", "profile", "email"],
        "redirect_uri":    "http://localhost:8765/callback",
        "user_id_claim":   "preferred_username",
        "org_id_claim":    "org_id",
        "token_cache":     True
    },

    "ldap": {
        "_comment": "LDAP / Active Directory — user_id auto-pulled from logged-in account",
        "server":          "ldap://dc.corp.example.com:389",
        "use_ssl":         False,
        "bind_dn":         "cn=aurora-svc,ou=service-accounts,dc=corp,dc=example,dc=com",
        "bind_password":   "${AURORA_LDAP_BIND_PASSWORD}",
        "base_dn":         "dc=corp,dc=example,dc=com",
        "user_filter":     "(sAMAccountName={username})",
        "user_id_attr":    "sAMAccountName",
        "org_id_attr":     "department",
        "auto_detect_current_user": True
    },

    "saml": {
        "_comment": "SAML 2.0 — for Okta, Azure AD, ADFS, Shibboleth",
        "idp_metadata_url": "https://your-idp.example.com/metadata",
        "sp_entity_id":    "aurora-platform",
        "acs_url":         "http://localhost:8765/saml/acs",
        "user_id_attr":    "uid",
        "org_id_attr":     "department"
    }
}

ORG_CONFIG_SCHEMA = {
    "_comment": "AURORA Org Config — register org once, IDs auto-populate forever",
    "org_id":          "your-org-id",
    "org_name":        "Your Organisation Name",
    "departments":     ["IT", "Finance", "HR", "Engineering", "Legal"],
    "default_user_id": "",
    "users": [
        {
            "user_id":    "jsmith",
            "name":       "Jane Smith",
            "department": "Engineering",
            "role":       "developer",
            "risk_profile": "medium"
        }
    ]
}

# ─────────────────────────────────────────────────────────────────────────────


def _resolve_env(val: str) -> str:
    """Expand ${ENV_VAR} tokens in config values."""
    if isinstance(val, str) and val.startswith("${") and val.endswith("}"):
        key = val[2:-1]
        resolved = os.environ.get(key, "")
        if not resolved:
            logger.debug(f"Env var {key} not set")
        return resolved
    return val or ""


def _load_cfg(path: Path, schema: dict) -> dict:
    """Load a JSON config file, writing schema template on first run."""
    if not path.exists():
        try:
            path.write_text(json.dumps(schema, indent=2))
            logger.info(f"Created config template at {path}")
        except OSError:
            pass
        return {}
    try:
        return json.loads(path.read_text())
    except Exception as e:
        logger.warning(f"Could not read {path}: {e}")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Backend implementations
# ─────────────────────────────────────────────────────────────────────────────


class _SSOBackend:
    """
    OAuth2 / OpenID Connect backend.
    Opens a local browser flow on first use and caches the token.
    """

    def __init__(self, cfg: dict):
        self._cfg = cfg
        self._token_file = _AURORA_HOME / ".sso_token_cache"

    def _cached_token(self) -> Optional[dict]:
        if not self._cfg.get("token_cache", True):
            return None
        if not self._token_file.exists():
            return None
        try:
            data = json.loads(self._token_file.read_text())
            if data.get("expires_at", 0) > time.time() + 60:
                return data
        except Exception:
            pass
        return None

    def _save_token(self, token_data: dict, userinfo: dict) -> None:
        if not self._cfg.get("token_cache", True):
            return
        try:
            payload = {**token_data, "userinfo": userinfo,
                       "expires_at": time.time() + token_data.get("expires_in", 3600)}
            self._token_file.write_text(json.dumps(payload))
            self._token_file.chmod(0o600)
        except Exception as e:
            logger.warning(f"Could not cache SSO token: {e}")

    def _userinfo_from_token(self, access_token: str) -> dict:
        try:
            import urllib.request
            issuer = _resolve_env(self._cfg.get("issuer_url", ""))
            url = issuer.rstrip("/") + "/v1/userinfo"
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {access_token}"})
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except Exception as e:
            logger.error(f"SSO userinfo fetch failed: {e}")
            return {}

    def resolve(self) -> Tuple[Optional[str], Optional[str]]:
        """Return (user_id, org_id) from SSO session or None on failure."""
        # Check cache first
        cached = self._cached_token()
        if cached:
            ui = cached.get("userinfo", {})
            user_claim = self._cfg.get("user_id_claim", "preferred_username")
            org_claim  = self._cfg.get("org_id_claim",  "org_id")
            uid = ui.get(user_claim) or ui.get("sub")
            oid = ui.get(org_claim)  or ui.get("email", "").split("@")[-1]
            if uid:
                return uid, oid

        # Trigger browser auth flow
        try:
            import urllib.parse
            import urllib.request
            import secrets as _secrets
            import webbrowser

            issuer     = _resolve_env(self._cfg.get("issuer_url", ""))
            client_id  = _resolve_env(self._cfg.get("client_id", ""))
            client_sec = _resolve_env(self._cfg.get("client_secret", ""))
            redirect   = self._cfg.get("redirect_uri", "http://localhost:8765/callback")
            scopes     = " ".join(self._cfg.get("scopes", ["openid", "profile", "email"]))

            if not issuer or not client_id:
                logger.debug("SSO issuer_url or client_id not configured")
                return None, None

            state = _secrets.token_urlsafe(16)
            auth_url = (f"{issuer.rstrip('/')}/v1/authorize?"
                        f"response_type=code&client_id={client_id}"
                        f"&redirect_uri={urllib.parse.quote(redirect)}"
                        f"&scope={urllib.parse.quote(scopes)}&state={state}")

            # Start local callback server in background thread
            auth_code_holder: dict = {}
            import threading, http.server

            class _Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self_h):
                    params = dict(urllib.parse.parse_qsl(
                        urllib.parse.urlparse(self_h.path).query))
                    auth_code_holder["code"] = params.get("code", "")
                    self_h.send_response(200)
                    self_h.end_headers()
                    self_h.wfile.write(b"<html><body><h2>AURORA: Authentication complete. "
                                       b"Return to the terminal.</h2></body></html>")
                def log_message(self_h, *args):
                    pass  # Suppress access logs

            port = int(redirect.split(":")[-1].split("/")[0])
            srv = http.server.HTTPServer(("127.0.0.1", port), _Handler)
            t = threading.Thread(target=srv.handle_request, daemon=True)
            t.start()

            logger.info(f"[SSO] Opening browser for authentication… ({self._cfg.get('provider','SSO')})")
            webbrowser.open(auth_url)
            t.join(timeout=120)
            srv.server_close()

            code = auth_code_holder.get("code", "")
            if not code:
                logger.warning("SSO auth code not received within 120s")
                return None, None

            # Exchange code for token
            token_url = f"{issuer.rstrip('/')}/v1/token"
            data = urllib.parse.urlencode({
                "grant_type": "authorization_code", "code": code,
                "redirect_uri": redirect, "client_id": client_id,
                "client_secret": client_sec,
            }).encode()
            req = urllib.request.Request(token_url, data=data,
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=15) as r:
                token_data = json.loads(r.read())

            userinfo = self._userinfo_from_token(token_data.get("access_token", ""))
            self._save_token(token_data, userinfo)

            user_claim = self._cfg.get("user_id_claim", "preferred_username")
            org_claim  = self._cfg.get("org_id_claim",  "org_id")
            uid = userinfo.get(user_claim) or userinfo.get("sub")
            oid = userinfo.get(org_claim)  or userinfo.get("email", "").split("@")[-1]
            return uid, oid

        except Exception as e:
            logger.error(f"SSO auth flow failed: {e}")
            return None, None


class _LDAPBackend:
    """
    LDAP / Active Directory backend.
    Auto-detects the currently logged-in OS user and looks them up in AD.
    """

    def __init__(self, cfg: dict):
        self._cfg = cfg

    def resolve(self) -> Tuple[Optional[str], Optional[str]]:
        try:
            import ldap3  # type: ignore
        except ImportError:
            logger.debug("ldap3 not installed — LDAP backend skipped")
            return None, None

        server_url  = _resolve_env(self._cfg.get("server", ""))
        bind_dn     = _resolve_env(self._cfg.get("bind_dn", ""))
        bind_pw     = _resolve_env(self._cfg.get("bind_password", ""))
        base_dn     = self._cfg.get("base_dn", "")
        uid_attr    = self._cfg.get("user_id_attr", "sAMAccountName")
        org_attr    = self._cfg.get("org_id_attr", "department")
        user_filter = self._cfg.get("user_filter", "(sAMAccountName={username})")
        auto        = self._cfg.get("auto_detect_current_user", True)

        # Skip silently if server is the placeholder template value
        if not server_url or "example.com" in server_url:
            return None, None

        # Detect OS username
        username = os.environ.get("USERNAME") or os.environ.get("USER") or ""
        if not username and auto:
            try:
                import getpass
                username = getpass.getuser()
            except Exception:
                pass

        if not username:
            return None, None

        try:
            use_ssl = self._cfg.get("use_ssl", False)
            srv = ldap3.Server(server_url, use_ssl=use_ssl, get_info=ldap3.ALL)
            conn = ldap3.Connection(srv, user=bind_dn, password=bind_pw, auto_bind=True)
            filt = user_filter.format(username=ldap3.utils.conv.escape_filter_chars(username))
            conn.search(base_dn, filt, attributes=[uid_attr, org_attr])
            if conn.entries:
                entry = conn.entries[0]
                uid = str(getattr(entry, uid_attr, username) or username)
                oid = str(getattr(entry, org_attr, "") or "")
                conn.unbind()
                logger.info(f"LDAP resolved: user={uid} org={oid}")
                return uid, oid or None
            conn.unbind()
        except Exception as e:
            logger.debug(f"LDAP backend unavailable: {e}")
        return None, None


class _OrgConfigBackend:
    """
    org_config.json backend.
    Admin registers org + user roster once; IDs auto-populate thereafter.
    """

    def __init__(self):
        self._data = _load_cfg(_ORG_CFG_FILE, ORG_CONFIG_SCHEMA)

    @property
    def org_id(self) -> Optional[str]:
        val = self._data.get("org_id", "")
        return val if val and not val.startswith("your-") else None

    @property
    def default_user_id(self) -> Optional[str]:
        val = self._data.get("default_user_id", "")
        return val if val else None

    @property
    def org_name(self) -> Optional[str]:
        return self._data.get("org_name")

    @property
    def departments(self) -> List[str]:
        return self._data.get("departments", [])

    def resolve(self) -> Tuple[Optional[str], Optional[str]]:
        return self.default_user_id, self.org_id

    def lookup_user(self, user_id: str) -> Optional[dict]:
        for u in self._data.get("users", []):
            if u.get("user_id") == user_id:
                return u
        return None

    def list_users(self) -> List[dict]:
        return self._data.get("users", [])

    def save(self) -> None:
        try:
            _ORG_CFG_FILE.write_text(json.dumps(self._data, indent=2))
        except OSError as e:
            logger.error(f"Could not save org_config: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# CSV / JSON Bulk Import
# ─────────────────────────────────────────────────────────────────────────────


def import_roster_csv(path: str, target: str = "org_config") -> dict:
    """
    Import employees from a CSV file into org_config.json (or roster cache).

    Expected CSV columns (case-insensitive, extras ignored):
      employee_id / user_id, name, department, role, risk_profile

    Returns: { "imported": N, "skipped": M, "errors": [...] }
    """
    result = {"imported": 0, "skipped": 0, "errors": []}
    col_map = {
        "user_id": ["user_id", "employee_id", "id", "username", "login"],
        "name":    ["name", "full_name", "display_name"],
        "department": ["department", "dept", "team", "group"],
        "role":    ["role", "job_title", "title", "position"],
        "risk_profile": ["risk_profile", "risk", "risk_level"],
    }

    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            headers = [h.lower().strip() for h in (reader.fieldnames or [])]

            def _find(field):
                for alias in col_map[field]:
                    if alias in headers:
                        return alias
                return None

            uid_col  = _find("user_id")
            if not uid_col:
                result["errors"].append("No user_id/employee_id column found in CSV")
                return result

            org_cfg = _OrgConfigBackend()
            existing_ids = {u["user_id"] for u in org_cfg.list_users()}
            new_users = []

            for row in reader:
                row_lower = {k.lower().strip(): v for k, v in row.items()}
                uid = (row_lower.get(uid_col) or "").strip()
                if not uid:
                    result["skipped"] += 1
                    continue
                if uid in existing_ids:
                    result["skipped"] += 1
                    continue

                def _get(field):
                    col = _find(field)
                    return row_lower.get(col, "").strip() if col else ""

                user = {
                    "user_id":    uid,
                    "name":       _get("name") or uid,
                    "department": _get("department") or "Unknown",
                    "role":       _get("role") or "operator",
                    "risk_profile": (_get("risk_profile") or "medium").lower(),
                }
                new_users.append(user)
                existing_ids.add(uid)
                result["imported"] += 1

            if new_users:
                org_cfg._data.setdefault("users", []).extend(new_users)
                org_cfg.save()
                logger.info(f"Roster CSV import: {result['imported']} users added")

    except FileNotFoundError:
        result["errors"].append(f"File not found: {path}")
    except Exception as e:
        result["errors"].append(str(e))

    return result


def import_roster_json(path: str) -> dict:
    """
    Import employees from a JSON file into org_config.json.

    Accepts formats:
      [ { "user_id": ..., "name": ..., ... } ]           — flat array
      { "users": [...] }                                  — wrapped object
      { "employees": [...] }                              — alt key
    """
    result = {"imported": 0, "skipped": 0, "errors": []}
    try:
        data = json.loads(Path(path).read_text())
        users = (data if isinstance(data, list)
                 else data.get("users", data.get("employees", [])))
        if not isinstance(users, list):
            result["errors"].append("JSON must be an array or object with 'users' key")
            return result

        org_cfg = _OrgConfigBackend()
        existing_ids = {u["user_id"] for u in org_cfg.list_users()}

        for item in users:
            if not isinstance(item, dict):
                result["skipped"] += 1
                continue
            uid = (item.get("user_id") or item.get("employee_id") or item.get("id") or "").strip()
            if not uid or uid in existing_ids:
                result["skipped"] += 1
                continue
            org_cfg._data.setdefault("users", []).append({
                "user_id":    uid,
                "name":       item.get("name", uid),
                "department": item.get("department", "Unknown"),
                "role":       item.get("role", "operator"),
                "risk_profile": item.get("risk_profile", "medium"),
            })
            existing_ids.add(uid)
            result["imported"] += 1

        if result["imported"] > 0:
            org_cfg.save()
            logger.info(f"Roster JSON import: {result['imported']} users added")

    except FileNotFoundError:
        result["errors"].append(f"File not found: {path}")
    except Exception as e:
        result["errors"].append(str(e))

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Identity Resolver — main public API
# ─────────────────────────────────────────────────────────────────────────────


class IdentityResolver:
    """
    Central identity resolution engine.

    Usage:
        resolver = IdentityResolver()
        user_id, source = resolver.resolve_user()
        org_id,  source = resolver.resolve_org()

    Sources tried in priority order:
      sso → ldap → org_config → env → prompt
    """

    def __init__(self):
        self._id_cfg  = _load_cfg(_IDENTITY_CFG_FILE, IDENTITY_CONFIG_SCHEMA)
        self._org_cfg = _OrgConfigBackend()
        self._active  = self._id_cfg.get("active_backend", "auto")

        # Lazy-init SSO / LDAP
        self._sso:  Optional[_SSOBackend]  = None
        self._ldap: Optional[_LDAPBackend] = None
        if self._active in ("auto", "sso"):
            sso_cfg = self._id_cfg.get("sso", {})
            if sso_cfg and _resolve_env(sso_cfg.get("issuer_url", "")):
                self._sso = _SSOBackend(sso_cfg)
        if self._active in ("auto", "ldap"):
            ldap_cfg = self._id_cfg.get("ldap", {})
            if ldap_cfg and _resolve_env(ldap_cfg.get("server", "")):
                self._ldap = _LDAPBackend(ldap_cfg)

        # SSO-resolved cache (shared between user + org resolve)
        self._sso_user: Optional[str] = None
        self._sso_org:  Optional[str] = None
        self._sso_tried = False

    def _try_sso(self) -> Tuple[Optional[str], Optional[str]]:
        if self._sso_tried:
            return self._sso_user, self._sso_org
        self._sso_tried = True
        if self._sso:
            self._sso_user, self._sso_org = self._sso.resolve()
        return self._sso_user, self._sso_org

    def resolve_user(self, prompt_label: str = "User ID",
                     fallback: str = "user_demo") -> Tuple[str, str]:
        """
        Returns (user_id, source_label).
        source_label is one of: session | sso | ldap | org_config | env | prompt
        """
        # 0. Authenticated AURORA session (highest priority — no prompts needed)
        try:
            from core.auth import get_session
            sess = get_session()
            if sess and sess.get("employee_id"):
                return str(sess["employee_id"]), "session"
        except Exception:
            pass
        # 1. SSO
        if self._active in ("auto", "sso"):
            uid, _ = self._try_sso()
            if uid:
                return uid, "sso"

        # 2. LDAP
        if self._active in ("auto", "ldap") and self._ldap:
            uid, _ = self._ldap.resolve()
            if uid:
                return uid, "ldap"

        # 3. org_config default_user_id
        if self._active in ("auto", "org_config"):
            uid, _ = self._org_cfg.resolve()
            if uid:
                return uid, "org_config"

        # 4. Environment variable
        env_uid = os.environ.get("AURORA_USER_ID", "")
        if env_uid:
            return env_uid, "env"

        # 5. Interactive prompt (fallback to fallback value)
        return self._prompt_or_fallback(prompt_label, fallback), "prompt"

    def resolve_org(self, prompt_label: str = "Organization ID",
                    fallback: str = "enterprise_demo") -> Tuple[str, str]:
        """
        Returns (org_id, source_label).
        """
        # 0. org_config org_id takes precedence when session is active
        try:
            from core.auth import get_session
            sess = get_session()
            if sess:
                oid = self._org_cfg.org_id
                if oid:
                    return oid, "org_config"
        except Exception:
            pass
        # 1. SSO
        if self._active in ("auto", "sso"):
            _, oid = self._try_sso()
            if oid:
                return oid, "sso"

        # 2. LDAP
        if self._active in ("auto", "ldap") and self._ldap:
            _, oid = self._ldap.resolve()
            if oid:
                return oid, "ldap"

        # 3. org_config
        if self._active in ("auto", "org_config"):
            oid = self._org_cfg.org_id
            if oid:
                return oid, "org_config"

        # 4. Environment variable
        env_oid = os.environ.get("AURORA_ORG_ID", "")
        if env_oid:
            return env_oid, "env"

        # 5. Interactive prompt
        return self._prompt_or_fallback(prompt_label, fallback), "prompt"

    @staticmethod
    def _prompt_or_fallback(label: str, fallback: str) -> str:
        try:
            val = input(f"  \033[96m{label}\033[0m: ").strip()
            return val or fallback
        except (EOFError, KeyboardInterrupt):
            return fallback

    def org_display_name(self) -> str:
        return self._org_cfg.org_name or "Unknown Organisation"

    def list_users(self) -> List[dict]:
        return self._org_cfg.list_users()

    def lookup_user(self, user_id: str) -> Optional[dict]:
        return self._org_cfg.lookup_user(user_id)

    def status(self) -> dict:
        """Return a human-readable status dict for display in UI."""
        backends = []
        if self._sso:
            backends.append("SSO (OAuth2/OIDC)")
        if self._ldap:
            backends.append("LDAP/AD")
        if self._org_cfg.org_id:
            backends.append(f"org_config ({self._org_cfg.org_id})")
        if os.environ.get("AURORA_USER_ID") or os.environ.get("AURORA_ORG_ID"):
            backends.append("env vars")
        if not backends:
            backends.append("interactive prompt (configure identity.json to automate)")
        return {
            "active_backend": self._active,
            "configured_backends": backends,
            "org_id":    self._org_cfg.org_id or "(not set)",
            "org_name":  self._org_cfg.org_name or "(not set)",
            "user_count": len(self._org_cfg.list_users()),
            "config_file": str(_IDENTITY_CFG_FILE),
            "org_config":  str(_ORG_CFG_FILE),
        }


# Module-level singleton
_resolver: Optional[IdentityResolver] = None


def get_resolver() -> IdentityResolver:
    global _resolver
    if _resolver is None:
        _resolver = IdentityResolver()
    return _resolver
