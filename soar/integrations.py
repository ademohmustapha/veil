"""
AURORA SOAR Workflow Integrations
===================================
Security Orchestration, Automation and Response (SOAR) connectors for:

  • Jira         — Create/update/transition issues via Jira Cloud REST API v3
                   or Jira Server/Data Center (v2).
  • ServiceNow   — Create/update incidents via Table API (Tokyo+ / Utah+).
  • Containment Webhooks — Signed JSON POST fired on every containment event.

Configuration — ~/.aurora/soar.json  OR  environment variables:

  {
    "jira": {
      "base_url":  "${AURORA_JIRA_URL}",
      "user":      "${AURORA_JIRA_USER}",
      "api_token": "${AURORA_JIRA_TOKEN}",
      "project":   "${AURORA_JIRA_PROJECT}",
      "issue_type":"${AURORA_JIRA_ISSUE_TYPE}",
      "labels":    ["aurora","auto"],
      "api_version": "3"
    },
    "servicenow": {
      "base_url":  "${AURORA_SN_URL}",
      "user":      "${AURORA_SN_USER}",
      "password":  "${AURORA_SN_PASS}",
      "category":  "security",
      "assignment_group": "${AURORA_SN_GROUP}",
      "urgency":   "1"
    },
    "containment_webhook": {
      "url":    "${AURORA_CONTAINMENT_WH_URL}",
      "secret": "${AURORA_CONTAINMENT_WH_SECRET}"
    }
  }

Idempotency:
  A built-in _Deduplicator prevents duplicate Jira/ServiceNow tickets when
  sandbox.contain() is called more than once for the same containment_id
  (retry scenarios, at-least-once delivery). Each (channel, dedup_key) pair
  is tracked for _DEDUP_TTL_S seconds (default 3600 s).

All connectors:
  • Are non-blocking (daemon threads — never stall AURORA's response loop)
  • Retry once after 5 s on transient HTTP 5xx / network errors
  • Log success / failure without revealing secrets
  • Sign outbound payloads with HMAC-SHA256 where applicable
  • Are idempotent for the same containment_id within the TTL window

Severity → Jira priority / ServiceNow urgency mapping:
  CRITICAL → Highest / 1   HIGH → High / 1
  WARN     → Medium  / 2   INFO → Low  / 3
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("aurora.soar")

# ── Config ────────────────────────────────────────────────────────────────────

try:
    from core.paths import AURORA_HOME as _AURORA_HOME
except ImportError:
    _AURORA_HOME = Path.home() / ".aurora"

_CONFIG_FILE   = _AURORA_HOME / "soar.json"
_RETRY_DELAY_S = 5
_TIMEOUT_S     = 15
_DEDUP_TTL_S   = 3600   # 1 hour dedup window — configurable via AURORA_SOAR_DEDUP_TTL


def _resolve(val: Any) -> str:
    """Expand ${ENV_VAR} references in config strings."""
    if isinstance(val, str) and val.startswith("${") and val.endswith("}"):
        key = val[2:-1]
        resolved = os.environ.get(key, "")
        if not resolved:
            logger.debug("[soar] env var %s not set", key)
        return resolved
    return str(val) if val else ""


def _load_config() -> Dict:
    cfg: Dict = {}
    try:
        if _CONFIG_FILE.exists():
            cfg = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("[soar] config load failed: %s", exc)

    for section, keys in [
        ("jira",                 ["base_url","user","api_token","project"]),
        ("servicenow",           ["base_url","user","password"]),
        ("containment_webhook",  ["url","secret"]),
    ]:
        env_prefix = {
            "jira":               "AURORA_JIRA_",
            "servicenow":         "AURORA_SN_",
            "containment_webhook":"AURORA_CONTAINMENT_WH_",
        }[section]
        for key in keys:
            env_key = env_prefix + key.upper()
            if os.environ.get(env_key) and key not in cfg.get(section, {}):
                cfg.setdefault(section, {})[key] = os.environ[env_key]

    return cfg


# ── Idempotency / Deduplication ───────────────────────────────────────────────

def _dedup_key(event_type: str, containment_id: str, summary: str) -> str:
    """
    Build a stable deduplication key for a SOAR dispatch.

    If containment_id is provided (containment events), it is used directly
    so duplicate calls for the same containment are suppressed reliably.
    For other event types, we fall back to a SHA-256 hash of the summary.
    """
    if containment_id:
        return f"{event_type}:{containment_id}"
    h = hashlib.sha256(summary.encode("utf-8")).hexdigest()[:24]
    return f"{event_type}:{h}"


class _Deduplicator:
    """
    Thread-safe, TTL-based deduplication map.

    is_duplicate(channel, key) returns True if (channel, key) was seen
    within the last `ttl` seconds.  The first call always returns False.
    Expired entries are pruned lazily on each is_duplicate() call.
    """

    def __init__(self, ttl: float = _DEDUP_TTL_S):
        self._ttl   = ttl
        self._seen: Dict[str, float] = {}   # (channel:key) → first_seen_ts
        self._lock  = threading.Lock()

    def is_duplicate(self, channel: str, key: str) -> bool:
        composite = f"{channel}:{key}"
        now = time.monotonic()
        with self._lock:
            self._prune_locked(now)
            if composite in self._seen:
                return True
            self._seen[composite] = now
            return False

    def _prune_locked(self, now: float) -> None:
        expired = [k for k, ts in self._seen.items() if now - ts > self._ttl]
        for k in expired:
            del self._seen[k]

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()

    def prune_expired(self) -> int:
        """Explicitly prune expired entries. Returns count removed."""
        now = time.monotonic()
        with self._lock:
            before = len(self._seen)
            self._prune_locked(now)
            return before - len(self._seen)


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _basic_auth(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _http_post(
    url: str,
    payload: Dict,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = _TIMEOUT_S,
    retries: int = 1,
) -> Tuple[int, str]:
    body = json.dumps(payload).encode("utf-8")
    req_hdrs = {
        "Content-Type": "application/json",
        "Accept":       "application/json",
        "User-Agent":   "AURORA-SOAR/2",
    }
    if headers:
        req_hdrs.update(headers)

    ctx = ssl.create_default_context()
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=body, headers=req_hdrs, method="POST")
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            if exc.code >= 500 and attempt < retries:
                logger.warning("[soar] HTTP %d from %s — retrying in %ds", exc.code, url, _RETRY_DELAY_S)
                time.sleep(_RETRY_DELAY_S)
                continue
            return exc.code, text
        except Exception as exc:
            if attempt < retries:
                logger.warning("[soar] POST error to %s (%s) — retrying", url, exc)
                time.sleep(_RETRY_DELAY_S)
                continue
            return 0, str(exc)
    return 0, "max retries exceeded"


def _http_patch(
    url: str,
    payload: Dict,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = _TIMEOUT_S,
) -> Tuple[int, str]:
    body = json.dumps(payload).encode("utf-8")
    req_hdrs = {
        "Content-Type": "application/json",
        "Accept":       "application/json",
        "User-Agent":   "AURORA-SOAR/2",
    }
    if headers:
        req_hdrs.update(headers)
    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(url, data=body, headers=req_hdrs, method="PATCH")
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace") if exc.fp else ""
    except Exception as exc:
        return 0, str(exc)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _secret_ref(s: str) -> str:
    if not s:
        return "<empty>"
    return "sha256:" + hashlib.sha256(s.encode()).hexdigest()[:12] + "…"


# ── Severity mappings ─────────────────────────────────────────────────────────

_JIRA_PRIORITY = {
    "CRITICAL": "Highest",
    "HIGH":     "High",
    "WARN":     "Medium",
    "INFO":     "Low",
}

_SN_URGENCY = {
    "CRITICAL": "1",
    "HIGH":     "1",
    "WARN":     "2",
    "INFO":     "3",
}

_SN_IMPACT = {
    "CRITICAL": "1",
    "HIGH":     "2",
    "WARN":     "3",
    "INFO":     "3",
}


# ── Jira connector ────────────────────────────────────────────────────────────

class JiraConnector:
    """
    Creates and optionally updates Jira issues for AURORA security events.

    Jira Cloud REST API v3:  POST /rest/api/3/issue
    Jira Server/DC API v2:   POST /rest/api/2/issue
    """

    def __init__(self, cfg: Dict):
        self._base   = _resolve(cfg.get("base_url", "")).rstrip("/")
        self._user   = _resolve(cfg.get("user", ""))
        self._token  = _resolve(cfg.get("api_token", ""))
        self._proj   = _resolve(cfg.get("project", "SEC"))
        self._itype  = _resolve(cfg.get("issue_type", "Task"))
        self._labels = cfg.get("labels", ["aurora"])
        self._ver    = str(cfg.get("api_version", "3"))

    @property
    def _configured(self) -> bool:
        return bool(self._base and self._user and self._token and self._proj)

    def _auth_header(self) -> str:
        return _basic_auth(self._user, self._token)

    def _api_url(self, path: str) -> str:
        return f"{self._base}/rest/api/{self._ver}{path}"

    def create_issue(
        self,
        severity: str,
        event_type: str,
        summary: str,
        detail: Dict,
    ) -> Optional[str]:
        if not self._configured:
            logger.debug("[soar/jira] not configured — skipping")
            return None

        priority    = _JIRA_PRIORITY.get(severity, "Medium")
        detail_text = json.dumps(detail, indent=2)
        description_v3 = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": f"AURORA {severity} — {event_type}"}],
                },
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": f"Summary: {summary}"}],
                },
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": f"Timestamp: {_now_iso()}"}],
                },
                {
                    "type": "codeBlock",
                    "attrs": {"language": "json"},
                    "content": [{"type": "text", "text": detail_text[:4000]}],
                },
            ],
        }
        description_v2 = (
            f"*AURORA {severity} — {event_type}*\n\n"
            f"Summary: {summary}\n"
            f"Timestamp: {_now_iso()}\n\n"
            f"{{code:json}}\n{detail_text[:4000]}\n{{code}}"
        )

        payload: Dict[str, Any] = {
            "fields": {
                "project":     {"key": self._proj},
                "summary":     f"[AURORA {severity}] {event_type}: {summary[:200]}",
                "issuetype":   {"name": self._itype},
                "priority":    {"name": priority},
                "labels":      self._labels + [severity.lower(), event_type.lower()],
                "description": description_v3 if self._ver == "3" else description_v2,
            }
        }

        status, body = _http_post(
            self._api_url("/issue"),
            payload,
            headers={
                "Authorization":     self._auth_header(),
                "X-Atlassian-Token": "no-check",
            },
        )

        if 200 <= status < 300:
            try:
                key = json.loads(body).get("key", "UNKNOWN")
                logger.info("[soar/jira] issue created: %s (severity=%s)", key, severity)
                return key
            except Exception:
                return None
        else:
            logger.warning("[soar/jira] create_issue failed: HTTP %d — %s", status, body[:200])
            return None

    def add_comment(self, issue_key: str, comment: str) -> bool:
        if not self._configured or not issue_key:
            return False
        payload_v3 = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": comment}]}
                ],
            }
        }
        payload_v2 = {"body": comment}
        status, body = _http_post(
            self._api_url(f"/issue/{issue_key}/comment"),
            payload_v3 if self._ver == "3" else payload_v2,
            headers={"Authorization": self._auth_header()},
        )
        return 200 <= status < 300

    def transition_issue(self, issue_key: str, transition_name: str) -> bool:
        if not self._configured or not issue_key:
            return False
        ctx = ssl.create_default_context()
        url = self._api_url(f"/issue/{issue_key}/transitions")
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": self._auth_header(),
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, context=ctx, timeout=_TIMEOUT_S) as resp:
                data = json.loads(resp.read())
        except Exception as exc:
            logger.warning("[soar/jira] transitions fetch failed: %s", exc)
            return False
        transitions = data.get("transitions", [])
        match = next(
            (t for t in transitions if t.get("name", "").lower() == transition_name.lower()),
            None,
        )
        if not match:
            logger.warning("[soar/jira] transition '%s' not found on %s", transition_name, issue_key)
            return False
        status, _ = _http_post(
            self._api_url(f"/issue/{issue_key}/transitions"),
            {"transition": {"id": match["id"]}},
            headers={"Authorization": self._auth_header()},
        )
        return 200 <= status < 300

    def status(self) -> Dict:
        return {
            "configured": self._configured,
            "base_url":   self._base or None,
            "project":    self._proj or None,
            "api_version": self._ver,
        }


# ── ServiceNow connector ──────────────────────────────────────────────────────

class ServiceNowConnector:
    """
    Creates and updates ServiceNow incidents via the Table API.
    Endpoint: POST /api/now/table/incident
    """

    def __init__(self, cfg: Dict):
        self._base     = _resolve(cfg.get("base_url", "")).rstrip("/")
        self._user     = _resolve(cfg.get("user", ""))
        self._password = _resolve(cfg.get("password", ""))
        self._category = _resolve(cfg.get("category", "security"))
        self._group    = _resolve(cfg.get("assignment_group", ""))
        self._urgency  = _resolve(cfg.get("urgency", "1"))

    @property
    def _configured(self) -> bool:
        return bool(self._base and self._user and self._password)

    def _auth_header(self) -> str:
        return _basic_auth(self._user, self._password)

    def _table_url(self, table: str, sys_id: str = "") -> str:
        base = f"{self._base}/api/now/table/{table}"
        return f"{base}/{sys_id}" if sys_id else base

    def create_incident(
        self,
        severity: str,
        event_type: str,
        summary: str,
        detail: Dict,
    ) -> Optional[str]:
        if not self._configured:
            logger.debug("[soar/servicenow] not configured — skipping")
            return None

        urgency    = _SN_URGENCY.get(severity, "2")
        impact     = _SN_IMPACT.get(severity, "2")
        short_desc = f"[AURORA {severity}] {event_type}: {summary}"[:160]
        description = (
            f"AURORA Security Alert\n"
            f"{'='*50}\n"
            f"Severity  : {severity}\n"
            f"Event Type: {event_type}\n"
            f"Summary   : {summary}\n"
            f"Timestamp : {_now_iso()}\n\n"
            f"Detail:\n{json.dumps(detail, indent=2)[:5000]}"
        )

        payload: Dict[str, Any] = {
            "short_description":  short_desc,
            "description":        description,
            "urgency":            urgency,
            "impact":             impact,
            "category":           self._category,
            "subcategory":        event_type.lower()[:40],
            "caller_id":          "aurora-platform",
            "work_notes":         json.dumps(detail, separators=(",",":"))[:5000],
            "u_source":           "AURORA",
        }
        if self._group:
            payload["assignment_group"] = self._group

        status, body = _http_post(
            self._table_url("incident"),
            payload,
            headers={
                "Authorization":     self._auth_header(),
                "X-no-response-body":"false",
            },
        )

        if 200 <= status < 300:
            try:
                sys_id = json.loads(body)["result"]["sys_id"]
                logger.info("[soar/servicenow] incident created: %s", sys_id)
                return sys_id
            except Exception:
                return None
        else:
            logger.warning("[soar/servicenow] create_incident failed: HTTP %d — %s", status, body[:200])
            return None

    def update_incident(self, sys_id: str, fields: Dict) -> bool:
        if not self._configured or not sys_id:
            return False
        status, _ = _http_patch(
            self._table_url("incident", sys_id),
            fields,
            headers={"Authorization": self._auth_header()},
        )
        return 200 <= status < 300

    def resolve_incident(self, sys_id: str, resolution_notes: str = "") -> bool:
        return self.update_incident(sys_id, {
            "state":       "6",
            "close_code":  "Resolved",
            "close_notes": resolution_notes or "Resolved by AURORA automated response",
            "resolved_by": "aurora-platform",
        })

    def status(self) -> Dict:
        return {
            "configured": self._configured,
            "base_url":   self._base or None,
            "category":   self._category,
        }


# ── Containment Webhook ───────────────────────────────────────────────────────

class ContainmentWebhook:
    """
    HMAC-SHA256-signed JSON POST fired on every containment event.

    Signature header:
      X-Aurora-Signature: t=<unix_ts>,v1=<hmac_sha256_hex>

    Verification:
      signed_string = f"{ts}.{json_body}"
      expected = hmac.new(secret.encode(), signed_string.encode(), sha256).hexdigest()
    """

    def __init__(self, cfg: Dict):
        self._url    = _resolve(cfg.get("url", ""))
        self._secret = _resolve(cfg.get("secret", ""))

    @property
    def _configured(self) -> bool:
        return bool(self._url)

    def fire(
        self,
        containment_id: str,
        action: str,
        user_id: str,
        severity: str,
        summary: str,
        detail: Dict,
    ) -> bool:
        if not self._configured:
            return False

        ts = str(int(time.time()))
        payload = {
            "aurora_containment": {
                "containment_id": containment_id,
                "action":         action,
                "user_id":        user_id,
                "severity":       severity,
                "event_type":     "CONTAINMENT",
                "summary":        summary,
                "detail":         detail,
                "timestamp":      _now_iso(),
            }
        }

        headers: Dict[str, str] = {}
        if self._secret:
            body_str   = json.dumps(payload)
            sign_input = f"{ts}.{body_str}".encode("utf-8")
            sig = hmac.new(
                self._secret.encode("utf-8"),
                msg=sign_input,
                digestmod=hashlib.sha256,
            ).hexdigest()
            headers["X-Aurora-Signature"] = f"t={ts},v1={sig}"

        status, body = _http_post(self._url, payload, headers=headers)
        if 200 <= status < 300:
            logger.info("[soar/containment_wh] fired ok (status=%d)", status)
            return True
        logger.warning("[soar/containment_wh] fire failed HTTP %d — %s", status, body[:200])
        return False

    def status(self) -> Dict:
        return {
            "configured": self._configured,
            "url":        self._url or None,
            "signing":    bool(self._secret),
        }


# ── SOAR Manager ──────────────────────────────────────────────────────────────

class SOARManager:
    """
    Unified SOAR facade. All dispatches are non-blocking (daemon threads).

    Idempotency: duplicate dispatches for the same containment_id within
    _DEDUP_TTL_S seconds are silently dropped — no duplicate tickets created.

    Usage:
        from soar.integrations import get_soar_manager
        mgr = get_soar_manager()
        mgr.dispatch(
            severity="CRITICAL",
            event_type="CONTAINMENT",
            summary="Session frozen: mass_download by alice",
            detail={"containment_id": "ab12cd34", "user_id": "alice"},
            containment_id="ab12cd34",
            action="bulk_data_export",
            user_id="alice",
        )
    """

    def __init__(self):
        cfg              = _load_config()
        self._jira       = JiraConnector(cfg.get("jira", {}))
        self._snow       = ServiceNowConnector(cfg.get("servicenow", {}))
        self._wh         = ContainmentWebhook(cfg.get("containment_webhook", {}))
        self._lock       = threading.Lock()
        self._dispatches: Dict[str, int] = {"jira": 0, "servicenow": 0, "webhook": 0}
        self._failures:   Dict[str, int] = {"jira": 0, "servicenow": 0, "webhook": 0}
        ttl = float(os.environ.get("AURORA_SOAR_DEDUP_TTL", _DEDUP_TTL_S))
        self._dedup      = _Deduplicator(ttl=ttl)

    def dispatch(
        self,
        severity: str,
        event_type: str,
        summary: str,
        detail: Optional[Dict] = None,
        *,
        containment_id: str = "",
        action: str = "",
        user_id: str = "",
    ) -> None:
        """
        Fire all configured SOAR channels in background daemon threads.
        Never blocks the calling thread. Idempotent for same containment_id.
        """
        if detail is None:
            detail = {}

        dk = _dedup_key(event_type, containment_id, summary)
        tasks: List[Tuple[str, Any]] = []

        if self._jira._configured:
            if not self._dedup.is_duplicate("jira", dk):
                tasks.append(("jira", lambda: self._jira.create_issue(
                    severity, event_type, summary, detail
                )))
            else:
                logger.debug("[soar/jira] duplicate suppressed for key=%s", dk)

        if self._snow._configured:
            if not self._dedup.is_duplicate("servicenow", dk):
                tasks.append(("servicenow", lambda: self._snow.create_incident(
                    severity, event_type, summary, detail
                )))
            else:
                logger.debug("[soar/servicenow] duplicate suppressed for key=%s", dk)

        if event_type == "CONTAINMENT" and self._wh._configured:
            if not self._dedup.is_duplicate("webhook", dk):
                tasks.append(("webhook", lambda: self._wh.fire(
                    containment_id=containment_id,
                    action=action,
                    user_id=user_id,
                    severity=severity,
                    summary=summary,
                    detail=detail,
                )))
            else:
                logger.debug("[soar/webhook] duplicate suppressed for key=%s", dk)

        for name, fn in tasks:
            t = threading.Thread(
                target=self._run,
                args=(name, fn),
                daemon=True,
                name=f"aurora-soar-{name}",
            )
            t.start()

    def _run(self, channel: str, fn) -> None:
        try:
            result = fn()
            with self._lock:
                self._dispatches[channel] += 1
            logger.info("[soar/%s] dispatched ok → %s", channel, result)
        except Exception as exc:
            with self._lock:
                self._failures[channel] += 1
            logger.error("[soar/%s] dispatch exception: %s", channel, exc)

    def status(self) -> Dict:
        """Return SOAR status dict for /health and `aurora doctor`."""
        with self._lock:
            return {
                "jira":                self._jira.status(),
                "servicenow":          self._snow.status(),
                "containment_webhook": self._wh.status(),
                "dispatches_ok":       dict(self._dispatches),
                "dispatches_failed":   dict(self._failures),
                "dedup_ttl_s":         self._dedup._ttl,
            }

    def test_channels(self) -> Dict[str, Any]:
        """
        Synchronous channel test (does NOT spawn threads).
        Sends a test payload to every configured channel.
        Returns {channel: result}.
        """
        results: Dict[str, Any] = {}
        test_detail = {"test": True, "timestamp": _now_iso()}

        if self._jira._configured:
            key = self._jira.create_issue("INFO", "SYSTEM_TEST",
                                          "AURORA SOAR channel test", test_detail)
            results["jira"] = key or False

        if self._snow._configured:
            sys_id = self._snow.create_incident("INFO", "SYSTEM_TEST",
                                                "AURORA SOAR channel test", test_detail)
            results["servicenow"] = sys_id or False

        if self._wh._configured:
            ok = self._wh.fire("test-0000", "SYSTEM_TEST", "aurora",
                               "INFO", "AURORA SOAR channel test", test_detail)
            results["containment_webhook"] = ok

        return results


# ── Singleton ─────────────────────────────────────────────────────────────────

_manager: Optional[SOARManager] = None
_mgr_lock = threading.Lock()


def get_soar_manager() -> SOARManager:
    """Return the module-level SOARManager singleton (thread-safe lazy init)."""
    global _manager
    if _manager is None:
        with _mgr_lock:
            if _manager is None:
                _manager = SOARManager()
    return _manager
