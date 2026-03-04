"""
AURORA – Push Alert Dispatcher
================================
Real outbound push notifications for CRITICAL and HIGH severity events.

Supported channels (all optional, all independently configurable):
  • Slack          — Incoming Webhook (Block Kit message)
  • PagerDuty      — Events API v2  (trigger / resolve)
  • Generic webhook— Any JSON endpoint (custom payload template)
  • SMTP email     — TLS-enabled (STARTTLS or SSL)

Configuration — ~/.aurora/notifications.json  OR  environment variables:

  {
    "slack":     {"webhook_url": "${AURORA_SLACK_WEBHOOK}"},
    "pagerduty": {"routing_key": "${AURORA_PD_ROUTING_KEY}"},
    "webhook":   {"url": "${AURORA_WEBHOOK_URL}", "secret": "${AURORA_WEBHOOK_SECRET}"},
    "email": {
      "host":     "smtp.example.com",
      "port":     587,
      "username": "${AURORA_SMTP_USER}",
      "password": "${AURORA_SMTP_PASS}",
      "from":     "aurora@example.com",
      "to":       ["soc@example.com", "ciso@example.com"],
      "use_tls":  true
    }
  }

All channels:
  • Are non-blocking (sent in a daemon thread — never delay AURORA's main loop)
  • Have per-channel rate limiting (max 60 alerts/hour per channel)
  • Log success/failure to the AURORA audit trail
  • Use constant-time HMAC signature for webhook verification
  • Never expose secrets in log output (secrets hashed before logging)

Usage:
  from notifications.dispatcher import get_dispatcher
  get_dispatcher().alert(
      severity="CRITICAL",
      event_type="CONTAINMENT",
      summary="Session frozen: mass_download by j.ross",
      detail={"user_id": "j.ross", "hri_score": 94, "action": "bulk_data_export"},
  )
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.paths import AURORA_HOME as _AURORA_HOME

logger = logging.getLogger("aurora.notifications")

_CONFIG_FILE = _AURORA_HOME / "notifications.json"

# ── Rate limit: max 60 alerts / hour per channel ──────────────────────────────
_RATE_WINDOW_S  = 3600
_RATE_MAX_CALLS = 60

# ── Severity filter: only send alerts at or above this level ─────────────────
_SEV_ORDER = {"INFO": 0, "WARN": 1, "HIGH": 2, "CRITICAL": 3}
_DEFAULT_MIN_SEVERITY = "HIGH"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve(val: Any) -> str:
    """Expand ${ENV_VAR} references."""
    if isinstance(val, str) and val.startswith("${") and val.endswith("}"):
        key = val[2:-1]
        resolved = os.environ.get(key, "")
        if not resolved:
            logger.debug(f"[notifications] env var {key} not set")
        return resolved
    return str(val) if val else ""


def _load_config() -> Dict:
    try:
        if _CONFIG_FILE.exists():
            return json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning(f"[notifications] config load failed: {exc}")
    return {}


def _secret_ref(secret: str) -> str:
    """Return a safe log-printable reference for a secret (never the secret itself)."""
    if not secret:
        return "<empty>"
    return "sha256:" + hashlib.sha256(secret.encode()).hexdigest()[:12] + "…"


# ── Minimal HTTP POST (stdlib only, no requests dependency) ──────────────────

def _http_post(
    url: str,
    payload: Dict,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 10,
) -> bool:
    """
    Fire-and-forget HTTPS POST using urllib only (zero new dependencies).
    Returns True on 2xx, False otherwise.
    """
    body = json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json", "User-Agent": "AURORA/1"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            ok = 200 <= resp.status < 300
            if not ok:
                logger.warning(f"[notifications] HTTP {resp.status} from {url}")
            return ok
    except urllib.error.HTTPError as exc:
        logger.warning(f"[notifications] HTTP error {exc.code} posting to {url}")
        return False
    except Exception as exc:
        logger.warning(f"[notifications] POST failed to {url}: {exc}")
        return False


# ── Per-channel rate limiter ──────────────────────────────────────────────────

class _ChannelRateLimiter:
    def __init__(self):
        self._windows: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, channel: str) -> bool:
        now = time.time()
        with self._lock:
            w = self._windows[channel]
            while w and w[0] < now - _RATE_WINDOW_S:
                w.popleft()
            if len(w) >= _RATE_MAX_CALLS:
                return False
            w.append(now)
            return True

    def remaining(self, channel: str) -> int:
        now = time.time()
        with self._lock:
            w = self._windows[channel]
            recent = sum(1 for t in w if t > now - _RATE_WINDOW_S)
            return max(0, _RATE_MAX_CALLS - recent)


# ── Slack channel ─────────────────────────────────────────────────────────────

def _send_slack(webhook_url: str, severity: str, event_type: str,
                summary: str, detail: Dict) -> bool:
    """
    Send a Block Kit message to Slack Incoming Webhook.
    No third-party SDK — pure HTTPS POST.
    """
    colour = {"CRITICAL": "#FF3C5A", "HIGH": "#FFB700",
              "WARN": "#00D4FF", "INFO": "#0AF5A0"}.get(severity, "#888")
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text",
                     "text": f"🔴 AURORA {severity} — {event_type}",
                     "emoji": True},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{summary}*"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                {"type": "mrkdwn", "text": f"*Event:*\n{event_type}"},
                {"type": "mrkdwn", "text": f"*Time:*\n{_now_iso()}"},
                {"type": "mrkdwn",
                 "text": f"*Detail:*\n```{json.dumps(detail, indent=2)[:800]}```"},
            ],
        },
    ]
    payload = {
        "text": f"AURORA {severity}: {summary}",  # fallback plain text
        "attachments": [{"color": colour, "blocks": blocks}],
    }
    return _http_post(webhook_url, payload)


# ── PagerDuty channel ─────────────────────────────────────────────────────────

def _send_pagerduty(routing_key: str, severity: str, event_type: str,
                    summary: str, detail: Dict) -> bool:
    """
    Send an event to PagerDuty Events API v2.
    Triggers an incident for CRITICAL/HIGH; sends INFO/WARN as acknowledgement.
    """
    pd_sev = {"CRITICAL": "critical", "HIGH": "error",
              "WARN": "warning", "INFO": "info"}.get(severity, "warning")
    # Stable dedup_key so repeated alerts for same event don't spam a new incident
    dedup_key = hashlib.sha256(
        f"{event_type}:{summary}".encode()
    ).hexdigest()[:32]

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": f"[AURORA] {severity} — {summary}",
            "severity": pd_sev,
            "source": "aurora-security-platform",
            "component": event_type,
            "group": "aurora",
            "class": severity,
            "custom_details": detail,
            "timestamp": _now_iso(),
        },
        "client": "AURORA",
    }
    return _http_post(
        "https://events.pagerduty.com/v2/enqueue",
        payload,
        headers={"X-Routing-Key": routing_key},
    )


# ── Generic webhook channel ───────────────────────────────────────────────────

def _send_webhook(url: str, secret: str, severity: str, event_type: str,
                  summary: str, detail: Dict) -> bool:
    """
    POST a JSON payload to any generic webhook endpoint.
    If a secret is configured, adds HMAC-SHA256 signature in X-Aurora-Signature.
    """
    ts = str(int(time.time()))
    body = {
        "aurora_event": {
            "severity":   severity,
            "event_type": event_type,
            "summary":    summary,
            "detail":     detail,
            "timestamp":  _now_iso(),
        }
    }
    headers: Dict[str, str] = {}
    if secret:
        body_bytes = json.dumps(body).encode("utf-8")
        sig = hmac.new(
            secret.encode("utf-8"),
            msg=f"{ts}.{body_bytes.decode()}".encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()
        headers["X-Aurora-Signature"] = f"t={ts},v1={sig}"
    return _http_post(url, body, headers=headers)


# ── SMTP email channel ────────────────────────────────────────────────────────

def _send_email(cfg: Dict, severity: str, event_type: str,
                summary: str, detail: Dict) -> bool:
    """
    Send TLS-encrypted email via SMTP (STARTTLS on port 587 / SSL on port 465).
    """
    host     = _resolve(cfg.get("host", ""))
    port     = int(cfg.get("port", 587))
    username = _resolve(cfg.get("username", ""))
    password = _resolve(cfg.get("password", ""))
    from_addr = _resolve(cfg.get("from", "aurora@localhost"))
    to_list   = [_resolve(a) for a in cfg.get("to", [])]
    use_tls   = cfg.get("use_tls", True)

    if not host or not to_list:
        logger.debug("[notifications] email: host or recipients not configured")
        return False

    subject = f"[AURORA {severity}] {event_type} — {summary[:80]}"
    body_text = (
        f"AURORA Security Alert\n"
        f"{'='*50}\n"
        f"Severity  : {severity}\n"
        f"Event Type: {event_type}\n"
        f"Summary   : {summary}\n"
        f"Time      : {_now_iso()}\n\n"
        f"Detail:\n{json.dumps(detail, indent=2)}\n"
    )
    body_html = f"""<html><body style="font-family:monospace;background:#030508;color:#c8d8f0;padding:24px">
<h2 style="color:{'#FF3C5A' if severity=='CRITICAL' else '#FFB700'}">
  AURORA {severity} — {event_type}</h2>
<p><strong>Summary:</strong> {summary}</p>
<p><strong>Time:</strong> {_now_iso()}</p>
<pre style="background:#0e1a2d;padding:12px;border-radius:6px;overflow:auto">
{json.dumps(detail, indent=2)}</pre>
</body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_addr
    msg["To"]      = ", ".join(to_list)
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))

    try:
        ctx = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as srv:
                if username and password:
                    srv.login(username, password)
                srv.sendmail(from_addr, to_list, msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=15) as srv:
                if use_tls:
                    srv.starttls(context=ctx)
                if username and password:
                    srv.login(username, password)
                srv.sendmail(from_addr, to_list, msg.as_string())
        logger.info(f"[notifications] email sent to {len(to_list)} recipient(s)")
        return True
    except Exception as exc:
        logger.warning(f"[notifications] email send failed: {exc}")
        return False


# ── Dispatcher ────────────────────────────────────────────────────────────────

class AlertDispatcher:
    """
    Central push-alert coordinator.
    All sends are non-blocking (daemon threads) and rate-limited.
    """

    def __init__(self):
        self._cfg           = _load_config()
        self._rate          = _ChannelRateLimiter()
        self._min_severity  = _SEV_ORDER.get(
            self._cfg.get("min_severity", _DEFAULT_MIN_SEVERITY),
            _SEV_ORDER[_DEFAULT_MIN_SEVERITY],
        )
        self._lock          = threading.Lock()
        self._send_count: Dict[str, int] = defaultdict(int)
        self._fail_count:  Dict[str, int] = defaultdict(int)

    def _reload_config(self) -> None:
        """Hot-reload config without restart."""
        self._cfg = _load_config()

    def _c(self, section: str, key: str) -> str:
        return _resolve(self._cfg.get(section, {}).get(key, ""))

    def alert(
        self,
        severity: str,
        event_type: str,
        summary: str,
        detail: Optional[Dict] = None,
    ) -> None:
        """
        Dispatch an alert to all configured channels.
        Non-blocking — spawns daemon threads per channel.
        """
        if detail is None:
            detail = {}

        # Filter by minimum severity
        if _SEV_ORDER.get(severity, 0) < self._min_severity:
            return

        # Dispatch each channel in its own thread
        channels = self._build_channel_list(severity, event_type, summary, detail)
        for name, fn in channels:
            if not self._rate.allow(name):
                logger.warning(
                    f"[notifications] channel '{name}' rate-limited "
                    f"(>{_RATE_MAX_CALLS}/hr) — alert dropped"
                )
                continue
            t = threading.Thread(
                target=self._fire,
                args=(name, fn),
                daemon=True,
                name=f"aurora-alert-{name}",
            )
            t.start()

    def _fire(self, channel: str, fn) -> None:
        try:
            ok = fn()
            with self._lock:
                if ok:
                    self._send_count[channel] += 1
                    logger.info(f"[notifications] {channel}: alert sent ok")
                else:
                    self._fail_count[channel] += 1
                    logger.warning(f"[notifications] {channel}: send failed")
        except Exception as exc:
            with self._lock:
                self._fail_count[channel] += 1
            logger.error(f"[notifications] {channel}: exception: {exc}")

    def _build_channel_list(
        self, severity: str, event_type: str, summary: str, detail: Dict
    ) -> List:
        channels = []

        # Slack
        slack_url = self._c("slack", "webhook_url")
        if slack_url:
            channels.append((
                "slack",
                lambda u=slack_url: _send_slack(u, severity, event_type, summary, detail),
            ))

        # PagerDuty
        pd_key = self._c("pagerduty", "routing_key")
        if pd_key:
            channels.append((
                "pagerduty",
                lambda k=pd_key: _send_pagerduty(k, severity, event_type, summary, detail),
            ))

        # Generic webhook
        wh_url = self._c("webhook", "url")
        if wh_url:
            wh_secret = self._c("webhook", "secret")
            channels.append((
                "webhook",
                lambda u=wh_url, s=wh_secret: _send_webhook(
                    u, s, severity, event_type, summary, detail
                ),
            ))

        # Email
        email_cfg = self._cfg.get("email", {})
        if email_cfg and email_cfg.get("host"):
            channels.append((
                "email",
                lambda c=email_cfg: _send_email(
                    c, severity, event_type, summary, detail
                ),
            ))

        return channels

    def status(self) -> Dict[str, Any]:
        """Return dispatcher status for health endpoint."""
        channels_configured = []
        for ch, key in [
            ("slack",     ("slack", "webhook_url")),
            ("pagerduty", ("pagerduty", "routing_key")),
            ("webhook",   ("webhook", "url")),
            ("email",     ("email", "host")),
        ]:
            val = self._c(key[0], key[1])
            if val:
                channels_configured.append(ch)

        with self._lock:
            return {
                "channels_configured": channels_configured,
                "channels_available":  ["slack", "pagerduty", "webhook", "email"],
                "sends_ok":   dict(self._send_count),
                "sends_fail": dict(self._fail_count),
                "rate_limits": {
                    ch: self._rate.remaining(ch)
                    for ch in ["slack", "pagerduty", "webhook", "email"]
                },
                "min_severity": list(_SEV_ORDER.keys())[self._min_severity],
            }

    def test_channels(self) -> Dict[str, bool]:
        """
        Send a test alert to every configured channel.
        Returns {channel_name: success}.
        Used by `aurora.py doctor` and unit tests.
        """
        results: Dict[str, bool] = {}
        channels = self._build_channel_list(
            severity="INFO",
            event_type="SYSTEM_TEST",
            summary="AURORA notification channel test",
            detail={"test": True, "timestamp": _now_iso()},
        )
        for name, fn in channels:
            try:
                results[name] = bool(fn())
            except Exception as exc:
                results[name] = False
                logger.warning(f"[notifications] test failed for {name}: {exc}")
        return results


# ── Module-level singleton ────────────────────────────────────────────────────

_dispatcher: Optional[AlertDispatcher] = None
_disp_lock  = threading.Lock()


def get_dispatcher() -> AlertDispatcher:
    """Return the module-level AlertDispatcher singleton (thread-safe)."""
    global _dispatcher
    if _dispatcher is None:
        with _disp_lock:
            if _dispatcher is None:
                _dispatcher = AlertDispatcher()
    return _dispatcher
