"""
AURORA Live Dashboard — SSE-Powered Security Intelligence
===========================================================
HTML5 + Server-Sent Events dashboard that connects directly to the running
AURORA REST API for real-time push updates.

This module serves:
  GET  /dashboard              — Full HTML dashboard page
  GET  /dashboard/config       — JS-safe config JSON (api_url, sse_endpoint, …)
  POST /dashboard/session      — Exchange an API token for a signed server-side
                                  session cookie (NOC screen support)
  GET  /dashboard/session      — Refresh / validate an existing session cookie
  POST /dashboard/logout       — Delete a session cookie (server-side)

Architecture — data flow:
  Browser ──── GET /events?token=<tok> ────> AURORA REST API (/events)
       <──── SSE frames (heartbeat / snapshot) ──────────────────────────

Token persistence strategy (two tiers):
  Tier 1 — Ephemeral (default, most secure):
    Token stored in browser sessionStorage. Cleared when the tab or browser
    closes. Suitable for individual analyst workstations.

  Tier 2 — Server-side session cookie (NOC screen / shared display):
    Operator POSTs their API token to /dashboard/session once.
    Server validates the token against AURORA REST API /health, then stores it
    in AURORA_HOME/dashboard_sessions/<session_id>.json (mode 0o600).
    A short-lived, HMAC-SHA256-signed HttpOnly cookie is returned.
    Cookie flags: HttpOnly; SameSite=Strict; Secure (on HTTPS).
    Cookie lifetime: configurable, default 8 hours.
    On browser restart, the cookie is sent automatically — no re-entry needed.
    Sessions are pruned on each request and on server start.

Performance:
  The SSE stream replaces all polling. The browser reconnects automatically
  if the connection drops (built-in EventSource retry logic).

Usage:
  from dashboard.live_dashboard import DashboardServer
  DashboardServer(api_url="http://127.0.0.1:9100").serve(port=9102)

  CLI:
    aurora.py dashboard [--api-url http://127.0.0.1:9100] [--port 9102]
    aurora.py dashboard [--session-ttl 28800]    # 8-hour NOC sessions
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import html
import io
import json
import logging
import os
import secrets
import socketserver
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import wsgiref.simple_server
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("aurora.dashboard")

try:
    from core.paths import AURORA_HOME as _AURORA_HOME
except ImportError:
    _AURORA_HOME = Path.home() / ".aurora"

_TOKEN_FILE      = _AURORA_HOME / "api_token"
_SESSION_DIR     = _AURORA_HOME / "dashboard_sessions"
_DEFAULT_API_URL = "http://127.0.0.1:9100"
_COOKIE_NAME     = "aurora_dash_sess"
_DEFAULT_SESSION_TTL_S = 8 * 3600   # 8 hours default for NOC use

# Per-process HMAC key — signs session IDs in cookies.
# Restarting the dashboard server invalidates existing cookies (acceptable:
# operators must re-authenticate after a server restart).
_COOKIE_KEY = secrets.token_bytes(32)


# ── Token loading ─────────────────────────────────────────────────────────────

def _load_token() -> str:
    tok = os.environ.get("AURORA_API_TOKEN", "")
    if tok:
        return tok
    try:
        if _TOKEN_FILE.exists():
            return _TOKEN_FILE.read_text().strip()
    except Exception:
        pass
    return ""


# ── Session store ─────────────────────────────────────────────────────────────

class _SessionStore:
    """
    File-backed session store for NOC dashboard tokens.

    Session files: AURORA_HOME/dashboard_sessions/<id>.json (mode 0o600)
    Cookie value:  <session_id>.<hmac_sha256_hex>  (tamper-evident)

    Sessions expire after `ttl` seconds and are pruned on every operation.
    Session data layout:
        {
          "api_token":   "aurora_token_…",
          "api_url":     "http://127.0.0.1:9100",
          "issued_at":   1700000000.0,
          "expires_at":  1700028800.0
        }
    """

    def __init__(self, ttl: int = _DEFAULT_SESSION_TTL_S):
        self._ttl  = ttl
        self._lock = threading.Lock()
        try:
            _SESSION_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning("[dashboard] session dir creation failed: %s", exc)

    # ── Cookie signing ────────────────────────────────────────────────────────

    def _sign(self, sid: str) -> str:
        mac = _hmac.new(_COOKIE_KEY, sid.encode(), hashlib.sha256).hexdigest()
        return f"{sid}.{mac}"

    def _verify(self, cookie_val: str) -> Optional[str]:
        if "." not in cookie_val:
            return None
        sid, _, mac = cookie_val.rpartition(".")
        expected = _hmac.new(_COOKIE_KEY, sid.encode(), hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(mac, expected):
            return None
        return sid

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def create(self, api_token: str, api_url: str) -> str:
        """Persist a session and return a signed cookie value."""
        self._prune()
        sid  = secrets.token_urlsafe(32)
        now  = time.time()
        data = {"api_token":  api_token,
                "api_url":    api_url,
                "issued_at":  now,
                "expires_at": now + self._ttl}
        path = _SESSION_DIR / f"{sid}.json"
        try:
            path.write_text(json.dumps(data), encoding="utf-8")
            path.chmod(0o600)
        except Exception as exc:
            logger.warning("[dashboard] session write failed: %s", exc)
        return self._sign(sid)

    def get(self, cookie_val: str) -> Optional[Dict]:
        """Return session data dict or None if invalid / expired."""
        sid = self._verify(cookie_val)
        if not sid:
            return None
        path = _SESSION_DIR / f"{sid}.json"
        with self._lock:
            try:
                if not path.exists():
                    return None
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return None
        if time.time() > data.get("expires_at", 0):
            self._delete_file(path)
            return None
        return data

    def delete(self, cookie_val: str) -> None:
        """Delete a session on logout."""
        sid = self._verify(cookie_val)
        if not sid:
            return
        self._delete_file(_SESSION_DIR / f"{sid}.json")

    def _delete_file(self, path: Path) -> None:
        with self._lock:
            try:
                if path.exists():
                    path.unlink()
            except Exception:
                pass

    def _prune(self) -> int:
        """Delete all expired session files. Returns count pruned."""
        now   = time.time()
        count = 0
        try:
            for p in list(_SESSION_DIR.glob("*.json")):
                try:
                    data = json.loads(p.read_text())
                    if now > data.get("expires_at", 0):
                        p.unlink()
                        count += 1
                except Exception:
                    pass
        except Exception:
            pass
        if count:
            logger.debug("[dashboard] pruned %d expired session(s)", count)
        return count

    def cookie_header(self, signed: str, secure: bool = False) -> str:
        """Build a Set-Cookie header value with security flags."""
        flags = [f"{_COOKIE_NAME}={signed}",
                 f"Max-Age={self._ttl}",
                 "HttpOnly",
                 "SameSite=Strict",
                 "Path=/"]
        if secure:
            flags.append("Secure")
        return "; ".join(flags)

    def clear_cookie_header(self) -> str:
        """Build a Set-Cookie header to clear the cookie on logout."""
        return (f"{_COOKIE_NAME}=deleted; Max-Age=0; "
                "HttpOnly; SameSite=Strict; Path=/")


# ── HTML template ─────────────────────────────────────────────────────────────

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AURORA Live Dashboard</title>
<style>
  :root {
    --bg:      #030508;
    --surface: #0a1120;
    --border:  #1a2a44;
    --low:     #0af5a0;
    --medium:  #ffd700;
    --high:    #ff8c00;
    --critical:#ff3c5a;
    --text:    #c8d8f0;
    --dim:     #5a7099;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Courier New', monospace;
    padding: 24px;
    min-height: 100vh;
  }
  h1 { font-size: 1.4rem; letter-spacing: 0.15em; color: var(--low); margin-bottom: 4px; }
  .sub { color: var(--dim); font-size: 0.75rem; margin-bottom: 24px; }

  /* Status bar */
  #status-bar {
    display: flex; align-items: center; gap: 10px;
    padding: 10px 16px; border-radius: 6px;
    background: var(--surface); border: 1px solid var(--border);
    margin-bottom: 20px; font-size: 0.8rem;
  }
  #conn-dot { width: 10px; height: 10px; border-radius: 50%; background: var(--dim); }
  #conn-dot.live        { background: var(--low); box-shadow: 0 0 6px var(--low); }
  #conn-dot.reconnecting{ background: var(--medium); animation: blink 1s infinite; }
  #conn-dot.offline     { background: var(--critical); }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

  /* NOC session badge */
  #session-badge {
    display: none; margin-left: auto; padding: 2px 10px;
    border-radius: 10px; font-size: 0.7rem;
    background: #0af5a011; color: var(--low);
    border: 1px solid var(--low);
  }
  #session-badge.show { display: inline-block; }

  /* Grid */
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }

  /* Cards */
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 18px;
  }
  .card h3 { font-size: 0.7rem; color: var(--dim); text-transform: uppercase;
             letter-spacing: 0.1em; margin-bottom: 14px; }

  /* Risk gauge */
  #risk-score {
    font-size: 3.5rem; font-weight: bold; text-align: center; line-height: 1;
    transition: color 0.5s;
  }
  #risk-level {
    text-align: center; font-size: 0.85rem; letter-spacing: 0.2em;
    margin-top: 6px; transition: color 0.5s;
  }
  #risk-bar-wrap { background: #0d1f36; border-radius: 4px; height: 8px; margin-top: 14px; overflow: hidden; }
  #risk-bar {
    height: 100%; border-radius: 4px; transition: width 0.8s ease, background 0.5s;
    background: var(--low);
  }

  /* Health */
  .health-row { display: flex; justify-content: space-between; align-items: center;
                font-size: 0.8rem; padding: 5px 0; border-bottom: 1px solid #0d1f36; }
  .health-row:last-child { border-bottom: none; }
  .badge {
    padding: 2px 8px; border-radius: 10px; font-size: 0.7rem; font-weight: bold;
  }
  .badge-ok   { background: #0af5a022; color: var(--low); border: 1px solid var(--low); }
  .badge-warn { background: #ffd70022; color: var(--medium); border: 1px solid var(--medium); }
  .badge-err  { background: #ff3c5a22; color: var(--critical); border: 1px solid var(--critical); }

  /* Event log */
  #event-log {
    max-height: 220px; overflow-y: auto; font-size: 0.72rem; line-height: 1.6;
    color: var(--dim);
  }
  .log-entry { padding: 2px 0; border-bottom: 1px solid #0d1f36; }
  .log-entry .ts  { color: #2a4070; margin-right: 8px; }
  .log-entry.snap { color: var(--text); }
  .log-entry.err  { color: var(--critical); }

  /* Horizon */
  #horizon-list { font-size: 0.78rem; }
  .horizon-item { padding: 5px 0; border-bottom: 1px solid #0d1f36; display: flex; justify-content: space-between; }
  .horizon-item:last-child { border-bottom: none; }

  /* Notifications badge */
  #notif-channels { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }

  /* ── Token / session modal ── */
  #token-modal {
    display: none; position: fixed; inset: 0;
    background: rgba(0,0,0,0.82); z-index: 100;
    justify-content: center; align-items: center;
  }
  #token-modal.show { display: flex; }
  #token-box {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 32px; max-width: 440px; width: 92%;
  }
  #token-box h2 { color: var(--low); margin-bottom: 10px; font-size: 1rem; }
  #token-box p  { color: var(--dim); font-size: 0.78rem; margin-bottom: 14px; line-height: 1.5; }
  .token-field {
    width: 100%; background: #040c18; border: 1px solid var(--border);
    color: var(--text); font-family: monospace; padding: 10px;
    border-radius: 4px; font-size: 0.85rem; margin-bottom: 10px;
  }
  .token-btn {
    width: 100%; padding: 10px;
    background: var(--low); color: #030508; border: none;
    border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 0.85rem;
    margin-bottom: 8px;
  }
  .token-btn:hover { opacity: 0.85; }
  .token-btn.secondary {
    background: transparent; color: var(--dim);
    border: 1px solid var(--border);
  }
  .token-hint { font-size: 0.7rem; color: var(--dim); margin-top: 4px; }
  #session-mode-tabs { display: flex; gap: 8px; margin-bottom: 16px; }
  .tab-btn {
    flex: 1; padding: 6px; border: 1px solid var(--border);
    background: transparent; color: var(--dim); border-radius: 4px;
    cursor: pointer; font-size: 0.75rem;
  }
  .tab-btn.active { border-color: var(--low); color: var(--low); background: #0af5a011; }
  #noc-session-panel { display: none; }
  #session-expiry { margin-top: 8px; font-size: 0.7rem; color: var(--dim); }
</style>
</head>
<body>

<h1>▸ AURORA LIVE DASHBOARD</h1>
<p class="sub">Real-time security intelligence · Server-Sent Events stream</p>

<div id="status-bar">
  <div id="conn-dot"></div>
  <span id="conn-label">Connecting…</span>
  <span id="session-badge" title="NOC session active — token persisted server-side">
    🖥️ NOC SESSION
  </span>
  <span style="margin-left:auto;color:var(--dim)" id="last-update">—</span>
</div>

<div class="grid">

  <!-- Risk gauge -->
  <div class="card">
    <h3>Human Risk Index</h3>
    <div id="risk-score">—</div>
    <div id="risk-level">—</div>
    <div id="risk-bar-wrap"><div id="risk-bar" style="width:0%"></div></div>
  </div>

  <!-- Health -->
  <div class="card">
    <h3>System Health</h3>
    <div id="health-rows">
      <div class="health-row"><span>API</span><span class="badge badge-warn" id="h-api">…</span></div>
      <div class="health-row"><span>Storage</span><span class="badge badge-warn" id="h-storage">…</span></div>
      <div class="health-row"><span>TLS</span><span class="badge badge-warn" id="h-tls">…</span></div>
      <div class="health-row"><span>Notifications</span><div id="notif-channels">…</div></div>
    </div>
  </div>

  <!-- Horizon -->
  <div class="card">
    <h3>Event Horizon (next 24 h)</h3>
    <div id="horizon-list"><span style="color:var(--dim)">Awaiting stream…</span></div>
  </div>

  <!-- Event log -->
  <div class="card" style="grid-column: 1 / -1">
    <h3>Live Event Log <span style="font-size:0.65rem;color:var(--dim)" id="frame-count">(0 frames)</span></h3>
    <div id="event-log"></div>
  </div>

</div>

<!-- Token / session modal -->
<div id="token-modal">
  <div id="token-box">
    <h2>🔐 AURORA Authentication</h2>

    <!-- Tab switcher -->
    <div id="session-mode-tabs">
      <button class="tab-btn active" onclick="switchTab('ephemeral')" id="tab-ephemeral">
        🔒 This session only
      </button>
      <button class="tab-btn" onclick="switchTab('noc')" id="tab-noc">
        🖥️ Persist (NOC screen)
      </button>
    </div>

    <!-- Ephemeral token panel -->
    <div id="ephemeral-panel">
      <p>Token stored in <strong>sessionStorage</strong> only — cleared when this tab closes.
         Best for individual analyst workstations.</p>
      <input id="token-input" class="token-field" type="password"
             placeholder="aurora_token_…" autocomplete="off"
             onkeydown="if(event.key==='Enter') submitEphemeral()">
      <button class="token-btn" onclick="submitEphemeral()">Connect →</button>
    </div>

    <!-- NOC session panel -->
    <div id="noc-session-panel">
      <p>Token is securely stored in an <strong>HttpOnly server-side session cookie</strong>
         (signed, time-limited). The cookie persists across browser restarts — no re-entry
         needed for shared NOC displays.</p>
      <input id="noc-token-input" class="token-field" type="password"
             placeholder="aurora_token_…" autocomplete="off"
             onkeydown="if(event.key==='Enter') submitNOCSession()">
      <button class="token-btn" onclick="submitNOCSession()">Save &amp; Connect →</button>
      <button class="token-btn secondary" onclick="clearNOCSession()">Clear saved session</button>
      <div id="session-expiry"></div>
      <p class="token-hint">Session expires in __SESSION_TTL_HOURS__ hours. Cookie flags: HttpOnly; SameSite=Strict.</p>
    </div>
  </div>
</div>

<script>
// ── Server-injected config ────────────────────────────────────────────────────
const AURORA_API_URL   = '__AURORA_API_URL__';
const DASH_SESSION_TTL = __SESSION_TTL_S__;   // seconds

// ── State ─────────────────────────────────────────────────────────────────────
let es = null;
let frameCount = 0;
const MAX_LOG = 20;
let _nocSessionActive = false;

// ── Tab switcher ──────────────────────────────────────────────────────────────
function switchTab(mode) {
  document.getElementById('ephemeral-panel').style.display   = mode === 'ephemeral' ? '' : 'none';
  document.getElementById('noc-session-panel').style.display = mode === 'noc' ? '' : 'none';
  document.getElementById('tab-ephemeral').classList.toggle('active', mode === 'ephemeral');
  document.getElementById('tab-noc').classList.toggle('active', mode === 'noc');
}

// ── Token management — Tier 1: ephemeral (sessionStorage) ─────────────────────
function getEphemeralToken() {
  return sessionStorage.getItem('aurora_token') || '';
}
function setEphemeralToken(tok) {
  sessionStorage.setItem('aurora_token', tok);
}
function clearEphemeralToken() {
  sessionStorage.removeItem('aurora_token');
}

function submitEphemeral() {
  const tok = document.getElementById('token-input').value.trim();
  if (!tok) return;
  setEphemeralToken(tok);
  closeModal();
  _nocSessionActive = false;
  startStream(tok);
}

// ── Token management — Tier 2: NOC server-side session cookie ─────────────────
// The browser POSTs the API token to /dashboard/session.
// The server validates it, stores it, and returns a signed HttpOnly cookie.
// On subsequent page loads, JS calls GET /dashboard/session to check if a
// valid server-side session exists and retrieves the token transparently.

async function submitNOCSession() {
  const tok = document.getElementById('noc-token-input').value.trim();
  if (!tok) return;
  try {
    const resp = await fetch('/dashboard/session', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({api_token: tok, api_url: AURORA_API_URL}),
      credentials: 'same-origin'   // send/receive cookies
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({error: 'unknown'}));
      logEntry('NOC session error: ' + (err.error || resp.status), 'err');
      return;
    }
    const data = await resp.json();
    _nocSessionActive = true;
    document.getElementById('session-badge').classList.add('show');
    const exp = new Date(Date.now() + DASH_SESSION_TTL * 1000);
    document.getElementById('session-expiry').textContent =
      'Session expires: ' + exp.toLocaleString();
    closeModal();
    startStream(tok);
  } catch(e) {
    logEntry('NOC session create failed: ' + e.message, 'err');
  }
}

async function resolveNOCSession() {
  // Try to retrieve an existing server-side session on page load.
  // Returns the api_token if a valid session exists, else null.
  try {
    const resp = await fetch('/dashboard/session', {
      method: 'GET', credentials: 'same-origin'
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    if (data && data.api_token) {
      _nocSessionActive = true;
      document.getElementById('session-badge').classList.add('show');
      const exp = new Date((data.expires_at || 0) * 1000);
      document.getElementById('session-expiry').textContent =
        'Session expires: ' + exp.toLocaleString();
      return data.api_token;
    }
  } catch(_) {}
  return null;
}

async function clearNOCSession() {
  try {
    await fetch('/dashboard/logout', {method: 'POST', credentials: 'same-origin'});
  } catch(_) {}
  _nocSessionActive = false;
  document.getElementById('session-badge').classList.remove('show');
  clearEphemeralToken();
  if (es) { es.close(); es = null; }
  setStatus('offline', 'Logged out');
  promptToken();
}

// ── Modal ─────────────────────────────────────────────────────────────────────
function promptToken() {
  document.getElementById('token-modal').classList.add('show');
}
function closeModal() {
  document.getElementById('token-modal').classList.remove('show');
}

// ── Connection status ─────────────────────────────────────────────────────────
function setStatus(state, label) {
  const dot = document.getElementById('conn-dot');
  dot.className = '';
  dot.classList.add(state);
  document.getElementById('conn-label').textContent = label;
}

// ── Risk gauge ────────────────────────────────────────────────────────────────
const LEVEL_COLOURS = {
  LOW:      'var(--low)',
  MEDIUM:   'var(--medium)',
  HIGH:     'var(--high)',
  CRITICAL: 'var(--critical)',
};

function updateRisk(risk) {
  if (!risk || risk.error) return;
  const score = risk.score ?? 0;
  const level = risk.level ?? 'LOW';
  const colour = LEVEL_COLOURS[level] || 'var(--text)';
  document.getElementById('risk-score').textContent = score.toFixed(1);
  document.getElementById('risk-score').style.color = colour;
  document.getElementById('risk-level').textContent = level;
  document.getElementById('risk-level').style.color = colour;
  document.getElementById('risk-bar').style.width = Math.min(score, 100) + '%';
  document.getElementById('risk-bar').style.background = colour;
}

// ── Health ────────────────────────────────────────────────────────────────────
function updateHealth(health) {
  if (!health || health.error) return;
  document.getElementById('h-api').outerHTML =
    `<span class="badge badge-ok" id="h-api">${health.health || 'OK'}</span>`;
  const st = health.storage || {};
  document.getElementById('h-storage').outerHTML =
    `<span class="badge ${st.backend ? 'badge-ok' : 'badge-warn'}" id="h-storage">${st.backend || '?'}</span>`;
  const tls = health.tls || {};
  document.getElementById('h-tls').outerHTML =
    `<span class="badge ${tls.tls_enabled ? 'badge-ok' : 'badge-warn'}" id="h-tls">${tls.tls_enabled ? 'ENABLED' : 'HTTP'}</span>`;
  const notif = health.notifications || {};
  const chs = notif.channels_configured || [];
  const nc = document.getElementById('notif-channels');
  if (nc) {
    nc.innerHTML = chs.length
      ? chs.map(c => `<span class="badge badge-ok">${c}</span>`).join('')
      : '<span class="badge badge-warn">none</span>';
  }
}

// ── Horizon ───────────────────────────────────────────────────────────────────
function updateHorizon(horizon) {
  const el = document.getElementById('horizon-list');
  if (!horizon || horizon.error) {
    el.innerHTML = '<span style="color:var(--dim)">No data</span>';
    return;
  }
  const threats = horizon.emerging_threats || horizon.predictions || [];
  if (!threats.length) {
    el.innerHTML = '<span style="color:var(--dim)">No emerging threats</span>';
    return;
  }
  el.innerHTML = threats.slice(0,5).map(t => {
    const name = t.threat || t.name || JSON.stringify(t).slice(0,40);
    const prob = t.probability != null ? (t.probability * 100).toFixed(0) + '%' : '';
    return `<div class="horizon-item"><span>${escHtml(name)}</span><span style="color:var(--medium)">${prob}</span></div>`;
  }).join('');
}

// ── Event log ─────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function logEntry(msg, cls='') {
  const log = document.getElementById('event-log');
  const ts  = new Date().toLocaleTimeString();
  const div = document.createElement('div');
  div.className = 'log-entry ' + cls;
  div.innerHTML = `<span class="ts">${ts}</span>${escHtml(msg)}`;
  log.prepend(div);
  while (log.children.length > MAX_LOG) log.removeChild(log.lastChild);
  frameCount++;
  document.getElementById('frame-count').textContent = `(${frameCount} frames)`;
  document.getElementById('last-update').textContent = 'Last: ' + ts;
}

// ── SSE stream ────────────────────────────────────────────────────────────────
function startStream(token) {
  if (!token) { promptToken(); return; }
  if (es) { es.close(); es = null; }

  const url = AURORA_API_URL + '/events?token=' + encodeURIComponent(token);
  setStatus('reconnecting', 'Connecting…');

  es = new EventSource(url);

  es.addEventListener('aurora_update', function(e) {
    let data;
    try { data = JSON.parse(e.data); } catch(_) { return; }
    if (data.type === 'heartbeat') {
      setStatus('live', 'Live · heartbeat'); logEntry('heartbeat'); return;
    }
    if (data.type === 'snapshot') {
      setStatus('live', 'Live · streaming');
      updateRisk(data.risk); updateHealth(data.health); updateHorizon(data.horizon);
      const riskStr = data.risk
        ? `risk=${data.risk.score?.toFixed(1)} [${data.risk.level}]`
        : 'no risk data';
      logEntry(`snapshot · ${riskStr}`, 'snap');
    }
  });

  es.addEventListener('aurora_error', function(e) {
    let msg = e.data;
    try { msg = JSON.parse(e.data).error || msg; } catch(_) {}
    setStatus('offline', 'Error');
    logEntry('ERROR: ' + msg, 'err');
    if (msg && msg.includes('Unauthorized')) {
      clearEphemeralToken();
      _nocSessionActive = false;
      setTimeout(promptToken, 1500);
    }
  });

  es.onerror  = function() {
    setStatus('reconnecting', 'Reconnecting…');
    logEntry('Connection lost — EventSource will retry…', 'err');
  };
  es.onopen   = function() {
    setStatus('live', 'Live'); logEntry('SSE connection established');
  };
}

// ── Boot ──────────────────────────────────────────────────────────────────────
(async function init() {
  // 1. Try server-side session cookie first (NOC screens, persists across restarts)
  const nocToken = await resolveNOCSession();
  if (nocToken) {
    startStream(nocToken);
    return;
  }
  // 2. Fall back to sessionStorage (ephemeral)
  const ephToken = getEphemeralToken();
  if (ephToken) {
    startStream(ephToken);
    return;
  }
  // 3. No token anywhere — prompt
  promptToken();
})();
</script>
</body>
</html>
"""


def _build_html(api_url: str, session_ttl: int) -> str:
    return (_DASHBOARD_HTML
            .replace("__AURORA_API_URL__", html.escape(api_url, quote=True))
            .replace("__SESSION_TTL_S__",  str(session_ttl))
            .replace("__SESSION_TTL_HOURS__", str(round(session_ttl / 3600, 1))))


# ── WSGI token-validation helper ──────────────────────────────────────────────

def _validate_token_against_api(api_url: str, token: str, timeout: int = 5) -> bool:
    """
    Validate an API token by calling the AURORA REST API /health endpoint.
    Returns True if the server returns 200 with the given token.
    """
    try:
        ctx = ssl.create_default_context() if api_url.startswith("https") else None
        url = api_url.rstrip("/") + "/health"
        req = urllib.request.Request(
            url,
            headers={"X-Aurora-Token": token, "Accept": "application/json"})
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        # If AURORA API is down, accept the token optimistically
        # (the SSE connection itself will reject bad tokens)
        logger.warning("[dashboard] token validation skipped — AURORA API unreachable")
        return True


# ── DashboardServer ────────────────────────────────────────────────────────────

class DashboardServer:
    """
    Serves the AURORA live dashboard as a WSGI application.

    Endpoints:
      GET  /dashboard          — Full dashboard HTML
      GET  /dashboard/config   — JSON config for external embedding
      POST /dashboard/session  — Create a NOC server-side session cookie
      GET  /dashboard/session  — Retrieve current session (for init() check)
      POST /dashboard/logout   — Delete session cookie
      *                        — Redirect to /dashboard

    Token tiers:
      1. Server-side session cookie  (POST /dashboard/session) — NOC screens
      2. sessionStorage              (client-only)             — analyst workstations
    """

    def __init__(self, api_url: str = _DEFAULT_API_URL, token: str = "",
                 session_ttl: int = _DEFAULT_SESSION_TTL_S):
        self._api_url     = api_url.rstrip("/")
        self._token       = token or _load_token()
        self._session_ttl = session_ttl
        self._sessions    = _SessionStore(ttl=session_ttl)
        self._html        = _build_html(self._api_url, session_ttl)

    # ── Request helpers ───────────────────────────────────────────────────────

    def _common_headers(self) -> list:
        return [("X-Frame-Options",     "DENY"),
                ("X-Content-Type-Options","nosniff"),
                ("Cache-Control",        "no-store")]

    def _get_cookie(self, environ: dict) -> str:
        """Extract the aurora_dash_sess cookie value from request."""
        cookie_header = environ.get("HTTP_COOKIE", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith(f"{_COOKIE_NAME}="):
                return part[len(f"{_COOKIE_NAME}="):]
        return ""

    def _read_body(self, environ: dict) -> bytes:
        try:
            length = int(environ.get("CONTENT_LENGTH", 0) or 0)
            return environ["wsgi.input"].read(length)
        except Exception:
            return b""

    # ── WSGI dispatcher ───────────────────────────────────────────────────────

    def wsgi_app(self, environ: dict, start_response):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path   = environ.get("PATH_INFO", "/").rstrip("/") or "/"

        if path == "/":
            start_response("302 Found", [("Location", "/dashboard")])
            return [b""]

        if path in ("/dashboard", "/dashboard/"):
            return self._handle_dashboard(environ, start_response)

        if path == "/dashboard/config":
            return self._handle_config(environ, start_response)

        if path == "/dashboard/session" and method == "POST":
            return self._handle_session_create(environ, start_response)

        if path == "/dashboard/session" and method == "GET":
            return self._handle_session_get(environ, start_response)

        if path == "/dashboard/logout" and method == "POST":
            return self._handle_logout(environ, start_response)

        # Catch-all redirect
        start_response("302 Found", [("Location", "/dashboard")])
        return [b""]

    # ── Handlers ──────────────────────────────────────────────────────────────

    def _handle_dashboard(self, environ, start_response):
        body = self._html.encode("utf-8")
        start_response("200 OK",
                       [("Content-Type",   "text/html; charset=utf-8"),
                        ("Content-Length", str(len(body)))]
                       + self._common_headers())
        return [body]

    def _handle_config(self, environ, start_response):
        cfg = {
            "api_url":      self._api_url,
            "token_set":    bool(self._token),
            "sse_endpoint": self._api_url + "/events",
            "session_ttl":  self._session_ttl,
        }
        body = json.dumps(cfg).encode("utf-8")
        start_response("200 OK",
                       [("Content-Type",  "application/json"),
                        ("Content-Length", str(len(body)))]
                       + self._common_headers())
        return [body]

    def _handle_session_create(self, environ, start_response):
        """
        POST /dashboard/session  body: {api_token, api_url?}
        Validates the token, creates a server-side session, sets cookie.
        """
        try:
            body_bytes = self._read_body(environ)
            payload    = json.loads(body_bytes)
            api_token  = payload.get("api_token", "").strip()
            api_url    = payload.get("api_url", self._api_url).strip() or self._api_url
        except Exception:
            start_response("400 Bad Request", [("Content-Type", "application/json")])
            return [json.dumps({"error": "malformed JSON body"}).encode()]

        if not api_token:
            start_response("400 Bad Request", [("Content-Type", "application/json")])
            return [json.dumps({"error": "api_token required"}).encode()]

        # Validate the token
        if not _validate_token_against_api(api_url, api_token):
            start_response("401 Unauthorized", [("Content-Type", "application/json")])
            return [json.dumps({"error": "token validation failed"}).encode()]

        signed = self._sessions.create(api_token, api_url)
        secure = environ.get("wsgi.url_scheme", "http") == "https"
        cookie = self._sessions.cookie_header(signed, secure=secure)

        body = json.dumps({"ok": True, "expires_in": self._session_ttl}).encode()
        start_response("200 OK",
                       [("Content-Type",   "application/json"),
                        ("Content-Length", str(len(body))),
                        ("Set-Cookie",     cookie)]
                       + self._common_headers())
        return [body]

    def _handle_session_get(self, environ, start_response):
        """
        GET /dashboard/session
        Return session data if a valid server-side session cookie exists.
        Used by init() on page load to restore NOC sessions across restarts.
        """
        cookie_val = self._get_cookie(environ)
        if not cookie_val:
            start_response("204 No Content", self._common_headers())
            return [b""]
        session = self._sessions.get(cookie_val)
        if not session:
            # Cookie present but invalid/expired — clear it
            start_response("401 Unauthorized",
                           [("Content-Type", "application/json"),
                            ("Set-Cookie",   self._sessions.clear_cookie_header())]
                           + self._common_headers())
            return [json.dumps({"error": "session expired"}).encode()]

        # Return the stored token so init() can start the SSE stream
        body = json.dumps({
            "ok":          True,
            "api_token":   session["api_token"],
            "api_url":     session["api_url"],
            "expires_at":  session["expires_at"],
        }).encode()
        start_response("200 OK",
                       [("Content-Type",   "application/json"),
                        ("Content-Length", str(len(body)))]
                       + self._common_headers())
        return [body]

    def _handle_logout(self, environ, start_response):
        """DELETE session cookie and remove server-side session file."""
        cookie_val = self._get_cookie(environ)
        if cookie_val:
            self._sessions.delete(cookie_val)
        start_response("200 OK",
                       [("Content-Type", "application/json"),
                        ("Set-Cookie",   self._sessions.clear_cookie_header())]
                       + self._common_headers())
        return [json.dumps({"ok": True}).encode()]

    # ── Server ────────────────────────────────────────────────────────────────

    def serve(self, host: str = "127.0.0.1", port: int = 9102):
        """Start the dashboard server (blocking)."""
        # Prune any expired sessions left from previous runs
        pruned = self._sessions._prune()
        if pruned:
            logger.info("[dashboard] pruned %d stale session(s) on startup", pruned)

        class _Silent(wsgiref.simple_server.WSGIRequestHandler):
            def log_message(self, fmt, *a): pass

        class _Threaded(socketserver.ThreadingMixIn, wsgiref.simple_server.WSGIServer):
            daemon_threads      = True
            allow_reuse_address = True

        with _Threaded((host, port), _Silent) as httpd:
            httpd.set_app(self.wsgi_app)
            print(f"[AURORA] Dashboard:  http://{host}:{port}/dashboard")
            print(f"[AURORA] API stream: {self._api_url}/events")
            print(f"[AURORA] NOC sessions: {_SESSION_DIR}  (TTL={self._session_ttl}s)")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\n[AURORA] Dashboard stopped.")
