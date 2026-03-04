"""
AURORA REST API Server
======================
FIXED:
  - X-Forwarded-For validated and sanitized — no longer spoofable for rate-limit bypass
  - API token check uses constant-time comparison across ALL tokens (timing side-channel fixed)
  - Input validation on all request body fields before passing to engines

SSE (Server-Sent Events) — /events:
  Real-time push endpoint. The dashboard connects once and receives a stream
  of newline-delimited SSE frames instead of polling every 30 s.

  Protocol:
    GET /events  (with X-Aurora-Token header or ?token= query param)
    Content-Type: text/event-stream; charset=utf-8
    Cache-Control: no-cache
    Connection: keep-alive

  Each frame:
    event: aurora_update
    data: <JSON payload>\n\n

  Payload schema:
    {
      "type":      "heartbeat" | "snapshot",
      "timestamp": float,
      "risk":      {...} | null,
      "horizon":   {...} | null,
      "health":    {...} | null
    }

  Heartbeat frames (type="heartbeat") are sent every 15 s so the browser
  EventSource does not time out on idle connections.
  Full snapshots are pushed every 30 s.
  The stream is intentionally infinite; the client disconnects when done.

  WSGI streaming:
    wsgi_app in cli/interface.py detects GET /events and calls
    AuroraAPIServer.sse_stream() which returns (http_status, headers, iterator).
    The iterator is returned directly as the WSGI iterable.
"""
from __future__ import annotations
import json, time, hashlib, secrets, hmac as _hmac, re, threading
from typing import Dict, Generator, Iterator, Optional, Tuple
from hardening.self_defense import SelfDefense

# Regex to validate IPv4/IPv6 from X-Forwarded-For (first IP only)
_IP_RE = re.compile(
    r"^("
    r"(\d{1,3}\.){3}\d{1,3}"         # IPv4
    r"|"
    r"[0-9a-fA-F:]{2,39}"            # IPv6
    r")$"
)

_SSE_HEARTBEAT_S  = 15   # seconds between heartbeat frames
_SSE_SNAPSHOT_S   = 30   # seconds between full data snapshots


def _extract_client_ip(headers: Dict) -> str:
    """
    FIXED: Safely extract client IP.
    X-Forwarded-For may contain a comma-separated list; take LAST entry
    (the one added by the trusted reverse proxy), validate as IP address.
    Fall back to a hashed unknown identifier if malformed.
    """
    xff = headers.get("X-Forwarded-For", "")
    if xff:
        parts = [p.strip() for p in xff.split(",")]
        candidate = parts[-1] if parts else ""
        if candidate and _IP_RE.match(candidate):
            return candidate
    raw = headers.get("X-Real-IP", headers.get("Remote-Addr", "unknown"))
    return hashlib.sha256(str(raw)[:64].encode()).hexdigest()[:16] + "_hashed"


class AuroraAPIServer:
    def __init__(self):
        self.rate_limiter = SelfDefense()
        self._api_tokens: Dict[str, str] = {}
        self._generate_default_token()

    def _generate_default_token(self):
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        self._api_tokens["default"] = token_hash
        # Exposed once for operator display at startup; cleared after first read.
        self.startup_token: str = token

    def _clear_startup_token(self) -> None:
        """Wipe the plaintext token from memory after it has been displayed."""
        self.startup_token = ""

    def security_headers(self) -> Dict[str, str]:
        """
        Version not disclosed in headers — prevents information disclosure.
        """
        return {
            "X-Content-Type-Options":   "nosniff",
            "X-Frame-Options":          "DENY",
            "X-XSS-Protection":         "1; mode=block",
            "Referrer-Policy":          "no-referrer",
            "Cache-Control":            "no-store, no-cache, must-revalidate, private",
            "Content-Security-Policy":  "default-src 'none'; frame-ancestors 'none'",
            "Permissions-Policy":       "geolocation=(), microphone=(), camera=()",
            "Strict-Transport-Security":"max-age=63072000; includeSubDomains; preload",
            # "X-AURORA-Version" intentionally omitted — no version disclosure
        }

    def sse_headers(self) -> Dict[str, str]:
        """
        Headers for the SSE /events stream.
        NOTE: Cache-Control and Content-Type intentionally override the
        standard security_headers() for SSE — no-store would prevent
        EventSource buffering; text/event-stream is required by spec.
        All other security headers are preserved.

        IMPORTANT: 'Connection' and 'Transfer-Encoding' are hop-by-hop headers
        forbidden by PEP 3333 / wsgiref. They are intentionally omitted here.
        The WSGI server (wsgiref / gunicorn) manages connection lifecycle.
        Reverse-proxy operators can add 'Connection: keep-alive' at the
        nginx/Caddy layer; WSGI apps must not set it.
        """
        h = self.security_headers()
        h["Content-Type"]  = "text/event-stream; charset=utf-8"
        h["Cache-Control"] = "no-cache"
        h["X-Accel-Buffering"] = "no"  # disable nginx proxy buffering if present
        # 'Connection: keep-alive' intentionally omitted — hop-by-hop, PEP 3333 §2
        return h

    def authenticate_request(self, headers: Dict) -> bool:
        """
        FIXED: Constant-time comparison across ALL tokens regardless of match position.
        Timing side-channel eliminated.
        """
        token = headers.get("X-Aurora-Token", "")
        if not token:
            return False
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        # Accumulate all comparisons — result is OR of all, but timing is constant
        result = False
        for stored_hash in self._api_tokens.values():
            # compare_digest on every stored hash — no short-circuit
            match = _hmac.compare_digest(token_hash, stored_hash)
            result = result or match
        return result

    def handle_request(self, method: str, path: str, body: dict, headers: dict) -> Dict:
        # FIXED: Use validated/sanitized client IP for rate limiting
        client_ip = _extract_client_ip(headers)

        # /health is unauthenticated but returns NO version info
        if path == "/health":
            if not self.rate_limiter.check_rate_limit(client_ip, "health"):
                return {"status": 429, "error": "Rate limit exceeded", "retry_after": 60}
            return {**self._health(body), "headers": self.security_headers()}

        if not self.rate_limiter.check_rate_limit(client_ip, path):
            return {"status": 429, "error": "Rate limit exceeded", "retry_after": 60}
        if not self.authenticate_request(headers):
            return {"status": 401, "error": "Unauthorized"}

        routes = {
            "/risk":         self._risk_assessment,
            "/contain":      self._contain,
            "/evolve":       self._evolve,
            "/horizon":      self._horizon,
            "/supply-chain": self._supply_chain,
        }
        handler = routes.get(path, self._not_found)
        result = handler(body)
        return {**result, "headers": self.security_headers()}

    # ── SSE streaming endpoint ─────────────────────────────────────────────────

    def sse_stream(
        self,
        headers: Dict,
        user_id: str = "sse_user",
    ) -> Tuple[str, Dict[str, str], Iterator[bytes]]:
        """
        Authenticate and return an SSE stream triple:
          (http_status_str, response_headers, byte_iterator)

        The WSGI handler in cli/interface.py returns the iterator directly
        as the WSGI iterable — wsgiref will flush each chunk immediately
        because Content-Type is text/event-stream.

        Authentication:
          Token is read from the X-Aurora-Token header (same as all other
          endpoints).  EventSource in browsers cannot send custom headers,
          so we also accept a ?token= query parameter — the dashboard
          passes the token it already holds.  The token is validated with
          the same constant-time comparison as authenticate_request().

        Rate limiting:
          /events shares the same per-IP bucket as other endpoints.
          One connection counts as one request; frames are free thereafter.
        """
        client_ip = _extract_client_ip(headers)
        if not self.rate_limiter.check_rate_limit(client_ip, "/events"):
            error_event = (
                "event: aurora_error\n"
                'data: {"error":"Rate limit exceeded","retry_after":60}\n\n'
            )
            return "429 Too Many Requests", self.sse_headers(), iter([error_event.encode()])

        if not self.authenticate_request(headers):
            error_event = (
                "event: aurora_error\n"
                'data: {"error":"Unauthorized"}\n\n'
            )
            return "401 Unauthorized", self.sse_headers(), iter([error_event.encode()])

        return "200 OK", self.sse_headers(), self._sse_generator(user_id)

    def _sse_generator(self, user_id: str = "sse_user") -> Iterator[bytes]:
        """
        Infinite SSE generator.  Yields:
          - A heartbeat frame every _SSE_HEARTBEAT_S seconds (keeps connection alive)
          - A full snapshot frame every _SSE_SNAPSHOT_S seconds

        Design:
          - Sleeps in 1-second increments so the thread is responsive to
            client disconnect (wsgiref raises BrokenPipeError on write to a
            closed socket — the generator will be garbage-collected then).
          - All data collection is wrapped in try/except so a failing engine
            never kills the stream; partial data is emitted with error flags.
          - No shared mutable state — each generator instance is independent.
        """
        last_heartbeat = 0.0
        last_snapshot  = 0.0

        while True:
            now = time.time()

            # ── Heartbeat ─────────────────────────────────────────────────────
            if now - last_heartbeat >= _SSE_HEARTBEAT_S:
                frame = _sse_frame("aurora_update", {
                    "type":      "heartbeat",
                    "timestamp": now,
                })
                yield frame
                last_heartbeat = now

            # ── Full snapshot ─────────────────────────────────────────────────
            if now - last_snapshot >= _SSE_SNAPSHOT_S:
                payload: Dict = {
                    "type":      "snapshot",
                    "timestamp": now,
                    "risk":      None,
                    "horizon":   None,
                    "health":    None,
                }
                # Risk score
                try:
                    from layers.l3_human_risk.risk_index import HumanRiskIndex
                    score = HumanRiskIndex().compute(user_id, {})
                    level = (
                        "CRITICAL" if score > 80 else
                        "HIGH"     if score > 60 else
                        "MEDIUM"   if score > 40 else "LOW"
                    )
                    payload["risk"] = {"score": score, "level": level}
                except Exception as exc:
                    payload["risk"] = {"error": str(exc)[:120]}

                # Horizon
                try:
                    from layers.l7_evolution.event_horizon import EventHorizon
                    payload["horizon"] = EventHorizon().get_horizon_report()
                except Exception as exc:
                    payload["horizon"] = {"error": str(exc)[:120]}

                # Health
                try:
                    payload["health"] = self._health({})
                    payload["health"].pop("headers", None)  # strip internal key
                except Exception as exc:
                    payload["health"] = {"error": str(exc)[:120]}

                yield _sse_frame("aurora_update", payload)
                last_snapshot = now

            time.sleep(1)

    # ── Standard endpoint handlers ─────────────────────────────────────────────

    def _health(self, body):
        """
        Returns liveness + storage, TLS, and notifications status.
        No version disclosure, no secrets.
        """
        storage_info = {}
        try:
            from core.storage import get_db
            storage_info = get_db().stats()
        except Exception:
            storage_info = {"backend": "unknown"}

        tls_info = {}
        try:
            from core.tls import TLSConfig
            tls_info = TLSConfig.from_config().info()
        except Exception:
            tls_info = {"tls_enabled": False}

        notif_info = {}
        try:
            from notifications.dispatcher import get_dispatcher
            notif_info = get_dispatcher().status()
        except Exception:
            notif_info = {"channels_configured": []}

        return {
            "status": 200,
            "health": "OK",
            "timestamp": time.time(),
            "storage": storage_info,
            "tls": tls_info,
            "notifications": notif_info,
        }

    def _risk_assessment(self, body):
        # FIXED: Validate types before passing to engine (prevents DoS)
        user_id = str(body.get("user_id", "unknown"))[:128]
        safe_ctx = self._sanitize_context(body)
        from layers.l3_human_risk.risk_index import HumanRiskIndex
        score = HumanRiskIndex().compute(user_id, safe_ctx)
        return {"status": 200, "risk_score": score}

    def _contain(self, body):
        action  = str(body.get("action",  "unknown"))[:256]
        user_id = str(body.get("user_id", "unknown"))[:128]
        from layers.l4_containment.sandbox import Sandbox
        result = Sandbox().contain(action, user_id)
        return {"status": 200, "containment": result}

    def _evolve(self, body):
        from layers.l7_evolution.co_evolution import CoEvolutionEngine
        result = CoEvolutionEngine().run_evolution_cycle()
        return {"status": 200, "evolution": result}

    def _horizon(self, body):
        from layers.l7_evolution.event_horizon import EventHorizon
        result = EventHorizon().get_horizon_report()
        return {"status": 200, "horizon": result}

    def _supply_chain(self, body):
        from layers.l6_supply_chain.resilience import SupplyChainResilience
        result = SupplyChainResilience().generate_risk_heatmap()
        return {"status": 200, "heatmap": result}

    def _not_found(self, body):
        return {"status": 404, "error": "Endpoint not found"}

    @staticmethod
    def _sanitize_context(body: dict) -> dict:
        """
        FIXED: Type-validate all context fields before passing to ML engines.
        Prevents DoS via malformed float strings like float('x'*1000000).
        """
        safe = {}
        float_fields = {
            "behavioral_anomaly", "privilege_misuse_score",
            "error_rate_today", "phishing_clicked_30d",
            "hours_worked_today", "incident_count",
            "supply_chain_risk", "containment_pressure",
        }
        bool_fields = {
            "after_hours_access", "mass_download", "termination_pending",
            "performance_pip", "financial_stress", "accessed_hr_systems",
            "training_completed", "phishing_clicked", "email_heavy_role",
            "cognitive_fatigue", "late_night_session", "meeting_heavy_day",
            "authority_compliance_high", "new_employee", "isolation_from_team",
        }
        for k, v in body.items():
            if k in float_fields:
                try:
                    safe[k] = float(v)
                except (TypeError, ValueError):
                    pass  # Silently ignore malformed values; engine uses defaults
            elif k in bool_fields:
                safe[k] = bool(v)
            elif isinstance(v, (str, int, float, bool, type(None))):
                safe[k] = v
        return safe


# ── SSE frame helper ──────────────────────────────────────────────────────────

def _sse_frame(event: str, data: dict) -> bytes:
    """
    Encode a single SSE frame.

    Format (per spec https://html.spec.whatwg.org/multipage/server-sent-events.html):
      event: <name>\\n
      data: <json>\\n
      \\n

    The double newline terminates the frame.  json.dumps with separators=(',',':')
    produces a compact single-line payload — critical because SSE data fields
    must not span multiple lines (each 'data:' line is a separate chunk).
    """
    payload = json.dumps(data, separators=(",", ":"), default=str)
    return f"event: {event}\ndata: {payload}\n\n".encode("utf-8")
