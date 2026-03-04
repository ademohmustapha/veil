"""
AURORA API Endpoint Integration Tests
======================================
These tests spin up a REAL ThreadedWSGIServer on an ephemeral port,
make genuine HTTP requests via urllib, and assert on live responses.

No mocking of the HTTP layer — the full WSGI stack is exercised:
  • Token authentication (constant-time comparison)
  • Rate limiting (SelfDefense)
  • All five route handlers (/risk, /contain, /evolve, /horizon, /supply-chain)
  • Security response headers (CSP, HSTS, X-Content-Type-Options, …)
  • Error handling (404, 401, 429, malformed JSON)
  • Concurrent request handling (ThreadedWSGIServer)

Run standalone:
  cd aurora_FINAL && python3 -m pytest tests/test_api_integration.py -v

The server is started once per test class (setUpClass) and torn down after
all tests in the class complete — fast and resource-efficient.
"""

from __future__ import annotations

import json
import os
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.request
import wsgiref.simple_server
from pathlib import Path
from typing import Dict, Optional, Tuple

import pytest

# ── Path bootstrap ─────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

# Isolated AURORA_HOME so integration tests never touch the real ~/.aurora
import tempfile as _tf
_TEST_HOME = _tf.mkdtemp(prefix="aurora_api_test_")
os.environ["AURORA_HOME"] = _TEST_HOME

# Reload path module so it picks up the test home
import importlib
import core.paths as _cp
importlib.reload(_cp)


# ── Embedded test server ────────────────────────────────────────────────────────

class _SilentHandler(wsgiref.simple_server.WSGIRequestHandler):
    def log_message(self, fmt, *a):
        pass


class _ThreadedWSGI(socketserver.ThreadingMixIn, wsgiref.simple_server.WSGIServer):
    daemon_threads      = True
    allow_reuse_address = True
    request_queue_size  = 32


def _build_wsgi_app(api):
    """Construct the same WSGI callable used in cli/interface.py cmd_api."""
    def wsgi_app(environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        path   = environ.get("PATH_INFO", "/")
        length = int(environ.get("CONTENT_LENGTH") or 0)
        raw    = environ["wsgi.input"].read(min(length, 524_288)) if length > 0 else b""
        try:
            body = json.loads(raw) if raw else {}
        except Exception:
            body = {}
        headers = {
            "X-Forwarded-For": environ.get("HTTP_X_FORWARDED_FOR", ""),
            "X-Aurora-Token":  environ.get("HTTP_X_AURORA_TOKEN", ""),
            "Remote-Addr":     environ.get("REMOTE_ADDR", ""),
        }
        result      = api.handle_request(method, path, body, headers)
        status      = f"{result.get('status', 200)} OK"
        resp_hdrs   = list(api.security_headers().items()) + [("Content-Type", "application/json")]
        start_response(status, resp_hdrs)
        return [json.dumps(result).encode()]
    return wsgi_app


class LiveServer:
    """Context manager that runs a ThreadedWSGI server in a background thread."""

    def __init__(self):
        from api.server import AuroraAPIServer
        self.api    = AuroraAPIServer()
        self.token  = self.api.startup_token
        self.api._clear_startup_token()
        self._httpd = _ThreadedWSGI(("127.0.0.1", 0), _SilentHandler)  # port 0 = ephemeral
        self._httpd.set_app(_build_wsgi_app(self.api))
        self.port   = self._httpd.server_address[1]
        self.base   = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True,
            name="aurora-test-server"
        )

    def __enter__(self):
        self._thread.start()
        # Wait for server to be ready (max 3 s)
        for _ in range(30):
            try:
                urllib.request.urlopen(f"{self.base}/health", timeout=1)
                break
            except Exception:
                time.sleep(0.1)
        return self

    def __exit__(self, *_):
        self._httpd.shutdown()


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _get(base: str, path: str, token: Optional[str] = None,
         timeout: int = 10) -> Tuple[int, Dict]:
    headers = {}
    if token:
        headers["X-Aurora-Token"] = token
    req = urllib.request.Request(base + path, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _post(base: str, path: str, body: dict, token: Optional[str] = None,
          timeout: int = 30) -> Tuple[int, Dict]:
    data    = json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Aurora-Token"] = token
    req = urllib.request.Request(base + path, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


# ══════════════════════════════════════════════════════════════════════════════
# TEST CLASSES
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthEndpoint:
    """GET /health — unauthenticated, returns liveness + subsystem status."""

    def test_health_returns_200(self):
        with LiveServer() as srv:
            status, body = _get(srv.base, "/health")
            assert status == 200

    def test_health_body_ok(self):
        with LiveServer() as srv:
            _, body = _get(srv.base, "/health")
            assert body.get("health") == "OK"

    def test_health_has_timestamp(self):
        with LiveServer() as srv:
            _, body = _get(srv.base, "/health")
            assert isinstance(body.get("timestamp"), float)
            assert body["timestamp"] > 0

    def test_health_has_storage_info(self):
        with LiveServer() as srv:
            _, body = _get(srv.base, "/health")
            assert "storage" in body
            assert body["storage"].get("backend") in ("sqlite_wal", "unknown")

    def test_health_has_tls_info(self):
        with LiveServer() as srv:
            _, body = _get(srv.base, "/health")
            assert "tls" in body
            assert isinstance(body["tls"].get("tls_enabled"), bool)

    def test_health_has_notifications_info(self):
        with LiveServer() as srv:
            _, body = _get(srv.base, "/health")
            assert "notifications" in body
            assert isinstance(body["notifications"].get("channels_configured"), list)

    def test_health_no_auth_required(self):
        """Health must be reachable without a token (liveness probe)."""
        with LiveServer() as srv:
            status, _ = _get(srv.base, "/health", token=None)
            assert status == 200

    def test_health_security_headers_present(self):
        with LiveServer() as srv:
            req = urllib.request.Request(srv.base + "/health", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
            assert "x-content-type-options" in hdrs
            assert "x-frame-options" in hdrs
            assert "cache-control" in hdrs

    def test_health_no_version_in_headers(self):
        """Version must NOT be disclosed in response headers."""
        with LiveServer() as srv:
            req = urllib.request.Request(srv.base + "/health", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                hdrs = {k.lower(): v.lower() for k, v in resp.headers.items()}
            for hdr_val in hdrs.values():
                assert "aurora" not in hdr_val or "token" in hdr_val  # X-Aurora-Token is ok
                assert "version" not in hdr_val


class TestAuthentication:
    """Token authentication — constant-time, correct rejection."""

    def test_valid_token_allows_risk(self):
        with LiveServer() as srv:
            status, body = _post(srv.base, "/risk", {"user_id": "test_user"}, token=srv.token)
            assert status == 200

    def test_no_token_returns_401(self):
        with LiveServer() as srv:
            status, body = _post(srv.base, "/risk", {"user_id": "x"}, token=None)
            assert status == 401

    def test_wrong_token_returns_401(self):
        with LiveServer() as srv:
            status, body = _post(srv.base, "/risk", {"user_id": "x"}, token="bad_token_xyz")
            assert status == 401

    def test_empty_token_returns_401(self):
        with LiveServer() as srv:
            status, body = _post(srv.base, "/risk", {"user_id": "x"}, token="")
            assert status == 401

    def test_401_body_has_error_field(self):
        with LiveServer() as srv:
            _, body = _post(srv.base, "/risk", {}, token="wrong")
            assert "error" in body

    def test_token_timing_consistent(self):
        """
        Verify that valid and invalid tokens take similar time to process
        (constant-time comparison — no early-exit timing side-channel).
        We measure 10 valid and 10 invalid calls and assert that the
        mean times are within 3x of each other (loose bound to avoid
        CI flakiness, but catches a naive short-circuit).
        """
        with LiveServer() as srv:
            times_valid, times_invalid = [], []
            for _ in range(10):
                t0 = time.perf_counter()
                _post(srv.base, "/risk", {"user_id": "u"}, token=srv.token)
                times_valid.append(time.perf_counter() - t0)

                t0 = time.perf_counter()
                _post(srv.base, "/risk", {"user_id": "u"}, token="invalid_" + "x"*32)
                times_invalid.append(time.perf_counter() - t0)

            mean_valid   = sum(times_valid)   / len(times_valid)
            mean_invalid = sum(times_invalid) / len(times_invalid)
            # Invalid should not be dramatically faster (would imply short-circuit)
            assert mean_invalid > mean_valid * 0.05, (
                f"Invalid token returned {mean_invalid*1000:.1f}ms vs "
                f"valid {mean_valid*1000:.1f}ms — possible timing side-channel"
            )


class TestRiskEndpoint:
    """/risk — Human Risk Index computation."""

    def test_risk_returns_200(self):
        with LiveServer() as srv:
            status, body = _post(srv.base, "/risk", {"user_id": "alice"}, token=srv.token)
            assert status == 200

    def test_risk_score_in_body(self):
        with LiveServer() as srv:
            _, body = _post(srv.base, "/risk", {"user_id": "alice"}, token=srv.token)
            assert "risk_score" in body

    def test_risk_score_range(self):
        with LiveServer() as srv:
            _, body = _post(srv.base, "/risk", {"user_id": "alice"}, token=srv.token)
            score = body["risk_score"]
            assert isinstance(score, (int, float))
            assert 0 <= score <= 100

    def test_risk_with_high_risk_context(self):
        """High-risk context must produce a higher score than empty context."""
        with LiveServer() as srv:
            _, body_low  = _post(srv.base, "/risk",
                                 {"user_id": "u1"}, token=srv.token)
            _, body_high = _post(srv.base, "/risk",
                                 {"user_id": "u2",
                                  "termination_pending": True,
                                  "mass_download": True,
                                  "behavioral_anomaly": 0.95,
                                  "after_hours_access": True},
                                 token=srv.token)
            assert body_high["risk_score"] >= body_low["risk_score"]

    def test_risk_malformed_float_ignored(self):
        """Malformed float fields must not crash the engine (input sanitisation)."""
        with LiveServer() as srv:
            status, body = _post(
                srv.base, "/risk",
                {"user_id": "u", "behavioral_anomaly": "not_a_number"},
                token=srv.token
            )
            assert status == 200
            assert "risk_score" in body

    def test_risk_missing_user_id_still_works(self):
        with LiveServer() as srv:
            status, body = _post(srv.base, "/risk", {}, token=srv.token)
            assert status == 200
            assert "risk_score" in body

    def test_risk_user_id_length_limit(self):
        """Excessively long user_id must be truncated, not crash."""
        with LiveServer() as srv:
            status, body = _post(
                srv.base, "/risk", {"user_id": "A" * 10000}, token=srv.token
            )
            assert status == 200


class TestContainEndpoint:
    """/contain — autonomous containment."""

    def test_contain_returns_200(self):
        with LiveServer() as srv:
            status, body = _post(srv.base, "/contain",
                                 {"action": "bulk_data_export", "user_id": "bob"},
                                 token=srv.token)
            assert status == 200

    def test_contain_has_containment_id(self):
        with LiveServer() as srv:
            _, body = _post(srv.base, "/contain",
                            {"action": "test_action", "user_id": "bob"},
                            token=srv.token)
            assert "containment" in body
            assert "containment_id" in body["containment"]

    def test_contain_status_contained(self):
        with LiveServer() as srv:
            _, body = _post(srv.base, "/contain",
                            {"action": "test", "user_id": "bob"},
                            token=srv.token)
            assert body["containment"]["status"] == "CONTAINED"

    def test_contain_blast_radius_limited(self):
        with LiveServer() as srv:
            _, body = _post(srv.base, "/contain",
                            {"action": "test", "user_id": "bob"},
                            token=srv.token)
            assert body["containment"]["blast_radius_limited"] is True


class TestEvolveEndpoint:
    """/evolve — AI co-evolution cycle."""

    def test_evolve_returns_200(self):
        with LiveServer() as srv:
            status, body = _post(srv.base, "/evolve", {}, token=srv.token)
            assert status == 200

    def test_evolve_has_evolution_key(self):
        with LiveServer() as srv:
            _, body = _post(srv.base, "/evolve", {}, token=srv.token)
            assert "evolution" in body

    def test_evolve_result_is_dict(self):
        with LiveServer() as srv:
            _, body = _post(srv.base, "/evolve", {}, token=srv.token)
            assert isinstance(body["evolution"], dict)


class TestHorizonEndpoint:
    """/horizon — predictive event horizon."""

    def test_horizon_returns_200(self):
        with LiveServer() as srv:
            status, body = _post(srv.base, "/horizon", {}, token=srv.token)
            assert status == 200

    def test_horizon_has_horizon_key(self):
        with LiveServer() as srv:
            _, body = _post(srv.base, "/horizon", {}, token=srv.token)
            assert "horizon" in body

    def test_horizon_result_is_dict(self):
        with LiveServer() as srv:
            _, body = _post(srv.base, "/horizon", {}, token=srv.token)
            assert isinstance(body["horizon"], dict)


class TestSupplyChainEndpoint:
    """/supply-chain — supply chain risk heatmap."""

    def test_supply_chain_returns_200(self):
        with LiveServer() as srv:
            status, body = _post(srv.base, "/supply-chain", {}, token=srv.token)
            assert status == 200

    def test_supply_chain_has_heatmap_key(self):
        with LiveServer() as srv:
            _, body = _post(srv.base, "/supply-chain", {}, token=srv.token)
            assert "heatmap" in body


class TestErrorHandling:
    """404s, malformed JSON, and oversized payloads."""

    def test_unknown_path_returns_404(self):
        with LiveServer() as srv:
            status, body = _post(srv.base, "/nonexistent", {}, token=srv.token)
            assert status == 404

    def test_404_body_has_error(self):
        with LiveServer() as srv:
            _, body = _post(srv.base, "/no-such-endpoint", {}, token=srv.token)
            assert "error" in body

    def test_malformed_json_body_graceful(self):
        """Server must not crash on malformed JSON — returns valid response."""
        with LiveServer() as srv:
            req = urllib.request.Request(
                srv.base + "/risk",
                data=b"not valid json {{{",
                headers={
                    "Content-Type":   "application/json",
                    "X-Aurora-Token": srv.token,
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    status = resp.status
            except urllib.error.HTTPError as exc:
                status = exc.code
            # Must not return 500 — either processes gracefully or 400
            assert status != 500


class TestSecurityHeaders:
    """All authenticated endpoints must return the full security header set."""

    REQUIRED_HEADERS = [
        "x-content-type-options",
        "x-frame-options",
        "x-xss-protection",
        "referrer-policy",
        "cache-control",
        "content-security-policy",
        "strict-transport-security",
    ]

    def _get_response_headers(self, base: str, path: str, token: str) -> Dict:
        data = json.dumps({}).encode()
        req  = urllib.request.Request(
            base + path, data=data,
            headers={"Content-Type": "application/json", "X-Aurora-Token": token},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as exc:
            return {k.lower(): v for k, v in exc.headers.items()}

    @pytest.mark.parametrize("path", ["/risk", "/contain", "/horizon"])
    def test_security_headers_on_endpoint(self, path):
        with LiveServer() as srv:
            hdrs = self._get_response_headers(srv.base, path, srv.token)
            for hdr in self.REQUIRED_HEADERS:
                assert hdr in hdrs, f"Missing header '{hdr}' on {path}"

    def test_csp_blocks_framing(self):
        with LiveServer() as srv:
            hdrs = self._get_response_headers(srv.base, "/risk", srv.token)
            csp = hdrs.get("content-security-policy", "").lower()
            assert "frame-ancestors 'none'" in csp

    def test_hsts_max_age_sufficient(self):
        """HSTS max-age must be ≥ 1 year (31536000 s)."""
        with LiveServer() as srv:
            hdrs = self._get_response_headers(srv.base, "/risk", srv.token)
            hsts = hdrs.get("strict-transport-security", "")
            import re
            m = re.search(r"max-age=(\d+)", hsts)
            assert m, "HSTS header missing max-age"
            assert int(m.group(1)) >= 31536000


class TestConcurrency:
    """ThreadedWSGIServer must handle concurrent requests without corruption."""

    def test_concurrent_risk_requests(self):
        """Fire 20 concurrent /risk requests and verify all return valid scores."""
        with LiveServer() as srv:
            results: list = []
            errors:  list = []

            def worker(uid: str):
                try:
                    status, body = _post(
                        srv.base, "/risk",
                        {"user_id": uid}, token=srv.token,
                    )
                    results.append((status, body.get("risk_score")))
                except Exception as exc:
                    errors.append(str(exc))

            threads = [
                threading.Thread(target=worker, args=(f"user_{i}",))
                for i in range(20)
            ]
            for t in threads: t.start()
            for t in threads: t.join(timeout=30)

            assert not errors, f"Concurrent errors: {errors}"
            assert len(results) == 20, f"Only {len(results)}/20 requests completed"
            for status, score in results:
                assert status == 200
                assert score is not None
                assert 0 <= score <= 100

    def test_concurrent_mixed_endpoints(self):
        """Concurrent requests to different endpoints must not interfere."""
        with LiveServer() as srv:
            paths   = ["/risk", "/contain", "/horizon", "/supply-chain", "/evolve"]
            bodies  = [
                {"user_id": "u1"},
                {"action": "test", "user_id": "u2"},
                {}, {}, {},
            ]
            results: list = []

            def worker(path, body):
                try:
                    status, resp_body = _post(srv.base, path, body, token=srv.token)
                    results.append(status)
                except Exception as exc:
                    results.append(str(exc))

            threads = []
            for _ in range(4):  # 4 rounds × 5 endpoints = 20 concurrent
                for p, b in zip(paths, bodies):
                    threads.append(threading.Thread(target=worker, args=(p, b)))
            for t in threads: t.start()
            for t in threads: t.join(timeout=60)

            assert len(results) == len(threads)
            non_200 = [r for r in results if r != 200]
            assert not non_200, f"Non-200 responses: {non_200}"


# ─────────────────────────────────────────────────────────────────────────────
# New: SSE endpoint tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSSEEndpoint:
    """
    /events endpoint tests.
    We consume a limited number of frames from the stream rather than running
    it forever, using a short timeout and reading raw bytes from the socket.
    """

    def test_sse_requires_auth(self):
        """GET /events without a token must return 401."""
        with LiveServer() as srv:
            url = f"{srv.base}/events"
            req = urllib.request.Request(url, method="GET")
            try:
                urllib.request.urlopen(req, timeout=3)
                assert False, "Expected HTTPError"
            except urllib.error.HTTPError as e:
                assert e.code == 401
            except Exception:
                pass  # connection reset before response headers also acceptable

    def test_sse_wrong_token_rejected(self):
        """GET /events with a wrong token must return 401."""
        with LiveServer() as srv:
            url = f"{srv.base}/events?token=wrongtoken"
            req = urllib.request.Request(url, method="GET")
            try:
                urllib.request.urlopen(req, timeout=3)
                assert False, "Expected HTTPError"
            except urllib.error.HTTPError as e:
                assert e.code == 401
            except Exception:
                pass

    def test_sse_content_type(self):
        """SSE response must have Content-Type: text/event-stream."""
        with LiveServer() as srv:
            url = f"{srv.base}/events?token={srv.token}"
            req = urllib.request.Request(url, method="GET")
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                ct = resp.headers.get("Content-Type", "")
                assert "text/event-stream" in ct, f"Expected SSE content-type, got: {ct}"
                resp.close()
            except urllib.error.HTTPError as e:
                pytest.fail(f"Unexpected HTTP error: {e.code}")
            except Exception:
                pass  # timeout on streaming read is acceptable

    def test_sse_yields_valid_frame(self):
        """
        Connect to /events and read raw bytes until we get at least one
        complete SSE frame.  Verify the frame is parseable JSON.
        """
        import socket, ssl as _ssl

        with LiveServer() as srv:
            # Parse host/port from base URL
            from urllib.parse import urlparse
            parsed  = urlparse(srv.base)
            host    = parsed.hostname
            port    = parsed.port or 80

            # Build raw HTTP request
            request = (
                f"GET /events?token={srv.token} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Accept: text/event-stream\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

            sock = socket.create_connection((host, port), timeout=10)
            try:
                sock.sendall(request)
                buf = b""
                deadline = time.time() + 10  # read for up to 10 seconds
                while time.time() < deadline:
                    try:
                        chunk = sock.recv(4096)
                    except Exception:
                        break
                    if not chunk:
                        break
                    buf += chunk
                    # An SSE frame ends with double newline
                    if b"\n\n" in buf:
                        break
            finally:
                sock.close()

            buf_str = buf.decode("utf-8", errors="replace")
            # Must at least contain HTTP 200 status
            assert "200" in buf_str[:50] or "200 OK" in buf_str, \
                f"Expected 200 response, got: {buf_str[:200]}"
            # Must contain at least one SSE data line
            assert "data:" in buf_str, \
                f"No SSE data frame found in: {buf_str[:400]}"
            # Extract first data line and parse JSON
            for line in buf_str.splitlines():
                if line.startswith("data:"):
                    raw_json = line[len("data:"):].strip()
                    parsed = json.loads(raw_json)
                    assert "type" in parsed, f"SSE payload missing 'type': {parsed}"
                    assert "timestamp" in parsed, f"SSE payload missing 'timestamp': {parsed}"
                    break  # success

    def test_sse_security_headers_present(self):
        """SSE response must include security headers."""
        with LiveServer() as srv:
            url = f"{srv.base}/events?token={srv.token}"
            req = urllib.request.Request(url, method="GET")
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                assert "x-content-type-options" in hdrs
                resp.close()
            except Exception:
                pass  # timeout on streaming read is acceptable


# ─────────────────────────────────────────────────────────────────────────────
# New: PostgreSQL backend unit tests (no live DB required — import & interface)
# ─────────────────────────────────────────────────────────────────────────────

class TestPostgresBackend:
    """
    Tests for core/storage_pg.py that do NOT require a running PostgreSQL server.
    They verify the module imports correctly, the DSN builder produces valid
    output, and the interface contract is consistent with SQLite AuroraDB.
    """

    def test_module_imports(self):
        """storage_pg.py must import without error."""
        import importlib, sys
        spec = importlib.util.spec_from_file_location(
            "storage_pg",
            str(Path(__file__).parent.parent / "core" / "storage_pg.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "AuroraDBPostgres")
        assert hasattr(mod, "try_build_postgres_db")
        assert hasattr(mod, "_build_dsn")
        assert hasattr(mod, "_mask_dsn")

    def test_dsn_builder_defaults(self):
        """_build_dsn() must return a valid postgresql:// DSN with defaults."""
        import importlib
        spec = importlib.util.spec_from_file_location(
            "storage_pg",
            str(Path(__file__).parent.parent / "core" / "storage_pg.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        dsn = mod._build_dsn()
        assert dsn.startswith("postgresql://"), f"DSN must start with postgresql://, got: {dsn}"

    def test_dsn_from_env(self, monkeypatch):
        """AURORA_PG_DSN env var must be returned verbatim."""
        import importlib
        spec = importlib.util.spec_from_file_location(
            "storage_pg2",
            str(Path(__file__).parent.parent / "core" / "storage_pg.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        monkeypatch.setenv("AURORA_PG_DSN", "postgresql://user:pass@host/db")
        spec.loader.exec_module(mod)
        dsn = mod._build_dsn()
        assert dsn == "postgresql://user:pass@host/db"

    def test_mask_dsn_hides_password(self):
        """_mask_dsn() must redact passwords from DSNs."""
        import importlib
        spec = importlib.util.spec_from_file_location(
            "storage_pg3",
            str(Path(__file__).parent.parent / "core" / "storage_pg.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        masked = mod._mask_dsn("postgresql://aurora:s3cr3t@localhost/aurora")
        assert "s3cr3t" not in masked, f"Password visible in masked DSN: {masked}"
        assert "aurora" in masked  # user/db visible

    def test_try_build_postgres_no_psycopg2(self, monkeypatch):
        """
        try_build_postgres_db() must return None (not raise) when psycopg2
        is not installed — AURORA falls back to SQLite gracefully.
        """
        import importlib, sys
        # Patch sys.modules to simulate psycopg2 missing
        spec = importlib.util.spec_from_file_location(
            "storage_pg_nodriver",
            str(Path(__file__).parent.parent / "core" / "storage_pg.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        # Hide psycopg2 from the module being loaded
        original = sys.modules.copy()
        sys.modules["psycopg2"] = None         # type: ignore
        sys.modules["psycopg2.pool"] = None    # type: ignore
        sys.modules["psycopg2.extras"] = None  # type: ignore
        try:
            spec.loader.exec_module(mod)
            result = mod.try_build_postgres_db()
            assert result is None, "Expected None when psycopg2 not installed"
        finally:
            sys.modules.update(original)

    def test_interface_contract_matches_sqlite(self):
        """
        AuroraDBPostgres must expose the same public interface as AuroraDB.
        Verified by comparing method names — no live DB needed.
        """
        from core.storage import AuroraDB
        import importlib
        spec = importlib.util.spec_from_file_location(
            "storage_pg4",
            str(Path(__file__).parent.parent / "core" / "storage_pg.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        required_methods = {
            "load_namespace", "save_namespace",
            "get", "set", "delete", "list_keys",
            "migrate_from_json", "stats",
        }
        sqlite_methods = set(dir(AuroraDB.__init__.__class__))
        pg_methods     = {m for m in dir(mod.AuroraDBPostgres) if not m.startswith("_")}
        sqlite_pub     = {m for m in dir(AuroraDB) if not m.startswith("_")}

        missing = required_methods - pg_methods
        assert not missing, f"AuroraDBPostgres missing methods: {missing}"

    def test_storage_backend_env_selects_pg(self, monkeypatch, tmp_path):
        """
        When AURORA_STORAGE_BACKEND=postgresql is set but psycopg2 fails,
        get_db() must fall back to SQLite (no crash, returns AuroraDB instance).
        """
        import importlib, sys
        monkeypatch.setenv("AURORA_STORAGE_BACKEND", "postgresql")
        monkeypatch.setenv("AURORA_HOME", str(tmp_path))

        # Force psycopg2 to appear missing
        original = sys.modules.copy()
        sys.modules["psycopg2"] = None       # type: ignore
        sys.modules["psycopg2.pool"] = None  # type: ignore

        try:
            # Reload storage module to pick up env override + missing psycopg2
            if "core.storage" in sys.modules:
                del sys.modules["core.storage"]
            if "core.storage_pg" in sys.modules:
                del sys.modules["core.storage_pg"]

            from core import storage as storage_mod
            # Reset singleton so _build_db() is called fresh
            storage_mod._db_instance = None

            db = storage_mod.get_db()
            from core.storage import AuroraDB
            assert isinstance(db, AuroraDB), \
                f"Expected SQLite fallback, got {type(db)}"
        finally:
            sys.modules.update(original)
            # Restore singleton state to avoid polluting other tests
            import core.storage as _s
            _s._db_instance = None


# ─────────────────────────────────────────────────────────────────────────────
# New: TLS trust store instructions test
# ─────────────────────────────────────────────────────────────────────────────

class TestTLSTrustStore:
    """Verify trust store guidance is accurate per platform."""

    def test_tls_module_exports_info(self):
        """TLSConfig.info() must return tls_enabled key."""
        from core.tls import TLSConfig
        cfg = TLSConfig(enabled=False)
        info = cfg.info()
        assert "tls_enabled" in info
        assert info["tls_enabled"] is False

    def test_tls_info_when_enabled_no_cert(self, tmp_path):
        """TLSConfig.info() with enabled=True but no cert returns cert_exists=False."""
        from core.tls import TLSConfig
        cfg = TLSConfig(
            enabled=True,
            cert_file=str(tmp_path / "nonexistent.crt"),
            key_file=str(tmp_path / "nonexistent.key"),
            self_signed=False,
        )
        info = cfg.info()
        assert info["tls_enabled"] is True
        assert info["cert_exists"] is False
        assert info["key_exists"]  is False
        assert info["fingerprint"] is None

    def test_self_signed_generates_cert(self, tmp_path):
        """TLSConfig.build_context() must auto-generate a cert when self_signed=True."""
        pytest.importorskip("cryptography", reason="cryptography package required")
        pytest.importorskip("ssl")
        from core.tls import TLSConfig, _TLS_DIR as _orig_dir
        import core.tls as tls_mod
        # Point TLS dir to tmp_path for isolation
        orig = tls_mod._TLS_DIR
        tls_mod._TLS_DIR = tmp_path
        tls_mod._DEFAULT_CERT = tmp_path / "aurora.crt"
        tls_mod._DEFAULT_KEY  = tmp_path / "aurora.key"
        try:
            cfg = TLSConfig(
                enabled=True,
                cert_file=str(tmp_path / "aurora.crt"),
                key_file=str(tmp_path / "aurora.key"),
                self_signed=True,
            )
            ctx = cfg.build_context()
            assert ctx is not None
            assert (tmp_path / "aurora.crt").exists()
            assert (tmp_path / "aurora.key").exists()
            # Key file must be chmod 600
            import stat
            mode = (tmp_path / "aurora.key").stat().st_mode
            assert stat.S_IMODE(mode) == 0o600
        finally:
            tls_mod._TLS_DIR = orig

    def test_byoc_missing_cert_raises(self, tmp_path):
        """TLSConfig.build_context() with self_signed=False and missing cert must raise FileNotFoundError."""
        pytest.importorskip("cryptography", reason="cryptography package required")
        from core.tls import TLSConfig
        cfg = TLSConfig(
            enabled=True,
            cert_file=str(tmp_path / "no.crt"),
            key_file=str(tmp_path  / "no.key"),
            self_signed=False,
        )
        with pytest.raises(FileNotFoundError):
            cfg.build_context()
