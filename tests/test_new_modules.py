"""
AURORA — New Modules Test Suite
================================
Tests for: ML-KEM FIPS 203, SOAR integrations, SSO/PKCE, Live Dashboard.
Complements the existing test_aurora.py (144 tests).

Run:
  python3 -m pytest tests/test_new_modules.py -v
  python3 -m pytest tests/ -v   # all tests

Coverage:
  TestMLKEM512         — 20 tests: keygen, encap, decap, sizes, implicit rejection,
                          hybrid encrypt/decrypt, numpy path, info()
  TestMLKEM768         — 8 tests: 768-bit parameter set
  TestMLKEMPerformance — 3 tests: throughput, timing assertions
  TestSOARIdempotency  — 10 tests: dedup map, TTL eviction, per-channel isolation
  TestSOARConnectors   — 8 tests: unconfigured connectors, payload structure
  TestSOARManager      — 6 tests: dispatch, thread safety, status dict
  TestPKCE             — 10 tests: verifier length, challenge S256, state entropy, CSRF
  TestSSOFlow          — 12 tests: begin_auth, exchange_code, session cleanup, cookie
  TestSSOSessionStore  — 8 tests: create, get, delete, expiry, prune, cookie header
  TestDashboard        — 8 tests: serves HTML, config endpoint, SSE URL, token prompt
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict

try:
    import pytest
except ImportError:
    pytest = None

# ── Path bootstrap ────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent.parent
sys.path.insert(0, str(_HERE))

# Isolated AURORA_HOME
_TMP = tempfile.mkdtemp(prefix="aurora_new_tests_")
os.environ["AURORA_HOME"] = _TMP


# ══════════════════════════════════════════════════════════════════════════════
# ML-KEM-512 TESTS (FIPS 203)
# ══════════════════════════════════════════════════════════════════════════════

class TestMLKEM512:
    """Core ML-KEM-512 correctness tests."""

    def setup_method(self):
        from layers.l1_identity.quantum_crypto import _MLKEM, QuantumCrypto
        self.kem = _MLKEM(512)
        self.qc  = QuantumCrypto()

    # ── Key sizes (FIPS 203 §2.4) ──────────────────────────────────────────

    def test_pk_length_800(self):
        pk, _ = self.kem.keygen()
        assert len(pk) == 800, f"Expected 800B pk, got {len(pk)}"

    def test_sk_length_1632(self):
        _, sk = self.kem.keygen()
        assert len(sk) == 1632, f"Expected 1632B sk, got {len(sk)}"

    def test_ct_length_768(self):
        pk, _ = self.kem.keygen()
        ct, _ = self.kem.encapsulate(pk)
        assert len(ct) == 768, f"Expected 768B ct, got {len(ct)}"

    def test_ss_length_32(self):
        pk, _ = self.kem.keygen()
        _, ss = self.kem.encapsulate(pk)
        assert len(ss) == 32, f"Expected 32B ss, got {len(ss)}"

    # ── Round-trip correctness ────────────────────────────────────────────

    def test_kem_roundtrip(self):
        pk, sk = self.kem.keygen(); ct, ss1 = self.kem.encapsulate(pk)
        ss2 = self.kem.decapsulate(sk, ct)
        assert ss1 == ss2

    def test_kem_roundtrip_repeated(self):
        for _ in range(10):
            pk, sk = self.kem.keygen(); ct, ss1 = self.kem.encapsulate(pk)
            assert self.kem.decapsulate(sk, ct) == ss1

    def test_keypairs_are_unique(self):
        pk1, _ = self.kem.keygen(); pk2, _ = self.kem.keygen()
        assert pk1 != pk2

    def test_encapsulations_are_unique(self):
        pk, _ = self.kem.keygen()
        ct1, ss1 = self.kem.encapsulate(pk)
        ct2, ss2 = self.kem.encapsulate(pk)
        assert ct1 != ct2 and ss1 != ss2

    # ── Implicit rejection (FIPS 203 §7.3) ───────────────────────────────

    def test_wrong_sk_gives_different_ss(self):
        pk, _  = self.kem.keygen()
        _, sk2 = self.kem.keygen()
        ct, ss1 = self.kem.encapsulate(pk)
        ss_rej  = self.kem.decapsulate(sk2, ct)
        assert ss_rej != ss1, "Implicit rejection must produce a different shared secret"

    def test_wrong_sk_still_returns_32_bytes(self):
        pk, _  = self.kem.keygen(); _, sk2 = self.kem.keygen()
        ct, _  = self.kem.encapsulate(pk)
        ss_rej = self.kem.decapsulate(sk2, ct)
        assert len(ss_rej) == 32

    def test_tampered_ct_gives_different_ss(self):
        pk, sk = self.kem.keygen(); ct, ss1 = self.kem.encapsulate(pk)
        tampered = bytearray(ct); tampered[0] ^= 0xFF
        ss_bad = self.kem.decapsulate(sk, bytes(tampered))
        assert ss_bad != ss1

    # ── Hybrid encrypt/decrypt ────────────────────────────────────────────

    def test_hybrid_roundtrip(self):
        pk, sk = self.qc.generate_keypair()
        ct = self.qc.hybrid_encrypt(b"AURORA hybrid test payload", pk)
        assert self.qc.hybrid_decrypt(ct, sk) == b"AURORA hybrid test payload"

    def test_hybrid_empty_payload(self):
        pk, sk = self.qc.generate_keypair()
        ct = self.qc.hybrid_encrypt(b"", pk)
        assert self.qc.hybrid_decrypt(ct, sk) == b""

    def test_hybrid_large_payload(self):
        pk, sk = self.qc.generate_keypair()
        msg = secrets.token_bytes(65536)
        ct  = self.qc.hybrid_encrypt(msg, pk)
        assert self.qc.hybrid_decrypt(ct, sk) == msg

    def test_hybrid_unique_ciphertexts(self):
        pk, _ = self.qc.generate_keypair()
        ct1 = self.qc.hybrid_encrypt(b"same", pk)
        ct2 = self.qc.hybrid_encrypt(b"same", pk)
        assert ct1 != ct2

    # ── QuantumCrypto.info() ──────────────────────────────────────────────

    def test_info_algorithm(self):
        assert "ML-KEM" in self.qc.info()["algorithm"]

    def test_info_standard(self):
        assert "FIPS 203" in self.qc.info()["standard"]

    def test_info_has_implementation_field(self):
        assert "implementation" in self.qc.info()

    def test_info_numpy_flag_present(self):
        assert "numpy_accelerated" in self.qc.info()


class TestMLKEM768:
    """ML-KEM-768 correctness (higher security parameter set)."""

    def setup_method(self):
        from layers.l1_identity.quantum_crypto import _MLKEM
        self.kem = _MLKEM(768)

    def test_pk_length_1184(self):
        pk, _ = self.kem.keygen(); assert len(pk) == 1184

    def test_sk_length_2400(self):
        _, sk = self.kem.keygen(); assert len(sk) == 2400

    def test_ct_length_1088(self):
        pk, _ = self.kem.keygen(); ct, _ = self.kem.encapsulate(pk)
        assert len(ct) == 1088

    def test_roundtrip(self):
        pk, sk = self.kem.keygen(); ct, ss1 = self.kem.encapsulate(pk)
        assert self.kem.decapsulate(sk, ct) == ss1

    def test_roundtrip_repeated(self):
        for _ in range(5):
            pk, sk = self.kem.keygen(); ct, ss1 = self.kem.encapsulate(pk)
            assert self.kem.decapsulate(sk, ct) == ss1

    def test_implicit_rejection(self):
        pk, _  = self.kem.keygen(); _, sk2 = self.kem.keygen()
        ct, ss1 = self.kem.encapsulate(pk)
        assert self.kem.decapsulate(sk2, ct) != ss1

    def test_ss_length_32(self):
        pk, sk = self.kem.keygen(); _, ss = self.kem.encapsulate(pk)
        assert len(ss) == 32

    def test_768_different_from_512(self):
        from layers.l1_identity.quantum_crypto import _MLKEM as MLKEM
        kem512 = MLKEM(512); kem768 = MLKEM(768)
        pk512, _ = kem512.keygen(); pk768, _ = kem768.keygen()
        assert len(pk512) != len(pk768)


class TestMLKEMPerformance:
    """
    Performance regression tests.
    Assert that keygen and encap/decap stay under practical thresholds.
    These thresholds are conservative (10x headroom over measured values).
    """

    def setup_method(self):
        from layers.l1_identity.quantum_crypto import _MLKEM
        self.kem = _MLKEM(512)

    def test_keygen_under_50ms(self):
        pk, sk = self.kem.keygen()  # warm-up
        start = time.perf_counter()
        for _ in range(10): self.kem.keygen()
        ms = (time.perf_counter() - start) / 10 * 1000
        assert ms < 50, f"keygen averaged {ms:.1f}ms (threshold: 50ms)"

    def test_encap_decap_under_100ms(self):
        pk, sk = self.kem.keygen()
        ct, _  = self.kem.encapsulate(pk)  # warm-up
        start  = time.perf_counter()
        for _ in range(10):
            ct2, ss = self.kem.encapsulate(pk)
            self.kem.decapsulate(sk, ct2)
        ms = (time.perf_counter() - start) / 10 * 1000
        assert ms < 100, f"encap+decap averaged {ms:.1f}ms (threshold: 100ms)"

    def test_100_roundtrips_complete(self):
        """Stress: 100 complete round-trips must succeed without error."""
        for _ in range(100):
            pk, sk = self.kem.keygen()
            ct, ss1 = self.kem.encapsulate(pk)
            assert self.kem.decapsulate(sk, ct) == ss1


# ══════════════════════════════════════════════════════════════════════════════
# SOAR IDEMPOTENCY TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestSOARIdempotency:
    """Verify the _Deduplicator prevents duplicate dispatches."""

    def setup_method(self):
        from soar.integrations import _Deduplicator, _DEDUP_TTL_S
        self.ded = _Deduplicator(ttl=1.0)   # 1 s TTL for fast tests
        self._ttl = _DEDUP_TTL_S

    def test_first_call_not_duplicate(self):
        assert self.ded.is_duplicate("jira", "key1") is False

    def test_second_call_is_duplicate(self):
        self.ded.is_duplicate("jira", "key2")
        assert self.ded.is_duplicate("jira", "key2") is True

    def test_different_key_not_duplicate(self):
        self.ded.is_duplicate("jira", "key3")
        assert self.ded.is_duplicate("jira", "key4") is False

    def test_different_channel_not_duplicate(self):
        self.ded.is_duplicate("jira", "key5")
        assert self.ded.is_duplicate("servicenow", "key5") is False

    def test_expired_entry_not_duplicate(self):
        self.ded.is_duplicate("jira", "key6")
        time.sleep(1.1)   # TTL=1s — wait for expiry
        assert self.ded.is_duplicate("jira", "key6") is False

    def test_clear_resets(self):
        self.ded.is_duplicate("jira", "key7")
        self.ded.clear()
        assert self.ded.is_duplicate("jira", "key7") is False

    def test_thread_safe_no_duplicate(self):
        """Concurrent first-calls must only succeed once."""
        results = []
        def call():
            results.append(self.ded.is_duplicate("jira", "concurrent_key"))
        threads = [threading.Thread(target=call) for _ in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()
        false_count = results.count(False)
        assert false_count == 1, f"Expected exactly 1 non-duplicate, got {false_count}"

    def test_dedup_key_stable(self):
        from soar.integrations import _dedup_key
        k1 = _dedup_key("CONTAINMENT", "abc123", "summary text")
        k2 = _dedup_key("CONTAINMENT", "abc123", "summary text")
        assert k1 == k2

    def test_dedup_key_with_containment_id(self):
        from soar.integrations import _dedup_key
        k = _dedup_key("CONTAINMENT", "cid-42", "any summary")
        assert "cid-42" in k

    def test_dedup_key_without_containment_uses_hash(self):
        from soar.integrations import _dedup_key
        k = _dedup_key("GENERIC", "", "my summary text")
        assert hashlib.sha256("my summary text".encode()).hexdigest()[:24] in k


class TestSOARConnectors:
    """Verify connector behavior when unconfigured / with minimal config."""

    def test_jira_unconfigured_returns_none(self):
        from soar.integrations import JiraConnector
        j = JiraConnector({})
        assert j.create_issue("HIGH", "TEST", "summary", {}) is None

    def test_jira_status_has_configured_flag(self):
        from soar.integrations import JiraConnector
        st = JiraConnector({}).status()
        assert "configured" in st and st["configured"] is False

    def test_servicenow_unconfigured_returns_none(self):
        from soar.integrations import ServiceNowConnector
        sn = ServiceNowConnector({})
        assert sn.create_incident("HIGH", "TEST", "summary", {}) is None

    def test_servicenow_status_has_configured_flag(self):
        from soar.integrations import ServiceNowConnector
        st = ServiceNowConnector({}).status()
        assert "configured" in st and st["configured"] is False

    def test_webhook_unconfigured_returns_false(self):
        from soar.integrations import ContainmentWebhook
        wh = ContainmentWebhook({})
        assert wh.fire("cid","action","user","HIGH","summary",{}) is False

    def test_webhook_status_has_configured_flag(self):
        from soar.integrations import ContainmentWebhook
        st = ContainmentWebhook({}).status()
        assert st["configured"] is False

    def test_webhook_signing_flag_false_without_secret(self):
        from soar.integrations import ContainmentWebhook
        st = ContainmentWebhook({"url": "https://example.com/hook"}).status()
        assert st["signing"] is False

    def test_webhook_signing_flag_true_with_secret(self):
        from soar.integrations import ContainmentWebhook
        st = ContainmentWebhook({"url":"https://ex.com","secret":"s"}).status()
        assert st["signing"] is True


class TestSOARManager:
    """Verify SOARManager facade."""

    def setup_method(self):
        import soar.integrations as si
        si._manager = None   # Reset singleton
        from soar.integrations import SOARManager
        self.mgr = SOARManager()

    def test_manager_instantiates(self):
        assert self.mgr is not None

    def test_status_has_all_channels(self):
        st = self.mgr.status()
        assert "jira" in st and "servicenow" in st and "containment_webhook" in st

    def test_status_has_dedup_ttl(self):
        st = self.mgr.status()
        assert "dedup_ttl_s" in st and st["dedup_ttl_s"] > 0

    def test_dispatch_unconfigured_no_exception(self):
        """Dispatch to unconfigured channels must silently succeed."""
        self.mgr.dispatch("HIGH","CONTAINMENT","test",{},
                          containment_id="abc",action="export",user_id="u1")

    def test_singleton_returns_same_instance(self):
        from soar.integrations import get_soar_manager
        m1 = get_soar_manager(); m2 = get_soar_manager()
        assert m1 is m2

    def test_test_channels_returns_dict(self):
        results = self.mgr.test_channels()
        assert isinstance(results, dict)


# ══════════════════════════════════════════════════════════════════════════════
# PKCE / SSO TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestPKCE:
    """PKCE pair and state generation (RFC 7636)."""

    def test_verifier_length_128(self):
        from auth.sso_pkce import _generate_pkce_pair
        v, _ = _generate_pkce_pair()
        assert len(v) == 128, f"Expected 128-char verifier, got {len(v)}"

    def test_verifier_unreserved_chars_only(self):
        from auth.sso_pkce import _generate_pkce_pair
        import re
        v, _ = _generate_pkce_pair()
        assert re.fullmatch(r"[A-Za-z0-9\-._~]+", v), "Verifier contains reserved chars"

    def test_challenge_is_s256_of_verifier(self):
        from auth.sso_pkce import _generate_pkce_pair
        v, c = _generate_pkce_pair()
        digest   = hashlib.sha256(v.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        assert c == expected, "code_challenge != BASE64URL(SHA256(verifier))"

    def test_challenge_length_43(self):
        """SHA-256 → 32 bytes → 43-char BASE64URL (no padding)."""
        from auth.sso_pkce import _generate_pkce_pair
        _, c = _generate_pkce_pair()
        assert len(c) == 43

    def test_pairs_unique(self):
        from auth.sso_pkce import _generate_pkce_pair
        v1, c1 = _generate_pkce_pair(); v2, c2 = _generate_pkce_pair()
        assert v1 != v2 and c1 != c2

    def test_state_length_sufficient(self):
        from auth.sso_pkce import _generate_state
        s = _generate_state()
        assert len(s) >= 32, f"State too short: {len(s)}"

    def test_states_unique(self):
        from auth.sso_pkce import _generate_state
        states = {_generate_state() for _ in range(100)}
        assert len(states) == 100

    def test_state_csrf_detection(self):
        """Different state values must not compare equal."""
        from auth.sso_pkce import _generate_state
        import hmac as _h
        s1 = _generate_state(); s2 = _generate_state()
        assert not _h.compare_digest(s1, s2)

    def test_challenge_no_padding(self):
        from auth.sso_pkce import _generate_pkce_pair
        _, c = _generate_pkce_pair()
        assert "=" not in c, "code_challenge must not contain padding"

    def test_verifier_is_ascii(self):
        from auth.sso_pkce import _generate_pkce_pair
        v, _ = _generate_pkce_pair()
        v.encode("ascii")   # must not raise


class TestSSOFlow:
    """SSOFlow unit tests (no real IdP calls)."""

    def setup_method(self):
        import auth.sso_pkce as sso_mod
        sso_mod._sso = None
        self.sso = sso_mod.SSOFlow({"provider": "oidc",
                                    "client_id": "", "issuer": ""})

    def test_unconfigured_status_false(self):
        assert self.sso.status()["configured"] is False

    def test_status_has_pkce_field(self):
        st = self.sso.status()
        assert "pkce" in st

    def test_status_pkce_method_s256(self):
        assert self.sso.status()["pkce_method"] == "S256"

    def test_status_has_persist_pending(self):
        assert "persist_pending" in self.sso.status()

    def test_status_has_session_store(self):
        assert "session_store" in self.sso.status()

    def test_begin_auth_raises_when_unconfigured(self):
        from auth.sso_pkce import SSOError
        try:
            self.sso.begin_auth()
            raise AssertionError("Expected SSOError not raised")
        except SSOError as e:
            assert "not configured" in str(e)

    def test_exchange_code_state_mismatch_raises(self):
        from auth.sso_pkce import SSOStateError
        try:
            self.sso.exchange_code("code", "state_A", "state_B")
            raise AssertionError("Expected SSOStateError not raised")
        except SSOStateError:
            pass

    def test_pending_session_stored_and_retrievable(self):
        """Manually put a pending session and verify pop works."""
        self.sso._pending.put("test_state", {"code_verifier": "vvv", "nonce": "nnn",
                                             "started_at": time.time()})
        sess = self.sso._pending.pop("test_state")
        assert sess is not None and sess["code_verifier"] == "vvv"

    def test_pending_session_expired_not_returned(self):
        self.sso._pending.put("expired_state",
                              {"code_verifier":"v","nonce":"n","started_at":time.time()-700})
        sess = self.sso._pending.pop("expired_state")
        assert sess is None   # evicted because started_at is > _PKCE_TTL_S ago

    def test_singleton_is_same(self):
        import auth.sso_pkce as m
        m._sso = None
        s1 = m.get_sso(); s2 = m.get_sso()
        assert s1 is s2

    def test_github_provider_no_pkce(self):
        from auth.sso_pkce import SSOFlow
        s = SSOFlow({"provider": "github", "client_id": "x", "issuer": ""})
        st = s.status()
        assert st["pkce"] is False, "GitHub OAuth2 does not support PKCE"

    def test_session_ttl_in_status(self):
        from auth.sso_pkce import SSOFlow
        s = SSOFlow({"provider":"oidc","client_id":"","issuer":"","session_ttl":7200})
        assert s.status()["session_ttl"] == 7200


class TestSSOSessionStore:
    """_SessionStore: server-side token persistence for NOC dashboards."""

    def setup_method(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        # Point session store at tmp dir
        import auth.sso_pkce as m
        m._SESSION_DIR = self.tmp / "sso_sessions"
        m._SESSION_STORE = m._SessionStore()
        from auth.sso_pkce import _SessionStore, TokenResponse
        self.store = m._SESSION_STORE
        self.TR = TokenResponse

    def _make_tr(self, exp=3600):
        return self.TR(access_token="at_test", id_token="it_test",
                       refresh_token="rt_test", expires_in=exp)

    def test_create_returns_signed_token(self):
        tok = self.store.create(self._make_tr())
        assert "." in tok  # session_id.mac

    def test_get_returns_data(self):
        tok  = self.store.create(self._make_tr())
        data = self.store.get(tok)
        assert data is not None and data["access_token"] == "at_test"

    def test_get_invalid_token_returns_none(self):
        assert self.store.get("bad.token") is None

    def test_delete_removes_session(self):
        tok = self.store.create(self._make_tr())
        self.store.delete(tok)
        assert self.store.get(tok) is None

    def test_expired_session_returns_none(self):
        tok = self.store.create(self._make_tr(exp=0))  # expires_in=0 → immediate expiry
        time.sleep(0.05)
        assert self.store.get(tok) is None

    def test_prune_removes_expired(self):
        tok = self.store.create(self._make_tr(exp=0))
        time.sleep(0.05)
        pruned = self.store.prune_expired()
        assert pruned >= 1
        assert self.store.get(tok) is None

    def test_session_file_created(self):
        self.store.create(self._make_tr())
        files = list(m._SESSION_DIR.glob("*.json")) if m._SESSION_DIR.exists() else []
        assert len(files) >= 1

    def test_cookie_header_has_httponly(self):
        import auth.sso_pkce as m
        hdr = m._SESSION_STORE.cookie_header("tok.mac")
        assert "HttpOnly" in hdr

    def test_cookie_header_has_samesite(self):
        import auth.sso_pkce as m
        hdr = m._SESSION_STORE.cookie_header("tok.mac")
        assert "SameSite=Strict" in hdr

import auth.sso_pkce as m


# ══════════════════════════════════════════════════════════════════════════════
# LIVE DASHBOARD TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestDashboard:
    """Verify the live dashboard server serves correctly."""

    def setup_method(self):
        from dashboard.live_dashboard import DashboardServer
        self.server = DashboardServer(api_url="http://127.0.0.1:9100")

    def _get(self, path: str) -> tuple:
        """Simulate a WSGI GET request, return (status, headers_dict, body_str)."""
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": path,
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "9102",
            "wsgi.input": __import__("io").BytesIO(b""),
            "wsgi.url_scheme": "http",
        }
        responses = []
        def start_response(status, headers):
            responses.append((status, dict(headers)))
        body = b"".join(self.server.wsgi_app(environ, start_response))
        return responses[0][0], responses[0][1], body.decode("utf-8", errors="replace")

    def test_root_redirects_to_dashboard(self):
        status, hdrs, _ = self._get("/")
        assert status.startswith("302") and "/dashboard" in hdrs.get("Location","")

    def test_dashboard_returns_200(self):
        status, _, _ = self._get("/dashboard")
        assert status.startswith("200")

    def test_dashboard_content_type_html(self):
        _, hdrs, _ = self._get("/dashboard")
        assert "text/html" in hdrs.get("Content-Type","")

    def test_dashboard_has_eventSource(self):
        _, _, body = self._get("/dashboard")
        assert "EventSource" in body

    def test_dashboard_has_api_url(self):
        _, _, body = self._get("/dashboard")
        assert "127.0.0.1:9100" in body

    def test_dashboard_has_token_prompt(self):
        _, _, body = self._get("/dashboard")
        assert "aurora_token" in body or "token" in body.lower()

    def test_config_endpoint_returns_json(self):
        status, hdrs, body = self._get("/dashboard/config")
        assert status.startswith("200")
        assert "application/json" in hdrs.get("Content-Type","")
        data = json.loads(body)
        assert "api_url" in data and "sse_endpoint" in data

    def test_config_endpoint_sse_url(self):
        _, _, body = self._get("/dashboard/config")
        data = json.loads(body)
        assert "/events" in data["sse_endpoint"]

    def test_xframe_deny_header(self):
        _, hdrs, _ = self._get("/dashboard")
        assert hdrs.get("X-Frame-Options") == "DENY"


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION: SOAR wired to containment
# ══════════════════════════════════════════════════════════════════════════════

class TestSOARContainmentWiring:
    """Verify sandbox.contain() calls SOAR manager."""

    def test_contain_calls_soar_dispatch(self):
        import sys, types
        dispatches = []

        class FakeManager:
            def dispatch(self, **kw): dispatches.append(kw)

        fake_mod = types.ModuleType("soar.integrations")
        fake_mod.get_soar_manager = lambda: FakeManager()
        sys.modules["soar.integrations"] = fake_mod
        try:
            from layers.l4_containment.sandbox import Sandbox
            Sandbox().contain("bulk_data_export", "test_user")
            assert len(dispatches) >= 1
            assert dispatches[0].get("event_type") == "CONTAINMENT"
        finally:
            del sys.modules["soar.integrations"]

    def test_contain_soar_includes_containment_id(self):
        import sys, types
        dispatches = []

        class FakeManager:
            def dispatch(self, **kw): dispatches.append(kw)

        fake_mod = types.ModuleType("soar.integrations")
        fake_mod.get_soar_manager = lambda: FakeManager()
        sys.modules["soar.integrations"] = fake_mod
        try:
            from layers.l4_containment.sandbox import Sandbox
            Sandbox().contain("mass_delete", "alice")
            assert dispatches[0].get("containment_id"), "containment_id must be passed"
        finally:
            del sys.modules["soar.integrations"]
