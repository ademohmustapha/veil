"""AURORA CLI Interface"""
from __future__ import annotations
import json, sys
from typing import List, Dict
from identity.provider import get_resolver as _get_resolver

class AuroraCLI:
    def __init__(self):
        self.commands = {
            "risk":     self.cmd_risk,
            "scan":     self.cmd_scan,
            "contain":  self.cmd_contain,
            "evolve":   self.cmd_evolve,
            "horizon":  self.cmd_horizon,
            "supply":   self.cmd_supply,
            "api":      self.cmd_api,
            "identity":  self.cmd_identity,
            "dashboard": self.cmd_dashboard,
            "sso":       self.cmd_sso,
            "soar":      self.cmd_soar,
        }

    def dispatch(self, args: List[str]) -> None:
        if not args: print(self.get_help_text()); return
        cmd = args[0]
        handler = self.commands.get(cmd)
        if handler:
            try:
                handler(args[1:])
            except (IndexError, ValueError) as e:
                print(f"[AURORA] Argument error: {e}\n{self.get_help_text()}")
        else:
            print(f"[AURORA] Unknown command: {cmd}\n{self.get_help_text()}")

    def get_help_text(self) -> str:
        return """AURORA CLI
  risk [--user <id>]   Compute Human Risk Index  (auto-resolves user if omitted)
  scan [--org <id>]    Full organizational intelligence scan (auto-resolves org if omitted)
  contain --action <a> Trigger autonomous containment
  evolve               Run AI co-evolution cycle
  horizon              Display predictive event horizon
  supply [--org <id>]  Supply chain risk analysis (auto-resolves org if omitted)
  identity             Show identity provider status
  dashboard [--port N] Start live web dashboard (default port 9102)
  sso [--status]       Show SSO configuration / run authentication flow
  soar [--test]        Show SOAR integration status / run channel tests"""

    def cmd_risk(self, args):
        if "--user" in args:
            try:
                user_id = args[args.index("--user") + 1]
            except IndexError:
                print("[AURORA] --user requires a value"); return
            uid_src = "cli"
        else:
            user_id, uid_src = _get_resolver().resolve_user(fallback="default_user")
        from layers.l3_human_risk.risk_index import HumanRiskIndex
        score = HumanRiskIndex().compute(user_id, {})
        level = "CRITICAL" if score>80 else ("HIGH" if score>60 else ("MEDIUM" if score>40 else "LOW"))
        print(json.dumps({"user_id": user_id, "identity_source": uid_src,
                          "risk_score": score, "level": level}, indent=2))

    def cmd_scan(self, args):
        if "--org" in args:
            try:
                org_id = args[args.index("--org") + 1]
            except IndexError:
                print("[AURORA] --org requires a value"); return
            oid_src = "cli"
        else:
            org_id, oid_src = _get_resolver().resolve_org(fallback="default_org")
        from layers.l2_intelligence.org_intel import OrgIntel
        from integrations import IntegrationManager

        mgr = IntegrationManager()
        live_findings = mgr.fetch_all()

        intel = OrgIntel()
        if live_findings:
            intel.ingest_findings(live_findings)

        result = intel.scan_organization(org_id)
        result["integrations"] = mgr.status()
        result["identity_source"] = oid_src
        result["data_source"] = (
            "live" if live_findings
            else "defaults_only — no integration sources configured. "
                 "See ~/.aurora/integrations.json"
        )
        print(json.dumps(result, indent=2))

    def cmd_contain(self, args):
        try:
            action = args[args.index("--action")+1] if "--action" in args else "unknown_action"
        except IndexError:
            print("[AURORA] --action requires a value"); return
        from layers.l4_containment.sandbox import Sandbox
        result = Sandbox().contain(action, "cli_user")
        print(json.dumps(result, indent=2))

    def cmd_evolve(self, args):
        from layers.l7_evolution.co_evolution import CoEvolutionEngine
        result = CoEvolutionEngine().run_evolution_cycle()
        print(json.dumps(result, indent=2))

    def cmd_horizon(self, args):
        from layers.l7_evolution.event_horizon import EventHorizon
        result = EventHorizon().get_horizon_report()
        print(json.dumps(result, indent=2))

    def cmd_supply(self, args):
        from layers.l6_supply_chain.resilience import SupplyChainResilience
        sc = SupplyChainResilience()
        sc.add_organization("org_test", {"sector":"finance"})
        result = sc.generate_risk_heatmap()
        print(json.dumps(result, indent=2))

    def cmd_api(self, args):
        """
        Start Aurora REST API server on the configured port (default: 9100).

        UPGRADES:
          1. ThreadedWSGIServer — each request runs in its own daemon thread.
          2. Native TLS — HTTPS served directly when api_tls_enabled=true.
             Self-signed cert auto-generated on first run; BYOC also supported.
             Set AURORA_API_TLS_ENABLED=true or api_tls_enabled in config.

        Thread safety:
          - AuroraAPIServer.handle_request() is stateless per-call.
          - SQLite storage uses WAL mode + per-thread connections (core.storage).
          - Rate limiter uses threading.Lock (hardening.self_defense).
          - Token map is read-only after startup.
        """
        import socketserver
        import ssl as _ssl
        import wsgiref.simple_server
        import json as _json
        from api.server import AuroraAPIServer
        from core.tls import TLSConfig
        from core.config import get_config as _get_config
        _cfg = _get_config()

        api = AuroraAPIServer()
        host = "127.0.0.1"
        port = _cfg.get("api_port", 9100)

        # Parse optional --port / --tls overrides
        try:
            if "--port" in args:
                port = int(args[args.index("--port")+1])
        except (IndexError, ValueError):
            pass

        tls_cfg = TLSConfig.from_config()
        if "--tls" in args:
            tls_cfg.enabled = True          # CLI flag forces TLS on
        if "--no-tls" in args:
            tls_cfg.enabled = False         # CLI flag forces TLS off

        # ── Threaded WSGI server (stdlib only, no new deps) ───────────────────
        class _SilentHandler(wsgiref.simple_server.WSGIRequestHandler):
            """Suppress per-request stdout noise; errors still go to stderr."""
            def log_message(self, fmt, *a):  # type: ignore[override]
                pass

        class ThreadedWSGIServer(
            socketserver.ThreadingMixIn,
            wsgiref.simple_server.WSGIServer,
        ):
            """
            Threaded WSGI server with optional native TLS.
            Each request is handled in a daemon thread (no head-of-line blocking).
            When ssl_context is provided, all connections are wrapped with TLS
            before the WSGI app sees them — same as gunicorn --certfile behaviour.
            """
            daemon_threads      = True   # threads reaped on process exit
            allow_reuse_address = True   # no TIME_WAIT on fast restart
            request_queue_size  = 64     # listen() backlog (was 5 in stdlib)

            def __init__(self, server_address, handler_class,
                         ssl_context=None):
                super().__init__(server_address, handler_class)
                self._ssl_context = ssl_context

            def get_request(self):
                """Wrap accepted socket in TLS if context is configured."""
                conn, addr = self.socket.accept()
                if self._ssl_context is not None:
                    try:
                        conn = self._ssl_context.wrap_socket(
                            conn, server_side=True
                        )
                    except _ssl.SSLError as exc:
                        # TLS handshake failure — close socket, let server loop continue
                        conn.close()
                        raise
                return conn, addr

        def wsgi_app(environ, start_response):
            method = environ.get("REQUEST_METHOD", "GET")
            path   = environ.get("PATH_INFO", "/")

            # ── SSE: GET /events ── real-time push stream ─────────────────────
            # EventSource (browser) cannot send custom headers, so we also
            # accept ?token= in the query string for the SSE path only.
            if path == "/events" and method == "GET":
                qs = environ.get("QUERY_STRING", "")
                token_from_qs = ""
                for part in qs.split("&"):
                    if part.startswith("token="):
                        token_from_qs = part[len("token="):]
                        break

                headers_sse = {
                    "X-Forwarded-For": environ.get("HTTP_X_FORWARDED_FOR", ""),
                    "X-Aurora-Token":  (
                        environ.get("HTTP_X_AURORA_TOKEN", "") or token_from_qs
                    ),
                    "Remote-Addr":     environ.get("REMOTE_ADDR", ""),
                }
                # Resolve user_id for per-user risk scoring in the stream
                user_id = environ.get("HTTP_X_AURORA_USER", "sse_user")

                http_status, sse_hdrs, byte_iter = api.sse_stream(
                    headers_sse, user_id=user_id
                )
                start_response(http_status, list(sse_hdrs.items()))
                return byte_iter  # WSGI will iterate this lazily

            # ── Standard JSON endpoints ───────────────────────────────────────
            length = int(environ.get("CONTENT_LENGTH") or 0)
            raw    = environ["wsgi.input"].read(min(length, 1_048_576)) if length > 0 else b""
            try:
                body = _json.loads(raw) if raw else {}
            except Exception:
                body = {}
            headers = {
                "X-Forwarded-For": environ.get("HTTP_X_FORWARDED_FOR", ""),
                "X-Aurora-Token":  environ.get("HTTP_X_AURORA_TOKEN", ""),
                "Remote-Addr":     environ.get("REMOTE_ADDR", ""),
            }
            result  = api.handle_request(method, path, body, headers)
            status  = f"{result.get('status', 200)} OK"
            resp_headers = list(api.security_headers().items()) + [("Content-Type", "application/json")]
            start_response(status, resp_headers)
            return [_json.dumps(result).encode()]

        # ── Build TLS context (None = plain HTTP) ─────────────────────────────
        ssl_ctx = None
        scheme  = "http"
        try:
            ssl_ctx = tls_cfg.build_context()
            if ssl_ctx is not None:
                scheme = "https"
                tls_info = tls_cfg.info()
                cert_file = tls_info.get("cert_file", "")
                print(f"[AURORA] TLS enabled — cert: {cert_file}")
                if tls_info.get("fingerprint"):
                    print(f"[AURORA] Cert fingerprint (SHA-256): {tls_info['fingerprint']}")
                if tls_info.get("expires"):
                    print(f"[AURORA] Cert expires: {tls_info['expires']}")

                # ── Trust store instructions (self-signed cert only) ────────
                if tls_info.get("self_signed", False) and cert_file:
                    import platform, sys as _sys
                    _os = platform.system()
                    print("")
                    print("[AURORA] ── TRUST STORE SETUP (self-signed cert) ──────────────")
                    print("[AURORA] To suppress browser warnings, add the cert to your OS trust store:")
                    if _os == "Linux":
                        print(f"[AURORA]   sudo cp \"{cert_file}\" /usr/local/share/ca-certificates/aurora.crt")
                        print("[AURORA]   sudo update-ca-certificates")
                        print("[AURORA]   # Restart your browser after running the above.")
                    elif _os == "Darwin":
                        print(f"[AURORA]   sudo security add-trusted-cert -d -r trustRoot \\")
                        print(f"[AURORA]     -k /Library/Keychains/System.keychain \"{cert_file}\"")
                        print("[AURORA]   # Restart your browser after running the above.")
                    elif _os == "Windows":
                        print(f"[AURORA]   certutil -addstore Root \"{cert_file}\"")
                        print("[AURORA]   (Run in an Administrator command prompt.)")
                    else:
                        print(f"[AURORA]   Add \"{cert_file}\" to your OS/browser trust store.")
                    print("[AURORA]   Or use a BYOC cert signed by your internal CA:")
                    print("[AURORA]   AURORA_API_TLS_CERT_FILE=/path/cert.pem AURORA_API_TLS_KEY_FILE=/path/key.pem")
                    print("[AURORA] ────────────────────────────────────────────────────────")
                    print("")

        except Exception as exc:
            print(f"[AURORA] WARNING: TLS setup failed ({exc}) — falling back to HTTP")
            ssl_ctx = None
            scheme  = "http"

        print(f"[AURORA] REST API listening on {scheme}://{host}:{port}  (threaded)")
        print(f"[AURORA] SSE stream:  {scheme}://{host}:{port}/events?token=<token>")
        print(f"[AURORA] Token: {api.startup_token}")
        print("[AURORA] Store this token — it will not be shown again.")
        api._clear_startup_token()
        print("[AURORA] Press Ctrl+C to stop")

        with ThreadedWSGIServer((host, port), _SilentHandler,
                                ssl_context=ssl_ctx) as httpd:
            httpd.set_app(wsgi_app)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\n[AURORA] API server stopped.")

    def cmd_identity(self, args):
        """Show identity provider status and resolved IDs."""
        import json as _json
        resolver = _get_resolver()
        st = resolver.status()
        uid, usrc = resolver.resolve_user()
        oid, osrc = resolver.resolve_org()
        print(_json.dumps({
            "identity_provider_status": st,
            "resolved_user_id":  uid,
            "user_id_source":    usrc,
            "resolved_org_id":   oid,
            "org_id_source":     osrc,
            "registered_users":  len(resolver.list_users()),
        }, indent=2))

    def cmd_dashboard(self, args):
        """Start the AURORA live dashboard server."""
        import json as _json
        from dashboard.live_dashboard import DashboardServer
        from core.config import get_config as _get_config
        _cfg = _get_config()

        port = 9102
        if "--port" in args:
            try: port = int(args[args.index("--port")+1])
            except (IndexError, ValueError): pass

        api_port = _cfg.get("api_port", 9100)
        api_url  = f"http://127.0.0.1:{api_port}"
        if "--api-url" in args:
            try: api_url = args[args.index("--api-url")+1]
            except IndexError: pass

        session_ttl = 3600
        if "--session-ttl" in args:
            try: session_ttl = int(args[args.index("--session-ttl")+1])
            except (IndexError, ValueError): pass

        print(f"[AURORA] Live dashboard starting on http://127.0.0.1:{port}")
        print(f"[AURORA] Connecting to API: {api_url}")
        print(f"[AURORA] Session TTL: {session_ttl}s")
        print(f"[AURORA] NOC tip: POST /dashboard/session with your API token for persistent cookie auth")
        DashboardServer(api_url=api_url, session_ttl=session_ttl).serve(port=port)

    def cmd_sso(self, args):
        """Show SSO status or run interactive authentication."""
        import json as _json
        from auth.sso_pkce import get_sso, SSOError

        sso = get_sso()
        if "--status" in args or not args:
            print(_json.dumps({"sso_status": sso.status()}, indent=2))
            return

        if "--auth" in args:
            try:
                token_resp = sso.authenticate_cli()
                print(_json.dumps({
                    "auth": "success",
                    "token_type": token_resp.token_type,
                    "expires_in": token_resp.expires_in,
                    "has_id_token": bool(token_resp.id_token),
                    "has_refresh_token": bool(token_resp.refresh_token),
                }, indent=2))
                if token_resp.id_token:
                    try:
                        user = sso.validate_id_token(token_resp.id_token)
                        print(_json.dumps({
                            "user": {"sub": user.sub, "email": user.email, "name": user.name}
                        }, indent=2))
                    except Exception as e:
                        print(f"[AURORA SSO] id_token validation: {e}")
            except SSOError as e:
                print(_json.dumps({"auth": "failed", "error": str(e)}, indent=2))

    def cmd_soar(self, args):
        """Show SOAR integration status or test channels."""
        import json as _json
        from soar.integrations import get_soar_manager

        mgr = get_soar_manager()
        if "--test" in args:
            print("[AURORA SOAR] Testing configured channels…")
            results = mgr.test_channels()
            print(_json.dumps({"soar_test": results}, indent=2))
        else:
            print(_json.dumps({"soar_status": mgr.status()}, indent=2))
