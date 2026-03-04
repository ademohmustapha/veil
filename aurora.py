#!/usr/bin/env python3
"""
AURORA — Autonomous Unified Resilience & Organizational Real-time Awareness
"""
from __future__ import annotations
import sys, os, warnings, signal, atexit

_MIN_PYTHON = (3, 8)
_VERIFIED_MAX = (3, 14)

if sys.version_info < _MIN_PYTHON:
    sys.exit(f"[AURORA] FATAL: Python {_MIN_PYTHON[0]}.{_MIN_PYTHON[1]}+ required.")

if sys.version_info[:2] > _VERIFIED_MAX:
    warnings.warn(
        f"AURORA verified on Python 3.8–3.14. "
        f"You are running Python {sys.version_info.major}.{sys.version_info.minor}. "
        "Will attempt to run. Report issues at: https://github.com/ademohmustapha/aurora/issues",
        FutureWarning, stacklevel=2,
    )

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from core.bootstrap import Bootstrap
_boot = Bootstrap()
_boot.ensure_deps()
_boot.ensure_keys()

def main() -> None:
    args = sys.argv[1:]

    # ── Commands that bypass authentication ────────────────────────────────
    if "doctor" in args:
        from core.bootstrap import Bootstrap
        Bootstrap().ensure_keys()
        from core.integrity import AuroraIntegrity
        report = AuroraIntegrity().run_full_diagnostics()
        if "--json" in args:
            import json; print(json.dumps(report, indent=2))
        else:
            _print_doctor(report)
        return
    if "--help" in args or "-h" in args:
        _print_help(); return

    # ── Provision command: python aurora.py provision <file.aup> ───────────
    if args and args[0] == "provision":
        from core.auth import run_provision_command
        aup = args[1] if len(args) > 1 else ""
        if not aup:
            print("Usage: python aurora.py provision <file.aup>")
            sys.exit(1)
        run_provision_command(aup)
        return

    # ── Authentication gate ────────────────────────────────────────────────
    from core.auth import is_first_run, first_time_setup, login_prompt
    if is_first_run():
        first_time_setup()
    if not login_prompt():
        sys.exit(1)
    # ──────────────────────────────────────────────────────────────────────

    if args and args[0] not in ("--no-verify-compat",):
        from cli.interface import AuroraCLI
        AuroraCLI().dispatch(args); return
    from ui.menu import AuroraMenu
    AuroraMenu().run()

def _print_help():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║       AURORA — Autonomous Unified Resilience & Awareness         ║
║                    7 Layers  |  144 Tests            ║
╚══════════════════════════════════════════════════════════════════╝
  python3 aurora.py                   Interactive menu
  python3 aurora.py doctor            Run 131 self-diagnostics
  python3 aurora.py risk --user <id>  Compute Human Risk Index
  python3 aurora.py scan --org <id>   Full organizational scan
  python3 aurora.py evolve            Run co-evolution cycle
  python3 aurora.py horizon           Predictive event horizon
  python3 aurora.py api               Start REST API (port 9100)
  python3 aurora.py dashboard          Start live web dashboard (port 9102)
  python3 aurora.py sso --auth         SSO/OIDC authentication (PKCE)
  python3 aurora.py soar --test        Test SOAR integrations (Jira/ServiceNow/webhook)
""")

def _print_doctor(report):
    passed = report.get("passed", 0); total = report.get("total", 0)
    rate = report.get("pass_rate", 0.0)
    status = "✅ ALL SYSTEMS NOMINAL" if rate == 100.0 else f"⚠️  {total-passed} CHECKS FAILED"
    print(f"\n  AURORA DOCTOR — Self-Diagnostic\n  {status}")
    print(f"  {passed}/{total} checks passed ({rate:.1f}%)")
    for layer, result in report.get("layers", {}).items():
        icon = "✓" if result.get("ok") else "✗"
        print(f"  {icon} {layer}: {result.get('message','OK')}")
    print()



# ── Graceful shutdown ──────────────────────────────────────────────────────────
def _graceful_shutdown(signum=None, frame=None):
    """Handle SIGTERM / SIGINT — flush logs and exit cleanly."""
    try:
        import logging
        logging.getLogger("aurora").info("AURORA received shutdown signal — exiting cleanly.")
    except Exception:
        pass
    sys.exit(0)

def _atexit_flush():
    """Flush logs at normal exit — does NOT call sys.exit (would raise SystemExit in atexit)."""
    try:
        import logging
        logging.getLogger("aurora").info("AURORA exiting normally.")
        logging.shutdown()
    except Exception:
        pass

signal.signal(signal.SIGTERM, _graceful_shutdown)
signal.signal(signal.SIGINT,  _graceful_shutdown)
# FIXED: register a flush-only function at atexit, not _graceful_shutdown which
# calls sys.exit() — sys.exit() inside atexit raises SystemExit and suppresses
# the real exit code, causing spurious non-zero exits in scripted environments.
atexit.register(_atexit_flush)
_sigterm_registered = True

if __name__ == "__main__":
    main()
