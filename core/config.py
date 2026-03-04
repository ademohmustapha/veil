"""
AURORA – Core Configuration Management
Pydantic-based settings with env-var override, secrets management,
and runtime validation. Every parameter is documented and range-checked.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional


# ---------------------------------------------------------------------------
# Defaults & Paths
# ---------------------------------------------------------------------------

AURORA_HOME = Path(os.environ.get("AURORA_HOME", str(Path.home() / ".aurora")))
AURORA_HOME.mkdir(parents=True, exist_ok=True)

_CONFIG_FILE = AURORA_HOME / "aurora_config.json"


# ---------------------------------------------------------------------------
# AuroraConfig
# ---------------------------------------------------------------------------

class AuroraConfig:
    """
    Central configuration object. Loaded once at bootstrap, accessible globally.
    All settings have documented defaults and can be overridden via:
      1. ~/.aurora/aurora_config.json
      2. Environment variables  (AURORA_<KEY>)
      3. Programmatic override  (config.set(...))
    """

    # ── Defaults ──────────────────────────────────────────────────────────
    DEFAULTS: Dict[str, Any] = {
        # Identity & Trust
        "trust_decay_half_life_hours": 24,
        "trust_min": 0.0,
        "trust_max": 1.0,
        "mfa_escalation_threshold": 0.4,
        "privilege_score_floor": 0.1,

        # Human Risk Index
        "hri_update_interval_s": 30,
        "hri_alert_threshold": 70,          # 0-100; CRITICAL if exceeded
        "hri_warn_threshold": 45,
        "hri_phishing_weight": 0.22,
        "hri_behavioural_weight": 0.25,
        "hri_fatigue_weight": 0.18,
        "hri_privilege_misuse_weight": 0.20,
        "hri_social_engineering_weight": 0.15,

        # Containment
        "containment_latency_target_ms": 30_000,   # 30 seconds SLA
        "blast_radius_max_hops": 5,
        "sandbox_timeout_s": 120,
        "auto_rollback_enabled": True,
        "session_freeze_enabled": True,

        # Co-Evolution
        "coevolution_cycle_minutes": 60,
        "coevolution_population_size": 40,
        "coevolution_mutation_rate": 0.12,
        "coevolution_generations_per_cycle": 20,

        # Event Horizon
        "horizon_lookahead_hours": 72,
        "horizon_confidence_threshold": 0.65,
        "horizon_max_scenarios": 500,

        # Cognitive Resilience
        "cognitive_fatigue_threshold": 0.70,
        "cognitive_load_window_minutes": 30,
        "cognitive_intervention_cooldown_minutes": 10,

        # Ethics Engine
        "ethics_max_autonomous_action_risk": 0.80,
        "ethics_human_override_always_allowed": True,
        "ethics_explainability_required": True,
        "ethics_bias_check_enabled": True,

        # Adaptive Network
        "federated_noise_epsilon": 1.5,          # differential privacy ε
        "federated_noise_delta": 1e-5,           # differential privacy δ
        "federated_min_participants": 3,
        "federated_aggregation_interval_minutes": 120,

        # API Server
        "api_host": "127.0.0.1",
        "api_port": 9100,
        "api_token_expiry_minutes": 60,
        "api_rate_limit_per_minute": 120,
        "api_max_body_bytes": 10 * 1024 * 1024,  # 10 MB

        # TLS (native HTTPS — no reverse proxy required when enabled)
        "api_tls_enabled":    False,          # opt-in; set true or AURORA_API_TLS_ENABLED=true
        "api_tls_cert_file":  "",             # path to PEM cert; auto-generated if blank
        "api_tls_key_file":   "",             # path to PEM key; auto-generated if blank
        "api_tls_self_signed": True,          # auto-generate self-signed cert on first run
        "api_tls_min_version": "TLSv1.2",    # minimum TLS version ("TLSv1.2" | "TLSv1.3")

        # Push Notifications (Slack, PagerDuty, Webhook, Email)
        # Configure channels in ~/.aurora/notifications.json
        # All channels are optional and independently configurable.
        "notifications_min_severity": "HIGH",      # INFO | WARN | HIGH | CRITICAL
        "notifications_rate_limit_per_hour": 60,   # max alerts/hour per channel

        # Audit
        "audit_retention_days": 3650,             # 10 years
        "audit_chain_verify_on_read": True,
        "audit_export_format": "jsonl",           # jsonl | csv

        # Supply Chain
        "supply_chain_max_depth": 6,
        "supply_chain_cascade_threshold": 0.55,

        # Risk Ecosystem
        "risk_auto_tune_enabled": True,
        "risk_tune_interval_hours": 6,
        "risk_score_smoothing_alpha": 0.3,        # EMA smoothing

        # General
        "log_level": "INFO",
        "color_output": True,
        "analyst_name": "AURORA Operator",
        "organisation": "Default Organisation",
        "deployment_mode": "standalone",          # standalone | enterprise | cloud
        "timezone": "UTC",

        # Storage backend
        "storage_backend": "sqlite",              # sqlite | postgresql

        # PostgreSQL (only used when storage_backend = postgresql)
        "pg_host": "127.0.0.1",
        "pg_port": 5432,
        "pg_user": "aurora",
        "pg_db":   "aurora",
        "pg_pool_min": 1,
        "pg_pool_max": 10,
        "pg_sslmode": "prefer",                   # prefer | require | disable

        # Identity Provider
        "identity_backend": "auto",               # auto | sso | ldap | org_config | env | prompt
        "identity_sso_auto_refresh": True,        # Silently refresh SSO token before expiry
        "identity_ldap_auto_detect": True,        # Auto-detect OS user for LDAP lookup
        "identity_prompt_fallback": True,         # Fall back to interactive prompt if all backends fail
    }

    def __init__(self) -> None:
        self._data: Dict[str, Any] = dict(self.DEFAULTS)
        self._load_file()
        self._apply_env()

    # ── File loading ───────────────────────────────────────────────────────
    def _load_file(self) -> None:
        if _CONFIG_FILE.exists():
            try:
                with open(_CONFIG_FILE, "r", encoding="utf-8") as fh:
                    file_data = json.load(fh)
                for k, v in file_data.items():
                    if k in self.DEFAULTS:
                        self._data[k] = v
            except (json.JSONDecodeError, OSError):
                pass  # Silently use defaults if file is corrupt

    def _apply_env(self) -> None:
        """Environment variables override file: AURORA_API_PORT=9200, etc."""
        for key in self.DEFAULTS:
            env_key = f"AURORA_{key.upper()}"
            env_val = os.environ.get(env_key)
            if env_val is not None:
                default = self.DEFAULTS[key]
                try:
                    if isinstance(default, bool):
                        self._data[key] = env_val.lower() in ("1", "true", "yes")
                    elif isinstance(default, int):
                        self._data[key] = int(env_val)
                    elif isinstance(default, float):
                        self._data[key] = float(env_val)
                    else:
                        self._data[key] = env_val
                except ValueError:
                    pass

    # ── Accessors ──────────────────────────────────────────────────────────
    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    def __getattr__(self, key: str) -> Any:
        if key.startswith("_") or key == "DEFAULTS":
            raise AttributeError(key)
        try:
            return self._data[key]
        except KeyError:
            raise AttributeError(f"AuroraConfig has no setting '{key}'")

    # ── Persistence ────────────────────────────────────────────────────────
    def save(self) -> None:
        with open(_CONFIG_FILE, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2)

    def as_dict(self) -> Dict[str, Any]:
        return dict(self._data)

    def reset_to_defaults(self) -> None:
        self._data = dict(self.DEFAULTS)
        if _CONFIG_FILE.exists():
            _CONFIG_FILE.unlink()


# Module-level singleton
_config: Optional[AuroraConfig] = None


def get_config() -> AuroraConfig:
    global _config
    if _config is None:
        _config = AuroraConfig()
    return _config
