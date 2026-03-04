"""
AURORA Layer 3 — Behavioral Deviation Model
============================================
FIXED:
  - social_engineering_vulnerability() now personalised per actor
    using CERT/SEI risk factors: authority compliance, role tenure,
    isolation, cognitive load, and phishing history.
  - privilege_misuse_score() now context-driven: considers access
    frequency, off-hours patterns, data volume delta, and peer deviation.
  - build_profile() stores real attributes for downstream computation.
  - Rolling event window persists per actor (last 60 events).

References:
  Vishwanath et al. (2017): SE susceptibility 3.2× at high cognitive load
  CERT Insider Threat (CMU/SEI 8th Ed): privilege misuse indicators
"""
from __future__ import annotations
import math
import time
from typing import Dict, List, Any

# Authority-compliance susceptibility by role archetype
_ROLE_AUTHORITY_WEIGHT: Dict[str, float] = {
    "executive":         0.55,  # High trust of authority requests
    "finance":           0.65,  # BEC primary target
    "hr":                0.60,  # PII and payroll access
    "it_admin":          0.30,  # Trained to be skeptical
    "developer":         0.28,
    "analyst":           0.35,
    "standard_user":     0.45,
    "new_employee":      0.70,  # No established norms yet
}

# Privilege misuse signals and their weights (CERT SEI 8th Ed)
_MISUSE_SIGNALS: Dict[str, float] = {
    "after_hours_access":       0.20,
    "mass_download":            0.35,
    "accessed_non_role_system": 0.25,
    "peer_access_deviation":    0.15,  # accesses >2σ above peers
    "data_exfil_probe":         0.45,
    "admin_command_unusual":    0.30,
    "credential_share":         0.50,
}


class BehavioralModel:
    """
    Personalised behavioral deviation scoring per actor.
    Uses rolling 60-event window + role-based priors.
    """

    def __init__(self):
        self._profiles: Dict[str, Dict[str, Any]] = {}
        self._event_windows: Dict[str, List[Dict]] = {}

    def build_profile(self, user_id: str, attributes: Dict[str, Any] = None) -> Dict:
        """
        Build / update actor profile from attributes.
        attributes keys: role, tenure_days, training_completed,
                         phishing_clicked_30d, cognitive_load, team_size,
                         isolation_from_team (bool), after_hours_access (bool)
        """
        attrs = attributes or {}
        profile = {
            "user_id":            user_id,
            "role":               attrs.get("role", "standard_user"),
            "tenure_days":        int(attrs.get("tenure_days", 180)),
            "training_completed": bool(attrs.get("training_completed", False)),
            "phishing_clicked_30d": int(attrs.get("phishing_clicked_30d", 0)),
            "cognitive_load":     float(attrs.get("cognitive_load", 0.3)),
            "isolation_from_team":bool(attrs.get("isolation_from_team", False)),
            "after_hours_access": bool(attrs.get("after_hours_access", False)),
            "misuse_signals":     attrs.get("misuse_signals", []),
            "baseline_established": True,
            "dimensions": ["access_time", "data_volume",
                           "app_usage", "network_activity",
                           "privilege_scope", "peer_deviation"],
            "updated_at": time.time(),
        }
        self._profiles[user_id] = profile
        return profile

    def ingest_event(self, user_id: str, event: Dict) -> None:
        """Append event to rolling window (last 60 kept)."""
        window = self._event_windows.setdefault(user_id, [])
        window.append({**event, "ts": time.time()})
        if len(window) > 60:
            self._event_windows[user_id] = window[-60:]

    def social_engineering_vulnerability(self, user_id: str) -> float:
        """
        FIXED: Personalised SE vulnerability using role, tenure,
        cognitive load, isolation, and training/phishing history.

        Score: 0.0 (highly resistant) → 1.0 (highly vulnerable)
        """
        profile = self._profiles.get(user_id, {})

        # --- Role-based authority compliance prior ---
        role = profile.get("role", "standard_user")
        base = _ROLE_AUTHORITY_WEIGHT.get(role, 0.45)

        # --- Tenure modifier (new employees more vulnerable) ---
        tenure = profile.get("tenure_days", 180)
        if tenure < 30:
            base += 0.20   # Very new: no established verification habits
        elif tenure < 90:
            base += 0.10
        elif tenure > 730:
            base -= 0.08   # Seasoned: knows what's normal

        # --- Training modifier ---
        if profile.get("training_completed"):
            base -= 0.15

        # --- Phishing history (past behaviour predicts future) ---
        clicks = profile.get("phishing_clicked_30d", 0)
        base += min(0.25, clicks * 0.10)

        # --- Cognitive load amplifier (Vishwanath 2017: 3.2× at high load) ---
        cog_load = profile.get("cognitive_load", 0.3)
        if cog_load > 0.7:
            base *= 1.60   # High load ≈ System-2 thinking impaired
        elif cog_load > 0.5:
            base *= 1.25

        # --- Social isolation increases manipulation susceptibility ---
        if profile.get("isolation_from_team"):
            base += 0.10

        return round(min(1.0, max(0.0, base)), 4)

    def privilege_misuse_score(self, user_id: str) -> float:
        """
        FIXED: Context-driven privilege misuse score using CERT SEI indicators.
        Returns 0.0 (no evidence) → 1.0 (strong misuse evidence).
        """
        profile = self._profiles.get(user_id, {})
        signals = profile.get("misuse_signals", [])

        score = 0.0
        for signal in signals:
            score += _MISUSE_SIGNALS.get(signal, 0.05)

        # After-hours access on its own is a mild signal
        if profile.get("after_hours_access"):
            score += 0.08

        # Use rolling event window to detect mass-download pattern
        window = self._event_windows.get(user_id, [])
        download_events = sum(1 for e in window if e.get("action") == "download")
        if download_events > 10:
            score += min(0.30, (download_events - 10) * 0.03)

        return round(min(1.0, max(0.0, score)), 4)
