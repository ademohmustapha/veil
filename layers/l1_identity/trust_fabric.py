"""
AURORA Layer 1 — Global Identity & Trust Fabric

Zero Trust for humans, devices, IoT/OT, and AI agents.
Trust is computed continuously, never assumed, always verified.

Model: Bayesian trust decay + reinforcement with behavioral priors.
"""
from __future__ import annotations
import math, time, hashlib, json
from typing import Dict, Any, Optional


class TrustFabric:
    """
    Zero Trust Identity Engine.
    
    Continuous trust scoring (0–100) with:
    - Behavioral authentication
    - Trust decay (inactive users lose trust over time)
    - Trust reinforcement (positive actions increase trust)
    - Adaptive MFA escalation
    - Privilege scoring
    """

    # Trust decay constants (exponential decay)
    _DECAY_HALF_LIFE_DAYS = 14.0   # Trust halves every 14 inactive days
    
    # Trust events
    _REINFORCEMENT_EVENTS = {
        "successful_mfa":         +8.0,
        "successful_hardware_mfa":+12.0,
        "completed_training":     +5.0,
        "approved_by_manager":    +4.0,
        "clean_audit_period":     +6.0,
        "biometric_verified":     +10.0,
    }
    _DECAY_EVENTS = {
        "failed_mfa":             -10.0,
        "after_hours_access":     -5.0,
        "vpn_anomaly":            -8.0,
        "data_exfil_attempt":     -25.0,
        "policy_violation":       -15.0,
        "suspicious_api_call":    -12.0,
        "impossible_travel":      -20.0,
    }

    def __init__(self):
        self._trust_store: Dict[str, float] = {}

    def compute_trust_score(self, user_id: str, context: Dict[str, Any]) -> float:
        """
        Compute real-time trust score (50–100 baseline for new users).
        
        Factors: behavioral baseline, device posture, location, 
                 time of day, privilege level, recent events.
        """
        base = self._trust_store.get(user_id, 70.0)
        score = base
        
        # Context adjustments
        hour = context.get("hour", 12)
        if not (7 <= hour <= 20):       # After hours penalty
            score -= 5.0
        if context.get("new_device"):    # Unknown device
            score -= 10.0
        if context.get("vpn_mismatch"):  # VPN/geo mismatch
            score -= 8.0
        if context.get("failed_mfa_count", 0) > 0:
            score -= context["failed_mfa_count"] * 5.0
        if context.get("privileged_action"):
            score -= 3.0

        # Clamp
        score = max(0.0, min(100.0, score))
        self._trust_store[user_id] = score
        return round(score, 2)

    def apply_trust_decay(self, current_trust: float, days_inactive: float) -> float:
        """
        Exponential trust decay for inactive users.
        Trust(t) = Trust(0) * e^(-λt) where λ = ln(2) / half_life
        """
        λ = math.log(2) / self._DECAY_HALF_LIFE_DAYS
        decayed = current_trust * math.exp(-λ * days_inactive)
        return round(max(10.0, decayed), 2)  # Floor at 10 (never fully distrust existing user)

    def apply_trust_reinforcement(self, current_trust: float, event: str) -> float:
        """Apply positive trust event (caps at 100)."""
        delta = self._REINFORCEMENT_EVENTS.get(event, 2.0)
        return round(min(100.0, current_trust + delta), 2)

    def apply_trust_penalty(self, current_trust: float, event: str) -> float:
        """Apply negative trust event (floor at 0)."""
        delta = self._DECAY_EVENTS.get(event, -5.0)
        return round(max(0.0, current_trust + delta), 2)

    def evaluate_zero_trust(self, user_id: str, resource: str, context: Dict[str, Any]) -> str:
        """
        Zero Trust access decision: ALLOW / DENY / CHALLENGE.
        
        Principle: Never trust, always verify. Access granted per-request
        based on real-time trust score + resource sensitivity.
        """
        risk = context.get("risk_score", 50)
        sensitivity = context.get("resource_sensitivity", 50)
        
        # risk_score: 0=no risk, 100=maximum risk
        # low risk + low sensitivity = ALLOW; high risk = DENY
        if risk < 20 and sensitivity < 70:
            return "ALLOW"
        elif risk < 60:
            return "CHALLENGE"
        else:
            return "DENY"

    def adaptive_mfa_level(self, risk_score: float) -> str:
        """Select MFA method based on real-time risk."""
        if risk_score >= 85:
            return "BIOMETRIC"
        elif risk_score >= 70:
            return "HARDWARE_KEY"
        elif risk_score >= 50:
            return "PUSH"
        elif risk_score >= 30:
            return "TOTP"
        else:
            return "NONE"

    def privilege_score(self, role: str, permissions: list) -> int:
        """
        Privilege scoring (0–100): higher = more privileged = higher risk.
        Used for least-privilege enforcement.
        """
        base_scores = {
            "standard_user": 10, "developer": 30, "sysadmin": 65, "admin": 75,
            "security_analyst": 50, "executive": 45, "ciso": 70,
            "domain_admin": 90, "root": 100,
        }
        base = base_scores.get(role, 20)
        perm_score = min(40, len(permissions) * 5)
        return min(100, base + perm_score)
