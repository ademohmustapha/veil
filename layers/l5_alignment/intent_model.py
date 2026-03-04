"""
AURORA Layer 5 — Intent & Cognitive State Modeling (ECLIPSE-X)

FIXED: classify_intent() previously did a pure Python set-membership
lookup — effective only for exact action-name matches, no context used.

Now implements genuine multi-signal intent scoring:
  1. Lexical analysis   — action name decomposed into risk tokens
  2. Contextual signals — time-of-day, velocity, data volume, access path
  3. Behavioural drift  — deviation from user's established baseline
  4. Cognitive state    — fatigue and load amplify risk of any signal
  5. Confidence score   — returned alongside the classification

The result is a probabilistic verdict, not a binary lookup. A user
legitimately running "bulk_export" during business hours with low
fatigue will score differently from the same action at 3 am after
eight hours of intense activity.

cognitive_load_estimate() and emotional_state() are preserved from
enhanced with additional signals.
"""
from __future__ import annotations
import math
import time
from typing import Dict, Any, Tuple


# ── Risk token vocabulary ─────────────────────────────────────────────────────
# Each token carries a base risk weight (0.0–1.0).
# Tokens are extracted from the normalised action string.

_TOKEN_WEIGHTS: Dict[str, float] = {
    # Data exfiltration / destruction
    "bulk_export":        0.80, "mass_delete":       0.90,
    "data_staging":       0.75, "cover_tracks":       0.95,
    "log_delete":         0.90, "wipe":               0.85,
    "exfil":              0.85, "exfiltrat":          0.85,
    "dump":               0.60, "harvest":            0.80,
    # Privilege & access
    "admin_escalate":     0.80, "escalat":            0.65,
    "credential":         0.60, "privilege":          0.55,
    "bypass":             0.70, "sudo":               0.50,
    "impersonat":         0.75, "shadow":             0.60,
    # Financial
    "wire_transfer":      0.70, "large_transfer":     0.65,
    "approve_large":      0.60, "payment":            0.45,
    # Comms / social engineering
    "forward_all":        0.65, "send_mass":          0.55,
    "mass_email":         0.55, "phish":              0.80,
    # Network / config changes
    "disable_security":   0.80, "disable_log":        0.85,
    "modify_acl":         0.60, "open_port":          0.55,
    "vpn_relay":          0.45, "tunnel":             0.50,
    # Reconnaissance
    "unusual_query":      0.40, "large_download":     0.50,
    "after_hours":        0.35, "new_recipient":      0.35,
    # Benign — reduce score
    "read":               -0.10, "view":              -0.10,
    "login":              -0.05, "logout":            -0.15,
    "approved_workflow":  -0.20, "scheduled":         -0.25,
}

# ── Contextual risk modifiers ─────────────────────────────────────────────────
# Primary keys. Aliases below map shorthand caller keys to canonical names.
_CONTEXT_KEYS: Dict[str, float] = {
    # Time context
    "after_hours_access":      0.15,
    "weekend_access":          0.10,
    # Volume / velocity signals
    "mass_download":           0.20,
    "high_velocity":           0.18,
    "large_volume_bytes":      0.12,
    # Destination / access path
    "external_destination":    0.15,
    "new_destination":         0.12,
    "tor_or_vpn":              0.20,
    # Account / privilege state
    "termination_pending":     0.30,
    "performance_pip":         0.12,
    "recently_demoted":        0.15,
    "account_shared":          0.10,
    # Anomaly signals
    "failed_access_attempts":  0.15,
    "geolocation_anomaly":     0.20,
    "device_anomaly":          0.18,
}

# Shorthand aliases — callers may pass abbreviated keys; we normalise them.
_CONTEXT_ALIASES: Dict[str, str] = {
    "after_hours":           "after_hours_access",
    "weekend":               "weekend_access",
    "mass_dl":               "mass_download",
    "velocity":              "high_velocity",
    "large_volume":          "large_volume_bytes",
    "external":              "external_destination",
    "new_dest":              "new_destination",
    "tor":                   "tor_or_vpn",
    "vpn":                   "tor_or_vpn",
    "pip":                   "performance_pip",
    "demoted":               "recently_demoted",
    "shared_account":        "account_shared",
    "failed_logins":         "failed_access_attempts",
    "geo_anomaly":           "geolocation_anomaly",
    "device_change":         "device_anomaly",
}


def _normalise_ctx(ctx: Dict) -> Dict:
    """Expand alias keys in caller-supplied context dict."""
    out = dict(ctx)
    for alias, canonical in _CONTEXT_ALIASES.items():
        if alias in out and canonical not in out:
            out[canonical] = out.pop(alias)
    return out


class IntentModel:
    """
    Multi-signal intent classification.
    Returns probabilistic intent class + confidence rather than binary lookup.
    """

    def classify_intent(self, action: str, context: Dict = None) -> str:
        """
        Classify intent from action string + optional context signals.
        Returns: MALICIOUS | RISKY | SUSPICIOUS | AMBIGUOUS | BENIGN
        """
        verdict, _ = self.classify_intent_with_confidence(action, context or {})
        return verdict

    def classify_intent_with_confidence(
        self, action: str, context: Dict = None
    ) -> Tuple[str, float]:
        """
        Full classification with confidence score.
        Returns: (verdict: str, confidence: float 0-1)
        """
        ctx = _normalise_ctx(context or {})
        risk_score, confidence = self._compute_risk_score(action, ctx)

        # Amplify risk for impaired cognitive state
        cog_load = self.cognitive_load_estimate("", ctx)
        emotion = self.emotional_state("", ctx)
        if emotion in ("STRESSED", "AGITATED"):
            risk_score = min(1.0, risk_score * 1.15)
            confidence = max(0.4, confidence - 0.08)
        if emotion == "FATIGUED" and risk_score > 0.3:
            risk_score = min(1.0, risk_score * 1.10)
        if cog_load > 0.7 and risk_score > 0.25:
            risk_score = min(1.0, risk_score * 1.08)

        # Classify by risk band
        if risk_score >= 0.50:
            return "MALICIOUS", round(min(0.97, confidence + 0.10), 3)
        if risk_score >= 0.35:
            return "RISKY", round(confidence, 3)
        if risk_score >= 0.25:
            return "SUSPICIOUS", round(confidence, 3)
        if risk_score >= 0.12:
            return "AMBIGUOUS", round(max(0.4, confidence - 0.10), 3)
        return "BENIGN", round(min(0.95, confidence + 0.05), 3)

    def _compute_risk_score(self, action: str, ctx: Dict) -> Tuple[float, float]:
        """Return (risk_score 0-1, confidence 0-1).

        Calibration notes:
        - confidence starts at 0.25 (not 0.50) — a score with no evidence
          should carry low confidence, not medium confidence
        - each signal adds 0.08 to confidence, capped at 0.95
        - token_component uses tanh(score) which naturally compresses large sums
        - negative benign tokens (read, logout, scheduled) can reduce score below zero,
          which is clamped to 0 at the composite stage — this is intentional
        """
        # 1. Lexical signal: tokenise action string and sum weighted tokens
        normalised = action.lower().replace("-", "_").replace(" ", "_")
        token_score = 0.0
        tokens_matched = 0
        for token, weight in _TOKEN_WEIGHTS.items():
            if token in normalised:
                token_score += weight
                tokens_matched += 1
        # tanh bounds to (-1, 1); allows benign tokens to pull score negative
        raw_token = math.tanh(token_score)
        token_component = max(-0.3, min(1.0, raw_token))

        # 2. Contextual signals
        ctx_score = 0.0
        ctx_matched = 0
        for key, weight in _CONTEXT_KEYS.items():
            val = ctx.get(key, False)
            if isinstance(val, bool) and val:
                ctx_score += weight
                ctx_matched += 1
            elif isinstance(val, (int, float)) and val > 0:
                ctx_score += weight * min(1.0, float(val))
                ctx_matched += 1
        ctx_component = math.tanh(ctx_score)

        # 3. Behavioural drift signal (0-1 from caller if available)
        drift = max(0.0, min(1.0, float(ctx.get("behavioral_anomaly_score", 0.0))))

        # 4. Composite: tokens carry most weight; context and drift add nuance
        composite = (
            0.50 * token_component +
            0.30 * ctx_component +
            0.20 * drift
        )
        risk_score = max(0.0, min(1.0, composite))

        # 5. Confidence: starts low (0.25) and grows with evidence.
        # A zero-signal verdict is genuinely uncertain — confidence reflects that.
        total_signals = tokens_matched + ctx_matched + (1 if drift > 0 else 0)
        confidence = min(0.95, 0.25 + total_signals * 0.08)

        return risk_score, confidence

    # ── Cognitive load estimator ──────────────────────────────────────────────

    def cognitive_load_estimate(self, user_id: str, context: Dict) -> float:
        """
        Estimate cognitive load from observable signals.
        Based on Sweller's Cognitive Load Theory and Paas et al. error-rate proxy.
        Returns 0.0 (minimal) to 1.0 (critically overloaded).
        """
        load = 0.20  # Baseline — no one operates at 0

        # Working memory proxy: simultaneous open contexts / tasks
        contexts = context.get("concurrent_tasks", context.get("simultaneous_contexts", 1))
        load += min(0.25, float(contexts) * 0.05)

        # Error rate as load indicator
        load += float(context.get("error_rate", 0)) * 0.35

        # Time pressure (Kahneman System 1 activation)
        load += float(context.get("time_pressure", 0)) * 0.25

        # Extended session (fatigue accumulation)
        hours = float(context.get("hours_worked_today", 8))
        if hours > 10:
            load += min(0.20, (hours - 10) * 0.04)
        elif hours > 8:
            load += 0.05

        # Interruptions disrupt working memory consolidation
        interrupts = int(context.get("interruptions_today", 0))
        if interrupts > 5:
            load += min(0.15, (interrupts - 5) * 0.02)

        # Explicit deadline pressure
        if context.get("deadline_pressure", False):
            load += 0.15

        return round(min(1.0, load), 4)

    # ── Emotional state classifier ────────────────────────────────────────────

    def emotional_state(self, user_id: str, context: Dict) -> str:
        """
        Classify emotional state from available signals.
        Returns: CALM | ALERT | ANXIOUS | STRESSED | FATIGUED | AGITATED
        """
        stress   = float(context.get("stress_indicators", context.get("keystroke_variability", 0)))
        fatigue  = float(context.get("fatigue_score", context.get("cognitive_fatigue_level", 0)))
        error_rt = float(context.get("error_rate", 0))
        undo_rt  = float(context.get("undo_rate", 0))

        # Composite stress from multiple indicators
        composite_stress = stress * 0.5 + error_rt * 0.3 + undo_rt * 0.2

        if fatigue > 0.70:
            return "FATIGUED"
        if composite_stress > 0.70:
            return "AGITATED"
        if composite_stress > 0.50:
            return "STRESSED"
        if composite_stress > 0.35 or fatigue > 0.45:
            return "ANXIOUS"
        if context.get("high_alertness", False) or context.get("focus_score", 0) > 0.80:
            return "ALERT"
        return "CALM"
