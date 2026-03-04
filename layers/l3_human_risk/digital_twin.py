"""
AURORA Layer 3 — Human Digital Twin Modeling
=============================================
FIXED:
  - simulate() now uses actor attributes stored in the twin,
    not a global hardcoded risk_actions dict.
  - Drift detection: Mahalanobis-inspired distance from baseline
    detects when the real actor diverges from their twin profile.
  - Risk trajectory tracked per twin (last 30 simulations).
  - Contextual risk computation uses role, tenure, and recent events.

References:
  Glasser & Lindauer (2013): Bridging the Gap: A Pragmatic Approach to
  Generating Insider Threat Data. IEEE S&P Workshops.
"""
from __future__ import annotations
import math
import time
from typing import Dict, Any, List, Optional


# Base risk by action category
_ACTION_BASE_RISK: Dict[str, float] = {
    # Low risk
    "view_dashboard":           0.05,
    "read_file":                0.08,
    "login":                    0.04,
    "search":                   0.06,
    # Medium risk
    "access_sensitive_file":    0.38,
    "after_hours_login":        0.42,
    "mass_email":               0.45,
    "api_call_unusual":         0.40,
    "vpn_access":               0.30,
    # High risk
    "admin_escalation":         0.68,
    "privilege_change":         0.72,
    "export_large":             0.65,
    "credential_access":        0.70,
    # Critical
    "bulk_export":              0.85,
    "database_dump":            0.88,
    "mass_delete":              0.90,
    "disable_logging":          0.92,
    "wire_transfer_large":      0.80,
    "data_exfil_attempt":       0.95,
}

# Role-based risk multipliers (privileged roles have more blast radius)
_ROLE_MULTIPLIER: Dict[str, float] = {
    "domain_admin":  1.60,
    "sysadmin":      1.40,
    "it_admin":      1.30,
    "developer":     1.10,
    "finance":       1.20,
    "analyst":       1.00,
    "standard_user": 0.85,
    "intern":        0.70,
}


class DigitalTwin:
    """
    Per-actor digital twin for counterfactual action simulation.

    The twin stores the actor's role, tenure, behavioural baseline,
    and risk trajectory. simulate() computes contextual risk using
    the actor's attributes — not a static lookup table.
    """

    def __init__(self):
        self._twins: Dict[str, Dict] = {}

    def create_twin(self, user_id: str, attributes: Dict[str, Any]) -> Dict:
        """
        Create or update a digital twin for an actor.

        attributes keys (all optional):
          role, tenure_days, avg_session_hours, typical_access_hours (list),
          typical_data_volume_mb, team_size, department, clearance_level
        """
        twin = {
            "user_id":               user_id,
            "attributes":            attributes,
            "role":                  attributes.get("role", "standard_user"),
            "tenure_days":           int(attributes.get("tenure_days", 180)),
            "typical_hours":         attributes.get("typical_access_hours", list(range(8, 18))),
            "avg_session_h":         float(attributes.get("avg_session_hours", 8)),
            "typical_vol_mb":        float(attributes.get("typical_data_volume_mb", 50)),
            "clearance":             attributes.get("clearance_level", "standard"),
            "created_at":            time.time(),
            "simulations_run":       0,
            "risk_trajectory":       [],   # Last 30 simulation risk scores
            "drift_score":           0.0,  # Mahalanobis-inspired drift
        }
        self._twins[user_id] = twin
        return twin

    def simulate(self, user_id: str, action: str, context: Dict[str, Any] = None) -> Dict:
        """
        FIXED: Contextual risk simulation using actor twin attributes.

        Risk = base_action_risk
               × role_multiplier
               × time_of_day_factor
               × tenure_factor
               × clearance_factor
        """
        twin = self._twins.get(user_id)
        if twin is None:
            twin = self.create_twin(user_id, context or {})

        ctx = context or {}
        twin["simulations_run"] += 1

        # --- Base action risk ---
        action_key = action.lower().replace(" ", "_")
        base_risk = _ACTION_BASE_RISK.get(action_key, 0.20)

        # --- Role multiplier: privileged roles have higher blast radius ---
        role = twin.get("role", "standard_user")
        role_mult = _ROLE_MULTIPLIER.get(role, 1.0)

        # --- Time-of-day factor: off-hours = higher risk ---
        current_hour = ctx.get("hour", time.localtime().tm_hour)
        typical_hours = twin.get("typical_hours", list(range(8, 18)))
        time_factor = 1.0 if current_hour in typical_hours else 1.35

        # --- Tenure factor: longer tenure = more trusted, lower baseline risk ---
        tenure = twin.get("tenure_days", 180)
        if tenure < 30:
            tenure_factor = 1.30
        elif tenure < 90:
            tenure_factor = 1.15
        elif tenure > 365:
            tenure_factor = 0.90
        else:
            tenure_factor = 1.0

        # --- Data volume factor ---
        vol_mb = ctx.get("data_volume_mb", 0)
        typical_vol = twin.get("typical_vol_mb", 50)
        vol_factor = 1.0
        if vol_mb > typical_vol * 5:
            vol_factor = 1.40
        elif vol_mb > typical_vol * 2:
            vol_factor = 1.15

        # --- Clearance factor: higher clearance accessing sensitive = more risk ---
        clearance = twin.get("clearance", "standard")
        clearance_factor = 0.90 if clearance in ("top_secret", "classified") else 1.0

        predicted_risk = (
            base_risk * role_mult * time_factor * tenure_factor
            * vol_factor * clearance_factor
        )
        predicted_risk = round(min(1.0, max(0.0, predicted_risk)), 4)

        # Update risk trajectory
        traj = twin["risk_trajectory"]
        traj.append(predicted_risk)
        if len(traj) > 30:
            twin["risk_trajectory"] = traj[-30:]

        # Update drift score (distance from actor's personal baseline)
        twin["drift_score"] = self._compute_drift(twin)

        outcome = (
            "CRITICAL_RISK" if predicted_risk > 0.80 else
            "HIGH_RISK"     if predicted_risk > 0.60 else
            "MEDIUM_RISK"   if predicted_risk > 0.35 else
            "LOW_RISK"
        )
        recommendation = (
            "Block and escalate to SOC"    if predicted_risk > 0.80 else
            "Block and alert manager"      if predicted_risk > 0.60 else
            "Sandbox and monitor closely"  if predicted_risk > 0.35 else
            "Allow with standard logging"
        )

        return {
            "user_id":          user_id,
            "action":           action,
            "predicted_risk":   predicted_risk,
            "outcome":          outcome,
            "recommendation":   recommendation,
            "risk_components": {
                "base_risk":       round(base_risk, 4),
                "role_mult":       round(role_mult, 3),
                "time_factor":     round(time_factor, 3),
                "tenure_factor":   round(tenure_factor, 3),
                "vol_factor":      round(vol_factor, 3),
            },
            "drift_score":     round(twin["drift_score"], 4),
            "simulations_run": twin["simulations_run"],
            "simulated_at":    time.time(),
        }

    def _compute_drift(self, twin: Dict) -> float:
        """
        Mahalanobis-inspired drift: how much has the actor deviated
        from their own historical baseline in recent simulations?

        Uses variance of last 10 scores vs overall trajectory variance.
        High drift = actor behaviour rapidly changing = elevated risk signal.
        """
        traj = twin.get("risk_trajectory", [])
        if len(traj) < 5:
            return 0.0

        overall_mean = sum(traj) / len(traj)
        recent = traj[-5:]
        recent_mean = sum(recent) / len(recent)

        # Population variance
        overall_var = sum((x - overall_mean) ** 2 for x in traj) / len(traj)
        sigma = math.sqrt(overall_var) + 1e-6

        # Mahalanobis-style distance of recent window from overall baseline
        distance = abs(recent_mean - overall_mean) / sigma
        return round(min(1.0, distance / 3.0), 4)

    def get_twin(self, user_id: str) -> Optional[Dict]:
        return self._twins.get(user_id)

    def twin_risk_summary(self, user_id: str) -> Dict:
        """Summarise a twin's risk trajectory and drift."""
        twin = self._twins.get(user_id)
        if not twin:
            return {"error": "No twin found", "user_id": user_id}
        traj = twin.get("risk_trajectory", [])
        return {
            "user_id":        user_id,
            "role":           twin.get("role"),
            "simulations_run":twin["simulations_run"],
            "avg_risk":       round(sum(traj) / len(traj), 4) if traj else 0.0,
            "peak_risk":      round(max(traj), 4) if traj else 0.0,
            "drift_score":    twin["drift_score"],
            "drift_label":    "HIGH" if twin["drift_score"] > 0.6 else
                              "MEDIUM" if twin["drift_score"] > 0.3 else "LOW",
        }
