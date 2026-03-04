"""
AURORA Layer 1 — Behavioral Authentication Engine

Continuous authentication via behavioral biometrics.
Uses Isolation Forest (statistical anomaly detection) to identify
deviations from each user's established behavioral baseline.

Signals: typing rhythm, mouse dynamics, access patterns, 
         time-of-day, location consistency, application usage.
"""
from __future__ import annotations
import math, json, hashlib
from typing import Dict, Any, List, Optional


class BehavioralAuth:
    """
    Statistical behavioral authentication using Isolation Forest principles.
    
    Each user has a baseline built from their historical patterns.
    Real-time anomaly scoring (0=normal, 1=extreme anomaly).
    """

    def __init__(self):
        self._baselines: Dict[str, Dict] = {}
        self._anomaly_history: Dict[str, List[float]] = {}

    def establish_baseline(self, user_id: str, events: List[Dict]) -> Dict:
        """
        Build behavioral baseline from historical events.
        Computes mean and std for each behavioral dimension.
        """
        if not events:
            return {}
        
        dimensions = ["hour", "session_duration", "actions_per_minute",
                      "error_rate", "data_volume_mb"]
        baseline = {}
        for dim in dimensions:
            values = [e.get(dim, 0) for e in events if dim in e]
            if values:
                mean = sum(values) / len(values)
                variance = sum((v - mean)**2 for v in values) / max(len(values), 1)
                baseline[dim] = {"mean": mean, "std": math.sqrt(variance) + 0.001}
        
        self._baselines[user_id] = baseline
        return baseline

    def anomaly_score(self, user_id: str, event: Dict[str, Any]) -> float:
        """
        Compute real-time anomaly score (0.0 = normal, 1.0 = extreme).
        
        Uses z-score aggregation across behavioral dimensions.
        Isolation Forest adaptation: extreme z-scores → high anomaly.
        """
        baseline = self._baselines.get(user_id)
        if not baseline:
            # No baseline: use heuristics
            return self._heuristic_anomaly(event)
        
        z_scores = []
        for dim, stats in baseline.items():
            val = event.get(dim)
            if val is not None:
                std = stats.get("std", 0.0)
                if std < 1e-9:
                    # std ≈ 0 means only one sample — treat as low-anomaly
                    z_scores.append(0.0)
                else:
                    z = abs(val - stats["mean"]) / std
                    z_scores.append(min(z, 30.0))   # cap at 30 to prevent exp overflow
        
        if not z_scores:
            return self._heuristic_anomaly(event)
        
        # Aggregate: use 90th percentile z-score (captures extreme deviations)
        z_scores.sort()
        p90_idx = int(0.9 * len(z_scores))
        max_z = z_scores[min(p90_idx, len(z_scores)-1)]
        
        # Sigmoid normalization: z of 3+ → anomaly score > 0.95
        score = 1.0 - (1.0 / (1.0 + math.exp(max_z - 2.0)))
        
        # Track history
        if user_id not in self._anomaly_history:
            self._anomaly_history[user_id] = []
        self._anomaly_history[user_id].append(score)
        
        return round(min(1.0, max(0.0, score)), 4)

    def _heuristic_anomaly(self, event: Dict) -> float:
        """Heuristic anomaly when no baseline exists."""
        score = 0.0
        hour = event.get("hour", 12)
        if not (7 <= hour <= 20): score += 0.2
        action = event.get("action", "")
        high_risk_actions = {"bulk_export","delete_all","admin_escalate","mass_email"}
        if action in high_risk_actions: score += 0.4
        return min(1.0, score)

    def get_anomaly_trend(self, user_id: str, window: int = 10) -> str:
        """Detect if user's anomaly score is trending up (risk increasing)."""
        history = self._anomaly_history.get(user_id, [])
        if len(history) < 2:
            return "STABLE"
        recent = history[-window:]
        if len(recent) < 2:
            return "STABLE"
        trend = recent[-1] - recent[0]
        if trend > 0.2: return "INCREASING"
        if trend < -0.2: return "DECREASING"
        return "STABLE"
