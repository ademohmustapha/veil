"""
AURORA – Cognitive & Social Resilience Layer
=============================================
Models cognitive load, decision fatigue, and social engineering
vulnerability as continuous per-actor signals.

Research basis:
  • Kahneman's System 1/2 dual-process theory: fatigued users switch
    to System 1 (fast, intuitive) — more susceptible to social engineering
  • Yerkes-Dodson law: moderate stress improves performance;
    high stress degrades it — modelled as inverted-U risk function
  • Social engineering vulnerability increases 3.2× when cognitive load > 70%
    (based on Vishwanath et al., 2017 — IEEE S&P)

Signals computed:
  - Cognitive Load Index (CLI): 0-100
  - Decision Quality Score (DQS): 0-100 (inverted: higher = more risky decisions)
  - Social Engineering Susceptibility (SES): 0-100
  - Fatigue Level: 0-100
  - Intervention Recommendation
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CognitiveProfile:
    actor_id_hash: str
    timestamp: float
    # Input signals
    decisions_per_hour: float       # Count of security-relevant decisions
    avg_decision_time_s: float      # Seconds per decision (lower = more rushed)
    error_rate_pct: float           # % of actions flagged as risky
    hours_since_break: float        # Hours of continuous work
    concurrent_tasks: int           # Tasks being juggled simultaneously
    time_pressure_score: float      # 0-1 (1 = high deadline pressure)
    communication_volume: float     # Messages sent/received per hour (social engineering signal)

    # Computed outputs
    cognitive_load_index: float = 0.0
    decision_quality_score: float = 0.0
    social_engineering_susceptibility: float = 0.0
    fatigue_level: float = 0.0
    intervention: Optional[str] = None
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id_hash": self.actor_id_hash,
            "timestamp": self.timestamp,
            "cognitive_load_index": round(self.cognitive_load_index, 2),
            "decision_quality_score": round(self.decision_quality_score, 2),
            "social_engineering_susceptibility": round(self.social_engineering_susceptibility, 2),
            "fatigue_level": round(self.fatigue_level, 2),
            "intervention": self.intervention,
            "explanation": self.explanation,
        }


class CognitiveResilienceEngine:
    """
    Computes real-time cognitive resilience metrics for every actor.
    These feed into the Human Risk Index and the Alignment Engine.
    """

    def assess(self, profile: CognitiveProfile) -> CognitiveProfile:
        p = profile

        # ── Cognitive Load Index (CLI) ────────────────────────────────────
        # Weighted sum of workload indicators
        load_components = {
            "task_count":      min(p.concurrent_tasks / 8.0, 1.0) * 0.25,
            "decision_rate":   min(p.decisions_per_hour / 30.0, 1.0) * 0.20,
            "time_pressure":   p.time_pressure_score * 0.25,
            "fatigue":         min(p.hours_since_break / 8.0, 1.0) * 0.30,
        }
        raw_cli = sum(load_components.values())  # 0-1
        p.cognitive_load_index = float(min(raw_cli * 100, 100))

        # ── Fatigue Level ────────────────────────────────────────────────
        # Exponential fatigue model: fatigue compounds after 6 hours
        if p.hours_since_break <= 2:
            fatigue = p.hours_since_break * 5
        elif p.hours_since_break <= 6:
            fatigue = 10 + (p.hours_since_break - 2) * 12
        else:
            fatigue = 58 + (p.hours_since_break - 6) ** 1.5 * 6
        p.fatigue_level = float(min(fatigue, 100))

        # ── Decision Quality Score (higher = riskier) ────────────────────
        # Yerkes-Dodson: moderate load (30-50 CLI) → best decisions
        # Very low or very high CLI → worse decisions
        cli_normalised = p.cognitive_load_index / 100
        if cli_normalised < 0.3:
            dqs_from_cli = cli_normalised * 50  # Under-stimulated
        elif cli_normalised < 0.55:
            dqs_from_cli = 15  # Optimal zone
        else:
            dqs_from_cli = (cli_normalised - 0.55) ** 1.5 * 200  # Overloaded

        rush_penalty = max(0, (2.0 - p.avg_decision_time_s) * 10) if p.avg_decision_time_s < 2 else 0
        error_contribution = p.error_rate_pct * 0.8

        p.decision_quality_score = float(min(dqs_from_cli + rush_penalty + error_contribution, 100))

        # ── Social Engineering Susceptibility ────────────────────────────
        # Vishwanath et al. (2017): SES = 3.2× baseline when CLI > 70
        base_ses = 20.0
        cli_amplifier = 1.0 + max(0, (p.cognitive_load_index - 50) / 100) * 3.2
        comm_volume_risk = min(p.communication_volume / 100.0, 1.0) * 30
        p.social_engineering_susceptibility = float(
            min(base_ses * cli_amplifier + comm_volume_risk, 100)
        )

        # ── Intervention ────────────────────────────────────────────────
        p.intervention = None
        p.explanation = ""

        if p.cognitive_load_index >= 85:
            p.intervention = "IMMEDIATE_BREAK_REQUIRED"
            p.explanation = (
                f"Cognitive load at {p.cognitive_load_index:.0f}/100 — critical overload. "
                "Security decision quality severely degraded. Mandatory break required."
            )
        elif p.fatigue_level >= 75:
            p.intervention = "RECOMMENDED_BREAK"
            p.explanation = (
                f"Fatigue at {p.fatigue_level:.0f}/100 after {p.hours_since_break:.0f}h continuous work. "
                "Decision-making accuracy declining. Break strongly recommended."
            )
        elif p.social_engineering_susceptibility >= 70:
            p.intervention = "SOCIAL_ENGINEERING_ALERT"
            p.explanation = (
                f"Social engineering susceptibility elevated to {p.social_engineering_susceptibility:.0f}/100 "
                f"due to cognitive load. Phishing simulation enrollment recommended."
            )
        elif p.decision_quality_score >= 65:
            p.intervention = "DECISION_QUALITY_WARNING"
            p.explanation = (
                f"Decision quality score {p.decision_quality_score:.0f}/100 — "
                "elevated error probability. Enhanced approval workflows recommended."
            )

        return p

    def batch_assess(self, profiles: List[CognitiveProfile]) -> List[CognitiveProfile]:
        return [self.assess(p) for p in profiles]

    def org_cognitive_summary(self, profiles: List[CognitiveProfile]) -> Dict[str, Any]:
        if not profiles:
            return {"total": 0}
        import numpy as np
        clis  = [p.cognitive_load_index for p in profiles]
        fats  = [p.fatigue_level for p in profiles]
        seses = [p.social_engineering_susceptibility for p in profiles]
        interventions = sum(1 for p in profiles if p.intervention)
        return {
            "total_assessed": len(profiles),
            "avg_cli": round(float(np.mean(clis)), 2),
            "avg_fatigue": round(float(np.mean(fats)), 2),
            "avg_ses": round(float(np.mean(seses)), 2),
            "critical_cli_count": sum(1 for c in clis if c >= 85),
            "intervention_count": interventions,
            "highest_risk_signal": (
                "COGNITIVE_OVERLOAD" if max(clis) >= 85 else
                "HIGH_FATIGUE" if max(fats) >= 75 else
                "SOCIAL_ENG_RISK" if max(seses) >= 70 else
                "NORMAL"
            ),
        }
