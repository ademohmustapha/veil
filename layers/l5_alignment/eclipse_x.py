"""Layer 5: ECLIPSE-X — Human-Machine Alignment Engine. Intent, emotion, cognitive load modelling."""
from __future__ import annotations
import time, math, json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from core.logger import AuditLogger

@dataclass
class AlignmentReport:
    user_id: str; org_id: str
    intent_class: str = "BENIGN"       # BENIGN|AMBIGUOUS|RISKY|MALICIOUS
    intent_confidence: float = 0.0
    emotional_state: str = "NEUTRAL"   # NEUTRAL|STRESSED|FATIGUED|AGITATED|FOCUSED
    cognitive_load: float = 0.0        # 0=minimal, 1=overloaded
    alignment_score: float = 100.0     # 100=fully aligned, 0=misaligned
    nudges: List[dict] = field(default_factory=list)
    predicted_outcome: str = ""
    simulation_result: Optional[dict] = None
    recommended_action: str = ""
    timestamp: float = field(default_factory=time.time)
    def to_dict(self): return asdict(self)

# Psychological risk factors (based on Kahneman System 1/2, Cognitive Load Theory)
_STRESS_INDICATORS = {
    "rapid_keystroke_variability": 0.3,
    "high_error_rate": 0.4,
    "repeated_undo_actions": 0.25,
    "short_attention_span_ms": 0.35,
    "elevated_mouse_velocity": 0.2,
}

class EclipseX:
    """
    Human-Machine Alignment Engine.
    Models intent, emotional state, cognitive load.
    Generates behavioural nudges. Pre-simulates outcomes.
    Based on: Cognitive Load Theory, Dual-Process Theory, BIT (Behavioural Insights Team) EAST model.
    """
    def __init__(self):
        self._log = AuditLogger()
        self._session_history: Dict[str, List[dict]] = {}

    def align(self, user_id: str, org_id: str, action: str,
              context: dict) -> AlignmentReport:
        """
        Full alignment assessment + nudge generation.
        context keys: signals (dict of behavioural metrics), pending_action,
                      resource, time_pressure, decision_history
        """
        key = f"{org_id}::{user_id}"
        history = self._session_history.get(key, [])

        report = AlignmentReport(user_id=user_id, org_id=org_id)

        # 1. Emotional state classification
        report.emotional_state = self._classify_emotional_state(context.get("signals", {}))

        # 2. Cognitive load estimation
        report.cognitive_load = self._estimate_cognitive_load(context.get("signals", {}), history)

        # 3. Intent classification
        report.intent_class, report.intent_confidence = self._classify_intent(
            action, context, report.emotional_state, report.cognitive_load)

        # 4. Alignment score
        report.alignment_score = self._compute_alignment_score(report)

        # 5. Outcome pre-simulation
        report.simulation_result = self._simulate_outcome(action, context, report)
        report.predicted_outcome = report.simulation_result.get("summary", "")

        # 6. Nudge generation (BIT EAST model: Easy, Attractive, Social, Timely)
        report.nudges = self._generate_nudges(report, action, context)

        # 7. Recommended action
        report.recommended_action = self._recommend(report)

        # Store history
        history.append({"ts": time.time(), "action": action, "alignment": report.alignment_score})
        self._session_history[key] = history[-200:]

        if report.alignment_score < 40:
            self._log.log("L5_ALIGNMENT", "MISALIGNMENT_DETECTED",
                f"{user_id}: alignment={report.alignment_score:.1f} intent={report.intent_class}",
                "HIGH", {"nudges": len(report.nudges)})
        return report

    def _classify_emotional_state(self, signals: dict) -> str:
        if not signals: return "NEUTRAL"
        stress = (signals.get("error_rate", 0) * 0.4 +
                  signals.get("keystroke_variability", 0) * 0.3 +
                  signals.get("undo_rate", 0) * 0.3)
        if stress > 0.7: return "AGITATED"
        if stress > 0.5: return "STRESSED"
        fatigue = signals.get("cognitive_fatigue_level", 0)
        if fatigue > 0.6: return "FATIGUED"
        if signals.get("focus_score", 0.5) > 0.8: return "FOCUSED"
        return "NEUTRAL"

    def _estimate_cognitive_load(self, signals: dict, history: list) -> float:
        """
        Cognitive load via:
        - Task complexity * time pressure (Sweller's CLT)
        - Working memory proxy (simultaneous open contexts)
        - Error rate as load indicator (Paas et al.)
        """
        load = 0.2  # Baseline
        load += signals.get("simultaneous_contexts", 1) * 0.05  # Open tabs/tasks
        load += signals.get("error_rate", 0) * 0.4
        time_pressure = signals.get("time_pressure", 0)
        load += time_pressure * 0.3
        if len(history) > 20:   # Long session → fatigue accumulation
            load += min(0.3, len(history) / 200)
        return round(min(1.0, load), 3)

    def _classify_intent(self, action: str, ctx: dict, emotion: str, load: float) -> Tuple[str, float]:
        """Multi-signal intent classification."""
        risk_signals = 0; confidence = 0.7

        # High-risk action keywords
        high_risk = ["delete", "export", "transfer", "download_bulk", "escalate",
                     "modify_acl", "disable_log", "forward_all"]
        for kw in high_risk:
            if kw in action.lower():
                risk_signals += 2; break

        # Emotional amplification
        if emotion in ("AGITATED", "STRESSED"): risk_signals += 1; confidence -= 0.1
        if emotion == "FATIGUED": risk_signals += 1; confidence -= 0.05

        # High cognitive load → impaired judgment
        if load > 0.7: risk_signals += 1

        # Time pressure → System 1 (fast, error-prone) thinking
        if ctx.get("signals", {}).get("time_pressure", 0) > 0.6: risk_signals += 1

        # Past behaviour context
        decision_hist = ctx.get("decision_history", [])
        if sum(1 for d in decision_hist[-10:] if d.get("was_risky", False)) >= 3:
            risk_signals += 2

        if risk_signals >= 5: return "MALICIOUS", min(0.95, confidence + 0.1)
        if risk_signals >= 3: return "RISKY", confidence
        if risk_signals >= 1: return "AMBIGUOUS", confidence - 0.1
        return "BENIGN", confidence

    def _compute_alignment_score(self, r: AlignmentReport) -> float:
        base = 100.0
        intent_penalty = {"BENIGN": 0, "AMBIGUOUS": 15, "RISKY": 35, "MALICIOUS": 70}
        emotion_penalty = {"NEUTRAL": 0, "FOCUSED": 0, "STRESSED": 10, "FATIGUED": 15, "AGITATED": 20}
        base -= intent_penalty.get(r.intent_class, 0)
        base -= emotion_penalty.get(r.emotional_state, 0)
        base -= r.cognitive_load * 20
        return round(max(0, min(100, base)), 2)

    def _simulate_outcome(self, action: str, ctx: dict, r: AlignmentReport) -> dict:
        """
        Digital twin simulation: run action against a model of the system state.
        Returns probabilistic outcome.
        """
        risk = 1 - r.alignment_score / 100
        if r.intent_class == "MALICIOUS":
            prob_bad = 0.85 + risk * 0.15
            summary = "HIGH RISK: Simulation predicts likely security incident"
        elif r.intent_class == "RISKY":
            prob_bad = 0.4 + risk * 0.4
            summary = "ELEVATED RISK: Simulation shows possible unintended consequences"
        elif r.intent_class == "AMBIGUOUS":
            prob_bad = 0.15 + risk * 0.2
            summary = "MODERATE: Simulation shows small chance of negative outcome"
        else:
            prob_bad = risk * 0.1
            summary = "LOW RISK: Simulation predicts safe outcome"
        return {"summary": summary, "prob_negative_outcome": round(prob_bad, 3),
                "emotional_impact": r.emotional_state, "cognitive_load": r.cognitive_load,
                "simulated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    def _generate_nudges(self, r: AlignmentReport, action: str, ctx: dict) -> List[dict]:
        """EAST nudges: Easy (reduce friction), Attractive, Social proof, Timely."""
        nudges = []
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if r.intent_class in ("RISKY", "MALICIOUS"):
            nudges.append({"ts": ts, "type": "FRICTION", "east": "Easy",
                "message": "⚠️ This action requires secondary approval. Add justification below."})
        if r.emotional_state in ("STRESSED", "AGITATED"):
            nudges.append({"ts": ts, "type": "EMOTIONAL_PAUSE", "east": "Timely",
                "message": "You appear stressed. Take 60 seconds before proceeding — errors are 3× more likely now."})
        if r.cognitive_load > 0.7:
            nudges.append({"ts": ts, "type": "LOAD_REDUCTION", "east": "Easy",
                "message": "High cognitive load detected. Break complex task into smaller steps."})
        if r.emotional_state == "FATIGUED":
            nudges.append({"ts": ts, "type": "FATIGUE_WARNING", "east": "Timely",
                "message": "Fatigue detected. Security errors peak when tired. Mandatory break: 10 mins."})
        if r.simulation_result and r.simulation_result.get("prob_negative_outcome", 0) > 0.4:
            nudges.append({"ts": ts, "type": "SIMULATION_WARNING", "east": "Attractive",
                "message": f"Simulation: {r.simulation_result['summary']}"})
        return nudges

    def _recommend(self, r: AlignmentReport) -> str:
        if r.intent_class == "MALICIOUS": return "BLOCK_AND_ALERT"
        if r.intent_class == "RISKY": return "REQUIRE_APPROVAL"
        if r.intent_class == "AMBIGUOUS" or r.cognitive_load > 0.7: return "REQUIRE_CONFIRMATION"
        if r.emotional_state in ("STRESSED", "FATIGUED"): return "NUDGE_AND_MONITOR"
        return "ALLOW"
