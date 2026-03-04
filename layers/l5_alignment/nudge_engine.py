"""
AURORA Layer 5 — Behavioral Nudge Engine

Evidence-based nudges using behavioral economics principles:
- Kahneman/Tversky Prospect Theory (loss aversion)
- Cialdini's Influence (social proof, authority, scarcity)
- Thaler/Sunstein Nudge Theory (choice architecture)
- Fogg Behavior Model (motivation + ability + trigger)
"""
from __future__ import annotations
from typing import Dict, Any

_NUDGES = {
    "loss_aversion":  "⚠️ This action puts your organization at risk. 89% of similar incidents resulted in data loss.",
    "social_proof":   "Your peers in {role} roles almost never perform this action outside business hours.",
    "authority":      "Your CISO has flagged this action type as high-risk. Please verify with your manager.",
    "commitment":     "You completed security training 2 weeks ago — this action contradicts your training commitment.",
    "reciprocity":    "AURORA protects you every day. Help protect the organization by pausing on this action.",
    "friction":       "This action requires additional verification. Are you sure you want to proceed?",
    "default_safe":   "The safest option has been pre-selected for you. Override only if you're certain.",
}

_BEHAVIORAL_ECON_RESPONSES = {
    "risky_download":   {"nudge":"loss_aversion","message":_NUDGES["loss_aversion"],"action":"WARN"},
    "after_hours_admin":{"nudge":"social_proof","message":"Peers rarely perform admin actions after 9pm.","action":"CHALLENGE"},
    "wire_transfer":    {"nudge":"authority","message":_NUDGES["authority"],"action":"MULTI_APPROVE"},
    "bulk_share":       {"nudge":"friction","message":_NUDGES["friction"],"action":"SANDBOX"},
    "credential_reset": {"nudge":"commitment","message":_NUDGES["commitment"],"action":"VERIFY"},
}

class NudgeEngine:
    def generate_nudge(self, user_id: str, risk_score: float) -> Dict:
        if risk_score >= 80:
            return {"type":"CRITICAL_INTERVENTION","message":"AURORA has detected critical risk. A security review has been triggered. Your manager has been notified.","action":"ESCALATE"}
        elif risk_score >= 65:
            return {"type":"STRONG_NUDGE","message":_NUDGES["authority"],"action":"CHALLENGE"}
        elif risk_score >= 45:
            return {"type":"MODERATE_NUDGE","message":_NUDGES["social_proof"],"action":"WARN"}
        else:
            return {"type":"PASSIVE","message":"Continuing with standard monitoring.","action":"ALLOW"}

    def apply_behavioral_economics(self, user_id: str, action: str) -> Dict:
        resp = _BEHAVIORAL_ECON_RESPONSES.get(action)
        if resp: return resp
        return {"nudge":"default_safe","message":_NUDGES["default_safe"],"action":"ALLOW"}
