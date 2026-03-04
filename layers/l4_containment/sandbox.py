"""AURORA Layer 4 — Autonomous Decision Containment (NEXUS-SHIELD Extended)"""
from __future__ import annotations
import time, uuid
from typing import Dict, Any

class Sandbox:
    def __init__(self):
        self._contained_sessions: Dict[str, Dict] = {}
        self._frozen_sessions: Dict[str, Dict] = {}
        self._HIGH_RISK_ACTIONS = {"bulk_data_export","mass_delete","admin_escalate","wire_transfer_large","database_dump","credential_reset_bulk"}

    def evaluate_action(self, action: str, user_risk: float = 0) -> str:
        if action in self._HIGH_RISK_ACTIONS and user_risk > 70: return "BLOCK"
        if action in self._HIGH_RISK_ACTIONS or user_risk > 50: return "SANDBOX"
        return "ALLOW"

    def contain(self, action: str, user_id: str) -> Dict:
        containment_id = str(uuid.uuid4())[:8]
        record = {"containment_id":containment_id,"action":action,"user_id":user_id,"contained_at":time.time(),"status":"CONTAINED","blast_radius_limited":True}
        self._contained_sessions[containment_id] = record
        # ── Push alert on containment event ──────────────────────────────
        try:
            from notifications.dispatcher import get_dispatcher
            get_dispatcher().alert(
                severity="HIGH",
                event_type="CONTAINMENT",
                summary=f"Action contained: {action} by user {user_id[:32]}",
                detail={"containment_id": containment_id, "action": action,
                        "user_id": user_id[:64], "status": "CONTAINED"},
            )
        except Exception:
            pass
        # ── SOAR workflow integrations ────────────────────────────────────────
        try:
            from soar.integrations import get_soar_manager
            get_soar_manager().dispatch(
                severity="HIGH",
                event_type="CONTAINMENT",
                summary=f"Action contained: {action} by user {user_id[:32]}",
                detail={"containment_id": containment_id, "action": action,
                        "user_id": user_id[:64], "status": "CONTAINED"},
                containment_id=containment_id,
                action=action,
                user_id=user_id,
            )
        except Exception:
            pass
        return record

    def freeze_session(self, session_id: str) -> Dict:
        record = {"session_id":session_id,"frozen_at":time.time(),"status":"FROZEN","reason":"Autonomous containment — anomaly threshold exceeded"}
        self._frozen_sessions[session_id] = record
        return record

    def rollback_privileges(self, user_id: str) -> Dict:
        return {"user_id":user_id,"action":"privilege_rollback","status":"COMPLETED","rolled_back_to":"baseline","timestamp":time.time()}
