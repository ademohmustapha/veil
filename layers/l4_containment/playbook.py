"""AURORA Layer 4 — Structured Incident Response Playbooks"""
from __future__ import annotations
import time
from typing import Dict, Any, Optional

_PLAYBOOKS = {
    "ransomware": {"name":"Ransomware Response","severity":"CRITICAL","steps":["isolate_affected_systems","disable_network_shares","notify_ciso","engage_ir_team","preserve_evidence","restore_from_backup","root_cause_analysis"],"sla_minutes":15},
    "phishing":   {"name":"Phishing Campaign Response","severity":"HIGH","steps":["block_sender_domain","quarantine_emails","identify_clicked_users","reset_credentials","enhanced_monitoring","user_awareness_notification"],"sla_minutes":30},
    "insider_threat":{"name":"Insider Threat Containment","severity":"HIGH","steps":["freeze_user_session","preserve_audit_logs","notify_hr_legal","restrict_data_access","forensic_capture","investigation_protocol"],"sla_minutes":10},
    "data_exfil": {"name":"Data Exfiltration Response","severity":"CRITICAL","steps":["terminate_session","block_egress_ip","identify_exfiltrated_data","regulatory_notification","forensic_investigation","remediation_plan"],"sla_minutes":20},
    "apt":        {"name":"Advanced Persistent Threat","severity":"CRITICAL","steps":["isolate_segment","threat_hunt_initiation","ioc_extraction","threat_intel_share","full_environment_audit","zero_trust_reset"],"sla_minutes":60},
}

class PlaybookEngine:
    def select_playbook(self, incident_type: str) -> Optional[Dict]:
        return _PLAYBOOKS.get(incident_type)

    def execute(self, incident_type: str, context: Dict = {}) -> Dict:
        pb = self.select_playbook(incident_type) or {"name":"Generic Response","severity":"MEDIUM","steps":["investigate","contain","remediate","recover"],"sla_minutes":60}
        return {"playbook":pb["name"],"severity":pb["severity"],"steps_total":len(pb["steps"]),"steps":pb["steps"],"sla_minutes":pb["sla_minutes"],"context":context,"executed_at":time.time(),"status":"EXECUTING"}
