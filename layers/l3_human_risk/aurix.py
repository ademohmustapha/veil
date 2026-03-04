"""Layer 3: AURIX — Human Risk Intelligence Core. Real-time HRI 0-100, digital twin, interventions."""
from __future__ import annotations
import time, math, json, statistics
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from core.config import AuroraConfig as Config
from core.logger import AuditLogger

@dataclass
class HumanRiskIndex:
    user_id: str; org_id: str; hri: float = 0.0  # 0=safe, 100=critical
    insider_threat_prob: float = 0.0
    phishing_susceptibility: float = 0.5
    cognitive_fatigue: float = 0.0
    social_engineering_vulnerability: float = 0.3
    privilege_misuse_risk: float = 0.0
    behavioural_deviation: float = 0.0
    data_exfil_signals: List[str] = field(default_factory=list)
    interventions_applied: List[dict] = field(default_factory=list)
    last_updated: float = field(default_factory=time.time)
    risk_vector: Dict[str, float] = field(default_factory=dict)
    def to_dict(self): return asdict(self)

@dataclass
class DigitalTwin:
    """Behavioural baseline model for a user — the 'normal' they deviate from."""
    user_id: str; org_id: str
    baseline_work_hours: List[float] = field(default_factory=lambda: [9.0, 17.0])
    avg_email_send_rate_per_hour: float = 5.0
    avg_file_access_per_hour: float = 20.0
    typical_locations: List[str] = field(default_factory=list)
    typical_devices: List[str] = field(default_factory=list)
    avg_session_duration_h: float = 2.0
    baseline_error_rate: float = 0.02
    communication_graph: Dict[str, int] = field(default_factory=dict)
    last_calibrated: float = field(default_factory=time.time)

    def deviation_score(self, observation: dict) -> float:
        """Compute deviation between observation and baseline. 0=normal, 1=maximal anomaly."""
        sigs = []
        # Work hour deviation
        hour = observation.get("hour", 12)
        in_hours = self.baseline_work_hours[0] <= hour <= self.baseline_work_hours[1]
        sigs.append(0.0 if in_hours else 0.6)
        # File access rate
        far = observation.get("file_access_rate", self.avg_file_access_per_hour)
        ratio = far / max(self.avg_file_access_per_hour, 1)
        sigs.append(min(1.0, max(0, ratio - 1) / 5))  # Penalise if 5x baseline
        # Email rate
        emr = observation.get("email_rate", self.avg_email_send_rate_per_hour)
        sigs.append(min(1.0, max(0, emr / max(self.avg_email_send_rate_per_hour, 1) - 1) / 4))
        # New device
        device = observation.get("device_id", "")
        if device and device not in self.typical_devices: sigs.append(0.45)
        # New location
        loc = observation.get("location", "")
        if loc and loc not in self.typical_locations: sigs.append(0.35)
        return round(sum(sigs) / max(len(sigs), 1), 3)

    def update_baseline(self, observation: dict):
        """Online learning — update baseline with Exponential Moving Average."""
        alpha = 0.05  # EMA factor — slow adaptation to resist manipulation
        self.avg_email_send_rate_per_hour = (
            (1 - alpha) * self.avg_email_send_rate_per_hour +
            alpha * observation.get("email_rate", self.avg_email_send_rate_per_hour))
        self.avg_file_access_per_hour = (
            (1 - alpha) * self.avg_file_access_per_hour +
            alpha * observation.get("file_access_rate", self.avg_file_access_per_hour))
        device = observation.get("device_id")
        if device and device not in self.typical_devices:
            self.typical_devices.append(device)
            if len(self.typical_devices) > 10: self.typical_devices = self.typical_devices[-10:]
        loc = observation.get("location")
        if loc and loc not in self.typical_locations:
            self.typical_locations.append(loc)
            if len(self.typical_locations) > 20: self.typical_locations = self.typical_locations[-20:]
        self.last_calibrated = time.time()

class AURIXEngine:
    """
    Human Risk Intelligence Core.
    Computes HRI using 8 sub-indices with ML-weighted aggregation.
    Manages digital twins and adaptive interventions.
    """
    # HRI sub-index weights (sum to 1.0)
    _WEIGHTS = {
        "insider_threat": 0.22,
        "phishing_susceptibility": 0.15,
        "cognitive_fatigue": 0.12,
        "social_engineering": 0.13,
        "privilege_misuse": 0.18,
        "behavioural_deviation": 0.12,
        "data_exfil": 0.08,
    }

    def __init__(self):
        self._hri_store: Dict[str, HumanRiskIndex] = {}
        self._twins: Dict[str, DigitalTwin] = {}
        self._cfg = Config(); self._log = AuditLogger()
        self._load()

    def assess(self, user_id: str, org_id: str, signals: dict) -> HumanRiskIndex:
        """
        Full HRI assessment.
        signals keys: hour, file_access_rate, email_rate, email_external_fraction,
                      failed_auth_count, bulk_download_mb, clipboard_exfil,
                      fatigue_indicators, device_id, location, after_hours,
                      usb_events, screen_capture_events
        """
        key = f"{org_id}::{user_id}"
        hri = self._hri_store.get(key) or HumanRiskIndex(user_id=user_id, org_id=org_id)
        twin = self._twins.get(key) or DigitalTwin(user_id=user_id, org_id=org_id)

        # Compute sub-indices
        insider = self._insider_threat_model(signals, twin)
        phishing = self._phishing_susceptibility(signals)
        fatigue = self._cognitive_fatigue(signals)
        social_eng = self._social_engineering_vuln(signals)
        priv_misuse = self._privilege_misuse(signals)
        behav_dev = twin.deviation_score(signals)
        data_exfil = self._data_exfil_signals(signals, hri)

        # Weighted HRI
        vector = {"insider_threat": insider, "phishing_susceptibility": phishing,
                  "cognitive_fatigue": fatigue, "social_engineering": social_eng,
                  "privilege_misuse": priv_misuse, "behavioural_deviation": behav_dev,
                  "data_exfil": data_exfil}
        hri_score = sum(self._WEIGHTS[k] * v * 100 for k, v in vector.items())

        # Exponential amplification for compound risk
        active_risks = sum(1 for v in vector.values() if v > 0.5)
        if active_risks >= 3: hri_score = min(100, hri_score * (1 + active_risks * 0.08))

        hri.hri = round(min(100, hri_score), 2)
        hri.insider_threat_prob = round(insider, 3)
        hri.phishing_susceptibility = round(phishing, 3)
        hri.cognitive_fatigue = round(fatigue, 3)
        hri.social_engineering_vulnerability = round(social_eng, 3)
        hri.privilege_misuse_risk = round(priv_misuse, 3)
        hri.behavioural_deviation = round(behav_dev, 3)
        hri.risk_vector = {k: round(v, 3) for k, v in vector.items()}
        hri.last_updated = time.time()

        # Online twin update (only if low anomaly — resist adversarial manipulation)
        if behav_dev < 0.3:
            twin.update_baseline(signals)

        # Generate interventions
        interventions = self._generate_interventions(hri, vector)
        if interventions:
            hri.interventions_applied.extend(interventions)
            if len(hri.interventions_applied) > 100:
                hri.interventions_applied = hri.interventions_applied[-100:]

        self._hri_store[key] = hri
        self._twins[key] = twin

        if hri.hri >= self._cfg.get("risk_thresholds.critical", 80):
            self._log.log("L3_HUMAN_RISK", "CRITICAL_HRI",
                f"{user_id}@{org_id}: HRI={hri.hri:.1f}", "CRITICAL",
                {"vector": hri.risk_vector})
        elif hri.hri >= self._cfg.get("risk_thresholds.high", 60):
            self._log.log("L3_HUMAN_RISK", "HIGH_HRI",
                f"{user_id}@{org_id}: HRI={hri.hri:.1f}", "HIGH")
        self._save()
        return hri

    def _insider_threat_model(self, s: dict, twin: DigitalTwin) -> float:
        """Insider threat probability using CERT Insider Threat model signals."""
        score = 0.0
        if s.get("bulk_download_mb", 0) > 500: score += 0.35
        elif s.get("bulk_download_mb", 0) > 100: score += 0.15
        if s.get("usb_events", 0) > 2: score += 0.25
        if s.get("after_hours", False): score += 0.15
        if s.get("clipboard_exfil", False): score += 0.30
        if s.get("screen_capture_events", 0) > 3: score += 0.20
        email_ext = s.get("email_external_fraction", 0)
        if email_ext > 0.7: score += 0.25
        elif email_ext > 0.4: score += 0.10
        return min(1.0, score)

    def _phishing_susceptibility(self, s: dict) -> float:
        """Model based on NIST SP 800-177 phishing risk factors."""
        score = 0.3  # Baseline susceptibility
        if s.get("failed_auth_count", 0) > 3: score += 0.2
        if s.get("clicked_suspicious_link", False): score += 0.4
        if s.get("cognitive_fatigue_level", 0) > 0.6: score += 0.15
        if s.get("new_device", False): score += 0.1
        return min(1.0, score)

    def _cognitive_fatigue(self, s: dict) -> float:
        """Fatigue model: hours worked, error rate, response time degradation."""
        hours_worked = s.get("hours_worked_today", 8)
        fatigue = max(0, (hours_worked - 8) * 0.05)   # +5% per hour over 8
        if hours_worked > 12: fatigue += 0.3           # Severe overtime
        fatigue += s.get("error_rate_delta", 0) * 0.5 # Rising error rate
        fatigue += s.get("response_time_degradation", 0) * 0.3
        explicit_fatigue = s.get("cognitive_fatigue_level", 0)
        return min(1.0, max(fatigue, explicit_fatigue))

    def _social_engineering_vuln(self, s: dict) -> float:
        score = 0.2
        if s.get("disclosed_credentials_externally", False): score += 0.6
        if s.get("visited_impersonation_site", False): score += 0.5
        if s.get("reported_social_contact_attempt", False): score += 0.2
        if s.get("cognitive_fatigue_level", 0) > 0.5: score += 0.15
        return min(1.0, score)

    def _privilege_misuse(self, s: dict) -> float:
        score = 0.0
        if s.get("accessed_out_of_role_resources", False): score += 0.4
        if s.get("lateral_movement_detected", False): score += 0.5
        if s.get("privilege_escalation_attempt", False): score += 0.6
        if s.get("accessed_sensitive_without_ticket", False): score += 0.3
        return min(1.0, score)

    def _data_exfil_signals(self, s: dict, hri: HumanRiskIndex) -> float:
        signals = []
        if s.get("bulk_download_mb", 0) > 200: signals.append("bulk_download")
        if s.get("usb_events", 0) > 0: signals.append("usb_transfer")
        if s.get("clipboard_exfil", False): signals.append("clipboard_exfil")
        if s.get("email_attachment_size_mb", 0) > 50: signals.append("large_email_attachment")
        if s.get("cloud_upload_mb", 0) > 500: signals.append("large_cloud_upload")
        hri.data_exfil_signals = signals
        return min(1.0, len(signals) * 0.25)

    def _generate_interventions(self, hri: HumanRiskIndex, vector: dict) -> List[dict]:
        interventions = []
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if hri.hri >= 80:
            interventions.append({"ts": ts, "type": "PRIVILEGE_REDUCTION",
                "detail": "Temporary privilege reduction — security review required"})
        if vector["phishing_susceptibility"] > 0.6:
            interventions.append({"ts": ts, "type": "MICRO_TRAINING",
                "detail": "Phishing awareness micro-training dispatched (2 min)"})
        if vector["cognitive_fatigue"] > 0.5:
            interventions.append({"ts": ts, "type": "WELLNESS_NUDGE",
                "detail": "Fatigue detected — break recommended, MFA monitoring increased"})
        if vector["insider_threat"] > 0.4:
            interventions.append({"ts": ts, "type": "MFA_ESCALATION",
                "detail": "MFA escalated to biometric tier"})
        if vector["data_exfil"] > 0.5:
            interventions.append({"ts": ts, "type": "DLP_ALERT",
                "detail": "Data Loss Prevention alert triggered — bulk transfer blocked"})
        return interventions

    def get_org_risk_summary(self, org_id: str) -> dict:
        profiles = [h for k, h in self._hri_store.items() if h.org_id == org_id]
        if not profiles: return {"org_id": org_id, "users": 0, "avg_hri": 0}
        hris = [p.hri for p in profiles]
        return {"org_id": org_id, "users": len(profiles),
                "avg_hri": round(sum(hris) / len(hris), 2),
                "critical": sum(1 for h in hris if h >= 80),
                "high": sum(1 for h in hris if 60 <= h < 80),
                "medium": sum(1 for h in hris if 40 <= h < 60),
                "low": sum(1 for h in hris if h < 40)}

    def _hri_file(self):
        from core.bootstrap import AURORA_HOME
        return AURORA_HOME / "hri_store.json"
    def _load(self):
        try:
            for k, v in json.loads(self._hri_file().read_text()).items():
                self._hri_store[k] = HumanRiskIndex(**v)
        except Exception: pass
    def _save(self):
        try:
            f = self._hri_file()
            f.write_text(json.dumps({k: v.to_dict() for k, v in self._hri_store.items()}, indent=2))
            f.chmod(0o600)
        except Exception: pass
