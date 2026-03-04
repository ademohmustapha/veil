"""
AURORA Layer 2 — Secure Organizational Intelligence (SOIN-X)

FIXED: scan_organization() previously returned hardcoded integers.
Now performs real multi-dimensional risk assessment across five domains:
  - Identity & Access (credential exposure, privilege abuse, MFA gaps)
  - Endpoint Hygiene (patching cadence, EDR coverage, encryption)
  - Cloud & Network (misconfigs, over-permissive policies, exposure)
  - Human Risk (phishing susceptibility, insider threat indicators)
  - Governance (policy age, audit trail completeness, compliance gaps)

Each domain scores independently 0-100; the org-level score is a
weighted composite. All scoring uses context from the passed-in
org_profile dict, with sensible defaults when data is absent.
Callers can pass partial context; the scorer degrades gracefully.
"""
from __future__ import annotations

import time
import json
import hashlib
import hmac as _hmac
import secrets
import math
from typing import Dict, Any, List, Optional


# ── Scoring weights (must sum to 1.0) ────────────────────────────────────────
_DOMAIN_WEIGHTS: Dict[str, float] = {
    "identity_access":   0.25,
    "endpoint_hygiene":  0.20,
    "cloud_network":     0.20,
    "human_risk":        0.20,
    "governance":        0.15,
}


class OrgIntel:
    """
    Secure Organizational Intelligence engine.
    Assesses org-level security posture across five risk domains.
    All state changes are appended to a tamper-evident blockchain-style audit log.
    """

    def __init__(self) -> None:
        self._audit_trail: List[Dict] = []
        self._crisis_active: bool = False
        self._last_block_hash: str = "0" * 64
        self._risk_history: List[Dict] = []

    @property
    def audit_trail(self) -> List[Dict]:
        return self._audit_trail

    # ── Primary scan ─────────────────────────────────────────────────────────

    def scan_organization(self, org_id: str, org_profile: Optional[Dict] = None) -> Dict:
        """
        Real multi-domain risk assessment.

        org_profile keys (all optional — scored from defaults when absent):
          identity_access:
            mfa_coverage_pct (0-100), privileged_accounts_audited (bool),
            credential_rotation_days (int), sso_enabled (bool),
            service_accounts_reviewed (bool)
          endpoint_hygiene:
            patch_compliance_pct (0-100), edr_coverage_pct (0-100),
            disk_encryption_pct (0-100), avg_patch_lag_days (int)
          cloud_network:
            public_buckets (int), overpermissive_iam_roles (int),
            open_security_groups (int), waf_enabled (bool),
            secrets_in_code_repos (bool)
          human_risk:
            phishing_click_rate_pct (0-100), security_training_completion_pct (0-100),
            insider_threat_incidents_12m (int), social_engineering_tests_failed (int)
          governance:
            policy_last_reviewed_days (int), audit_log_retention_days (int),
            incident_response_plan (bool), last_pentest_days (int),
            compliance_frameworks (list of str)
        """
        # Merge caller-supplied profile with any signals ingested via ingest_findings().
        # Explicit caller values take precedence; ingested signals fill in the gaps.
        ingested = getattr(self, "_ingested_profile", {})
        merged   = {k: {**ingested.get(k, {}), **org_profile.get(k, {})} for k in
                    ("identity_access", "endpoint_hygiene", "cloud_network", "human_risk", "governance")} \
                   if org_profile else ingested
        profile = merged

        domain_scores = {
            "identity_access":  self._score_identity_access(profile.get("identity_access", {})),
            "endpoint_hygiene": self._score_endpoint_hygiene(profile.get("endpoint_hygiene", {})),
            "cloud_network":    self._score_cloud_network(profile.get("cloud_network", {})),
            "human_risk":       self._score_human_risk(profile.get("human_risk", {})),
            "governance":       self._score_governance(profile.get("governance", {})),
        }

        # Weighted composite score (lower = worse risk)
        composite = sum(
            domain_scores[d] * _DOMAIN_WEIGHTS[d]
            for d in domain_scores
        )
        risk_score = round(100 - composite, 1)  # Invert: 0=safe, 100=critical

        # Derive categorical findings from domain scores
        findings = self._derive_findings(domain_scores, profile)

        has_live_data = bool(getattr(self, "_ingested_profile", None))
        data_quality  = (
            "live — scored from ingested integration data"
            if has_live_data else
            "statistical_defaults — no live data ingested. "
            "Results reflect assumed posture only. "
            "Configure integrations in ~/.aurora/integrations.json for real scoring."
        )

        result = {
            "org_id": org_id,
            "data_quality": data_quality,
            "risk_summary": {
                "risk_score":      risk_score,
                "risk_level":      self._risk_level(risk_score),
                "total_findings":  len(findings),
                "critical_count":  sum(1 for f in findings if f["severity"] == "CRITICAL"),
                "high_count":      sum(1 for f in findings if f["severity"] == "HIGH"),
                "medium_count":    sum(1 for f in findings if f["severity"] == "MEDIUM"),
                "domain_scores":   {d: round(s, 1) for d, s in domain_scores.items()},
                "weighted_composite": round(composite, 2),
            },
            "findings":   findings,
            "timestamp":  time.time(),
            "profile_completeness": self._profile_completeness(profile),
        }

        self._risk_history.append({
            "ts": time.time(), "org_id": org_id, "risk_score": risk_score,
        })
        self._append_audit({
            "event": "org_scan", "org_id": org_id,
            "risk_score": risk_score, "domain_scores": domain_scores,
        })
        return result

    # ── Domain scorers (return 0-100 where 100 = fully secure) ───────────────

    def _score_identity_access(self, d: Dict) -> float:
        score = 100.0
        mfa = d.get("mfa_coverage_pct", 50)          # default: 50% coverage
        score -= (100 - mfa) * 0.35                  # up to -35 for 0% MFA
        if not d.get("privileged_accounts_audited", False):
            score -= 20
        rot = d.get("credential_rotation_days", 180)
        if rot > 365: score -= 20
        elif rot > 180: score -= 10
        elif rot > 90: score -= 5
        if not d.get("sso_enabled", True): score -= 10
        if not d.get("service_accounts_reviewed", False): score -= 10
        return round(max(0.0, min(100.0, score)), 2)

    def _score_endpoint_hygiene(self, d: Dict) -> float:
        score = 100.0
        patch_pct = d.get("patch_compliance_pct", 70)
        score -= (100 - patch_pct) * 0.40            # patching is the biggest factor
        edr = d.get("edr_coverage_pct", 60)
        score -= (100 - edr) * 0.25
        enc = d.get("disk_encryption_pct", 60)
        score -= (100 - enc) * 0.20
        lag = d.get("avg_patch_lag_days", 30)
        if lag > 60: score -= 20
        elif lag > 30: score -= 10
        elif lag > 14: score -= 5
        return round(max(0.0, min(100.0, score)), 2)

    def _score_cloud_network(self, d: Dict) -> float:
        score = 100.0
        buckets = d.get("public_buckets", 0)
        score -= min(40, buckets * 10)               # each public bucket = -10, cap at -40
        iam = d.get("overpermissive_iam_roles", 0)
        score -= min(25, iam * 5)
        sgs = d.get("open_security_groups", 0)
        score -= min(20, sgs * 4)
        if not d.get("waf_enabled", True): score -= 10
        if d.get("secrets_in_code_repos", False): score -= 30
        return round(max(0.0, min(100.0, score)), 2)

    def _score_human_risk(self, d: Dict) -> float:
        score = 100.0
        click = d.get("phishing_click_rate_pct", 25)
        score -= click * 1.2                         # 25% click rate = -30
        training = d.get("security_training_completion_pct", 70)
        score -= (100 - training) * 0.30
        insider = d.get("insider_threat_incidents_12m", 0)
        score -= min(20, insider * 5)
        se_fail = d.get("social_engineering_tests_failed", 2)
        score -= min(15, se_fail * 3)
        return round(max(0.0, min(100.0, score)), 2)

    def _score_governance(self, d: Dict) -> float:
        score = 100.0
        pol_days = d.get("policy_last_reviewed_days", 365)
        if pol_days > 730: score -= 25
        elif pol_days > 365: score -= 15
        elif pol_days > 180: score -= 5
        ret = d.get("audit_log_retention_days", 90)
        if ret < 365: score -= 20
        elif ret < 90: score -= 30
        if not d.get("incident_response_plan", True): score -= 20
        pentest_days = d.get("last_pentest_days", 365)
        if pentest_days > 730: score -= 20
        elif pentest_days > 365: score -= 10
        frameworks = d.get("compliance_frameworks", [])
        score += min(15, len(frameworks) * 5)        # bonus for compliance investment
        return round(max(0.0, min(100.0, score)), 2)

    # ── Finding derivation ────────────────────────────────────────────────────

    def _derive_findings(self, domain_scores: Dict, profile: Dict) -> List[Dict]:
        findings: List[Dict] = []
        ts = time.time()

        ia = profile.get("identity_access", {})
        if ia.get("mfa_coverage_pct", 50) < 80:
            findings.append({
                "id": f"IAM-{int(ts)}-001", "domain": "identity_access",
                "title": "MFA Coverage Below Threshold",
                "severity": "CRITICAL" if ia.get("mfa_coverage_pct", 50) < 50 else "HIGH",
                "description": f"MFA coverage is {ia.get('mfa_coverage_pct', 50)}% — recommend ≥95%.",
                "remediation": "Enforce MFA on all user accounts via SSO/IdP policy.",
            })
        if not ia.get("privileged_accounts_audited", False):
            findings.append({
                "id": f"IAM-{int(ts)}-002", "domain": "identity_access",
                "title": "Privileged Accounts Not Audited",
                "severity": "HIGH",
                "description": "No evidence of privileged account review in the assessment window.",
                "remediation": "Conduct quarterly privileged access reviews. Remove dormant admin accounts.",
            })
        if ia.get("credential_rotation_days", 180) > 365:
            findings.append({
                "id": f"IAM-{int(ts)}-003", "domain": "identity_access",
                "title": "Stale Credentials — Rotation Overdue",
                "severity": "HIGH",
                "description": f"Credentials last rotated {ia.get('credential_rotation_days', 180)} days ago.",
                "remediation": "Enforce automated credential rotation ≤90 days. Use secrets management.",
            })

        ep = profile.get("endpoint_hygiene", {})
        if ep.get("patch_compliance_pct", 70) < 90:
            findings.append({
                "id": f"EP-{int(ts)}-001", "domain": "endpoint_hygiene",
                "title": "Patch Compliance Below Threshold",
                "severity": "CRITICAL" if ep.get("patch_compliance_pct", 70) < 70 else "HIGH",
                "description": f"Only {ep.get('patch_compliance_pct', 70)}% of endpoints are current.",
                "remediation": "Deploy patch management tooling. Enforce 14-day SLA for critical patches.",
            })

        cn = profile.get("cloud_network", {})
        if cn.get("public_buckets", 0) > 0:
            findings.append({
                "id": f"CN-{int(ts)}-001", "domain": "cloud_network",
                "title": f"Public Cloud Storage Buckets Detected ({cn['public_buckets']})",
                "severity": "CRITICAL",
                "description": f"{cn['public_buckets']} cloud storage bucket(s) are publicly accessible.",
                "remediation": "Enable Block Public Access. Audit bucket policies immediately.",
            })
        if cn.get("secrets_in_code_repos", False):
            findings.append({
                "id": f"CN-{int(ts)}-002", "domain": "cloud_network",
                "title": "Secrets Detected in Code Repositories",
                "severity": "CRITICAL",
                "description": "API keys, passwords, or tokens found in version-controlled repositories.",
                "remediation": "Rotate all exposed secrets immediately. Use a secrets manager. Add pre-commit scanning.",
            })

        hr = profile.get("human_risk", {})
        if hr.get("phishing_click_rate_pct", 25) > 20:
            findings.append({
                "id": f"HR-{int(ts)}-001", "domain": "human_risk",
                "title": "High Phishing Click Rate",
                "severity": "HIGH",
                "description": f"Phishing click rate is {hr.get('phishing_click_rate_pct', 25)}% — industry target is <5%.",
                "remediation": "Mandatory phishing simulation training. Deploy email filtering and DMARC.",
            })
        if hr.get("security_training_completion_pct", 70) < 80:
            findings.append({
                "id": f"HR-{int(ts)}-002", "domain": "human_risk",
                "title": "Security Awareness Training Incomplete",
                "severity": "MEDIUM",
                "description": f"Only {hr.get('security_training_completion_pct', 70)}% of staff completed training.",
                "remediation": "Make annual security training mandatory. Track completion in LMS.",
            })

        gv = profile.get("governance", {})
        if not gv.get("incident_response_plan", True):
            findings.append({
                "id": f"GV-{int(ts)}-001", "domain": "governance",
                "title": "No Incident Response Plan",
                "severity": "HIGH",
                "description": "No documented incident response plan found.",
                "remediation": "Develop and test an IRP aligned to NIST SP 800-61. Run tabletop exercises.",
            })
        if gv.get("last_pentest_days", 365) > 365:
            findings.append({
                "id": f"GV-{int(ts)}-002", "domain": "governance",
                "title": "No Recent Penetration Test",
                "severity": "MEDIUM",
                "description": f"Last penetration test was {gv.get('last_pentest_days', 365)} days ago.",
                "remediation": "Conduct an annual full-scope penetration test. Address critical findings within 30 days.",
            })

        return findings

    # ── Risk classification ───────────────────────────────────────────────────

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 80: return "CRITICAL"
        if score >= 60: return "HIGH"
        if score >= 40: return "MEDIUM"
        if score >= 20: return "LOW"
        return "MINIMAL"

    @staticmethod
    def _profile_completeness(profile: Dict) -> str:
        domains = ["identity_access", "endpoint_hygiene", "cloud_network", "human_risk", "governance"]
        provided = sum(1 for d in domains if d in profile and profile[d])
        pct = int(provided / len(domains) * 100)
        if pct == 100: return "COMPLETE"
        if pct >= 60:  return f"PARTIAL ({pct}% — {5-provided} domain(s) using defaults)"
        return f"MINIMAL ({pct}% — results use significant defaults)"

    # ── Live data ingestion ───────────────────────────────────────────────────

    def ingest_findings(self, findings: List[Dict]) -> None:
        """
        Accept normalised findings from the Integration Manager and map them
        onto the org_profile domains used by scan_organization().

        The method converts raw severity/category signals into domain-level
        context hints so the risk scorer gets live data instead of defaults.
        Stored on self._ingested_profile and passed automatically to
        scan_organization() on the next call.

        findings: list of dicts with keys: title, severity, category, source, ...
                  (output format of integrations.manager.IntegrationManager.fetch_all)
        """
        sev_weight = {"critical": 1.0, "high": 0.75, "medium": 0.45, "low": 0.15, "info": 0.05}

        # Accumulate signal strength per domain
        identity_signals:  List[float] = []
        endpoint_signals:  List[float] = []
        cloud_signals:     List[float] = []
        human_signals:     List[float] = []
        governance_signals: List[float] = []

        for f in findings:
            cat = str(f.get("category", "")).lower()
            w   = sev_weight.get(str(f.get("severity", "medium")).lower(), 0.45)

            if any(k in cat for k in ("identity", "auth", "credential", "mfa", "access", "privilege", "sso")):
                identity_signals.append(w)
            elif any(k in cat for k in ("endpoint", "edr", "patch", "encrypt", "malware", "antivirus")):
                endpoint_signals.append(w)
            elif any(k in cat for k in ("cloud", "aws", "azure", "gcp", "network", "firewall", "bucket", "iam")):
                cloud_signals.append(w)
            elif any(k in cat for k in ("human", "phish", "insider", "social", "training", "awareness")):
                human_signals.append(w)
            elif any(k in cat for k in ("governance", "compliance", "policy", "audit", "pentest", "log")):
                governance_signals.append(w)
            else:
                # Distribute unclassified findings across all domains proportionally
                for lst in (identity_signals, endpoint_signals, cloud_signals, human_signals, governance_signals):
                    lst.append(w * 0.3)

        def _avg_to_exposure(signals: List[float]) -> float:
            """Convert average signal weight to % exposure (inverted so 100 = fully secure)."""
            if not signals:
                return 50.0  # Default: assume moderate posture when no data
            avg_risk = min(1.0, sum(signals) / len(signals))
            return round((1.0 - avg_risk) * 100, 1)

        self._ingested_profile = {
            "identity_access": {
                "mfa_coverage_pct":             _avg_to_exposure(identity_signals),
                "privileged_accounts_audited":  len(identity_signals) == 0,
                "credential_rotation_days":     90 if not identity_signals else int(90 + 270 * (1 - min(1, len(identity_signals) / 10))),
                "sso_enabled":                  len(identity_signals) < 3,
                "service_accounts_reviewed":    len(identity_signals) < 2,
            },
            "endpoint_hygiene": {
                "patch_compliance_pct":         _avg_to_exposure(endpoint_signals),
                "edr_coverage_pct":             _avg_to_exposure(endpoint_signals),
                "disk_encryption_pct":          _avg_to_exposure(endpoint_signals),
            },
            "cloud_network": {
                "public_buckets":               max(0, len([s for s in cloud_signals if s > 0.7])),
                "overpermissive_iam_roles":     max(0, len([s for s in cloud_signals if s > 0.5])),
                "open_security_groups":         max(0, len([s for s in cloud_signals if s > 0.4])),
                "waf_enabled":                  len(cloud_signals) < 2,
                "secrets_in_code_repos":        any(s > 0.8 for s in cloud_signals),
            },
            "human_risk": {
                "phishing_click_rate_pct":      100 - _avg_to_exposure(human_signals),
                "security_training_completion_pct": _avg_to_exposure(human_signals),
                "insider_threat_incidents_12m": len([s for s in human_signals if s > 0.6]),
                "social_engineering_tests_failed": len([s for s in human_signals if s > 0.4]),
            },
            "governance": {
                "incident_response_plan":       len(governance_signals) < 5,
                "audit_log_retention_days":     365 if not governance_signals else 90,
                "policy_last_reviewed_days":    90 if not governance_signals else int(180 * (1 + min(1, len(governance_signals) / 10))),
                "last_pentest_days":            90 if not governance_signals else 365,
            },
        }
        self._append_audit({
            "event":            "findings_ingested",
            "count":            len(findings),
            "domain_signals": {
                "identity":   len(identity_signals),
                "endpoint":   len(endpoint_signals),
                "cloud":      len(cloud_signals),
                "human":      len(human_signals),
                "governance": len(governance_signals),
            },
        })

    # ── Trend analysis ────────────────────────────────────────────────────────

    def get_risk_trend(self, org_id: str) -> Dict:
        """Return historical risk score trend for an org."""
        history = [h for h in self._risk_history if h["org_id"] == org_id]
        if not history:
            return {"org_id": org_id, "trend": "NO_DATA", "history": []}
        scores = [h["risk_score"] for h in history[-10:]]
        if len(scores) < 2:
            trend = "INSUFFICIENT_DATA"
        elif scores[-1] > scores[0] + 5:
            trend = "DETERIORATING"
        elif scores[-1] < scores[0] - 5:
            trend = "IMPROVING"
        else:
            trend = "STABLE"
        return {
            "org_id": org_id,
            "trend": trend,
            "latest_score": scores[-1],
            "baseline_score": scores[0],
            "delta": round(scores[-1] - scores[0], 1),
            "history": history[-10:],
        }

    # ── Tamper-evident audit log ──────────────────────────────────────────────

    def _append_audit(self, event: Dict) -> None:
        ts = time.time_ns()
        prev_hash = self._last_block_hash
        block_data = json.dumps({**event, "ts": ts, "prev": prev_hash}, sort_keys=True)
        block_hash = hashlib.sha256(block_data.encode()).hexdigest()
        block = {**event, "ts": ts, "prev_hash": prev_hash, "block_hash": block_hash}
        self._audit_trail.append(block)
        self._last_block_hash = block_hash

    def get_tamper_proof_log(self) -> List[Dict]:
        return self._audit_trail.copy()

    def verify_audit_integrity(self) -> Dict:
        """Verify the blockchain-style audit trail has not been tampered with."""
        prev_hash = "0" * 64
        for i, block in enumerate(self._audit_trail):
            stored = block.get("block_hash", "")
            check = {k: v for k, v in block.items() if k != "block_hash"}
            recomputed = hashlib.sha256(
                json.dumps({**check, "prev": block.get("prev_hash", "")},
                           sort_keys=True).encode()
            ).hexdigest()
            if stored != recomputed:
                return {"valid": False, "tampered_at_entry": i, "entries_checked": i + 1}
            prev_hash = stored
        return {"valid": True, "entries_checked": len(self._audit_trail)}

    def activate_crisis_mode(self) -> str:
        if self._crisis_active:
            return "ALREADY_ACTIVE"
        self._crisis_active = True
        self._append_audit({"event": "crisis_mode_activated", "level": "CRITICAL"})
        return "ACTIVATED"

    def deactivate_crisis_mode(self) -> str:
        if not self._crisis_active:
            return "NOT_ACTIVE"
        self._crisis_active = False
        self._append_audit({"event": "crisis_mode_deactivated"})
        return "DEACTIVATED"
