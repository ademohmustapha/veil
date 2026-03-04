"""
AURORA Layer 7 — Predictive Event Horizon
==========================================
FIXED:
  - No more hardcoded historical list
  - Accepts real threat signals and builds a live rolling buffer
  - Holt-Winters double-exponential smoothing (trend + level)
  - Bayesian attack-class probability from 20 precursor signals
  - Monte Carlo forward simulation (200 runs) for confidence intervals
  - Feeds from real engine outputs (HRI, co-evolution, supply chain)
"""
from __future__ import annotations
import math, time, json, os, secrets, hashlib, hmac as _hmac
from typing import Dict, List, Any, Tuple
from pathlib import Path

from core.paths import AURORA_HOME as _AURORA_HOME
_SIGNALS_FILE = _AURORA_HOME / "horizon_signals.json"

# 20 precursor signals → each contributes to attack-class CPTs
_PRECURSOR_SIGNALS = [
    "recon_port_scan", "credential_stuffing", "phishing_failures",
    "after_hours_access", "priv_escalation", "lateral_movement",
    "data_staging", "exfil_probes", "vpn_anomaly", "new_admin_accounts",
    "mfa_bypass_attempts", "supply_chain_anomaly", "email_forward_rules",
    "bulk_downloads", "security_tool_disabled", "cloud_api_spike",
    "dns_tunneling", "c2_beaconing", "insider_hr_signal", "third_party_breach",
]

# Noisy-OR CPTs: for each attack class, which precursors indicate it (and weight)
_ATTACK_CLASSES: Dict[str, Dict[str, float]] = {
    "RANSOMWARE":         {"data_staging":0.7,"lateral_movement":0.6,"security_tool_disabled":0.8,"bulk_downloads":0.5,"c2_beaconing":0.6},
    "INSIDER_THREAT":     {"after_hours_access":0.6,"bulk_downloads":0.7,"insider_hr_signal":0.8,"data_staging":0.6,"email_forward_rules":0.5},
    "SUPPLY_CHAIN":       {"supply_chain_anomaly":0.9,"third_party_breach":0.8,"new_admin_accounts":0.5},
    "PHISHING_CAMPAIGN":  {"phishing_failures":0.8,"credential_stuffing":0.6,"email_forward_rules":0.5,"mfa_bypass_attempts":0.5},
    "DATA_EXFILTRATION":  {"exfil_probes":0.8,"data_staging":0.7,"dns_tunneling":0.7,"cloud_api_spike":0.5},
    "APT_CAMPAIGN":       {"recon_port_scan":0.6,"lateral_movement":0.7,"c2_beaconing":0.8,"priv_escalation":0.6,"new_admin_accounts":0.5},
    "CREDENTIAL_THEFT":   {"credential_stuffing":0.8,"mfa_bypass_attempts":0.7,"phishing_failures":0.6,"vpn_anomaly":0.5},
    "ZERO_DAY_EXPLOIT":   {"c2_beaconing":0.5,"priv_escalation":0.7,"lateral_movement":0.6,"security_tool_disabled":0.6},
    "AI_DRIVEN_ATTACK":   {"email_forward_rules":0.4,"phishing_failures":0.6,"credential_stuffing":0.5,"dns_tunneling":0.4},
}

_MONTE_CARLO_RUNS = 200


class EventHorizon:
    """
    Predictive threat horizon using live signals + Bayesian inference + Monte Carlo.
    """

    def __init__(self):
        self._signal_history: List[Dict[str, float]] = []   # rolling signal buffer
        self._level_smooth: float = 50.0     # Holt-Winters level
        self._trend_smooth: float = 0.5      # Holt-Winters trend
        self._alpha = 0.30                   # level smoothing
        self._beta  = 0.10                   # trend smoothing
        self._load_signals()

    def _load_signals(self):
        if _SIGNALS_FILE.exists():
            try:
                raw = _SIGNALS_FILE.read_bytes()
                sig_file = _AURORA_HOME / "horizon_signals.hmac"
                if sig_file.exists():
                    expected = sig_file.read_text().strip()
                    actual = _hmac.new(self._get_signal_secret(), raw, hashlib.sha256).hexdigest()
                    if not _hmac.compare_digest(expected, actual):
                        import warnings
                        warnings.warn("AURORA: Signal history HMAC verification FAILED — possible signal injection attack. Discarding.", RuntimeWarning)
                        self._signal_history = []
                        self._level_smooth = 50.0
                        self._trend_smooth = 0.5
                        # Re-seed fresh
                        for i in range(12):
                            base_level = 45 + i * 2.2 + self._gaussian_noise(3.0)
                            self._ingest_synthetic_signals(base_level)
                        return
                data = json.loads(raw.decode())
                self._signal_history = data.get("history", [])[-90:]
                self._level_smooth   = data.get("level", 50.0)
                self._trend_smooth   = data.get("trend", 0.5)
            except Exception:
                pass
        # Seed with bootstrap samples only when no real signals exist.
        # _synthetic_seed=True so get_horizon_report() can disclose this and
        # suppress misleading SOC-action recommendations based on fabricated data.
        if not self._signal_history:
            import math
            self._synthetic_seed = True
            for i in range(12):
                base_level = 45 + i * 2.2 + self._gaussian_noise(3.0)
                self._ingest_synthetic_signals(base_level)
        else:
            self._synthetic_seed = False

    def _get_signal_secret(self) -> bytes:
        sfile = _AURORA_HOME / ".signal_secret"
        if sfile.exists():
            return sfile.read_bytes()[:32]
        s = os.urandom(32)
        sfile.write_bytes(s); sfile.chmod(0o600)
        return s

    def _save_signals(self):
        data = json.dumps({
            "history": self._signal_history[-90:],
            "level": self._level_smooth,
            "trend": self._trend_smooth,
        }, indent=2).encode()
        sig = _hmac.new(self._get_signal_secret(), data, hashlib.sha256).hexdigest()
        _SIGNALS_FILE.write_bytes(data)
        _SIGNALS_FILE.chmod(0o600)
        sig_file = _AURORA_HOME / "horizon_signals.hmac"
        sig_file.write_text(sig)
        sig_file.chmod(0o600)

    def _gaussian_noise(self, std: float) -> float:
        u1 = (secrets.randbits(32) + 1) / (2**32 + 1)
        u2 = (secrets.randbits(32) + 1) / (2**32 + 1)
        return std * math.sqrt(-2 * math.log(u1)) * math.cos(2 * math.pi * u2)

    def _ingest_synthetic_signals(self, threat_level: float):
        """Convert a scalar threat level to a synthetic signal dict."""
        normalized = threat_level / 100.0
        signal = {sig: min(1.0, max(0.0, normalized + self._gaussian_noise(0.1)))
                  for sig in _PRECURSOR_SIGNALS}
        self._signal_history.append(signal)

    # ── Public ingestion API ─────────────────────────────────────────────────

    def ingest_signals(self, signals: Dict[str, float]) -> None:
        """
        Feed real precursor signals into the horizon.
        Called by other engines (HRI, containment, supply chain) on each event.
        signals: dict of precursor_name → strength [0.0–1.0]
        """
        validated = {k: max(0.0, min(1.0, float(v))) for k, v in signals.items()
                     if k in _PRECURSOR_SIGNALS}
        if not validated:
            return
        self._signal_history.append(validated)
        if len(self._signal_history) > 90:
            self._signal_history = self._signal_history[-90:]
        # Update Holt-Winters with current aggregate threat level
        current_level = self._aggregate_level(validated)
        self._update_holt_winters(current_level)
        self._save_signals()

    def _aggregate_level(self, signals: Dict[str, float]) -> float:
        """Aggregate signal dict to scalar threat level 0–100."""
        if not signals:
            return self._level_smooth
        return min(100.0, sum(signals.values()) / len(signals) * 100)

    def _update_holt_winters(self, observation: float):
        prev_level = self._level_smooth
        self._level_smooth = self._alpha * observation + (1 - self._alpha) * (prev_level + self._trend_smooth)
        self._trend_smooth = self._beta * (self._level_smooth - prev_level) + (1 - self._beta) * self._trend_smooth

    # ── Bayesian attack-class prediction ─────────────────────────────────────

    def _bayesian_attack_probabilities(self) -> Dict[str, float]:
        """
        Noisy-OR Bayesian model over last 7 days of signals.
        P(attack|signals) = 1 - ∏(1 - w_i × s_i)
        """
        if not self._signal_history:
            return {cls: 0.1 for cls in _ATTACK_CLASSES}
        # Average signals over last 7 observations
        recent = self._signal_history[-7:]
        avg_signals: Dict[str, float] = {}
        for sig in _PRECURSOR_SIGNALS:
            avg_signals[sig] = sum(obs.get(sig, 0.0) for obs in recent) / len(recent)

        probs = {}
        for attack_class, cpt in _ATTACK_CLASSES.items():
            # Noisy-OR: P(attack) = 1 - ∏(1 - w_i × s_i)
            prob = 1.0 - math.prod(
                1.0 - (weight * avg_signals.get(signal, 0.0))
                for signal, weight in cpt.items()
            )
            probs[attack_class] = round(min(0.99, max(0.01, prob)), 4)
        return probs

    # ── Monte Carlo forward simulation ───────────────────────────────────────

    def _monte_carlo_forecast(self, days: int = 30) -> List[Dict]:
        """
        Monte Carlo forward simulation (200 runs).
        Each run: Holt-Winters + random walk with trend uncertainty.
        Returns per-day mean ± confidence interval.
        """
        all_runs: List[List[float]] = []

        for _ in range(_MONTE_CARLO_RUNS):
            run = []
            level = self._level_smooth + self._gaussian_noise(5.0)
            trend = self._trend_smooth + self._gaussian_noise(0.3)
            for day in range(1, days + 1):
                # Drift + noise
                level = level + trend + self._gaussian_noise(3.5)
                level = max(0.0, min(100.0, level))
                # Slight mean-reversion to 50
                level = level * 0.97 + 50 * 0.03
                run.append(level)
            all_runs.append(run)

        # Aggregate across runs
        forecast = []
        for day_idx in range(days):
            day_vals = sorted([run[day_idx] for run in all_runs])
            p05 = day_vals[int(0.05 * _MONTE_CARLO_RUNS)]
            mean = sum(day_vals) / _MONTE_CARLO_RUNS
            p95 = day_vals[int(0.95 * _MONTE_CARLO_RUNS)]
            level = "CRITICAL" if mean > 80 else ("HIGH" if mean > 65 else ("MEDIUM" if mean > 45 else "LOW"))
            forecast.append({
                "day": day_idx + 1,
                "projected_threat_level": round(mean, 1),
                "ci_05": round(p05, 1),
                "ci_95": round(p95, 1),
                "level": level,
            })
        return forecast

    # ── Public API ───────────────────────────────────────────────────────────

    def forecast_threats(self, horizon_days: int = 30) -> Dict:
        forecast = self._monte_carlo_forecast(horizon_days)
        current = round(self._level_smooth, 1)
        trend_val = round(self._trend_smooth, 3)
        trend_label = "INCREASING" if trend_val > 0.3 else ("DECREASING" if trend_val < -0.3 else "STABLE")
        return {
            "horizon_days": horizon_days,
            "current_threat_level": current,
            "trend": trend_label,
            "trend_rate": trend_val,
            "forecast": forecast,
            "model": "HOLT-WINTERS + MONTE-CARLO-200",
            "generated_at": time.time(),
        }

    def get_attack_class_forecast(self) -> Dict:
        probs = self._bayesian_attack_probabilities()
        top = max(probs, key=lambda k: probs[k])
        return {
            "attack_class_probabilities": probs,
            "highest_risk_class": top,
            "highest_risk_probability": probs[top],
            "model": "NOISY-OR BAYESIAN",
        }

    def get_horizon_report(self) -> Dict:
        forecast_data = self.forecast_threats(30)
        attack_classes = self.get_attack_class_forecast()
        peak = max(forecast_data["forecast"], key=lambda x: x["projected_threat_level"])
        current = forecast_data["current_threat_level"]
        is_synthetic = getattr(self, "_synthetic_seed", True)

        if is_synthetic:
            recommendation = (
                "COLD START — no real signal data has been ingested. "
                "These numbers are bootstrap seeds, not intelligence. "
                "Configure a live data source via ~/.aurora/integrations.json "
                "before acting on any forecast."
            )
        else:
            recommendation = (
                "Activate predictive containment. Immediate SOC briefing required."
                if peak["projected_threat_level"] > 80 else
                "Increase monitoring cadence. Review supply chain dependencies."
                if peak["projected_threat_level"] > 65 else
                "Standard AURORA posture. Continue co-evolution cycles."
            )

        return {
            "summary": f"Peak threat {peak['projected_threat_level']} forecast on day {peak['day']} (CI: {peak['ci_05']}–{peak['ci_95']})",
            "trend": forecast_data["trend"],
            "trend_rate": forecast_data["trend_rate"],
            "peak_threat": peak,
            "current_threat_level": current,
            "30day_forecast": forecast_data,
            "attack_class_forecast": attack_classes,
            "strategic_recommendation": recommendation,
            "signal_observations": len(self._signal_history),
            "data_source": "synthetic_bootstrap — configure integrations for live data" if is_synthetic else "live",
            "report_generated": time.time(),
        }
