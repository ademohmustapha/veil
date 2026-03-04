"""
AURORA Layer 7 — Autonomous Co-Evolution Engine
================================================
Adapter that exposes the Layer-7 public API while delegating all
genetic algorithm work to engines.coevolution — the richer, fully-wired
implementation with:
  - Real 12-feature DetectionRule representation
  - Proper Incident dataclass for labelled training data
  - F1-score + CRITICAL-bonus + FP-penalty fitness function
  - Uniform crossover, Gaussian mutation, elitism, adaptive mutation rate
  - HMAC-signed genome persistence (tamper detection)
  - inject_incidents() so real telemetry can feed the GA

When no real incidents are available the engine bootstraps with
synthetic data (honest fall-back, clearly documented).
Over time, as real incidents are injected, evolution converges on
patterns that actually reflect the organisation's threat landscape.
"""
from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from engines.coevolution import (
    CoEvolutionEngine as _RealEngine,
    DetectionRule,
    Incident,
    mutate as _mutate_rule,
)
from core.paths import AURORA_HOME as _AURORA_HOME
from core.config import get_config

_INCIDENT_STORE_FILE = _AURORA_HOME / "aurora_incidents.jsonl"


def _bootstrap_synthetic_incidents(n_pos: int = 30, n_neg: int = 70) -> List[Incident]:
    """Cold-start fall-back only. Replaced by real data as soon as inject_incidents() is called."""
    try:
        import numpy as np
    except ImportError:
        return []
    rng = np.random.default_rng(int.from_bytes(secrets.token_bytes(4), "big"))
    incidents: List[Incident] = []
    for i in range(n_pos):
        incidents.append(Incident(
            incident_id=f"SYNTH-POS-{i}",
            features=[float(v) for v in rng.beta(5, 2, 12)],
            is_malicious=True, threat_class="synthetic", severity="HIGH",
        ))
    for i in range(n_neg):
        incidents.append(Incident(
            incident_id=f"SYNTH-NEG-{i}",
            features=[float(v) for v in rng.beta(2, 5, 12)],
            is_malicious=False, threat_class="benign", severity="LOW",
        ))
    return incidents


def _load_real_incidents() -> List[Incident]:
    if not _INCIDENT_STORE_FILE.exists():
        return []
    incidents: List[Incident] = []
    try:
        for line in _INCIDENT_STORE_FILE.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            incidents.append(Incident(
                incident_id=d["incident_id"],
                features=d["features"],
                is_malicious=d["is_malicious"],
                threat_class=d.get("threat_class", "unknown"),
                severity=d.get("severity", "MEDIUM"),
                timestamp=d.get("timestamp", time.time()),
            ))
    except Exception:
        pass
    return incidents[-10_000:]


def _append_incident(inc: Incident) -> None:
    try:
        with open(_INCIDENT_STORE_FILE, "a") as f:
            f.write(json.dumps({
                "incident_id": inc.incident_id, "features": inc.features,
                "is_malicious": inc.is_malicious, "threat_class": inc.threat_class,
                "severity": inc.severity, "timestamp": inc.timestamp,
            }) + "\n")
    except Exception:
        pass


class CoEvolutionEngine:
    """
    Layer-7 Co-Evolution Engine — now backed by engines.coevolution (the real GA).

    inject_incidents() / inject_raw_event() feed real labelled events.
    run_evolution_cycle() uses real data when available, synthetic cold-start otherwise.
    Genome is HMAC-signed; tampering triggers population reinitialisation.
    """

    def __init__(self) -> None:
        cfg = get_config()
        self._engine = _RealEngine(config=cfg)
        real = _load_real_incidents()
        self._real_incident_count: int = len(real)
        self._using_real_data: bool = self._real_incident_count > 0

    def inject_incidents(self, incidents: List[Incident]) -> Dict[str, Any]:
        """Feed real labelled incidents. Each valid one persists to disk across restarts."""
        valid: List[Incident] = []
        for inc in incidents:
            if isinstance(inc.features, list) and len(inc.features) == 12:
                if all(isinstance(f, (int, float)) for f in inc.features):
                    valid.append(inc)
                    _append_incident(inc)
        self._real_incident_count += len(valid)
        self._using_real_data = self._real_incident_count > 0
        return {
            "injected": len(valid), "rejected": len(incidents) - len(valid),
            "total_real_incidents": self._real_incident_count,
            "using_real_data": self._using_real_data,
        }

    def inject_raw_event(self, features: List[float], is_malicious: bool,
                         threat_class: str = "unknown", severity: str = "MEDIUM") -> None:
        """Convenience: inject a single raw feature vector as an incident."""
        self.inject_incidents([Incident(
            incident_id=f"REAL-{int(time.time()*1000)}-{secrets.token_hex(3)}",
            features=features, is_malicious=is_malicious,
            threat_class=threat_class, severity=severity,
        )])

    def run_evolution_cycle(self) -> Dict[str, Any]:
        """One full GA cycle. Uses real incidents if available; synthetic cold-start otherwise."""
        real = _load_real_incidents()
        if real:
            self._using_real_data = True
            self._real_incident_count = len(real)
            result = self._engine.evolve(real)
            result["data_source"] = "real"
            result["real_incident_count"] = len(real)
        else:
            result = self._engine.evolve(_bootstrap_synthetic_incidents())
            result["data_source"] = "synthetic_bootstrap"
            result["real_incident_count"] = 0
            result["note"] = (
                "No real incidents yet — synthetic cold-start used. "
                "Call inject_incidents() to feed real labelled events; "
                "evolution will re-run against real data on the next cycle."
            )
        return result

    def mutate_strategy(self, strategy_name: str) -> Dict[str, Any]:
        """Force-mutate rules matching a domain (e.g. after new threat intel)."""
        pop = self._engine._population
        if not pop:
            return {"error": "Population not initialised"}
        cfg = get_config()
        mr = getattr(cfg, "coevolution_mutation_rate", 0.12)
        matching_idx = [
            i for i, r in enumerate(pop)
            if strategy_name.lower() in r.label.lower()
            or strategy_name.lower() in r.rule_id.lower()
        ]
        if not matching_idx:
            import random
            matching_idx = random.sample(range(len(pop)), min(5, len(pop)))
        for i in matching_idx:
            pop[i] = _mutate_rule(pop[i], mr)
        self._engine._save_genome()
        return {
            "domain": strategy_name, "forced_mutation": True,
            "rules_mutated": len(matching_idx), "generation": self._engine._generation,
        }

    def detect(self, features: List[float], top_n: int = 5) -> Dict[str, Any]:
        """Run feature vector through the evolved ruleset."""
        return self._engine.detect(features, top_n=top_n)

    def get_evolution_report(self) -> Dict[str, Any]:
        status = self._engine.get_status()
        return {
            **status,
            "using_real_data": self._using_real_data,
            "real_incident_count": self._real_incident_count,
            "data_source": "real" if self._using_real_data else "synthetic_bootstrap",
            "incident_store": str(_INCIDENT_STORE_FILE),
        }

    def absorb_threat_intelligence(self, threat: Dict) -> None:
        features = threat.get("features")
        if features and len(features) == 12:
            self.inject_raw_event(
                features=features, is_malicious=True,
                threat_class=threat.get("domain", "threat_intel"),
                severity=threat.get("severity", "HIGH"),
            )
        domain = threat.get("domain")
        if domain:
            self.mutate_strategy(domain)

    def best_individual(self, domain: str) -> Optional[DetectionRule]:
        pop = self._engine._population
        if not pop:
            return None
        domain_rules = [r for r in pop if domain.lower() in r.label.lower()]
        return max(domain_rules if domain_rules else pop, key=lambda r: r.fitness)
