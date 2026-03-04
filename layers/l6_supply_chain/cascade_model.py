"""
AURORA Layer 6 — Supply Chain Cascade Model (Monte Carlo + NetworkX PageRank)
==============================================================================
FIXED:
  - _adj always initialised regardless of networkx availability
  - Default 9-org supply chain graph seeded on init (usable out of the box)
  - simulate_cascade() works immediately without manual add_org() calls
  - All keys required by tests present: cascades, financial_impact_estimate_usd,
    breach_propagation_probability, estimated_recovery_hours

References:
  Shao et al. (2015): Cascade-based attacks in complex networks
  IBM Cost of Data Breach Report (2024)
"""
from __future__ import annotations
import math, time, secrets
from typing import Dict, List, Optional, Tuple

try:
    import networkx as nx
    _HAS_NX = True
except ImportError:
    _HAS_NX = False

_SECTOR_BREACH_COST_M: Dict[str, float] = {
    "finance": 5.90, "healthcare": 9.77, "energy": 4.72,
    "technology": 4.66, "government": 2.07, "retail": 2.96,
    "education": 3.65, "manufacturing": 4.15, "default": 4.45,
}
_FAILURE_PROP_P: Dict[str, float] = {
    "ransomware": 0.70, "apt": 0.60, "supply_chain_compromise": 0.85,
    "phishing": 0.30, "ddos": 0.40, "data_breach": 0.50, "zero_day": 0.65,
}
_MONTE_CARLO_RUNS = 300


class CascadeModel:
    def __init__(self):
        # FIXED: always init _adj regardless of networkx
        self._adj: Dict[str, List[Tuple[str, float]]] = {}
        self._org_meta: Dict[str, Dict] = {}
        if _HAS_NX:
            self._graph = nx.DiGraph()
            self._pagerank: Dict[str, float] = {}
        self._seed_default_graph()

    def _seed_default_graph(self) -> None:
        """Seed a representative 9-org global supply chain for out-of-box use."""
        orgs = [
            ("org_finance_1",    "finance",      0.75),
            ("org_technology_1", "technology",   0.60),
            ("org_healthcare_1", "healthcare",   0.55),
            ("org_energy_1",     "energy",       0.65),
            ("org_retail_1",     "retail",       0.50),
            ("org_govt_1",       "government",   0.70),
            ("org_mfg_1",        "manufacturing",0.45),
            ("org_edu_1",        "education",    0.40),
            ("org_cloud_1",      "technology",   0.80),
        ]
        deps = [
            ("org_finance_1", "org_technology_1", 0.9),
            ("org_finance_1", "org_cloud_1",      0.8),
            ("org_healthcare_1", "org_technology_1", 0.7),
            ("org_healthcare_1", "org_cloud_1",   0.6),
            ("org_energy_1", "org_mfg_1",         0.8),
            ("org_retail_1", "org_technology_1",  0.7),
            ("org_govt_1", "org_cloud_1",         0.75),
            ("org_mfg_1", "org_energy_1",         0.6),
            ("org_edu_1", "org_technology_1",     0.5),
        ]
        for org_id, sector, resilience in orgs:
            self.add_org(org_id, sector=sector, resilience=resilience)
        for dependent, provider, criticality in deps:
            self.add_dependency(dependent, provider, criticality=criticality)

    def add_org(self, org_id: str, sector: str = "default",
                resilience: float = 0.5, **attrs) -> None:
        self._org_meta[org_id] = {"sector": sector, "resilience": resilience, **attrs}
        self._adj.setdefault(org_id, [])
        if _HAS_NX:
            self._graph.add_node(org_id, sector=sector, resilience=resilience, **attrs)

    def add_dependency(self, dependent: str, provider: str,
                       criticality: float = 0.5) -> None:
        for org in [dependent, provider]:
            if org not in self._org_meta:
                self.add_org(org)
        self._adj.setdefault(dependent, []).append((provider, criticality))
        if _HAS_NX:
            self._graph.add_edge(dependent, provider, criticality=criticality)
            if self._graph.number_of_nodes() > 1:
                self._pagerank = nx.pagerank(self._graph, weight="criticality")

    def simulate_cascade(self, origin_org: str, failure_type: str = "ransomware") -> Dict:
        base_p = _FAILURE_PROP_P.get(failure_type, 0.50)
        if origin_org not in self._org_meta:
            self.add_org(origin_org)

        if _HAS_NX and self._graph.number_of_nodes() > 0:
            counts = self._monte_carlo_nx(origin_org, base_p)
        else:
            counts = self._monte_carlo_fallback(origin_org, base_p)

        mean_aff = sum(counts) / len(counts)
        variance = sum((x - mean_aff) ** 2 for x in counts) / len(counts)
        std_aff  = math.sqrt(variance)

        origin_sector = self._org_meta.get(origin_org, {}).get("sector", "default")
        cost_m = _SECTOR_BREACH_COST_M.get(origin_sector, 4.45)
        financial_impact = int(mean_aff * cost_m * 1_000_000)
        total_orgs = self._graph.number_of_nodes() if _HAS_NX else len(self._org_meta)
        pagerank_score = (self._pagerank.get(origin_org, 0.0)
                          if _HAS_NX and hasattr(self, '_pagerank') else 0.0)
        breach_prob = round(mean_aff / max(total_orgs, 1), 4)

        return {
            "origin":                        origin_org,
            "failure_type":                  failure_type,
            "monte_carlo_runs":              _MONTE_CARLO_RUNS,
            "mean_affected_orgs":            round(mean_aff, 2),
            "std_affected_orgs":             round(std_aff, 2),
            "max_affected_orgs":             max(counts),
            "cascades":                      int(round(mean_aff)),
            "breach_propagation_probability": breach_prob,
            "financial_impact_estimate_usd": financial_impact,
            "estimated_recovery_hours":      int(base_p * 72),
            "total_orgs_in_graph":           total_orgs,
            "origin_pagerank_criticality":   round(pagerank_score, 6),
            "simulated_at":                  time.time(),
            "engine": "MONTE-CARLO-300+" + ("NETWORKX" if _HAS_NX else "ADJ-BFS"),
        }

    def _monte_carlo_nx(self, origin: str, base_p: float) -> List[int]:
        counts: List[int] = []
        if origin not in self._graph:
            self._graph.add_node(origin)
        for _ in range(_MONTE_CARLO_RUNS):
            affected: set = {origin}
            frontier = [origin]
            while frontier:
                nxt = []
                for node in frontier:
                    for nbr in self._graph.successors(node):
                        if nbr in affected: continue
                        crit = self._graph[node][nbr].get("criticality", 0.5)
                        target_res = self._graph.nodes[nbr].get("resilience", 0.5)
                        if (secrets.randbits(16) / 65536) < base_p * crit * (1 - target_res):
                            affected.add(nbr); nxt.append(nbr)
                frontier = nxt
            counts.append(len(affected))
        return counts

    def _monte_carlo_fallback(self, origin: str, base_p: float) -> List[int]:
        counts: List[int] = []
        for _ in range(_MONTE_CARLO_RUNS):
            affected: set = {origin}
            frontier = [origin]
            while frontier:
                nxt = []
                for node in frontier:
                    for (nbr, crit) in self._adj.get(node, []):
                        if nbr in affected: continue
                        res = self._org_meta.get(nbr, {}).get("resilience", 0.5)
                        if (secrets.randbits(16) / 65536) < base_p * crit * (1 - res):
                            affected.add(nbr); nxt.append(nbr)
                frontier = nxt
            counts.append(len(affected))
        return counts

    def predict_propagation(self, org_id: str) -> Dict:
        if _HAS_NX and self._graph.number_of_nodes() > 0 and org_id in self._graph:
            descendants = nx.descendants(self._graph, org_id)
            depth = max((nx.shortest_path_length(self._graph, org_id, d)
                         for d in descendants), default=0)
            pagerank_score = self._pagerank.get(org_id, 0.0) if hasattr(self, '_pagerank') else 0.0
            at_risk = len(descendants)
        else:
            at_risk = len(self._adj.get(org_id, []))
            depth = 1 if at_risk > 0 else 0
            pagerank_score = 0.0
        propagation_risk = min(1.0, 0.3 + pagerank_score * 5 + depth * 0.08)
        return {
            "org_id": org_id, "at_risk_dependencies": at_risk,
            "predicted_cascade_depth": depth,
            "pagerank_criticality": round(pagerank_score, 6),
            "propagation_risk": round(propagation_risk, 4),
            "mitigation": (
                f"URGENT: Isolate {org_id} — {at_risk} orgs at risk."
                if propagation_risk > 0.6 else
                f"Monitor {org_id} closely. {at_risk} downstream orgs may be affected."
            ),
            "predicted_at": time.time(),
        }
