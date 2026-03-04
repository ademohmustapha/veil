"""
AURORA Layer 4 — Blast Radius Prediction & Micro-segmentation
==============================================================
Uses networkx DiGraph BFS when available, adjacency-list BFS as fallback.
A default 9-node topology is seeded on init so the class is immediately usable.

FIXED:
  - _adj always initialised regardless of networkx availability (bug: AttributeError)
  - Default topology seeded so predict() works without manual add_node() calls
  - _bfs_blast_radius fallback path no longer AttributeErrors
"""
from __future__ import annotations
import math, time
from typing import Dict, List, Optional, Set, Tuple

try:
    import networkx as nx
    _HAS_NX = True
except ImportError:
    _HAS_NX = False

_THREAT_SEVERITY: Dict[str, float] = {
    "lateral_movement":    0.75, "ransomware":          0.92,
    "phishing":            0.35, "data_exfil":          0.55,
    "supply_chain_attack": 0.88, "insider_threat":      0.50,
    "apt":                 0.85, "credential_theft":    0.65,
    "zero_day_exploit":    0.80, "dns_tunneling":       0.45,
}


class BlastRadius:
    _DEFAULT_MAX_HOPS = 4

    def __init__(self):
        self._segments: Dict[str, Set[str]] = {}
        self._isolation_rules: List[Tuple[str, str]] = []
        # FIXED: always initialise _adj so fallback path never AttributeErrors
        self._adj: Dict[str, List[str]] = {}
        if _HAS_NX:
            self._graph = nx.DiGraph()
        self._seed_default_topology()

    def _seed_default_topology(self) -> None:
        """Seed a representative 9-node enterprise topology for out-of-box use."""
        nodes = [
            ("dc_primary",    0.95, "core"),
            ("dc_secondary",  0.85, "core"),
            ("app_server_1",  0.70, "app"),
            ("app_server_2",  0.65, "app"),
            ("db_server",     0.90, "data"),
            ("workstation_1", 0.40, "endpoint"),
            ("workstation_2", 0.35, "endpoint"),
            ("vpn_gateway",   0.75, "perimeter"),
            ("cloud_api",     0.60, "cloud"),
        ]
        edges = [
            ("dc_primary", "app_server_1", 0.9),
            ("dc_primary", "app_server_2", 0.8),
            ("dc_primary", "db_server",    0.95),
            ("dc_secondary", "app_server_1", 0.7),
            ("app_server_1", "workstation_1", 0.6),
            ("app_server_2", "workstation_2", 0.5),
            ("vpn_gateway", "dc_primary", 0.8),
            ("cloud_api", "app_server_1", 0.7),
            ("db_server", "dc_secondary", 0.6),
        ]
        for node_id, crit, seg in nodes:
            self.add_node(node_id, criticality=crit, segment=seg)
        for src, dst, trust in edges:
            self.add_edge(src, dst, trust=trust, bidirectional=False)

    def add_node(self, node_id: str, criticality: float = 0.5,
                 segment: str = "default", **attrs) -> None:
        if _HAS_NX:
            self._graph.add_node(node_id, criticality=criticality,
                                  segment=segment, **attrs)
        # Always update _adj too
        self._adj.setdefault(node_id, [])
        self._segments.setdefault(segment, set()).add(node_id)

    def add_edge(self, src: str, dst: str, trust: float = 0.5,
                 bidirectional: bool = True) -> None:
        if _HAS_NX:
            self._graph.add_edge(src, dst, trust=trust)
            if bidirectional:
                self._graph.add_edge(dst, src, trust=trust)
        # Always update _adj too
        self._adj.setdefault(src, []).append(dst)
        if bidirectional:
            self._adj.setdefault(dst, []).append(src)

    def microsegment(self, seg_a: str, seg_b: str) -> bool:
        self._isolation_rules.append((seg_a, seg_b))
        removed = 0
        if _HAS_NX:
            for a in self._segments.get(seg_a, set()):
                for b in self._segments.get(seg_b, set()):
                    if self._graph.has_edge(a, b):
                        self._graph.remove_edge(a, b); removed += 1
                    if self._graph.has_edge(b, a):
                        self._graph.remove_edge(b, a); removed += 1
        return True

    def predict(self, threat_type: str, origin: str = None,
                scope: str = "org", max_hops: int = None) -> float:
        hops = max_hops or self._DEFAULT_MAX_HOPS
        severity = _THREAT_SEVERITY.get(threat_type, 0.40)
        if _HAS_NX and self._graph.number_of_nodes() > 0:
            return self._bfs_blast_radius(origin, severity, hops, scope)
        if self._adj:
            o = origin if origin and origin in self._adj else (list(self._adj)[0] if self._adj else None)
            if o:
                return self._adj_bfs_blast_radius(o, severity, hops)
        return self._heuristic_blast(threat_type, scope)

    def _bfs_blast_radius(self, origin: Optional[str], severity: float,
                           max_hops: int, scope: str) -> float:
        total_nodes = self._graph.number_of_nodes()
        if total_nodes == 0:
            return severity * 0.3
        if origin is None or origin not in self._graph:
            criticalities = nx.get_node_attributes(self._graph, "criticality")
            origin = max(criticalities, key=criticalities.get) if criticalities else \
                     list(self._graph.nodes)[0]
        reachable: Set[str] = set()
        frontier = {origin}
        for _ in range(max_hops):
            nxt: Set[str] = set()
            for node in frontier:
                for nbr in self._graph.successors(node):
                    if nbr not in reachable and nbr != origin:
                        nxt.add(nbr)
            reachable.update(frontier)
            frontier = nxt
            if not frontier:
                break
        reachable_fraction = len(reachable) / total_nodes
        criticalities = nx.get_node_attributes(self._graph, "criticality")
        avg_crit = sum(criticalities.get(n, 0.5) for n in reachable) / max(len(reachable), 1)
        return round(min(1.0, reachable_fraction * severity * (0.5 + 0.5 * avg_crit)), 4)

    def _adj_bfs_blast_radius(self, origin: str, severity: float, max_hops: int) -> float:
        visited: Set[str] = {origin}
        frontier = [origin]
        for _ in range(max_hops):
            nxt = [n for node in frontier for n in self._adj.get(node, []) if n not in visited]
            for n in nxt: visited.add(n)
            frontier = nxt
        fraction = len(visited) / max(len(self._adj), 1)
        return round(min(1.0, fraction * severity), 4)

    def _heuristic_blast(self, threat_type: str, scope: str) -> float:
        severity = _THREAT_SEVERITY.get(threat_type, 0.40)
        mult = {"user": 0.25, "team": 0.45, "org": 0.80, "cross_org": 1.0}
        return round(min(1.0, severity * mult.get(scope, 0.80)), 4)

    def topology_summary(self) -> Dict:
        if _HAS_NX and self._graph.number_of_nodes() > 0:
            return {"nodes": self._graph.number_of_nodes(),
                    "edges": self._graph.number_of_edges(),
                    "segments": {k: len(v) for k, v in self._segments.items()},
                    "isolation_rules": len(self._isolation_rules),
                    "engine": "networkx-BFS"}
        return {"nodes": len(self._adj),
                "segments": {k: len(v) for k, v in self._segments.items()},
                "isolation_rules": len(self._isolation_rules),
                "engine": "adjacency-BFS-fallback"}
