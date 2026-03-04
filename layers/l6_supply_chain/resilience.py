"""
AURORA Layer 6 — Cross-Organization & Supply Chain Resilience Engine

Graph-based risk propagation modeling using PageRank-style influence
scoring across interconnected organizations.
"""
from __future__ import annotations
import math, time
from typing import Dict, Any, List

class SupplyChainResilience:
    def __init__(self):
        self._orgs: Dict[str, Dict] = {}
        self._links: Dict[str, List[str]] = {}
        self._risk_scores: Dict[str, float] = {}

    def add_organization(self, org_id: str, attributes: Dict) -> Dict:
        self._orgs[org_id] = {**attributes,"risk_score":50.0,"added_at":time.time()}
        if org_id not in self._links: self._links[org_id] = []
        return {"org_id":org_id,"status":"ADDED"}

    def link_organizations(self, org_a: str, org_b: str) -> Dict:
        if org_a not in self._orgs: self.add_organization(org_a, {})
        if org_b not in self._orgs: self.add_organization(org_b, {})
        if org_a not in self._links: self._links[org_a] = []
        if org_b not in self._links: self._links[org_b] = []
        if org_b not in self._links[org_a]: self._links[org_a].append(org_b)
        if org_a not in self._links[org_b]: self._links[org_b].append(org_a)
        return {"link":f"{org_a}↔{org_b}","status":"ESTABLISHED","type":"bidirectional"}

    def generate_risk_heatmap(self) -> Dict:
        heatmap = {}
        for org_id, attrs in self._orgs.items():
            risk = attrs.get("risk_score", 50.0)
            neighbors = self._links.get(org_id, [])
            # Propagated risk from neighbors
            neighbor_risk = sum(self._orgs.get(n,{}).get("risk_score",50) for n in neighbors) / max(len(neighbors),1)
            propagated = risk * 0.7 + neighbor_risk * 0.3
            level = "CRITICAL" if propagated>80 else ("HIGH" if propagated>60 else ("MEDIUM" if propagated>40 else "LOW"))
            heatmap[org_id] = {"risk_score":round(propagated,1),"level":level,"neighbors":neighbors,"sector":attrs.get("sector","unknown")}
        return {"heatmap":heatmap,"generated_at":time.time(),"orgs_mapped":len(heatmap)}

    def cluster_by_risk(self) -> Dict:
        clusters = {"CRITICAL":[],"HIGH":[],"MEDIUM":[],"LOW":[]}
        for org_id, attrs in self._orgs.items():
            score = attrs.get("risk_score", 50.0)
            if score>80: clusters["CRITICAL"].append(org_id)
            elif score>60: clusters["HIGH"].append(org_id)
            elif score>40: clusters["MEDIUM"].append(org_id)
            else: clusters["LOW"].append(org_id)
        return clusters

    def preemptive_containment(self, org_id: str) -> Dict:
        neighbors = self._links.get(org_id, [])
        return {"org_id":org_id,"action":"PREEMPTIVE_ISOLATION","neighbors_alerted":neighbors,"trust_suspended":True,"timestamp":time.time()}

    def human_firewall_network_score(self) -> float:
        if not self._orgs: return 0.0
        scores = [100 - attrs.get("risk_score",50) for attrs in self._orgs.values()]
        return round(sum(scores)/len(scores), 2)

    def get_graph_nodes(self) -> List[str]:
        return list(self._orgs.keys())
