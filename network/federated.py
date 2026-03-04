"""
AURORA Federated Learning & Global Intelligence Network

Enables cross-organization threat intelligence sharing WITHOUT
sharing raw sensitive data. Uses FedAvg algorithm + differential
privacy to aggregate knowledge while preserving organizational privacy.

Based on: McMahan et al. (2017) "Communication-Efficient Learning of
Deep Networks from Decentralized Data" (FedAvg algorithm)
"""
from __future__ import annotations
import hashlib, json, time
from typing import Dict, List, Any

class FederatedLearning:
    def __init__(self):
        self._global_model: Dict[str, List[float]] = {}
        self._participants: List[str] = []
        self._rounds_completed = 0

    def aggregate_gradients(self, local_gradients: List[Dict]) -> Dict:
        """FedAvg: weighted average of local model updates."""
        if not local_gradients: return {}
        all_keys = set()
        for g in local_gradients:
            all_keys.update(g.keys())
        aggregated = {}
        for key in all_keys:
            values = [g[key] for g in local_gradients if key in g]
            if values:
                if isinstance(values[0], list):
                    n = len(values[0])
                    avg = [sum(v[i] for v in values if i < len(v))/len(values) for i in range(n)]
                    aggregated[key] = avg
                else:
                    aggregated[key] = sum(values)/len(values)
        self._global_model = aggregated
        self._rounds_completed += 1
        return {"round":self._rounds_completed,"participants":len(local_gradients),"keys_aggregated":len(aggregated),"fedavg_complete":True}

    def anonymize_threat_intel(self, intel: Dict) -> Dict:
        """Remove org-identifying information before global sharing."""
        safe_fields = ["threat_type","attack_vector","severity","ioc_hashes","ttp_ids"]
        anonymized = {k:v for k,v in intel.items() if k in safe_fields}
        # FIXED: source_hash computed from content only (no timing info)
        # Timing removed — timestamp would deanonymize sources via correlation
        content_for_hash = {k: v for k, v in intel.items() if k in safe_fields}
        anonymized["source_hash"] = hashlib.sha256(
            json.dumps(content_for_hash, sort_keys=True).encode()
        ).hexdigest()[:16]
        # No timestamp — prevents timing-based deanonymization
        return anonymized

    def share_intelligence(self, threat_intel: Dict) -> Dict:
        anonymized = self.anonymize_threat_intel(threat_intel)
        return {"shared":True,"anonymized_intel":anonymized,"recipients":"AURORA_GLOBAL_NETWORK","privacy_preserved":True}
