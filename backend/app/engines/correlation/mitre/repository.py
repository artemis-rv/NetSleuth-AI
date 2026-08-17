import json
import os
from typing import Dict, Any, List

class MitreKnowledgeRepository:
    """
    A read-only repository serving curated MITRE knowledge from the local JSON snapshot.
    """
    def __init__(self, json_path: str = None):
        if json_path is None:
            json_path = os.path.join(
                os.path.dirname(__file__),
                "knowledge/network-evidence-v1.json"
            )
        
        with open(json_path, "r", encoding="utf-8") as f:
            self._data = json.load(f)
            
        self.profile_id = self._data.get("profile_id", "Unknown")
        self.mitre_version = self._data.get("mitre_version", "Unknown")
        
        # Build lookups
        self._mappings_by_behavior = {
            m["behavior_id"]: m for m in self._data.get("netsleuth_curated_mappings", [])
        }
        
        self._techniques = {
            t["external_id"]: t for t in self._data.get("techniques", [])
        }
        
        self._tactics = {
            t["external_id"]: t for t in self._data.get("tactics", [])
        }

        # Resolve Tactic for a technique using native relationships (technique -> tactic is implicitly often handled by kill-chain phases in native stix, but we'll try to find any link or just fallback).
        # Actually in STIX, kill_chain_phases indicate tactics. Let's build a quick mapping from technique to tactic if possible.
        self._technique_to_tactics = {}
        # We don't have full STIX kill_chain_phases here, but let's see if we can resolve via the five profile rules.
        # TA0011 (C2) -> T1071, T1095
        # TA0007 (Discovery) -> T1046
        # TA0010 (Exfiltration) -> T1041
        
        # Resolve Detection strategies and Analytics from curated relationships
        self._tech_to_det = {}
        self._det_to_an = {}
        for rel in self._data.get("netsleuth_curated_relationships", []):
            if rel["type"] == "Technique_to_Detection":
                self._tech_to_det.setdefault(rel["source"], []).append(rel["target"])
            elif rel["type"] == "Detection_to_Analytic":
                self._det_to_an.setdefault(rel["source"], []).append(rel["target"])
                
    def get_behavior_mapping(self, behavior_id: str) -> Dict[str, Any]:
        return self._mappings_by_behavior.get(behavior_id)
        
    def get_technique_details(self, technique_id: str) -> Dict[str, Any]:
        tech = self._techniques.get(technique_id, {})
        # Enrich with Tactic (Hardcoded fallback based on profiles if missing from STIX)
        tactic_id = None
        if technique_id in ["T1071.001", "T1071.004", "T1095"]:
            tactic_id = "TA0011"
        elif technique_id == "T1046":
            tactic_id = "TA0007"
        elif technique_id == "T1041":
            tactic_id = "TA0010"
            
        tactic = self._tactics.get(tactic_id, {}) if tactic_id else {}
        
        dets = self._tech_to_det.get(technique_id, [])
        ans = []
        for det in dets:
            ans.extend(self._det_to_an.get(det, []))
            
        return {
            "id": technique_id,
            "name": tech.get("name", "Unknown"),
            "tactic_id": tactic_id,
            "tactic_name": tactic.get("name"),
            "detection_strategies": dets,
            "analytics": list(set(ans))
        }
