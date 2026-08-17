import json
import os
import unittest

KNOWLEDGE_PATH = os.path.join(
    os.path.dirname(__file__),
    "../../app/engines/correlation/mitre/knowledge/network-evidence-v1.json"
)

class TestMitreKnowledge(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.path.exists(KNOWLEDGE_PATH), "Curated JSON not found")
        with open(KNOWLEDGE_PATH, "r") as f:
            self.data = json.load(f)

    def test_json_loads_and_metadata(self):
        self.assertEqual(self.data["profile_id"], "netsleuth-network-evidence-v1")
        self.assertIn("source_sha256", self.data)
        self.assertNotEqual(self.data["source_sha256"], "")
        self.assertIn("mitre_version", self.data)
        self.assertNotEqual(self.data["mitre_version"], "Unknown")
        self.assertEqual(self.data["mitre_version"], "19.2")
        self.assertEqual(self.data["stix_version"], "2.1")

    def test_exact_five_behaviors(self):
        expected_behaviors = [
            "C2_MALWARE_COMMUNICATION",
            "DNS_ANOMALY_TUNNELING",
            "SCANNING_RECONNAISSANCE",
            "POSSIBLE_EXFILTRATION",
            "SUSPICIOUS_WEB_ACTIVITY"
        ]
        self.assertCountEqual(self.data["behaviors"], expected_behaviors)
        
        mappings = self.data["netsleuth_curated_mappings"]
        mapping_ids = [m["behavior_id"] for m in mappings]
        self.assertCountEqual(mapping_ids, expected_behaviors)
        
        for m in mappings:
            self.assertEqual(m["provenance"], "NETSLEUTH_CURATED")

    def test_t1041_exfiltration_limitation(self):
        mapping = next(m for m in self.data["netsleuth_curated_mappings"] if m["behavior_id"] == "POSSIBLE_EXFILTRATION")
        tech = next(t for t in mapping["candidate_techniques"] if t["id"] == "T1041")
        self.assertEqual(tech["support_level"], "PARTIAL")
        self.assertIn("file access", tech.get("unavailable_telemetry", []))

    def test_t1046_scanning_limitation(self):
        mapping = next(m for m in self.data["netsleuth_curated_mappings"] if m["behavior_id"] == "SCANNING_RECONNAISSANCE")
        tech = next(t for t in mapping["candidate_techniques"] if t["id"] == "T1046")
        self.assertEqual(tech["support_level"], "PARTIAL")
        self.assertIn("auditd", tech.get("unavailable_telemetry", []))
        
    def test_suspicious_web_conditional(self):
        mapping = next(m for m in self.data["netsleuth_curated_mappings"] if m["behavior_id"] == "SUSPICIOUS_WEB_ACTIVITY")
        tech = next(t for t in mapping["candidate_techniques"] if t["id"] == "T1071.001")
        self.assertEqual(tech["mapping_condition"], "CONDITIONAL")
        self.assertNotIn("support_level", tech)
        self.assertIn("Unusual HTTP alone is insufficient", tech["rationale"])

    def test_no_invented_native_relationships(self):
        for rel in self.data.get("native_relationships", []):
            self.assertTrue(rel["source_ref"].startswith("x-mitre") or rel["source_ref"].startswith("attack-pattern"))

    def test_curated_relationships_provenance(self):
        for rel in self.data.get("netsleuth_curated_relationships", []):
            self.assertEqual(rel["provenance"], "NETSLEUTH_CURATED")

    def test_unsupported_telemetry_not_fabricated(self):
        scope = self.data["network_evidence_scope"]
        self.assertIn("conn.log", scope["local_channels"])
        self.assertIn("websocket.log", scope["unavailable_telemetry"])
        self.assertIn("auditd", scope["unavailable_telemetry"])
        
    def test_all_referenced_attack_objects_exist_and_types_are_correct(self):
        tactic_ids = [t["external_id"] for t in self.data["tactics"]]
        for target in ["TA0011", "TA0010", "TA0007"]:
            self.assertIn(target, tactic_ids)
        
        # Techniques must not be course-of-action
        tech_ids = [t["external_id"] for t in self.data["techniques"]]
        for t in ["T1071.001", "T1071.004", "T1095", "T1046", "T1041"]:
            self.assertIn(t, tech_ids)
            # Ensure it starts with attack-pattern
            obj = next(x for x in self.data["techniques"] if x["external_id"] == t)
            self.assertTrue(obj["stix_id"].startswith("attack-pattern"), f"{t} is not an attack-pattern")
            
        det_ids = [t["external_id"] for t in self.data["detection_strategies"]]
        for t in ["DET0027", "DET0400", "DET0376", "DET0348", "DET0457"]:
            self.assertIn(t, det_ids)

        an_ids = [t["external_id"] for t in self.data["analytics"]]
        for t in ["AN0079", "AN1124", "AN1058", "AN1258"]:
            self.assertIn(t, an_ids)
            
        dc_ids = [t["external_id"] for t in self.data["data_components"]]
        for t in ["DC0078", "DC0085"]:
            self.assertIn(t, dc_ids)

if __name__ == "__main__":
    unittest.main()
