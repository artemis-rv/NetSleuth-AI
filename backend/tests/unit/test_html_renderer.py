import unittest
import json
from pathlib import Path
from copy import deepcopy

from app.shared.contract_validation import ContractValidator
from app.engines.reporting.html_renderer import HTMLReportRenderer


class TestHTMLReportRendererVersionAware(unittest.TestCase):
    """
    Comprehensive tests for M4 HTMLReportRenderer V1/V1.1 support covering all 34 requirements.
    """

    def setUp(self):
        self.validator = ContractValidator()
        self.renderer = HTMLReportRenderer(self.validator)

        fixtures_dir = Path(__file__).resolve().parent.parent.parent.parent / "fixtures"

        # Load Report V1.1 fixture
        v1_1_path = fixtures_dir / "reports" / "report-v1.1-valid.json"
        with open(v1_1_path, "r", encoding="utf-8") as f:
            self.valid_report_v1_1 = json.load(f)

        # Create valid Report V1 fixture
        self.valid_report_v1 = deepcopy(self.valid_report_v1_1)
        self.valid_report_v1["schema_version"] = "report-v1"
        self.valid_report_v1.pop("mitre_mappings", None)
        self.valid_report_v1.pop("mitre_provenance", None)
        self.valid_report_v1.pop("attack_chain", None)

    # 1. Report V1 renders successfully.
    def test_1_report_v1_renders_successfully(self):
        rendered = self.renderer.render(self.valid_report_v1)
        self.assertTrue(rendered.startswith("<!DOCTYPE html>"))
        self.assertIn("Forensic Investigation Report", rendered)

    # 2. Report V1 validates against report-v1.json.
    def test_2_report_v1_validates_against_schema(self):
        self.validator.validate("report-v1.json", self.valid_report_v1)
        rendered = self.renderer.render(self.valid_report_v1)
        self.assertTrue(len(rendered) > 0)

    # 3. Report V1.1 renders successfully.
    def test_3_report_v1_1_renders_successfully(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        self.assertTrue(rendered.startswith("<!DOCTYPE html>"))
        self.assertIn("MITRE ATT&CK Findings", rendered)

    # 4. Report V1.1 validates against report-v1.1.json.
    def test_4_report_v1_1_validates_against_schema(self):
        self.validator.validate("report-v1.1.json", self.valid_report_v1_1)
        rendered = self.renderer.render(self.valid_report_v1_1)
        self.assertTrue(len(rendered) > 0)

    # 5. Report ID preserved.
    def test_5_report_id_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        self.assertIn(self.valid_report_v1_1["report_id"], rendered)

    # 6. Case ID preserved.
    def test_6_case_id_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        self.assertIn(self.valid_report_v1_1["case_id"], rendered)

    # 7. Findings preserved.
    def test_7_findings_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        finding = self.valid_report_v1_1["findings"][0]
        self.assertIn(finding["finding_id"], rendered)
        self.assertIn(finding["title"], rendered)

    # 8. Timeline preserved.
    def test_8_timeline_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        evt = self.valid_report_v1_1["timeline"][0]
        self.assertIn(evt["event_id"], rendered)
        self.assertIn(evt["title"], rendered)

    # 9. Entities preserved.
    def test_9_entities_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        ent = self.valid_report_v1_1["entities"][0]
        self.assertIn(ent["entity_id"], rendered)
        self.assertIn(ent["value"], rendered)

    # 10. Relationships preserved.
    def test_10_relationships_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        rel = self.valid_report_v1_1["relationships"][0]
        self.assertIn(rel["relationship_id"], rendered)
        self.assertIn(rel["relationship_type"], rendered)

    # 11. Evidence integrity preserved.
    def test_11_evidence_integrity_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        ev = self.valid_report_v1_1["evidence_integrity"][0]
        self.assertIn(ev["evidence_id"], rendered)
        self.assertIn(ev["verification_status"], rendered)

    # 12. Chain of custody preserved.
    def test_12_chain_of_custody_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        custody = self.valid_report_v1_1["evidence_integrity"][0]["chain_of_custody"][0]
        self.assertIn(custody["custodian_id"], rendered)
        self.assertIn(custody["action"], rendered)

    # 13. Assessment preserved.
    def test_13_assessment_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        ass = self.valid_report_v1_1["assessment"]
        self.assertIn(ass["summary"], rendered)

    # 14. Provenance preserved.
    def test_14_provenance_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        prov = self.valid_report_v1_1["provenance"]
        self.assertIn(prov["collector_id"], rendered)

    # 15. MITRE mappings rendered.
    def test_15_mitre_mappings_rendered(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        self.assertIn("MITRE ATT&CK Findings", rendered)
        self.assertIn("T1071.004", rendered)

    # 16. All 16 MITRE mapping fields preserved.
    def test_16_all_16_mitre_mapping_fields_preserved(self):
        report = deepcopy(self.valid_report_v1_1)
        report["mitre_mappings"] = [
            {
                "technique_id": "T1071.004",
                "technique_name": "DNS",
                "tactic_id": "TA0011",
                "tactic_name": "Command and Control",
                "behavior_id": "BEH-001",
                "mapping_status": "SUPPORTED",
                "mapping_confidence": 0.95,
                "rationale": "High volume DNS queries",
                "source_finding_ids": ["FND-001"],
                "evidence_ids": ["EV-001"],
                "first_seen": "2026-08-15T10:00:00Z",
                "last_seen": "2026-08-15T10:05:00Z",
                "detection_strategy_ids": ["DET-001"],
                "analytic_ids": ["AN-001"],
                "data_component_ids": ["DC-001"],
                "channels": ["conn.log"]
            }
        ]
        rendered = self.renderer.render(report)
        for expected in [
            "T1071.004", "DNS", "TA0011", "Command and Control", "BEH-001",
            "SUPPORTED", "0.95", "High volume DNS queries", "FND-001", "EV-001",
            "2026-08-15T10:00:00Z", "2026-08-15T10:05:00Z", "DET-001", "AN-001", "DC-001", "conn.log"
        ]:
            self.assertIn(expected, rendered)

    # 17. MITRE provenance rendered.
    def test_17_mitre_provenance_rendered(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        m_prov = self.valid_report_v1_1["mitre_provenance"]
        self.assertIn("MITRE Provenance", rendered)
        self.assertIn(m_prov["framework"], rendered)
        self.assertIn(m_prov["domain"], rendered)
        self.assertIn(m_prov["version"], rendered)
        self.assertIn(m_prov["knowledge_profile_id"], rendered)

    # 18. Attack-chain status preserved.
    def test_18_attack_chain_status_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        self.assertIn("Attack Chain", rendered)
        self.assertIn(self.valid_report_v1_1["attack_chain"]["status"], rendered)

    # 19. Attack-chain stages preserved.
    def test_19_attack_chain_stages_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        stage = self.valid_report_v1_1["attack_chain"]["stages"][0]
        self.assertIn(stage["stage_id"], rendered)
        self.assertIn(stage["name"], rendered)

    # 20. Stage finding_ids preserved.
    def test_20_stage_finding_ids_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        stage = self.valid_report_v1_1["attack_chain"]["stages"][0]
        for fid in stage["finding_ids"]:
            self.assertIn(fid, rendered)

    # 21. Stage event_ids preserved.
    def test_21_stage_event_ids_preserved(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        stage = self.valid_report_v1_1["attack_chain"]["stages"][0]
        for eid in stage["event_ids"]:
            self.assertIn(eid, rendered)

    # 22. Unsupported report version rejected.
    def test_22_unsupported_report_version_rejected(self):
        invalid_report = deepcopy(self.valid_report_v1_1)
        invalid_report["schema_version"] = "report-v9.9"
        with self.assertRaises(ValueError):
            self.renderer.render(invalid_report)

    # 23. Invalid Report V1.1 rejected.
    def test_23_invalid_report_v1_1_rejected(self):
        invalid_report = deepcopy(self.valid_report_v1_1)
        invalid_report["mitre_mappings"][0]["mapping_confidence"] = 5.0 # > 1.0
        with self.assertRaises(Exception):
            self.renderer.render(invalid_report)

    # 24. Empty MITRE mappings handled safely.
    def test_24_empty_mitre_mappings_handled_safely(self):
        report = deepcopy(self.valid_report_v1_1)
        report["mitre_mappings"] = []
        rendered = self.renderer.render(report)
        self.assertIn("No MITRE ATT&CK mappings recorded.", rendered)

    # 25. Empty attack chain handled safely.
    def test_25_empty_attack_chain_handled_safely(self):
        report = deepcopy(self.valid_report_v1_1)
        report["attack_chain"]["stages"] = []
        rendered = self.renderer.render(report)
        self.assertIn("No attack chain stages recorded.", rendered)

    # 26. Nullable fields handled safely.
    def test_26_nullable_fields_handled_safely(self):
        report = deepcopy(self.valid_report_v1_1)
        report["mitre_mappings"][0]["tactic_id"] = None
        report["mitre_mappings"][0]["tactic_name"] = None
        rendered = self.renderer.render(report)
        self.assertIn("T1071.004", rendered)

    # 27. Unicode preserved.
    def test_27_unicode_preserved(self):
        report = deepcopy(self.valid_report_v1_1)
        report["summary"]["case_title"] = "Accès non autorisé 🔒 - Investigative Team"
        rendered = self.renderer.render(report)
        self.assertIn("Accès non autorisé 🔒 - Investigative Team", rendered)

    # 28. Hostile HTML/script strings escaped.
    def test_28_hostile_html_script_strings_escaped(self):
        report = deepcopy(self.valid_report_v1_1)
        report["summary"]["case_title"] = '<script>alert("xss")</script>'
        report["mitre_mappings"][0]["rationale"] = '<img src=x onerror=alert(1)>'
        rendered = self.renderer.render(report)
        self.assertNotIn('<script>alert("xss")</script>', rendered)
        self.assertIn('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;', rendered)
        self.assertNotIn('<img src=x onerror=alert(1)>', rendered)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', rendered)

    # 29. No executable script is introduced.
    def test_29_no_executable_script_introduced(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("onload=", rendered)
        self.assertNotIn("onerror=", rendered)

    # 30. No external network resources.
    def test_30_no_external_network_resources(self):
        rendered = self.renderer.render(self.valid_report_v1_1)
        self.assertNotIn("http://", rendered)
        self.assertNotIn("https://", rendered)

    # 31. Input dictionary is not mutated.
    def test_31_input_dictionary_not_mutated(self):
        original = deepcopy(self.valid_report_v1_1)
        _ = self.renderer.render(self.valid_report_v1_1)
        self.assertEqual(self.valid_report_v1_1, original)

    # 32. Rendering is deterministic.
    def test_32_rendering_is_deterministic(self):
        r1 = self.renderer.render(self.valid_report_v1_1)
        r2 = self.renderer.render(self.valid_report_v1_1)
        self.assertEqual(r1, r2)

    # 33. No fields are invented.
    def test_33_no_fields_are_invented(self):
        rendered_v1 = self.renderer.render(self.valid_report_v1)
        self.assertNotIn("MITRE ATT&CK Findings", rendered_v1)

    # 34. No fields are silently dropped.
    def test_34_no_fields_silently_dropped(self):
        rendered_v1_1 = self.renderer.render(self.valid_report_v1_1)
        self.assertIn("MITRE ATT&CK Findings", rendered_v1_1)
        self.assertIn("MITRE Provenance", rendered_v1_1)
        self.assertIn("Attack Chain", rendered_v1_1)


if __name__ == "__main__":
    unittest.main()
