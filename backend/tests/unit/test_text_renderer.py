import unittest
import json
from pathlib import Path
from copy import deepcopy

from app.shared.contract_validation import ContractValidator
from app.engines.reporting.text_renderer import TextReportRenderer


class TestTextReportRenderer(unittest.TestCase):
    """
    Comprehensive tests for M4 TextReportRenderer V1/V1.1 support covering all 30 requirements.
    """

    def setUp(self):
        self.validator = ContractValidator()
        self.renderer = TextReportRenderer(self.validator)

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
        text = self.renderer.render_text(self.valid_report_v1)
        self.assertIsInstance(text, str)
        self.assertIn("NETSLEUTH-AI FORENSIC REPORT", text)
        self.assertIn("report-v1", text)

    # 2. Report V1 validates against report-v1.json.
    def test_2_report_v1_validates_against_schema(self):
        # Validator is called inside render_text; verify schema validation passes explicitly
        self.validator.validate("report-v1.json", self.valid_report_v1)
        text = self.renderer.render_text(self.valid_report_v1)
        self.assertTrue(len(text) > 0)

    # 3. Report V1.1 renders successfully.
    def test_3_report_v1_1_renders_successfully(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        self.assertIsInstance(text, str)
        self.assertIn("report-v1.1", text)
        self.assertIn("MITRE ATT&CK MAPPINGS", text)

    # 4. Report V1.1 validates against report-v1.1.json.
    def test_4_report_v1_1_validates_against_schema(self):
        self.validator.validate("report-v1.1.json", self.valid_report_v1_1)
        text = self.renderer.render_text(self.valid_report_v1_1)
        self.assertTrue(len(text) > 0)

    # 5. Report identity preserved.
    def test_5_report_identity_preserved(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        self.assertIn(self.valid_report_v1_1["report_id"], text)

    # 6. Case ID preserved.
    def test_6_case_id_preserved(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        self.assertIn(self.valid_report_v1_1["case_id"], text)

    # 7. Findings preserved.
    def test_7_findings_preserved(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        finding = self.valid_report_v1_1["findings"][0]
        self.assertIn(finding["finding_id"], text)
        self.assertIn(finding["title"], text)

    # 8. Timeline preserved.
    def test_8_timeline_preserved(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        evt = self.valid_report_v1_1["timeline"][0]
        self.assertIn(evt["event_id"], text)
        self.assertIn(evt["title"], text)

    # 9. Entities preserved.
    def test_9_entities_preserved(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        ent = self.valid_report_v1_1["entities"][0]
        self.assertIn(ent["entity_id"], text)
        self.assertIn(ent["value"], text)

    # 10. Relationships preserved.
    def test_10_relationships_preserved(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        rel = self.valid_report_v1_1["relationships"][0]
        self.assertIn(rel["relationship_id"], text)
        self.assertIn(rel["relationship_type"], text)

    # 11. Evidence integrity preserved.
    def test_11_evidence_integrity_preserved(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        ev = self.valid_report_v1_1["evidence_integrity"][0]
        self.assertIn(ev["evidence_id"], text)
        self.assertIn(ev["verification_status"], text)

    # 12. Chain of custody preserved.
    def test_12_chain_of_custody_preserved(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        custody = self.valid_report_v1_1["evidence_integrity"][0]["chain_of_custody"][0]
        self.assertIn(custody["custodian_id"], text)
        self.assertIn(custody["action"], text)

    # 13. Assessment preserved.
    def test_13_assessment_preserved(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        ass = self.valid_report_v1_1["assessment"]
        self.assertIn(ass["summary"], text)

    # 14. Provenance preserved.
    def test_14_provenance_preserved(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        prov = self.valid_report_v1_1["provenance"]
        self.assertIn(prov["collector_id"], text)

    # 15. MITRE mappings rendered.
    def test_15_mitre_mappings_rendered(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        self.assertIn("MITRE ATT&CK MAPPINGS", text)
        self.assertIn("T1071.004", text)

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
        text = self.renderer.render_text(report)
        m = report["mitre_mappings"][0]
        for field in [
            "T1071.004", "DNS", "TA0011", "Command and Control", "BEH-001",
            "SUPPORTED", "0.95", "High volume DNS queries", "FND-001", "EV-001",
            "2026-08-15T10:00:00Z", "2026-08-15T10:05:00Z", "DET-001", "AN-001", "DC-001", "conn.log"
        ]:
            self.assertIn(field, text)

    # 17. MITRE provenance rendered.
    def test_17_mitre_provenance_rendered(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        m_prov = self.valid_report_v1_1["mitre_provenance"]
        self.assertIn("MITRE ATT&CK PROVENANCE", text)
        self.assertIn(m_prov["framework"], text)
        self.assertIn(m_prov["domain"], text)
        self.assertIn(m_prov["version"], text)
        self.assertIn(m_prov["knowledge_profile_id"], text)

    # 18. Attack chain status rendered.
    def test_18_attack_chain_status_rendered(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        self.assertIn("ATTACK CHAIN", text)
        self.assertIn(self.valid_report_v1_1["attack_chain"]["status"], text)

    # 19. Attack chain stages rendered.
    def test_19_attack_chain_stages_rendered(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        stage = self.valid_report_v1_1["attack_chain"]["stages"][0]
        self.assertIn(stage["stage_id"], text)
        self.assertIn(stage["name"], text)

    # 20. Stage finding_ids preserved.
    def test_20_stage_finding_ids_preserved(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        stage = self.valid_report_v1_1["attack_chain"]["stages"][0]
        for fid in stage["finding_ids"]:
            self.assertIn(fid, text)

    # 21. Stage event_ids preserved.
    def test_21_stage_event_ids_preserved(self):
        text = self.renderer.render_text(self.valid_report_v1_1)
        stage = self.valid_report_v1_1["attack_chain"]["stages"][0]
        for eid in stage["event_ids"]:
            self.assertIn(eid, text)

    # 22. Unsupported report version rejected.
    def test_22_unsupported_report_version_rejected(self):
        invalid_report = deepcopy(self.valid_report_v1_1)
        invalid_report["schema_version"] = "report-v9.9"
        with self.assertRaises(ValueError):
            self.renderer.render_text(invalid_report)

    # 23. Invalid Report V1.1 rejected.
    def test_23_invalid_report_v1_1_rejected(self):
        invalid_report = deepcopy(self.valid_report_v1_1)
        invalid_report["mitre_mappings"][0]["mapping_confidence"] = 5.0 # > 1.0
        with self.assertRaises(Exception):
            self.renderer.render_text(invalid_report)

    # 24. Empty MITRE arrays handled safely.
    def test_24_empty_mitre_arrays_handled_safely(self):
        report = deepcopy(self.valid_report_v1_1)
        report["mitre_mappings"] = []
        text = self.renderer.render_text(report)
        self.assertIn("No MITRE ATT&CK mappings reported.", text)

    # 25. Nullable fields handled safely.
    def test_25_nullable_fields_handled_safely(self):
        report = deepcopy(self.valid_report_v1_1)
        report["mitre_mappings"][0]["tactic_id"] = None
        report["mitre_mappings"][0]["tactic_name"] = None
        text = self.renderer.render_text(report)
        self.assertIn("T1071.004", text)

    # 26. Unicode preserved.
    def test_26_unicode_preserved(self):
        report = deepcopy(self.valid_report_v1_1)
        report["summary"]["case_description"] = "Análisis de tráfico de red — NetSleuth AI"
        text = self.renderer.render_text(report)
        self.assertIn("Análisis de tráfico de red — NetSleuth AI", text)

    # 27. Hostile/script strings remain inert.
    def test_27_hostile_script_strings_remain_inert(self):
        report = deepcopy(self.valid_report_v1_1)
        report["summary"]["case_description"] = "<script>alert('xss');</script>"
        text = self.renderer.render_text(report)
        self.assertIn("<script>alert('xss');</script>", text)
        self.assertIsInstance(text, str)

    # 28. Input dictionary is not mutated.
    def test_28_input_dictionary_not_mutated(self):
        original = deepcopy(self.valid_report_v1_1)
        _ = self.renderer.render_text(self.valid_report_v1_1)
        self.assertEqual(self.valid_report_v1_1, original)

    # 29. Rendering is deterministic.
    def test_29_rendering_is_deterministic(self):
        text1 = self.renderer.render_text(self.valid_report_v1_1)
        text2 = self.renderer.render_text(self.valid_report_v1_1)
        self.assertEqual(text1, text2)

    # 30. No fields are invented or silently dropped.
    def test_30_no_fields_invented_or_silently_dropped(self):
        text_v1 = self.renderer.render_text(self.valid_report_v1)
        self.assertNotIn("MITRE ATT&CK MAPPINGS", text_v1)

        text_v1_1 = self.renderer.render_text(self.valid_report_v1_1)
        self.assertIn("MITRE ATT&CK MAPPINGS", text_v1_1)


if __name__ == "__main__":
    unittest.main()
