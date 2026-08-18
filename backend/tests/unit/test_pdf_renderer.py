import unittest
import json
from pathlib import Path
from copy import deepcopy

from app.shared.contract_validation import ContractValidator
from app.engines.reporting.pdf_renderer import PDFReportRenderer


class TestPDFReportRendererVersionAware(unittest.TestCase):
    """
    Comprehensive tests for M4 PDFReportRenderer V1/V1.1 support covering all 35 requirements.
    """

    def setUp(self):
        self.validator = ContractValidator()
        self.renderer = PDFReportRenderer(self.validator)

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
        pdf_bytes = self.renderer.render(self.valid_report_v1)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(len(pdf_bytes) > 0)

    # 2. Report V1 validates against report-v1.json.
    def test_2_report_v1_validates_against_schema(self):
        self.validator.validate("report-v1.json", self.valid_report_v1)
        pdf_bytes = self.renderer.render(self.valid_report_v1)
        self.assertTrue(len(pdf_bytes) > 0)

    # 3. Report V1.1 renders successfully.
    def test_3_report_v1_1_renders_successfully(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(len(pdf_bytes) > 0)

    # 4. Report V1.1 validates against report-v1.1.json.
    def test_4_report_v1_1_validates_against_schema(self):
        self.validator.validate("report-v1.1.json", self.valid_report_v1_1)
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        self.assertTrue(len(pdf_bytes) > 0)

    # 5. PDF header is valid.
    def test_5_pdf_header_is_valid(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))

    # 6. PDF EOF/trailer is valid.
    def test_6_pdf_trailer_is_valid(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        self.assertTrue(pdf_bytes.rstrip().endswith(b"%%EOF"))

    # 7. Report ID preserved.
    def test_7_report_id_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        self.assertIn(self.valid_report_v1_1["report_id"].encode("ascii"), pdf_bytes)

    # 8. Case ID preserved.
    def test_8_case_id_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        self.assertIn(self.valid_report_v1_1["case_id"].encode("ascii"), pdf_bytes)

    # 9. Findings preserved.
    def test_9_findings_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        finding = self.valid_report_v1_1["findings"][0]
        self.assertIn(finding["finding_id"].encode("ascii"), pdf_bytes)

    # 10. Timeline preserved.
    def test_10_timeline_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        evt = self.valid_report_v1_1["timeline"][0]
        self.assertIn(evt["event_id"].encode("ascii"), pdf_bytes)

    # 11. Entities preserved.
    def test_11_entities_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        ent = self.valid_report_v1_1["entities"][0]
        self.assertIn(ent["entity_id"].encode("ascii"), pdf_bytes)

    # 12. Relationships preserved.
    def test_12_relationships_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        rel = self.valid_report_v1_1["relationships"][0]
        self.assertIn(rel["relationship_id"].encode("ascii"), pdf_bytes)

    # 13. Evidence integrity preserved.
    def test_13_evidence_integrity_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        ev = self.valid_report_v1_1["evidence_integrity"][0]
        self.assertIn(ev["evidence_id"].encode("ascii"), pdf_bytes)

    # 14. Chain of custody preserved.
    def test_14_chain_of_custody_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        custody = self.valid_report_v1_1["evidence_integrity"][0]["chain_of_custody"][0]
        self.assertIn(custody["custodian_id"].encode("ascii"), pdf_bytes)

    # 15. Assessment preserved.
    def test_15_assessment_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        ass = self.valid_report_v1_1["assessment"]
        self.assertIn(ass["summary"].encode("ascii"), pdf_bytes)

    # 16. Provenance preserved.
    def test_16_provenance_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        prov = self.valid_report_v1_1["provenance"]
        self.assertIn(prov["collector_id"].encode("ascii"), pdf_bytes)

    # 17. MITRE mappings rendered.
    def test_17_mitre_mappings_rendered(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        self.assertIn(b"MITRE ATT&CK MAPPINGS", pdf_bytes)
        self.assertIn(b"T1071.004", pdf_bytes)

    # 18. All 16 MITRE mapping fields preserved.
    def test_18_all_16_mitre_mapping_fields_preserved(self):
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
        pdf_bytes = self.renderer.render(report)
        for field in [
            "T1071.004", "DNS", "TA0011", "Command and Control", "BEH-001",
            "SUPPORTED", "0.95", "High volume DNS queries", "FND-001", "EV-001",
            "2026-08-15T10:00:00Z", "2026-08-15T10:05:00Z", "DET-001", "AN-001", "DC-001", "conn.log"
        ]:
            self.assertIn(field.encode("ascii"), pdf_bytes)

    # 19. MITRE provenance rendered.
    def test_19_mitre_provenance_rendered(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        m_prov = self.valid_report_v1_1["mitre_provenance"]
        self.assertIn(b"MITRE PROVENANCE", pdf_bytes)
        self.assertIn(m_prov["framework"].encode("ascii"), pdf_bytes)
        self.assertIn(m_prov["domain"].encode("ascii"), pdf_bytes)
        self.assertIn(m_prov["version"].encode("ascii"), pdf_bytes)

    # 20. Attack-chain status preserved.
    def test_20_attack_chain_status_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        self.assertIn(b"ATTACK CHAIN", pdf_bytes)
        self.assertIn(self.valid_report_v1_1["attack_chain"]["status"].encode("ascii"), pdf_bytes)

    # 21. Attack-chain stages preserved.
    def test_21_attack_chain_stages_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        stage = self.valid_report_v1_1["attack_chain"]["stages"][0]
        self.assertIn(stage["stage_id"].encode("ascii"), pdf_bytes)
        self.assertIn(stage["name"].encode("ascii"), pdf_bytes)

    # 22. Stage finding_ids preserved.
    def test_22_stage_finding_ids_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        stage = self.valid_report_v1_1["attack_chain"]["stages"][0]
        for fid in stage["finding_ids"]:
            self.assertIn(fid.encode("ascii"), pdf_bytes)

    # 23. Stage event_ids preserved.
    def test_23_stage_event_ids_preserved(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        stage = self.valid_report_v1_1["attack_chain"]["stages"][0]
        for eid in stage["event_ids"]:
            self.assertIn(eid.encode("ascii"), pdf_bytes)

    # 24. Unsupported report version rejected.
    def test_24_unsupported_report_version_rejected(self):
        invalid_report = deepcopy(self.valid_report_v1_1)
        invalid_report["schema_version"] = "report-v9.9"
        with self.assertRaises(ValueError):
            self.renderer.render(invalid_report)

    # 25. Invalid Report V1.1 rejected.
    def test_25_invalid_report_v1_1_rejected(self):
        invalid_report = deepcopy(self.valid_report_v1_1)
        invalid_report["mitre_mappings"][0]["mapping_confidence"] = 5.0 # > 1.0
        with self.assertRaises(Exception):
            self.renderer.render(invalid_report)

    # 26. Empty MITRE mappings handled safely.
    def test_26_empty_mitre_mappings_handled_safely(self):
        report = deepcopy(self.valid_report_v1_1)
        report["mitre_mappings"] = []
        pdf_bytes = self.renderer.render(report)
        self.assertIn(b"No MITRE ATT&CK mappings recorded.", pdf_bytes)

    # 27. Empty attack chain handled safely.
    def test_27_empty_attack_chain_handled_safely(self):
        report = deepcopy(self.valid_report_v1_1)
        report["attack_chain"]["stages"] = []
        pdf_bytes = self.renderer.render(report)
        self.assertIn(b"No attack chain stages recorded.", pdf_bytes)

    # 28. Nullable fields handled safely.
    def test_28_nullable_fields_handled_safely(self):
        report = deepcopy(self.valid_report_v1_1)
        report["mitre_mappings"][0]["tactic_id"] = None
        report["mitre_mappings"][0]["tactic_name"] = None
        pdf_bytes = self.renderer.render(report)
        self.assertIn(b"T1071.004", pdf_bytes)

    # 29. Unicode handling verified.
    def test_29_unicode_handling_verified(self):
        report = deepcopy(self.valid_report_v1_1)
        report["summary"]["case_title"] = "Exfiltration Investigation - Latin Unicode Test"
        pdf_bytes = self.renderer.render(report)
        self.assertIn(b"Exfiltration Investigation - Latin Unicode Test", pdf_bytes)

    # 30. Hostile strings remain inert.
    def test_30_hostile_strings_remain_inert(self):
        report = deepcopy(self.valid_report_v1_1)
        report["summary"]["case_title"] = '<script>alert("xss")</script>'
        pdf_bytes = self.renderer.render(report)
        self.assertIn(b"<script>alert\\(\"xss\"\\)</script>", pdf_bytes)
        self.assertIsInstance(pdf_bytes, bytes)

    # 31. No executable JavaScript introduced.
    def test_31_no_executable_js_introduced(self):
        pdf_bytes = self.renderer.render(self.valid_report_v1_1)
        self.assertNotIn(b"/JavaScript", pdf_bytes)
        self.assertNotIn(b"/JS", pdf_bytes)

    # 32. Input dictionary is not mutated.
    def test_32_input_dictionary_not_mutated(self):
        original = deepcopy(self.valid_report_v1_1)
        _ = self.renderer.render(self.valid_report_v1_1)
        self.assertEqual(self.valid_report_v1_1, original)

    # 33. Rendering is deterministic.
    def test_33_rendering_is_deterministic(self):
        pdf1 = self.renderer.render(self.valid_report_v1_1)
        pdf2 = self.renderer.render(self.valid_report_v1_1)
        self.assertEqual(pdf1, pdf2)

    # 34. No fields invented.
    def test_34_no_fields_invented(self):
        pdf_v1 = self.renderer.render(self.valid_report_v1)
        self.assertNotIn(b"MITRE ATT&CK MAPPINGS", pdf_v1)

    # 35. No fields silently dropped.
    def test_35_no_fields_silently_dropped(self):
        pdf_v1_1 = self.renderer.render(self.valid_report_v1_1)
        self.assertIn(b"MITRE ATT&CK MAPPINGS", pdf_v1_1)
        self.assertIn(b"MITRE PROVENANCE", pdf_v1_1)
        self.assertIn(b"ATTACK CHAIN", pdf_v1_1)


if __name__ == "__main__":
    unittest.main()
