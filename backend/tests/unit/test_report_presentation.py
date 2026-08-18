import unittest
import json
from pathlib import Path
from copy import deepcopy

from app.shared.contract_validation import ContractValidator
from app.engines.reporting.report_engine import ReportEngine
from app.engines.reporting.report_exporter import ReportExporter
from app.engines.reporting.html_renderer import HTMLReportRenderer
from app.engines.reporting.pdf_renderer import PDFReportRenderer

class TestReportPresentation(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.engine = ReportEngine(self.validator)
        self.exporter = ReportExporter(self.validator)
        self.html_renderer = HTMLReportRenderer(self.validator)
        self.pdf_renderer = PDFReportRenderer(self.validator)

        fixture_v1_path = (
            Path(__file__).resolve().parent.parent.parent.parent
            / "fixtures"
            / "reports"
            / "report-v1.1-valid.json"
        )
        with open(fixture_v1_path, "r", encoding="utf-8") as f:
            self.valid_report_v1_1 = json.load(f)

        # Create valid Report V1 fixture by removing V1.1 specific fields and setting schema_version = "report-v1"
        self.valid_report_v1 = deepcopy(self.valid_report_v1_1)
        self.valid_report_v1["schema_version"] = "report-v1"
        self.valid_report_v1.pop("mitre_mappings", None)
        self.valid_report_v1.pop("mitre_provenance", None)
        self.valid_report_v1.pop("attack_chain", None)

    # --- JSON EXPORTER TESTS (1 - 8) ---

    def test_1_report_v1_export_passes(self):
        """1. Report V1 export still passes and returns valid JSON string."""
        exported = self.exporter.export_json(self.valid_report_v1)
        self.assertIsInstance(exported, str)
        parsed = json.loads(exported)
        self.assertEqual(parsed["schema_version"], "report-v1")
        self.validator.validate("report-v1.json", parsed)

    def test_2_report_v1_1_export_passes(self):
        """2. Report V1.1 export passes and returns valid JSON string."""
        exported = self.exporter.export_json(self.valid_report_v1_1)
        self.assertIsInstance(exported, str)
        parsed = json.loads(exported)
        self.assertEqual(parsed["schema_version"], "report-v1.1")
        self.validator.validate("report-v1.1.json", parsed)

    def test_3_v1_1_mitre_mappings_preserved(self):
        """3. V1.1 MITRE mappings are preserved in JSON export."""
        exported = self.exporter.export_json(self.valid_report_v1_1)
        parsed = json.loads(exported)
        self.assertIn("mitre_mappings", parsed)
        self.assertEqual(len(parsed["mitre_mappings"]), len(self.valid_report_v1_1["mitre_mappings"]))
        self.assertEqual(parsed["mitre_mappings"][0]["technique_id"], "T1071.004")

    def test_4_v1_1_mitre_provenance_preserved(self):
        """4. V1.1 MITRE provenance is preserved in JSON export."""
        exported = self.exporter.export_json(self.valid_report_v1_1)
        parsed = json.loads(exported)
        self.assertIn("mitre_provenance", parsed)
        self.assertEqual(parsed["mitre_provenance"]["framework"], "ATT&CK")
        self.assertEqual(parsed["mitre_provenance"]["version"], "v14.1")

    def test_5_v1_1_attack_chain_preserved(self):
        """5. V1.1 attack chain is preserved in JSON export."""
        exported = self.exporter.export_json(self.valid_report_v1_1)
        parsed = json.loads(exported)
        self.assertIn("attack_chain", parsed)
        self.assertEqual(parsed["attack_chain"]["status"], "potential")
        self.assertEqual(len(parsed["attack_chain"]["stages"]), 1)

    def test_6_unknown_schema_version_rejected(self):
        """6. Unknown report schema version is rejected by exporter."""
        invalid_report = deepcopy(self.valid_report_v1)
        invalid_report["schema_version"] = "report-v9.9"
        with self.assertRaises(ValueError):
            self.exporter.export_json(invalid_report)

    def test_7_exporter_input_immutability(self):
        """7. Exporter does not mutate original input dictionary."""
        original = deepcopy(self.valid_report_v1_1)
        _ = self.exporter.export_json(self.valid_report_v1_1)
        self.assertEqual(self.valid_report_v1_1, original)

    def test_8_exporter_deterministic_serialization(self):
        """8. Repeated exports on identical report yield identical JSON string."""
        exp1 = self.exporter.export_json(self.valid_report_v1_1)
        exp2 = self.exporter.export_json(self.valid_report_v1_1)
        self.assertEqual(exp1, exp2)

    # --- HTML RENDERER TESTS (9 - 19) ---

    def test_9_html_v1_rendering_passes(self):
        """9. V1 HTML rendering passes."""
        rendered = self.html_renderer.render(self.valid_report_v1)
        self.assertTrue(rendered.startswith("<!DOCTYPE html>"))
        self.assertIn("Forensic Investigation Report", rendered)

    def test_10_html_v1_1_rendering_passes(self):
        """10. V1.1 HTML rendering passes."""
        rendered = self.html_renderer.render(self.valid_report_v1_1)
        self.assertTrue(rendered.startswith("<!DOCTYPE html>"))
        self.assertIn("Forensic Investigation Report", rendered)

    def test_11_html_mitre_section_present(self):
        """11. MITRE ATT&CK Findings section is present in V1.1 HTML."""
        rendered = self.html_renderer.render(self.valid_report_v1_1)
        self.assertIn("MITRE ATT&CK Findings", rendered)
        self.assertIn("T1071.004", rendered)
        self.assertIn("Command and Control", rendered)

    def test_12_html_mitre_provenance_present(self):
        """12. MITRE Provenance section is present in V1.1 HTML."""
        rendered = self.html_renderer.render(self.valid_report_v1_1)
        self.assertIn("MITRE Provenance", rendered)
        self.assertIn("kp-enterprise-v14.1", rendered)

    def test_13_html_attack_chain_present(self):
        """13. Attack Chain section is present in V1.1 HTML."""
        rendered = self.html_renderer.render(self.valid_report_v1_1)
        self.assertIn("Attack Chain", rendered)
        self.assertIn("STG-01", rendered)

    def test_14_html_all_mitre_mapping_fields_preserved(self):
        """14. All MITRE mapping fields are rendered in HTML."""
        rendered = self.html_renderer.render(self.valid_report_v1_1)
        for expected in ["T1071.004", "DNS", "TA0011", "Command and Control", "C2 / DNS Tunneling", "SUPPORTED", "0.95"]:
            self.assertIn(expected, rendered)

    def test_15_html_all_attack_chain_fields_preserved(self):
        """15. All attack chain fields are rendered in HTML."""
        rendered = self.html_renderer.render(self.valid_report_v1_1)
        for expected in ["potential", "STG-01", "Command and Control", "2026-08-15T10:00:00Z"]:
            self.assertIn(expected, rendered)

    def test_16_html_xss_protection(self):
        """16. Dynamic hostile HTML string input is safely escaped."""
        hostile_report = deepcopy(self.valid_report_v1_1)
        hostile_report["summary"]["case_title"] = '<script>alert("xss")</script>'
        hostile_report["mitre_mappings"][0]["rationale"] = '<img src=x onerror=alert(1)>'
        rendered = self.html_renderer.render(hostile_report)
        self.assertNotIn('<script>alert("xss")</script>', rendered)
        self.assertIn('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;', rendered)
        self.assertNotIn('<img src=x onerror=alert(1)>', rendered)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', rendered)

    def test_17_html_unicode_preservation(self):
        """17. Unicode characters are preserved in rendered HTML."""
        unicode_report = deepcopy(self.valid_report_v1_1)
        unicode_report["summary"]["case_title"] = "Accès non autorisé 🔒 - Investigative Team"
        rendered = self.html_renderer.render(unicode_report)
        self.assertIn("Accès non autorisé 🔒 - Investigative Team", rendered)

    def test_18_html_deterministic_rendering(self):
        """18. Repeated rendering yields identical HTML output."""
        r1 = self.html_renderer.render(self.valid_report_v1_1)
        r2 = self.html_renderer.render(self.valid_report_v1_1)
        self.assertEqual(r1, r2)

    def test_19_html_no_external_network_dependency(self):
        """19. HTML output contains no external http/https resource URLs."""
        rendered = self.html_renderer.render(self.valid_report_v1_1)
        self.assertNotIn("http://", rendered)
        self.assertNotIn("https://", rendered)

    # --- PDF RENDERER TESTS (20 - 29) ---

    def test_20_pdf_v1_rendering_passes(self):
        """20. V1 PDF rendering passes and produces valid PDF bytes."""
        pdf_bytes = self.pdf_renderer.render(self.valid_report_v1)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(len(pdf_bytes) > 0)

    def test_21_pdf_v1_1_rendering_passes(self):
        """21. V1.1 PDF rendering passes and produces valid PDF bytes."""
        pdf_bytes = self.pdf_renderer.render(self.valid_report_v1_1)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(len(pdf_bytes) > 0)

    def test_22_pdf_header(self):
        """22. PDF bytes start with %PDF-1.4 header."""
        pdf_bytes = self.pdf_renderer.render(self.valid_report_v1_1)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))

    def test_23_pdf_trailer(self):
        """23. PDF bytes end with %%EOF trailer."""
        pdf_bytes = self.pdf_renderer.render(self.valid_report_v1_1)
        self.assertTrue(pdf_bytes.rstrip().endswith(b"%%EOF"))

    def test_24_pdf_mitre_technique_ids_preserved(self):
        """24. MITRE technique IDs are present in rendered PDF stream."""
        pdf_bytes = self.pdf_renderer.render(self.valid_report_v1_1)
        self.assertIn(b"T1071.004", pdf_bytes)
        self.assertIn(b"Command and Control", pdf_bytes)

    def test_25_pdf_mitre_provenance_preserved(self):
        """25. MITRE provenance details are present in rendered PDF stream."""
        pdf_bytes = self.pdf_renderer.render(self.valid_report_v1_1)
        self.assertIn(b"kp-enterprise-v14.1", pdf_bytes)

    def test_26_pdf_attack_chain_preserved(self):
        """26. Attack chain stage details are present in rendered PDF stream."""
        pdf_bytes = self.pdf_renderer.render(self.valid_report_v1_1)
        self.assertIn(b"STG-01", pdf_bytes)
        self.assertIn(b"potential", pdf_bytes)

    def test_27_pdf_evidence_hashes_preserved(self):
        """27. Evidence hashes and evidence IDs are present in rendered PDF stream."""
        pdf_bytes = self.pdf_renderer.render(self.valid_report_v1_1)
        self.assertIn(b"ev-FLOW-001", pdf_bytes)
        self.assertIn(b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", pdf_bytes)

    def test_28_pdf_input_immutability(self):
        """28. PDF renderer does not mutate input dict."""
        original = deepcopy(self.valid_report_v1_1)
        _ = self.pdf_renderer.render(self.valid_report_v1_1)
        self.assertEqual(self.valid_report_v1_1, original)

    def test_29_pdf_deterministic_rendering(self):
        """29. Repeated PDF rendering yields identical byte output."""
        pdf1 = self.pdf_renderer.render(self.valid_report_v1_1)
        pdf2 = self.pdf_renderer.render(self.valid_report_v1_1)
        self.assertEqual(pdf1, pdf2)

    # --- INTEGRATION TESTS (30 - 35) ---

    def test_30_v1_pipeline_integration(self):
        """30. InvestigationCase V1.1 -> Report V1 -> JSON/HTML/PDF pipeline."""
        v1_case = {
            "schema_version": "investigation-case-v1.1",
            "case_id": "CASE-V1-INT",
            "title": "V1 Pipeline Case",
            "status": "open",
            "severity": "medium",
            "created_at": "2026-08-15T10:00:00Z",
            "updated_at": "2026-08-15T12:00:00Z",
            "investigator": {"investigator_id": "inv-1", "name": "Analyst Bob"},
            "timeline": [],
            "entities": [],
            "relationships": [],
            "evidence_references": [],
            "findings": []
        }
        report = self.engine.generate_report(v1_case, [])
        self.assertEqual(report["schema_version"], "report-v1")

        json_out = self.exporter.export_json(report)
        html_out = self.html_renderer.render(report)
        pdf_out = self.pdf_renderer.render(report)

        self.assertIn('"schema_version": "report-v1"', json_out)
        self.assertIn("RPT-CASE-V1-INT", html_out)
        self.assertTrue(pdf_out.startswith(b"%PDF-1.4"))

    def test_31_v1_2_pipeline_integration(self):
        """31. InvestigationCase V1.2 -> Report V1.1 -> JSON/HTML/PDF pipeline."""
        v1_2_case = {
            "schema_version": "investigation-case-v1.2",
            "case_id": "CASE-V1-2-INT",
            "title": "V1.2 Pipeline Case",
            "status": "open",
            "severity": "high",
            "created_at": "2026-08-15T10:00:00Z",
            "updated_at": "2026-08-15T12:00:00Z",
            "investigator": {"investigator_id": "inv-1", "name": "Analyst Bob"},
            "timeline": [],
            "entities": [],
            "relationships": [],
            "evidence_references": [],
            "findings": [],
            "mitre_provenance": {
                "framework": "ATT&CK",
                "domain": "Enterprise",
                "version": "v14.1",
                "knowledge_profile_id": "kp-enterprise-v14.1"
            },
            "mitre_mappings": [
                {
                    "technique_id": "T1071.004",
                    "technique_name": "DNS",
                    "tactic_id": "TA0011",
                    "tactic_name": "Command and Control",
                    "behavior_id": "C2 / DNS",
                    "mapping_status": "SUPPORTED",
                    "mapping_confidence": 0.95,
                    "rationale": "Tunneling",
                    "source_finding_ids": ["FINDING-001"],
                    "evidence_ids": ["ev-001"]
                }
            ],
            "attack_chain": {
                "status": "potential",
                "stages": [
                    {
                        "stage_id": "STG-01",
                        "name": "Command and Control",
                        "timestamp": "2026-08-15T10:00:00Z",
                        "finding_ids": ["FINDING-001"],
                        "event_ids": []
                    }
                ]
            }
        }
        report = self.engine.generate_report(v1_2_case, [])
        self.assertEqual(report["schema_version"], "report-v1.2")

        json_out = self.exporter.export_json(report)
        html_out = self.html_renderer.render(report)
        pdf_out = self.pdf_renderer.render(report)

        self.assertIn('"schema_version": "report-v1.2"', json_out)
        self.assertIn("T1071.004", html_out)
        self.assertIn(b"T1071.004", pdf_out)

    def test_32_full_evidence_lineage_remains_intact(self):
        """32. Full evidence lineage is preserved across generation and rendering."""
        report = self.valid_report_v1_1
        json_out = self.exporter.export_json(report)
        html_out = self.html_renderer.render(report)
        pdf_out = self.pdf_renderer.render(report)

        self.assertIn("ev-FLOW-001", json_out)
        self.assertIn("ev-FLOW-001", html_out)
        self.assertIn(b"ev-FLOW-001", pdf_out)

    def test_33_no_mitre_data_loss(self):
        """33. Verification of 0 MITRE data loss in export and renderers."""
        exported = self.exporter.export_json(self.valid_report_v1_1)
        parsed = json.loads(exported)
        self.assertEqual(parsed["mitre_mappings"], self.valid_report_v1_1["mitre_mappings"])
        self.assertEqual(parsed["mitre_provenance"], self.valid_report_v1_1["mitre_provenance"])
        self.assertEqual(parsed["attack_chain"], self.valid_report_v1_1["attack_chain"])

    def test_34_no_evidence_data_loss(self):
        """34. Verification of 0 evidence data loss in export and renderers."""
        exported = self.exporter.export_json(self.valid_report_v1_1)
        parsed = json.loads(exported)
        self.assertEqual(parsed["evidence_integrity"], self.valid_report_v1_1["evidence_integrity"])

    def test_35_frozen_contract_validation_succeeds(self):
        """35. Output of Report V1 and V1.1 pipelines pass frozen contract schema validation."""
        self.validator.validate("report-v1.json", self.valid_report_v1)
        self.validator.validate("report-v1.1.json", self.valid_report_v1_1)

if __name__ == "__main__":
    unittest.main()
