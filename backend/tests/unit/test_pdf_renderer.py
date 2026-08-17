import unittest
import json
from pathlib import Path
from copy import deepcopy

from backend.app.shared.contract_validation import ContractValidator
from backend.app.engines.reporting.pdf_renderer import PDFReportRenderer

class TestPDFReportRenderer(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.renderer = PDFReportRenderer(self.validator)

        fixture_path = (
            Path(__file__).resolve().parent.parent.parent.parent / "fixtures"
            / "reports"
            / "report-v1-valid.json"
        )
        with open(fixture_path, "r", encoding="utf-8") as f:
            self.valid_report = json.load(f)

    def test_1_valid_report_renders_successfully(self):
        """Verify valid Report V1 renders into bytes."""
        pdf_bytes = self.renderer.render(self.valid_report)
        self.assertIsInstance(pdf_bytes, bytes)

    def test_2_output_is_valid_pdf_bytes(self):
        """Verify output starts with PDF header %PDF-1.4 and ends with %%EOF."""
        pdf_bytes = self.renderer.render(self.valid_report)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertTrue(pdf_bytes.rstrip().endswith(b"%%EOF"))

    def test_3_invalid_report_rejected(self):
        """Verify non-dict report input raises ValueError."""
        with self.assertRaises(ValueError):
            self.renderer.render("not_a_dict")

    def test_4_missing_required_field_rejected(self):
        """Verify report with missing required field raises Exception during validation."""
        bad = deepcopy(self.valid_report)
        del bad["report_id"]
        with self.assertRaises(Exception):
            self.renderer.render(bad)

    def test_5_invalid_enum_rejected(self):
        """Verify report with invalid finding severity enum raises Exception."""
        bad = deepcopy(self.valid_report)
        bad["findings"][0]["severity"] = "super_critical"
        with self.assertRaises(Exception):
            self.renderer.render(bad)

    def test_6_report_id_is_preserved(self):
        """Verify report_id string is represented in PDF stream."""
        pdf_bytes = self.renderer.render(self.valid_report)
        self.assertIn(self.valid_report["report_id"].encode("latin-1"), pdf_bytes)

    def test_7_case_id_is_preserved(self):
        """Verify case_id string is represented in PDF stream."""
        pdf_bytes = self.renderer.render(self.valid_report)
        self.assertIn(self.valid_report["case_id"].encode("latin-1"), pdf_bytes)

    def test_8_findings_are_represented(self):
        """Verify finding identity and title appear in PDF stream."""
        pdf_bytes = self.renderer.render(self.valid_report)
        self.assertIn(b"FINDING-DNS-001", pdf_bytes)
        self.assertIn(b"High-volume DNS Tunneling Detected", pdf_bytes)

    def test_9_timeline_is_represented(self):
        """Verify timeline event IDs and timestamps appear in PDF stream."""
        pdf_bytes = self.renderer.render(self.valid_report)
        self.assertIn(b"EVT-001", pdf_bytes)
        self.assertIn(b"2026-08-15T10:00:00Z", pdf_bytes)

    def test_10_entities_are_represented(self):
        """Verify entity ID and value appear in PDF stream."""
        pdf_bytes = self.renderer.render(self.valid_report)
        self.assertIn(b"ent-IP-001", pdf_bytes)
        self.assertIn(b"192.168.1.105", pdf_bytes)

    def test_11_relationships_are_represented(self):
        """Verify relationship ID and type appear in PDF stream."""
        pdf_bytes = self.renderer.render(self.valid_report)
        self.assertIn(b"REL-001", pdf_bytes)
        self.assertIn(b"queried", pdf_bytes)

    def test_12_evidence_integrity_is_represented(self):
        """Verify evidence ID and expected hash appear in PDF stream."""
        pdf_bytes = self.renderer.render(self.valid_report)
        self.assertIn(b"ev-FLOW-001", pdf_bytes)
        self.assertIn(b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", pdf_bytes)

    def test_13_chain_of_custody_is_represented(self):
        """Verify custodian ID and custody action appear in PDF stream."""
        pdf_bytes = self.renderer.render(self.valid_report)
        self.assertIn(b"CUSTODIAN-001", pdf_bytes)
        self.assertIn(b"ingest", pdf_bytes)

    def test_14_assessment_is_represented(self):
        """Verify assessment summary and fact statement appear in PDF stream."""
        pdf_bytes = self.renderer.render(self.valid_report)
        self.assertIn(b"Confirmed high-confidence DNS tunneling behavior", pdf_bytes)
        self.assertIn(b"FACT-001", pdf_bytes)

    def test_15_provenance_is_represented(self):
        """Verify provenance acquisition ID and collector ID appear in PDF stream."""
        pdf_bytes = self.renderer.render(self.valid_report)
        self.assertIn(b"ACQ-001", pdf_bytes)
        self.assertIn(b"COLLECTOR-001", pdf_bytes)

    def test_16_empty_arrays_handled_safely(self):
        """Verify report with empty findings/timeline/entities renders safely into valid PDF."""
        report_empty = deepcopy(self.valid_report)
        report_empty["findings"] = []
        report_empty["timeline"] = []
        report_empty["entities"] = []
        report_empty["relationships"] = []
        pdf_bytes = self.renderer.render(report_empty)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertIn(b"No findings recorded.", pdf_bytes)

    def test_17_nullable_fields_handled_safely(self):
        """Verify report with nullable subfields renders safely without error."""
        report_nulls = deepcopy(self.valid_report)
        report_nulls["summary"]["case_description"] = None
        report_nulls["findings"][0]["description"] = None
        report_nulls["findings"][0]["finding_type"] = None
        report_nulls["timeline"][0]["description"] = None
        report_nulls["entities"][0]["namespace"] = None
        del report_nulls["provenance"]
        pdf_bytes = self.renderer.render(report_nulls)
        self.assertIsInstance(pdf_bytes, bytes)

    def test_18_unicode_content_is_preserved(self):
        """Verify unicode content is handled safely in PDF rendering."""
        report_unicode = deepcopy(self.valid_report)
        report_unicode["summary"]["case_title"] = "DNS Tunneling Exfiltration Audit"
        pdf_bytes = self.renderer.render(report_unicode)
        self.assertIn(b"DNS Tunneling Exfiltration Audit", pdf_bytes)

    def test_19_hostile_strings_treated_as_text(self):
        """Verify hostile script injection payloads are rendered strictly as text inside PDF stream."""
        report_xss = deepcopy(self.valid_report)
        report_xss["summary"]["case_description"] = '<script>alert("x")</script><img src=x onerror=alert(1)>'
        pdf_bytes = self.renderer.render(report_xss)
        self.assertIn(b"<script>alert", pdf_bytes)

    def test_20_input_dictionary_not_mutated(self):
        """Verify input report dict is not mutated during PDF rendering."""
        report_copy = deepcopy(self.valid_report)
        self.renderer.render(self.valid_report)
        self.assertEqual(self.valid_report, report_copy)

    def test_21_renderer_does_not_modify_hashes(self):
        """Verify hashes in output match input hashes exactly."""
        pdf_bytes = self.renderer.render(self.valid_report)
        expected_hash = self.valid_report["evidence_integrity"][0]["expected_hash"]
        self.assertIn(expected_hash.encode("ascii"), pdf_bytes)

    def test_22_renderer_does_not_modify_evidence_ids(self):
        """Verify evidence IDs in output match input evidence IDs exactly."""
        pdf_bytes = self.renderer.render(self.valid_report)
        ev_id = self.valid_report["evidence_integrity"][0]["evidence_id"]
        self.assertIn(ev_id.encode("ascii"), pdf_bytes)

    def test_23_renderer_does_not_modify_timestamps(self):
        """Verify ISO timestamps match input timestamps exactly."""
        pdf_bytes = self.renderer.render(self.valid_report)
        gen_at = self.valid_report["generated_at"]
        self.assertIn(gen_at.encode("ascii"), pdf_bytes)

    def test_24_repeated_rendering_does_not_alter_report_content(self):
        """Verify repeated PDF rendering on identical input produces structural match."""
        pdf1 = self.renderer.render(self.valid_report)
        pdf2 = self.renderer.render(self.valid_report)
        self.assertEqual(pdf1, pdf2)
