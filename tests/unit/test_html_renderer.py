import unittest
import json
from pathlib import Path
from copy import deepcopy

from src.shared.contract_validation import ContractValidator
from src.m4_evidence.html_renderer import HTMLReportRenderer

class TestHTMLReportRenderer(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.renderer = HTMLReportRenderer(self.validator)

        fixture_path = (
            Path(__file__).resolve().parent.parent.parent
            / "fixtures"
            / "reports"
            / "report-v1-valid.json"
        )
        with open(fixture_path, "r", encoding="utf-8") as f:
            self.valid_report = json.load(f)

    def test_1_valid_report_renders_successfully(self):
        """Verify valid Report V1 renders into an HTML string."""
        rendered = self.renderer.render(self.valid_report)
        self.assertIsInstance(rendered, str)
        self.assertIn("<!DOCTYPE html>", rendered)

    def test_2_invalid_report_rejected(self):
        """Verify non-dict report input raises ValueError."""
        with self.assertRaises(ValueError):
            self.renderer.render("not_a_dict")

    def test_3_missing_required_field_rejected(self):
        """Verify report with missing required field raises Exception during validation."""
        bad = deepcopy(self.valid_report)
        del bad["report_id"]
        with self.assertRaises(Exception):
            self.renderer.render(bad)

    def test_4_invalid_enum_rejected(self):
        """Verify report with invalid finding severity enum raises Exception."""
        bad = deepcopy(self.valid_report)
        bad["findings"][0]["severity"] = "super_critical"
        with self.assertRaises(Exception):
            self.renderer.render(bad)

    def test_5_report_id_appears_in_html(self):
        """Verify report_id is rendered in HTML."""
        rendered = self.renderer.render(self.valid_report)
        self.assertIn(self.valid_report["report_id"], rendered)

    def test_6_case_id_appears_in_html(self):
        """Verify case_id is rendered in HTML."""
        rendered = self.renderer.render(self.valid_report)
        self.assertIn(self.valid_report["case_id"], rendered)

    def test_7_findings_appear_in_html(self):
        """Verify finding identity, title, and severity appear in HTML."""
        rendered = self.renderer.render(self.valid_report)
        self.assertIn("FINDING-DNS-001", rendered)
        self.assertIn("High-volume DNS Tunneling Detected", rendered)

    def test_8_timeline_appears_in_html(self):
        """Verify timeline event IDs and timestamps appear in HTML."""
        rendered = self.renderer.render(self.valid_report)
        self.assertIn("EVT-001", rendered)
        self.assertIn("2026-08-15T10:00:00Z", rendered)

    def test_9_entities_appear_in_html(self):
        """Verify entity ID and value appear in HTML."""
        rendered = self.renderer.render(self.valid_report)
        self.assertIn("ent-IP-001", rendered)
        self.assertIn("192.168.1.105", rendered)

    def test_10_relationships_appear_in_html(self):
        """Verify relationship ID and type appear in HTML."""
        rendered = self.renderer.render(self.valid_report)
        self.assertIn("REL-001", rendered)
        self.assertIn("queried", rendered)

    def test_11_evidence_integrity_appears_in_html(self):
        """Verify evidence ID and hashes appear in HTML."""
        rendered = self.renderer.render(self.valid_report)
        self.assertIn("ev-FLOW-001", rendered)
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", rendered)

    def test_12_chain_of_custody_appears_in_html(self):
        """Verify custodian ID and action appear in HTML."""
        rendered = self.renderer.render(self.valid_report)
        self.assertIn("CUSTODIAN-001", rendered)
        self.assertIn("ingest", rendered)

    def test_13_assessment_appears_in_html(self):
        """Verify assessment summary and fact statements appear in HTML."""
        rendered = self.renderer.render(self.valid_report)
        self.assertIn("Confirmed high-confidence DNS tunneling behavior", rendered)
        self.assertIn("FACT-001", rendered)

    def test_14_provenance_appears_in_html(self):
        """Verify provenance acquisition ID and collector ID appear in HTML."""
        rendered = self.renderer.render(self.valid_report)
        self.assertIn("ACQ-001", rendered)
        self.assertIn("COLLECTOR-001", rendered)

    def test_15_empty_arrays_render_safely(self):
        """Verify report with empty findings/timeline/entities renders safely without errors."""
        report_empty = deepcopy(self.valid_report)
        report_empty["findings"] = []
        report_empty["timeline"] = []
        report_empty["entities"] = []
        report_empty["relationships"] = []
        rendered = self.renderer.render(report_empty)
        self.assertIn("No findings recorded", rendered)
        self.assertIn("No timeline events recorded", rendered)

    def test_16_nullable_fields_render_safely(self):
        """Verify null/None fields render safely as dashes without crashing."""
        report_nulls = deepcopy(self.valid_report)
        report_nulls["summary"]["case_description"] = None
        report_nulls["findings"][0]["description"] = None
        report_nulls["findings"][0]["finding_type"] = None
        report_nulls["timeline"][0]["description"] = None
        report_nulls["entities"][0]["namespace"] = None
        del report_nulls["provenance"]
        rendered = self.renderer.render(report_nulls)
        self.assertIsInstance(rendered, str)

    def test_17_unicode_text_is_preserved(self):
        """Verify UTF-8 unicode text is preserved verbatim in HTML output."""
        report_unicode = deepcopy(self.valid_report)
        report_unicode["summary"]["case_title"] = "DNS Tunneling Exfiltration 🔬 🛡️"
        rendered = self.renderer.render(report_unicode)
        self.assertIn("DNS Tunneling Exfiltration 🔬 🛡️", rendered)

    def test_18_html_special_characters_are_escaped(self):
        """Verify HTML special characters <, >, &, quotes are escaped."""
        report_html = deepcopy(self.valid_report)
        report_html["summary"]["case_title"] = "Malware & Ransomware <Alert>"
        rendered = self.renderer.render(report_html)
        self.assertIn("Malware &amp; Ransomware &lt;Alert&gt;", rendered)
        self.assertNotIn("Malware & Ransomware <Alert>", rendered)

    def test_19_script_injection_payload_is_escaped(self):
        """Verify XSS script injection payloads are strictly HTML-escaped."""
        report_xss = deepcopy(self.valid_report)
        report_xss["summary"]["case_description"] = '<script>alert("x")</script><img src=x onerror=alert(1)>'
        rendered = self.renderer.render(report_xss)
        self.assertNotIn('<script>alert("x")</script>', rendered)
        self.assertIn('&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;', rendered)

    def test_20_input_dictionary_is_not_mutated(self):
        """Verify input report dictionary is not mutated during rendering."""
        report_copy = deepcopy(self.valid_report)
        self.renderer.render(self.valid_report)
        self.assertEqual(self.valid_report, report_copy)

    def test_21_repeated_rendering_is_deterministic(self):
        """Verify repeated rendering calls on identical input produce identical HTML string."""
        r1 = self.renderer.render(self.valid_report)
        r2 = self.renderer.render(self.valid_report)
        self.assertEqual(r1, r2)

    def test_22_no_external_network_resources_required(self):
        """Verify HTML document contains zero external http/https CSS or JS script links."""
        rendered = self.renderer.render(self.valid_report)
        self.assertNotIn("http://", rendered)
        self.assertNotIn("https://", rendered)

    def test_23_output_is_complete_html_document(self):
        """Verify rendered string starts with DOCTYPE html and ends with closing html tag."""
        rendered = self.renderer.render(self.valid_report)
        self.assertTrue(rendered.startswith("<!DOCTYPE html>"))
        self.assertTrue(rendered.rstrip().endswith("</html>"))

    def test_24_no_uncontracted_forensic_data_introduced(self):
        """Verify evidence IDs and hashes are preserved exactly without alteration."""
        rendered = self.renderer.render(self.valid_report)
        ev_id = self.valid_report["evidence_integrity"][0]["evidence_id"]
        expected_hash = self.valid_report["evidence_integrity"][0]["expected_hash"]
        self.assertIn(ev_id, rendered)
        self.assertIn(expected_hash, rendered)
