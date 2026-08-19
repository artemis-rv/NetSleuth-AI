import unittest
from pathlib import Path
import json
from copy import deepcopy
from app.shared.contract_validation import ContractValidator
from app.engines.reporting.pdf_renderer import PDFReportRenderer

class TestCrossCasePDFIsolation(unittest.TestCase):
    """
    Mandatory Phase 8 Cross-Case PDF Data Isolation and Individual Investigation Scoping Test.
    Ensures that PDF export for Case A contains ONLY Case A data and NO Case B data, and vice versa.
    """

    def setUp(self):
        self.validator = ContractValidator()
        self.renderer = PDFReportRenderer(self.validator)

        fixtures_dir = Path(__file__).resolve().parent.parent.parent.parent / "fixtures"
        v1_1_path = fixtures_dir / "reports" / "report-v1.1-valid.json"
        
        with open(v1_1_path, "r", encoding="utf-8") as f:
            base_report = json.load(f)

        # Baseline Report V1.1 for Case A
        self.case_a_report = deepcopy(base_report)
        self.case_a_report["report_id"] = "11111111-1111-1111-1111-111111111111"
        self.case_a_report["case_id"] = "aaaaa111-aaaa-1111-aaaa-111111111111"
        self.case_a_report["summary"]["case_title"] = "Case Alpha Forensic Investigation"
        self.case_a_report["findings"][0]["finding_id"] = "finding-alpha-001"
        self.case_a_report["findings"][0]["title"] = "Alpha Malicious Payload Detected"
        self.case_a_report["mitre_mappings"][0]["technique_id"] = "T1190"

        # Baseline Report V1.1 for Case B
        self.case_b_report = deepcopy(base_report)
        self.case_b_report["report_id"] = "22222222-2222-2222-2222-222222222222"
        self.case_b_report["case_id"] = "bbbbb222-bbbb-2222-bbbb-222222222222"
        self.case_b_report["summary"]["case_title"] = "Case Beta Ransomware Incident"
        self.case_b_report["findings"][0]["finding_id"] = "finding-beta-999"
        self.case_b_report["findings"][0]["title"] = "Beta Encryption Activity Observed"
        self.case_b_report["mitre_mappings"][0]["technique_id"] = "T1486"

    def test_case_a_pdf_contains_only_case_a_data(self):
        pdf_bytes_a = self.renderer.render(self.case_a_report)
        self.assertTrue(pdf_bytes_a.startswith(b"%PDF-"))
        self.assertTrue(b"%%EOF" in pdf_bytes_a)
        
        pdf_text_a = pdf_bytes_a.decode("latin-1", errors="replace")

        # Assert Case A data present
        self.assertIn("Case Alpha Forensic Investigation", pdf_text_a)
        self.assertIn("aaaaa111-aaaa-1111-aaaa-111111111111", pdf_text_a)
        self.assertIn("finding-alpha-001", pdf_text_a)
        self.assertIn("Alpha Malicious Payload Detected", pdf_text_a)
        self.assertIn("T1190", pdf_text_a)

        # Assert Case B data STRICTLY ABSENT
        self.assertNotIn("Case Beta Ransomware Incident", pdf_text_a)
        self.assertNotIn("bbbbb222-bbbb-2222-bbbb-222222222222", pdf_text_a)
        self.assertNotIn("finding-beta-999", pdf_text_a)
        self.assertNotIn("Beta Encryption Activity Observed", pdf_text_a)
        self.assertNotIn("T1486", pdf_text_a)

    def test_case_b_pdf_contains_only_case_b_data(self):
        pdf_bytes_b = self.renderer.render(self.case_b_report)
        self.assertTrue(pdf_bytes_b.startswith(b"%PDF-"))
        self.assertTrue(b"%%EOF" in pdf_bytes_b)
        
        pdf_text_b = pdf_bytes_b.decode("latin-1", errors="replace")

        # Assert Case B data present
        self.assertIn("Case Beta Ransomware Incident", pdf_text_b)
        self.assertIn("bbbbb222-bbbb-2222-bbbb-222222222222", pdf_text_b)
        self.assertIn("finding-beta-999", pdf_text_b)
        self.assertIn("Beta Encryption Activity Observed", pdf_text_b)
        self.assertIn("T1486", pdf_text_b)

        # Assert Case A data STRICTLY ABSENT
        self.assertNotIn("Case Alpha Forensic Investigation", pdf_text_b)
        self.assertNotIn("aaaaa111-aaaa-1111-aaaa-111111111111", pdf_text_b)
        self.assertNotIn("finding-alpha-001", pdf_text_b)
        self.assertNotIn("Alpha Malicious Payload Detected", pdf_text_b)
        self.assertNotIn("T1190", pdf_text_b)

if __name__ == "__main__":
    unittest.main()
