import unittest
import json
from pathlib import Path
from copy import deepcopy

from backend.app.shared.contract_validation import ContractValidator
from backend.app.engines.reporting.evidence_package import M4EvidencePackageBuilder
from backend.app.engines.reporting.report_engine import ReportEngine
from backend.app.engines.reporting.pdf_renderer import PDFReportRenderer

class TestM4PDFRenderingIntegration(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.package_builder = M4EvidencePackageBuilder(self.validator)
        self.engine = ReportEngine(self.validator)
        self.renderer = PDFReportRenderer(self.validator)

        fixture_case_path = (
            Path(__file__).resolve().parent.parent.parent.parent / "fixtures"
            / "investigations"
            / "investigation-case-v1-scenario-001-expected.json"
        )
        with open(fixture_case_path, "r", encoding="utf-8") as f:
            self.case_dict = json.load(f)

        self.evidence_package = self.package_builder.build(self.case_dict)
        self.report_v1 = self.engine.generate_report(self.case_dict, self.evidence_package)

    def test_end_to_end_scenario_001_pdf_rendering(self):
        """Verify full end-to-end PDF rendering from Scenario 001 case payload."""
        pdf_bytes = self.renderer.render(self.report_v1)

        # 1. Valid PDF header and trailer
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertTrue(pdf_bytes.rstrip().endswith(b"%%EOF"))

        # 2. Scenario 001 identities and values represented in PDF stream
        self.assertIn(b"RPT-CASE-SCENARIO-001", pdf_bytes)
        self.assertIn(b"CASE-SCENARIO-001", pdf_bytes)
        self.assertIn(b"FINDING-001", pdf_bytes)
        self.assertIn(b"evt-dns-1", pdf_bytes)
        self.assertIn(b"HOST-001", pdf_bytes)
        self.assertIn(b"ev-FLOW-001", pdf_bytes)
        self.assertIn(b"ev-EVENT-001", pdf_bytes)

    def test_rendering_determinism_and_input_immutability(self):
        """Verify repeated PDF rendering produces deterministic output and input report is not mutated."""
        report_copy = deepcopy(self.report_v1)
        pdf1 = self.renderer.render(self.report_v1)
        pdf2 = self.renderer.render(self.report_v1)

        self.assertEqual(pdf1, pdf2)
        self.assertEqual(self.report_v1, report_copy)
