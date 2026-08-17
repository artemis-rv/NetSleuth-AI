import unittest
import json
from pathlib import Path
from copy import deepcopy

from backend.app.shared.contract_validation import ContractValidator
from backend.app.engines.reporting.evidence_package import M4EvidencePackageBuilder
from backend.app.engines.reporting.report_engine import ReportEngine
from backend.app.engines.reporting.html_renderer import HTMLReportRenderer

class TestM4HTMLRenderingIntegration(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.package_builder = M4EvidencePackageBuilder(self.validator)
        self.engine = ReportEngine(self.validator)
        self.renderer = HTMLReportRenderer(self.validator)

        fixture_case_path = (
            Path(__file__).resolve().parent.parent.parent.parent / "fixtures"
            / "investigations"
            / "investigation-case-v1-scenario-001-expected.json"
        )
        with open(fixture_case_path, "r", encoding="utf-8") as f:
            self.case_dict = json.load(f)

        self.evidence_package = self.package_builder.build(self.case_dict)
        self.report_v1 = self.engine.generate_report(self.case_dict, self.evidence_package)

    def test_end_to_end_scenario_001_html_rendering(self):
        """Verify full end-to-end HTML rendering from Scenario 001 case payload."""
        html_doc = self.renderer.render(self.report_v1)

        # 1. Complete HTML structure
        self.assertTrue(html_doc.startswith("<!DOCTYPE html>"))
        self.assertTrue(html_doc.rstrip().endswith("</html>"))

        # 2. Major sections present
        self.assertIn("Case Summary", html_doc)
        self.assertIn("Findings", html_doc)
        self.assertIn("Timeline Events", html_doc)
        self.assertIn("Entities", html_doc)
        self.assertIn("Relationships", html_doc)
        self.assertIn("Evidence Integrity & Chain of Custody", html_doc)

        # 3. Scenario 001 identities and values preserved verbatim
        self.assertIn("RPT-CASE-SCENARIO-001", html_doc)
        self.assertIn("CASE-SCENARIO-001", html_doc)
        self.assertIn("FINDING-001", html_doc)
        self.assertIn("evt-dns-1", html_doc)
        self.assertIn("HOST-001", html_doc)
        self.assertIn("ev-FLOW-001", html_doc)
        self.assertIn("ev-EVENT-001", html_doc)

    def test_rendering_determinism_and_input_immutability(self):
        """Verify repeated rendering yields identical output and input report is not mutated."""
        report_copy = deepcopy(self.report_v1)
        r1 = self.renderer.render(self.report_v1)
        r2 = self.renderer.render(self.report_v1)

        self.assertEqual(r1, r2)
        self.assertEqual(self.report_v1, report_copy)
