import unittest
import json
import os
from copy import deepcopy

from app.engines.reporting.report_engine import ReportEngine
from app.engines.reporting.case_adapter import M3ToM4EvidenceAdapter
from app.engines.reporting.html_renderer import HTMLReportRenderer
from app.engines.reporting.pdf_renderer import PDFReportRenderer
from app.shared.contract_validation import ContractValidator

def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

class TestM4InvestigationV13Integration(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.report_engine = ReportEngine(self.validator)
        self.adapter = M3ToM4EvidenceAdapter(self.validator)
        self.html_renderer = HTMLReportRenderer(self.validator)
        self.pdf_renderer = PDFReportRenderer(self.validator)
        
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
        self.fixtures_dir = os.path.join(self.project_root, "fixtures")
        
        # Load a base case and dynamically augment it for integration testing
        v1_2_case_path = os.path.join(self.fixtures_dir, "investigations", "investigation-case-v1.2-valid.json")
        self.v1_3_case = load_json(v1_2_case_path)
        self.v1_3_case["schema_version"] = "investigation-case-v1.3"
        self.v1_3_case["assessment"] = {
            "hypotheses": [
                {
                    "hypothesis_id": "HYP-1",
                    "statement": "Integrative statement",
                    "hypothesis_type": "Compromise",
                    "status": "POTENTIAL",
                    "confidence": 0.5,
                    "supporting_evidence_ids": ["EV-1"]
                }
            ],
            "hypothesis_validations": [],
            "root_causes": [],
            "impact_assessments": []
        }
        
    def test_pipeline_integration(self):
        # 1. Adapter extracts evidence package
        evidence_package = self.adapter.adapt(self.v1_3_case)
        # Mocking verification status as verified for this test
        evidence_records = [
            {
                "schema_version": "evidence-integrity-v1",
                "evidence_id": "EV-1",
                "case_id": self.v1_3_case["case_id"],
                "evidence_type": "pcap",
                "verification_status": "verified"
            }
        ]
        
        # 2. Report Engine projects the package and generates report
        report = self.report_engine.generate_report(self.v1_3_case, evidence_records)
        
        self.assertEqual(report["schema_version"], "report-v1.3")
        self.assertIn("assessment", report)
        
        # 3. HTML Renderer converts to HTML
        html_out = self.html_renderer.render(report)
        self.assertIn("Investigation Hypotheses", html_out)
        self.assertIn("Integrative statement", html_out)
        
        # 4. PDF Renderer converts to PDF bytes
        pdf_out = self.pdf_renderer.render(report)
        self.assertIsInstance(pdf_out, bytes)
        pdf_str = pdf_out.decode("utf-8", errors="replace")
        self.assertIn("--- INVESTIGATION HYPOTHESES ---", pdf_str)
