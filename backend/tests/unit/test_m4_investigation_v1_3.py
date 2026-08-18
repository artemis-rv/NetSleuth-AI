import unittest
import json
import os
from copy import deepcopy
from datetime import datetime, timezone

from app.engines.reporting.report_engine import ReportEngine
from app.engines.reporting.case_adapter import M3ToM4EvidenceAdapter
from app.engines.reporting.html_renderer import HTMLReportRenderer
from app.engines.reporting.pdf_renderer import PDFReportRenderer
from app.shared.contract_validation import ContractValidator

def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

class TestM4InvestigationV13(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.report_engine = ReportEngine(self.validator)
        self.adapter = M3ToM4EvidenceAdapter(self.validator)
        self.html_renderer = HTMLReportRenderer(self.validator)
        self.pdf_renderer = PDFReportRenderer(self.validator)
        
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
        self.fixtures_dir = os.path.join(self.project_root, "fixtures")
        
        # We will build a valid V1.3 case in memory based on the V1.2 and adding V1.3 assessment fields
        v1_2_case_path = os.path.join(self.fixtures_dir, "investigations", "investigation-case-v1.2-valid.json")
        self.v1_2_case = load_json(v1_2_case_path)
        self.v1_2_case.pop("assessment", None)
        
        self.v1_3_case = deepcopy(self.v1_2_case)
        self.v1_3_case["schema_version"] = "investigation-case-v1.3"
        self.v1_3_case["assessment"] = {
            "hypotheses": [
                {
                    "hypothesis_id": "HYP-1",
                    "statement": "Attacker compromised host",
                    "hypothesis_type": "Compromise",
                    "status": "SUPPORTED",
                    "confidence": 0.9,
                    "supporting_evidence_ids": ["EV-1"],
                    "supporting_finding_ids": ["FIND-1"],
                    "missing_evidence": []
                }
            ],
            "hypothesis_validations": [
                {
                    "validation_id": "VAL-1",
                    "hypothesis_id": "HYP-1",
                    "validation_status": "VALIDATED",
                    "confidence": 0.9,
                    "supporting_evidence_ids": ["EV-1"],
                    "contradicting_evidence_ids": [],
                    "validated_at": "2026-08-18T10:00:00Z"
                }
            ],
            "root_causes": [
                {
                    "root_cause_id": "RC-1",
                    "statement": "Phishing email",
                    "status": "SUPPORTED",
                    "confidence": 0.95,
                    "supporting_hypothesis_ids": ["HYP-1"],
                    "supporting_evidence_ids": ["EV-1"],
                    "supporting_finding_ids": ["FIND-1"],
                    "missing_evidence": []
                }
            ],
            "impact_assessments": [
                {
                    "impact_id": "IMP-1",
                    "category": "Exfiltration",
                    "statement": "Data was stolen",
                    "status": "INFERRED",
                    "confidence": 0.8,
                    "supporting_evidence_ids": ["EV-1"],
                    "affected_entity_ids": ["ENT-1"],
                    "missing_evidence": []
                }
            ]
        }
        
        self.evidence_records = [
            {
                "schema_version": "evidence-integrity-v1",
                "evidence_id": "EV-1",
                "case_id": self.v1_3_case["case_id"],
                "evidence_type": "pcap",
                "verification_status": "verified"
            }
        ]

    def test_v1_1_behavior_unchanged(self):
        v1_1_case = deepcopy(self.v1_2_case)
        v1_1_case["schema_version"] = "investigation-case-v1.1"
        v1_1_case.pop("mitre_mappings", None)
        v1_1_case.pop("mitre_provenance", None)
        v1_1_case.pop("attack_chain", None)
        
        report = self.report_engine.generate_report(v1_1_case, self.evidence_records)
        self.assertEqual(report["schema_version"], "report-v1")
        
    def test_v1_2_behavior_unchanged(self):
        report = self.report_engine.generate_report(self.v1_2_case, self.evidence_records)
        self.assertEqual(report["schema_version"], "report-v1.2")

    def test_v1_3_routing_and_validation(self):
        input_copy = deepcopy(self.v1_3_case)
        report = self.report_engine.generate_report(self.v1_3_case, self.evidence_records)
        
        self.assertEqual(report["schema_version"], "report-v1.3")
        self.assertEqual(self.v1_3_case, input_copy) # Input immutability
        
        # Verify assessment arrays are correctly passed through
        assm = report["assessment"]
        self.assertEqual(len(assm["hypotheses"]), 1)
        self.assertEqual(assm["hypotheses"][0]["status"], "SUPPORTED")
        
        self.assertEqual(len(assm["hypothesis_validations"]), 1)
        self.assertEqual(assm["hypothesis_validations"][0]["validation_status"], "VALIDATED")
        
        self.assertEqual(len(assm["root_causes"]), 1)
        self.assertEqual(assm["root_causes"][0]["status"], "SUPPORTED")
        
        self.assertEqual(len(assm["impact_assessments"]), 1)
        self.assertEqual(assm["impact_assessments"][0]["status"], "INFERRED")
        
    def test_empty_investigation_arrays_supported(self):
        self.v1_3_case["assessment"]["hypotheses"] = []
        self.v1_3_case["assessment"]["hypothesis_validations"] = []
        self.v1_3_case["assessment"]["root_causes"] = []
        self.v1_3_case["assessment"]["impact_assessments"] = []
        
        report = self.report_engine.generate_report(self.v1_3_case, self.evidence_records)
        self.assertEqual(report["schema_version"], "report-v1.3")
        assm = report["assessment"]
        self.assertEqual(assm["hypotheses"], [])
        self.assertEqual(assm["hypothesis_validations"], [])
        
    def test_unsupported_version_rejected(self):
        self.v1_3_case["schema_version"] = "investigation-case-v1.4"
        with self.assertRaises(ValueError):
            self.report_engine.generate_report(self.v1_3_case, self.evidence_records)

    def test_malformed_v1_3_rejected(self):
        # Break the schema
        self.v1_3_case["assessment"]["hypotheses"][0]["status"] = "INVALID_STATUS"
        with self.assertRaises(Exception): # ContractValidator throws validation error
            self.report_engine.generate_report(self.v1_3_case, self.evidence_records)

    def test_case_adapter_evidence_extraction(self):
        package = self.adapter.adapt(self.v1_3_case)
        # Verify the evidence linkage for EV-1 contains our references, even if implicitly tracked via presence in linkages
        self.assertIn("EV-1", package.linkages)

    def test_html_renderer_security_and_fidelity(self):
        report = self.report_engine.generate_report(self.v1_3_case, self.evidence_records)
        # add hostile string
        report["assessment"]["hypotheses"][0]["statement"] = "<script>alert(1)</script>"
        html_out = self.html_renderer.render(report)
        
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_out)
        self.assertNotIn("<script>", html_out)
        
        # Verify headers exist
        self.assertIn("Investigation Hypotheses", html_out)
        self.assertIn("Hypothesis Validation", html_out)
        self.assertIn("Root Cause Analysis", html_out)
        self.assertIn("Impact Assessment", html_out)

    def test_pdf_renderer_security_and_fidelity(self):
        report = self.report_engine.generate_report(self.v1_3_case, self.evidence_records)
        report["assessment"]["hypotheses"][0]["statement"] = "Normal (string) with \\ escape"
        pdf_out = self.pdf_renderer.render(report)
        
        pdf_str = pdf_out.decode("utf-8", errors="replace")
        
        # Verify escapes
        self.assertIn("Normal", pdf_str)
        self.assertNotIn("Normal (string)", pdf_str)
        
        # Verify headers
        self.assertIn("--- INVESTIGATION HYPOTHESES ---", pdf_str)
        self.assertIn("--- HYPOTHESIS VALIDATION ---", pdf_str)
        self.assertIn("--- ROOT CAUSE ANALYSIS ---", pdf_str)
        self.assertIn("--- IMPACT ASSESSMENT ---", pdf_str)

    def test_determinism(self):
        report1 = self.report_engine.generate_report(self.v1_3_case, self.evidence_records)
        report2 = self.report_engine.generate_report(self.v1_3_case, self.evidence_records)
        
        # Zero out generated_at
        report1["generated_at"] = ""
        report2["generated_at"] = ""
        
        self.assertEqual(report1, report2)
