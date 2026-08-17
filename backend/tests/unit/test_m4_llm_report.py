import unittest
import json
import os
from copy import deepcopy
from app.shared.contract_validation import ContractValidator
from app.engines.reporting.report_engine import ReportEngine
from app.engines.reporting.html_renderer import HTMLReportRenderer
from app.engines.reporting.pdf_renderer import PDFReportRenderer

class TestM4LLMReportGeneration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
        cls.validator = ContractValidator()
        cls.report_engine = ReportEngine(cls.validator)
        cls.html_renderer = HTMLReportRenderer(cls.validator)
        cls.pdf_renderer = PDFReportRenderer(cls.validator)
        
        # Load fixtures
        with open(os.path.join(project_root, "fixtures", "investigations", "investigation-case-v1-valid.json")) as f:
            cls.v1_1_case = json.load(f)
            if "assessment" in cls.v1_1_case:
                del cls.v1_1_case["assessment"]
            
        with open(os.path.join(project_root, "fixtures", "investigations", "investigation-case-v1.2-valid.json")) as f:
            cls.v1_2_case = json.load(f)
            if "assessment" in cls.v1_2_case:
                del cls.v1_2_case["assessment"]
            
        cls.llm_enrichment = {
            "status": "SUCCESS",
            "request_id": "REQ-123",
            "case_id": "CASE-123",
            "summary": "This is an AI summary.",
            "mitre_explanations": [
                {
                    "technique_id": "T1071.001",
                    "technique_name": "Web Traffic",
                    "mapping_status": "POTENTIAL",
                    "mapping_confidence": 0.8,
                    "evidence_ids": ["E-1"],
                    "explanation": "C2 Traffic."
                }
            ],
            "investigator_answers": {"Q": "A"},
            "limitations": "May hallucinate.",
            "provenance": {"model": "qwen"}
        }

    def test_01_v1_1_case_produces_v1_report(self):
        report = self.report_engine.generate_report(self.v1_1_case, [])
        self.assertEqual(report["schema_version"], "report-v1")

    def test_02_v1_2_case_without_llm_produces_v1_2_report(self):
        report = self.report_engine.generate_report(self.v1_2_case, [])
        self.assertEqual(report["schema_version"], "report-v1.2")
        self.assertNotIn("llm_enrichment", report)

    def test_03_v1_2_case_with_llm_produces_v1_2_report(self):
        report = self.report_engine.generate_report(self.v1_2_case, [], llm_enrichment=self.llm_enrichment)
        self.assertEqual(report["schema_version"], "report-v1.2")
        self.assertIn("llm_enrichment", report)
        self.assertEqual(report["llm_enrichment"]["summary"], "This is an AI summary.")

    def test_04_llm_unavailable_status_is_valid(self):
        enrichment = dict(self.llm_enrichment)
        enrichment["status"] = "LLM_UNAVAILABLE"
        report = self.report_engine.generate_report(self.v1_2_case, [], llm_enrichment=enrichment)
        self.assertEqual(report["llm_enrichment"]["status"], "LLM_UNAVAILABLE")

    def test_05_llm_model_unavailable_status_is_valid(self):
        enrichment = dict(self.llm_enrichment)
        enrichment["status"] = "LLM_MODEL_UNAVAILABLE"
        report = self.report_engine.generate_report(self.v1_2_case, [], llm_enrichment=enrichment)
        self.assertEqual(report["llm_enrichment"]["status"], "LLM_MODEL_UNAVAILABLE")

    def test_06_llm_invalid_response_status_is_valid(self):
        enrichment = dict(self.llm_enrichment)
        enrichment["status"] = "LLM_INVALID_RESPONSE"
        report = self.report_engine.generate_report(self.v1_2_case, [], llm_enrichment=enrichment)
        self.assertEqual(report["llm_enrichment"]["status"], "LLM_INVALID_RESPONSE")

    def test_07_llm_ungrounded_status_is_valid(self):
        enrichment = dict(self.llm_enrichment)
        enrichment["status"] = "LLM_UNGROUNDED"
        report = self.report_engine.generate_report(self.v1_2_case, [], llm_enrichment=enrichment)
        self.assertEqual(report["llm_enrichment"]["status"], "LLM_UNGROUNDED")

    def test_08_llm_enrichment_copied_without_mutation(self):
        enrichment = deepcopy(self.llm_enrichment)
        report = self.report_engine.generate_report(self.v1_2_case, [], llm_enrichment=enrichment)
        
        # Modify the original dictionary, the report should not change
        enrichment["summary"] = "Mutated summary."
        self.assertEqual(report["llm_enrichment"]["summary"], "This is an AI summary.")

    def test_09_investigation_case_is_unchanged(self):
        case_snapshot = deepcopy(self.v1_2_case)
        self.report_engine.generate_report(self.v1_2_case, [], llm_enrichment=self.llm_enrichment)
        self.assertEqual(self.v1_2_case, case_snapshot)

    def test_10_mitre_mappings_remain_unchanged(self):
        report = self.report_engine.generate_report(self.v1_2_case, [], llm_enrichment=self.llm_enrichment)
        self.assertEqual(len(report["mitre_mappings"]), len(self.v1_2_case["mitre_mappings"]))
        # Just check the first one
        self.assertEqual(report["mitre_mappings"][0]["technique_id"], self.v1_2_case["mitre_mappings"][0]["technique_id"])

    def test_11_attack_chain_remains_unchanged(self):
        report = self.report_engine.generate_report(self.v1_2_case, [], llm_enrichment=self.llm_enrichment)
        self.assertEqual(report["attack_chain"]["status"], self.v1_2_case["attack_chain"]["status"])

    def test_12_evidence_references_remain_unchanged(self):
        report = self.report_engine.generate_report(self.v1_2_case, [], llm_enrichment=self.llm_enrichment)
        # Check an arbitrary finding evidence reference matches source case
        expected_ev = self.v1_2_case["findings"][0].get("evidence_references", [])
        actual_ev = report["findings"][0].get("evidence_references", [])
        self.assertEqual(expected_ev, actual_ev)

    def test_13_html_contains_optional_ai_section(self):
        report = self.report_engine.generate_report(self.v1_2_case, [], llm_enrichment=self.llm_enrichment)
        html_out = self.html_renderer.render(report)
        self.assertIn("<h2>AI-Assisted Narrative</h2>", html_out)
        self.assertIn("This is an AI summary.", html_out)

    def test_14_pdf_contains_optional_ai_section(self):
        report = self.report_engine.generate_report(self.v1_2_case, [], llm_enrichment=self.llm_enrichment)
        pdf_out = self.pdf_renderer.render(report)
        pdf_text = pdf_out.decode("latin-1")
        self.assertIn("--- AI-ASSISTED NARRATIVE ---", pdf_text)
        self.assertIn("This is an AI summary.", pdf_text)

    def test_15_no_llm_enrichment_no_fake_ai_section(self):
        report = self.report_engine.generate_report(self.v1_2_case, [])
        html_out = self.html_renderer.render(report)
        self.assertNotIn("<h2>AI-Assisted Narrative</h2>", html_out)
        pdf_out = self.pdf_renderer.render(report)
        self.assertNotIn("--- AI-ASSISTED NARRATIVE ---", pdf_out.decode("latin-1"))

    def test_16_v1_1_legacy_behavior_unchanged(self):
        report = self.report_engine.generate_report(self.v1_1_case, [])
        html_out = self.html_renderer.render(report)
        self.assertNotIn("<h2>AI-Assisted Narrative</h2>", html_out)
        self.assertIn("schema_version", report)
        self.assertEqual(report["schema_version"], "report-v1")

if __name__ == "__main__":
    unittest.main()
