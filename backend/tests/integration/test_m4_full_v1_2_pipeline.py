import unittest
import json
import os
from pathlib import Path
from copy import deepcopy
from datetime import datetime, timezone

from app.shared.contract_validation import ContractValidator
from app.engines.reporting.case_adapter import M3ToM4EvidenceAdapter
from app.engines.reporting.report_engine import ReportEngine
from app.engines.reporting.report_exporter import ReportExporter
from app.engines.reporting.text_renderer import TextReportRenderer
from app.engines.reporting.html_renderer import HTMLReportRenderer
from app.engines.reporting.pdf_renderer import PDFReportRenderer


class TestM4FullV12PipelineIntegration(unittest.TestCase):
    """
    Comprehensive End-to-End Integration Verification for M4 Evidence & Reporting Engine V1.2.
    Tests complete pipeline: InvestigationCase V1.2 -> M4 Adapter -> ReportEngine -> Report V1.1 -> Exporter/Renderers.
    Covers test families A through P.
    """

    def setUp(self):
        self.validator = ContractValidator()
        self.adapter = M3ToM4EvidenceAdapter(self.validator)
        self.engine = ReportEngine(self.validator)
        self.exporter = ReportExporter(self.validator)
        self.text_renderer = TextReportRenderer(self.validator)
        self.html_renderer = HTMLReportRenderer(self.validator)
        self.pdf_renderer = PDFReportRenderer(self.validator)

        fixtures_dir = Path(__file__).resolve().parent.parent.parent.parent / "fixtures"

        # Load InvestigationCase V1.1 fixture
        v1_1_case_path = fixtures_dir / "investigations" / "investigation-case-v1-valid.json"
        with open(v1_1_case_path, "r", encoding="utf-8") as f:
            self.v1_1_case = json.load(f)

        # Load InvestigationCase V1.2 fixture
        v1_2_case_path = fixtures_dir / "investigations" / "investigation-case-v1.2-valid.json"
        with open(v1_2_case_path, "r", encoding="utf-8") as f:
            self.v1_2_case = json.load(f)

        # Valid EvidenceIntegrity V1 fixture
        self.valid_evidence_records = [
            {
                "schema_version": "evidence-integrity-v1",
                "evidence_id": "ev-001",
                "case_id": "CASE-12345",
                "evidence_type": "flow",
                "source_id": "flow-001",
                "expected_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "calculated_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "hash_algorithm": "SHA-256",
                "verification_status": "verified",
                "verified_at": "2026-08-15T11:00:00Z",
                "collected_at": "2026-08-15T09:45:00Z",
                "ingested_at": "2026-08-15T09:50:00Z",
                "provenance": {
                    "collector_id": "collector-01"
                },
                "chain_of_custody": [
                    {
                        "custodian_id": "sys-01",
                        "action": "ingest",
                        "timestamp": "2026-08-15T09:50:00Z",
                        "signature": None
                    },
                    {
                        "custodian_id": "sys-01",
                        "action": "verify",
                        "timestamp": "2026-08-15T11:00:00Z",
                        "signature": None
                    }
                ]
            }
        ]

    # --- FAMILY A: V1.1 BACKWARD COMPATIBILITY ---
    def test_family_a_v1_1_backward_compatibility(self):
        # Adapt V1.1 case
        pkg = self.adapter.adapt(self.v1_1_case)
        self.assertEqual(pkg.schema_version, "investigation-case-v1.1")

        # Generate report
        report = self.engine.generate_report(self.v1_1_case, self.valid_evidence_records)
        self.assertEqual(report["schema_version"], "report-v1")
        self.validator.validate("report-v1.json", report)

        # Assert no V1.2 MITRE fields in V1.1 report
        self.assertNotIn("mitre_mappings", report)
        self.assertNotIn("mitre_provenance", report)
        self.assertNotIn("attack_chain", report)

        # Verify exporters/renderers accept V1 report
        exported_json = self.exporter.export_json(report)
        self.assertIn("report-v1", exported_json)
        text_out = self.text_renderer.render_text(report)
        self.assertIn("report-v1", text_out)
        html_out = self.html_renderer.render(report)
        self.assertIn("Forensic Investigation Report", html_out)
        pdf_out = self.pdf_renderer.render(report)
        self.assertTrue(pdf_out.startswith(b"%PDF-1.4"))

    # --- FAMILY B: V1.2 REPORT GENERATION ---
    def test_family_b_v1_2_report_generation(self):
        # Adapt V1.2 case
        pkg = self.adapter.adapt(self.v1_2_case)
        self.assertEqual(pkg.schema_version, "investigation-case-v1.2")

        # Generate report V1.2
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_records)
        self.assertEqual(report["schema_version"], "report-v1.2")
        self.validator.validate("report-v1.2.json", report)

        # Verify core V1 fields preserved
        self.assertEqual(report["case_id"], self.v1_2_case["case_id"])
        self.assertEqual(report["summary"]["case_title"], self.v1_2_case["title"])
        self.assertEqual(len(report["findings"]), len(self.v1_2_case["findings"]))
        self.assertEqual(len(report["timeline"]), len(self.v1_2_case["timeline"]))

    # --- FAMILY C: MITRE MAPPING LINEAGE ---
    def test_family_c_mitre_mapping_lineage(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_records)
        self.assertIn("mitre_mappings", report)
        mappings = report["mitre_mappings"]
        self.assertEqual(len(mappings), len(self.v1_2_case["mitre_mappings"]))

        m_in = self.v1_2_case["mitre_mappings"][0]
        m_out = mappings[0]

        # Verify all 16 MITRE fields preserved verbatim
        self.assertEqual(m_out["technique_id"], m_in["technique_id"])
        self.assertEqual(m_out["technique_name"], m_in["technique_name"])
        self.assertEqual(m_out["tactic_id"], m_in["tactic_id"])
        self.assertEqual(m_out["tactic_name"], m_in["tactic_name"])
        self.assertEqual(m_out["behavior_id"], m_in["behavior_id"])
        self.assertEqual(m_out["mapping_status"], m_in["mapping_status"])
        self.assertEqual(m_out["mapping_confidence"], m_in["mapping_confidence"])
        self.assertEqual(m_out["rationale"], m_in["rationale"])
        self.assertEqual(m_out["source_finding_ids"], m_in["source_finding_ids"])
        self.assertEqual(m_out["evidence_ids"], m_in["evidence_ids"])
        self.assertEqual(m_out["first_seen"], m_in["first_seen"])
        self.assertEqual(m_out["last_seen"], m_in["last_seen"])
        self.assertEqual(m_out["detection_strategy_ids"], m_in["detection_strategy_ids"])
        self.assertEqual(m_out["analytic_ids"], m_in["analytic_ids"])
        self.assertEqual(m_out["data_component_ids"], m_in["data_component_ids"])
        self.assertEqual(m_out["channels"], m_in["channels"])

        # Trace into outputs
        json_str = self.exporter.export_json(report)
        text_str = self.text_renderer.render_text(report)
        html_str = self.html_renderer.render(report)
        pdf_bytes = self.pdf_renderer.render(report)

        for field_val in [m_in["technique_id"], m_in["technique_name"], m_in["tactic_id"], m_in["tactic_name"]]:
            self.assertIn(field_val, json_str)
            self.assertIn(field_val, text_str)
            self.assertIn(field_val, html_str)
            self.assertIn(field_val.encode("ascii"), pdf_bytes)

    # --- FAMILY D: MITRE PROVENANCE LINEAGE ---
    def test_family_d_mitre_provenance_lineage(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_records)
        self.assertIn("mitre_provenance", report)
        p_in = self.v1_2_case["mitre_provenance"]
        p_out = report["mitre_provenance"]

        self.assertEqual(p_out["framework"], p_in["framework"])
        self.assertEqual(p_out["domain"], p_in["domain"])
        self.assertEqual(p_out["version"], p_in["version"])
        self.assertEqual(p_out["knowledge_profile_id"], p_in["knowledge_profile_id"])

        text_str = self.text_renderer.render_text(report)
        html_str = self.html_renderer.render(report)
        pdf_bytes = self.pdf_renderer.render(report)

        self.assertIn(p_in["framework"], text_str)
        self.assertIn(p_in["knowledge_profile_id"], html_str)
        self.assertIn(p_in["version"].encode("ascii"), pdf_bytes)

    # --- FAMILY E: ATTACK CHAIN LINEAGE ---
    def test_family_e_attack_chain_lineage(self):
        case = deepcopy(self.v1_2_case)
        case["attack_chain"] = {
            "status": "confirmed",
            "stages": [
                {
                    "stage_id": "STG-01",
                    "name": "Initial Access",
                    "timestamp": "2026-08-15T09:45:00Z",
                    "finding_ids": ["finding-001"],
                    "event_ids": ["evt-001"]
                },
                {
                    "stage_id": "STG-02",
                    "name": "Exfiltration",
                    "timestamp": "2026-08-15T10:00:00Z",
                    "finding_ids": ["finding-001"],
                    "event_ids": ["evt-001"]
                }
            ]
        }

        report = self.engine.generate_report(case, self.valid_evidence_records)
        self.assertIn("attack_chain", report)
        ac = report["attack_chain"]
        self.assertEqual(ac["status"], "confirmed")
        self.assertEqual(len(ac["stages"]), 2)
        self.assertEqual(ac["stages"][0]["stage_id"], "STG-01")
        self.assertEqual(ac["stages"][1]["stage_id"], "STG-02")

        json_str = self.exporter.export_json(report)
        text_str = self.text_renderer.render_text(report)
        html_str = self.html_renderer.render(report)
        pdf_bytes = self.pdf_renderer.render(report)

        self.assertIn("STG-01", json_str)
        self.assertIn("STG-02", text_str)
        self.assertIn("Initial Access", html_str)
        self.assertIn(b"Exfiltration", pdf_bytes)

    # --- FAMILY F: EVIDENCE LINEAGE ---
    def test_family_f_evidence_lineage(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_records)
        self.assertIn("evidence_integrity", report)
        rec = report["evidence_integrity"][0]
        orig = self.valid_evidence_records[0]

        self.assertEqual(rec["evidence_id"], orig["evidence_id"])
        self.assertEqual(rec["evidence_type"], orig["evidence_type"])
        self.assertEqual(rec["source_id"], orig["source_id"])
        self.assertEqual(rec["expected_hash"], orig["expected_hash"])
        self.assertEqual(rec["calculated_hash"], orig["calculated_hash"])
        self.assertEqual(rec["verification_status"], orig["verification_status"])
        self.assertEqual(len(rec["chain_of_custody"]), 2)

    # --- FAMILY G: SUMMARY COUNTER INTEGRITY ---
    def test_family_g_summary_counter_integrity(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_records)
        s = report["summary"]
        total = s["total_evidence_references"]
        verified = s["verified_evidence_count"]
        mismatched = s["mismatched_evidence_count"]
        unverified = s["unverified_evidence_count"]

        self.assertEqual(verified + mismatched + unverified, total)
        self.assertEqual(total, len(report["evidence_integrity"]))

    # --- FAMILY H: JSON FIDELITY ---
    def test_family_h_json_fidelity(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_records)
        exported = self.exporter.export_json(report)
        reloaded = json.loads(exported)

        self.validator.validate("report-v1.2.json", reloaded)
        self.assertEqual(set(reloaded.keys()), set(report.keys()))

    # --- FAMILY I: TEXT FIDELITY ---
    def test_family_i_text_fidelity(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_records)
        text = self.text_renderer.render_text(report)

        self.assertIn("CASE SUMMARY", text)
        self.assertIn("FINDINGS", text)
        self.assertIn("TIMELINE EVENTS", text)
        self.assertIn("ENTITIES", text)
        self.assertIn("RELATIONSHIPS", text)
        self.assertIn("EVIDENCE INTEGRITY & CHAIN OF CUSTODY", text)
        self.assertIn("MITRE ATT&CK MAPPINGS", text)
        self.assertIn("MITRE ATT&CK PROVENANCE", text)
        self.assertIn("ATTACK CHAIN", text)

    # --- FAMILY J: HTML FIDELITY ---
    def test_family_j_html_fidelity(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_records)
        html_doc = self.html_renderer.render(report)

        self.assertTrue(html_doc.startswith("<!DOCTYPE html>"))
        self.assertIn("<h2>Case Summary</h2>", html_doc)
        self.assertIn("<h2>MITRE ATT&CK Findings</h2>", html_doc)
        self.assertIn("<h2>MITRE Provenance</h2>", html_doc)
        self.assertIn("<h2>Attack Chain</h2>", html_doc)

    # --- FAMILY K: PDF FIDELITY ---
    def test_family_k_pdf_fidelity(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_records)
        pdf_bytes = self.pdf_renderer.render(report)

        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertTrue(pdf_bytes.rstrip().endswith(b"%%EOF"))
        self.assertIn(b"NetSleuth-AI Forensic Investigation Report", pdf_bytes)
        self.assertIn(b"MITRE ATT&CK MAPPINGS", pdf_bytes)

    # --- FAMILY L: CONTRACT VALIDATION ---
    def test_family_l_contract_validation(self):
        report_v1 = self.engine.generate_report(self.v1_1_case, self.valid_evidence_records)
        report_v1_1 = self.engine.generate_report(self.v1_2_case, self.valid_evidence_records)

        self.validator.validate("report-v1.json", report_v1)
        self.validator.validate("report-v1.2.json", report_v1_1)

    # --- FAMILY M: INPUT IMMUTABILITY ---
    def test_family_m_input_immutability(self):
        case_copy = deepcopy(self.v1_2_case)
        ev_copy = deepcopy(self.valid_evidence_records)

        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_records)
        _ = self.exporter.export_json(report)
        _ = self.text_renderer.render_text(report)
        _ = self.html_renderer.render(report)
        _ = self.pdf_renderer.render(report)

        self.assertEqual(self.v1_2_case, case_copy)
        self.assertEqual(self.valid_evidence_records, ev_copy)

    # --- FAMILY N: DETERMINISM ---
    def test_family_n_determinism(self):
        rep1 = self.engine.generate_report(self.v1_2_case, self.valid_evidence_records)
        rep2 = self.engine.generate_report(self.v1_2_case, self.valid_evidence_records)

        rep1_norm = deepcopy(rep1)
        rep2_norm = deepcopy(rep2)
        rep1_norm.pop("generated_at")
        rep2_norm.pop("generated_at")
        self.assertEqual(rep1_norm, rep2_norm)

        exp1 = self.exporter.export_json(rep1)
        exp2 = self.exporter.export_json(rep1)
        self.assertEqual(exp1, exp2)

        txt1 = self.text_renderer.render_text(rep1)
        txt2 = self.text_renderer.render_text(rep1)
        self.assertEqual(txt1, txt2)

        htm1 = self.html_renderer.render(rep1)
        htm2 = self.html_renderer.render(rep1)
        self.assertEqual(htm1, htm2)

        pdf1 = self.pdf_renderer.render(rep1)
        pdf2 = self.pdf_renderer.render(rep1)
        self.assertEqual(pdf1, pdf2)

    # --- FAMILY O: NEGATIVE / ERROR HANDLING ---
    def test_family_o_negative_error_handling(self):
        # 1. Unsupported InvestigationCase version
        bad_case = deepcopy(self.v1_2_case)
        bad_case["schema_version"] = "investigation-case-v9.9"
        with self.assertRaises(ValueError):
            self.engine.generate_report(bad_case, self.valid_evidence_records)

        # 2. Invalid MITRE confidence value (> 1.0)
        bad_mitre = deepcopy(self.v1_2_case)
        bad_mitre["mitre_mappings"][0]["mapping_confidence"] = 5.0
        with self.assertRaises(Exception):
            self.engine.generate_report(bad_mitre, self.valid_evidence_records)

        # 3. Invalid attack chain status enum
        bad_ac = deepcopy(self.v1_2_case)
        bad_ac["attack_chain"] = {"status": "INVALID_STATUS"}
        with self.assertRaises(Exception):
            self.engine.generate_report(bad_ac, self.valid_evidence_records)

        # 4. Unsupported Report version in Exporter/Renderers
        bad_report = deepcopy(self.v1_2_case)
        bad_report["schema_version"] = "report-v9.9"
        with self.assertRaises(ValueError):
            self.exporter.export_json(bad_report)
        with self.assertRaises(ValueError):
            self.text_renderer.render_text(bad_report)
        with self.assertRaises(ValueError):
            self.html_renderer.render(bad_report)
        with self.assertRaises(ValueError):
            self.pdf_renderer.render(bad_report)

    # --- FAMILY P: HTML & PDF SECURITY ---
    def test_family_p_html_and_pdf_security(self):
        case_hostile = deepcopy(self.v1_2_case)
        case_hostile["title"] = '<script>alert("xss")</script>'
        case_hostile["mitre_mappings"][0]["rationale"] = '<img src=x onerror=alert(1)>'

        report = self.engine.generate_report(case_hostile, self.valid_evidence_records)

        # HTML Security
        html_out = self.html_renderer.render(report)
        self.assertNotIn('<script>alert("xss")</script>', html_out)
        self.assertIn('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;', html_out)
        self.assertNotIn("<script>", html_out)
        self.assertNotIn('<img src=x onerror=alert(1)>', html_out)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', html_out)

        # PDF Security
        pdf_out = self.pdf_renderer.render(report)
        self.assertNotIn(b"/JavaScript", pdf_out)
        self.assertNotIn(b"/JS", pdf_out)
        self.assertIsInstance(pdf_out, bytes)


if __name__ == "__main__":
    unittest.main()
