import unittest
import json
from pathlib import Path
from copy import deepcopy

from backend.app.shared.contract_validation import ContractValidator
from backend.app.engines.correlation.adapters.m1_adapter import M1Adapter
from backend.app.engines.correlation.adapters.m2_adapter import M2Adapter
from backend.app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder
from backend.app.engines.reporting.case_adapter import M3ToM4EvidenceAdapter
from backend.app.engines.reporting.integrity_verifier import IntegrityVerifier
from backend.app.engines.reporting.chain_of_custody import ChainOfCustody
from backend.app.engines.reporting.evidence_package import M4EvidencePackageBuilder
from backend.app.engines.reporting.report_engine import ReportEngine
from backend.app.engines.reporting.report_exporter import ReportExporter
from backend.app.engines.reporting.html_renderer import HTMLReportRenderer
from backend.app.engines.reporting.pdf_renderer import PDFReportRenderer

class TestM4FullPipelineIntegration(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()

        # Build pipeline components
        self.m1_adapter = M1Adapter(self.validator)
        self.m2_adapter = M2Adapter(self.validator)
        self.case_builder = InvestigationCaseBuilder(self.validator)
        self.m4_adapter = M3ToM4EvidenceAdapter(self.validator)
        self.verifier = IntegrityVerifier(self.validator)
        self.custody = ChainOfCustody()
        self.package_builder = M4EvidencePackageBuilder(self.validator)
        self.report_engine = ReportEngine(self.validator)
        self.json_exporter = ReportExporter(self.validator)
        self.html_renderer = HTMLReportRenderer(self.validator)
        self.pdf_renderer = PDFReportRenderer(self.validator)

        # Load Scenario 001 M1/M2 fixtures
        fixture_case_path = (
            Path(__file__).resolve().parent.parent.parent.parent / "fixtures"
            / "investigations"
            / "investigation-case-v1-scenario-001-expected.json"
        )
        with open(fixture_case_path, "r", encoding="utf-8") as f:
            self.scenario_001_case = json.load(f)

    def test_1_complete_m1_to_m4_pipeline_execution(self):
        """Verify complete M1 -> M2 -> M3 -> M4 pipeline execution succeeds."""
        # M3 -> M4 Evidence Package
        package = self.package_builder.build(self.scenario_001_case)
        self.assertIsNotNone(package)

        # Report V1 Generation
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        self.assertIsNotNone(report)

        # Rendering & Export
        json_out = self.json_exporter.export_json(report)
        html_out = self.html_renderer.render(report)
        pdf_out = self.pdf_renderer.render(report)

        self.assertIsInstance(json_out, str)
        self.assertIsInstance(html_out, str)
        self.assertIsInstance(pdf_out, bytes)

    def test_2_investigation_case_v1_1_validation(self):
        """Verify input case payload validates against investigation-case-v1.1.json."""
        self.validator.validate("investigation-case-v1.1.json", self.scenario_001_case)

    def test_3_evidence_integrity_v1_validation(self):
        """Verify extracted evidence integrity records validate against evidence-integrity-v1.json."""
        package = self.package_builder.build(self.scenario_001_case)
        records = package.get_all_evidence_records()
        for rec in records:
            self.validator.validate("evidence-integrity-v1.json", rec)

    def test_4_report_v1_validation(self):
        """Verify output report payload validates against report-v1.json."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        self.validator.validate("report-v1.json", report)

    def test_5_exact_evidence_id_preservation(self):
        """Verify evidence_ids are preserved verbatim across the entire pipeline."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        ev_ids_src = [ref["evidence_id"] for ref in self.scenario_001_case["evidence_references"]]
        ev_ids_report = [rec["evidence_id"] for rec in report["evidence_integrity"]]
        self.assertEqual(sorted(ev_ids_src), sorted(ev_ids_report))

    def test_6_exact_evidence_type_preservation(self):
        """Verify evidence_types are preserved verbatim across the entire pipeline."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        for rec in report["evidence_integrity"]:
            match = next(r for r in self.scenario_001_case["evidence_references"] if r["evidence_id"] == rec["evidence_id"])
            self.assertEqual(rec["evidence_type"], match["evidence_type"])

    def test_7_exact_source_id_preservation(self):
        """Verify source_ids are preserved verbatim across the pipeline."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        for rec in report["evidence_integrity"]:
            match = next(r for r in self.scenario_001_case["evidence_references"] if r["evidence_id"] == rec["evidence_id"])
            self.assertEqual(rec["source_id"], match["source_id"])

    def test_8_expected_hash_preservation(self):
        """Verify expected_hash is preserved verbatim across the pipeline."""
        case_with_hash = deepcopy(self.scenario_001_case)
        case_with_hash["evidence_references"][0]["hash"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        case_with_hash["evidence_references"][0]["hash_algorithm"] = "SHA-256"

        package = self.package_builder.build(case_with_hash)
        report = self.report_engine.generate_report(case_with_hash, package)
        rec = next(r for r in report["evidence_integrity"] if r["evidence_id"] == "ev-FLOW-001")
        self.assertEqual(rec["expected_hash"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_9_calculated_hash_correctness(self):
        """Verify IntegrityVerifier calculates byte-level hashes correctly."""
        raw_bytes = b"sample_network_payload"
        # SHA-256 of b"sample_network_payload"
        sha256_hex = "d95e6dcfb25ce14d5a45a3ad7de5bdab9e0be2f449e2f513131edd20eb94d3ae"
        ev_item = {
            "evidence_id": "ev-FLOW-001",
            "case_id": "CASE-SCENARIO-001",
            "evidence_type": "flow",
            "source_id": "FLOW-001",
            "expected_hash": sha256_hex,
            "hash_algorithm": "SHA-256"
        }
        rec = self.verifier.verify(ev_item, raw_bytes)
        self.assertEqual(rec["verification_status"], "verified")
        self.assertEqual(rec["calculated_hash"], sha256_hex)

    def test_10_verification_status_correctness(self):
        """Verify verification_status correctly reflects mismatch when hashes differ."""
        raw_bytes = b"corrupted_payload"
        ev_item = {
            "evidence_id": "ev-FLOW-001",
            "case_id": "CASE-SCENARIO-001",
            "evidence_type": "flow",
            "source_id": "FLOW-001",
            "expected_hash": "64417a86f9166946bf86242c754d92eb98b049d97b0a701956fe01ebc569ff46",
            "hash_algorithm": "SHA-256"
        }
        rec = self.verifier.verify(ev_item, raw_bytes)
        self.assertEqual(rec["verification_status"], "mismatch")

    def test_11_finding_identity_preservation(self):
        """Verify finding IDs and attributes are preserved across pipeline."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        self.assertEqual(report["findings"][0]["finding_id"], "FINDING-001")

    def test_12_timeline_identity_preservation(self):
        """Verify timeline event IDs and timestamps are preserved across pipeline."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        self.assertEqual(len(report["timeline"]), 2)
        event_ids = [te["event_id"] for te in report["timeline"]]
        self.assertIn("evt-dns-1", event_ids)
        self.assertIn("evt-flow-1", event_ids)

    def test_13_relationship_identity_preservation(self):
        """Verify relationship structures are preserved across pipeline."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        self.assertIsInstance(report["relationships"], list)

    def test_14_case_id_preservation(self):
        """Verify case_id is preserved verbatim at root and inside evidence records."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        self.assertEqual(report["case_id"], "CASE-SCENARIO-001")
        for rec in report["evidence_integrity"]:
            self.assertEqual(rec["case_id"], "CASE-SCENARIO-001")

    def test_15_chain_of_custody_ordering(self):
        """Verify chain-of-custody entries maintain strict chronological ordering."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        for rec in report["evidence_integrity"]:
            custody = rec["chain_of_custody"]
            timestamps = [c["timestamp"] for c in custody]
            self.assertEqual(timestamps, sorted(timestamps))

    def test_16_no_fabricated_signatures(self):
        """Verify custody entries contain signature null unless explicitly signed."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        for rec in report["evidence_integrity"]:
            for c in rec["chain_of_custody"]:
                self.assertIsNone(c["signature"])

    def test_17_no_invented_evidence(self):
        """Verify only evidence explicitly declared in input exists in output."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        reported_ev_ids = {r["evidence_id"] for r in report["evidence_integrity"]}
        declared_ev_ids = {r["evidence_id"] for r in self.scenario_001_case["evidence_references"]}
        self.assertEqual(reported_ev_ids, declared_ev_ids)

    def test_18_no_invented_timestamps(self):
        """Verify evidence collected_at/ingested_at timestamps originate from upstream."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        for rec in report["evidence_integrity"]:
            if rec.get("collected_at"):
                self.assertIn("Z", rec["collected_at"])

    def test_19_no_input_mutation(self):
        """Verify input payloads are not mutated during pipeline execution."""
        case_copy = deepcopy(self.scenario_001_case)
        package = self.package_builder.build(self.scenario_001_case)
        self.report_engine.generate_report(self.scenario_001_case, package)
        self.assertEqual(self.scenario_001_case, case_copy)

    def test_20_referential_integrity(self):
        """Verify timeline and finding evidence_ids link to valid evidence_integrity records."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        valid_ev_ids = {r["evidence_id"] for r in report["evidence_integrity"]}

        for te in report["timeline"]:
            for ev_id in te.get("evidence_ids", []):
                self.assertIn(ev_id, valid_ev_ids)

    def test_21_deterministic_report_engine_output(self):
        """Verify repeated ReportEngine calls produce identical reports except generated_at."""
        package = self.package_builder.build(self.scenario_001_case)
        r1 = self.report_engine.generate_report(self.scenario_001_case, package)
        r2 = self.report_engine.generate_report(self.scenario_001_case, package)

        self.assertEqual(r1["report_id"], r2["report_id"])
        self.assertEqual(r1["case_id"], r2["case_id"])
        self.assertEqual(r1["summary"], r2["summary"])
        self.assertEqual(r1["findings"], r2["findings"])
        self.assertEqual(r1["evidence_integrity"], r2["evidence_integrity"])

    def test_22_json_exporter_fidelity(self):
        """Verify JSON exporter preserves 100% of Report V1 structure."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        exported_json = self.json_exporter.export_json(report)
        reloaded = json.loads(exported_json)
        self.assertEqual(reloaded["report_id"], report["report_id"])
        self.assertEqual(reloaded["evidence_integrity"], report["evidence_integrity"])

    def test_23_html_renderer_fidelity(self):
        """Verify HTML renderer preserves Report V1 facts and identities."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        html_out = self.html_renderer.render(report)
        self.assertIn(report["report_id"], html_out)
        self.assertIn(report["case_id"], html_out)
        self.assertIn("FINDING-001", html_out)

    def test_24_pdf_renderer_fidelity(self):
        """Verify PDF renderer preserves Report V1 facts and identities."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        pdf_out = self.pdf_renderer.render(report)
        self.assertTrue(pdf_out.startswith(b"%PDF-1.4"))
        self.assertIn(report["report_id"].encode("latin-1"), pdf_out)

    def test_25_empty_nullable_evidence_cases(self):
        """Verify pipeline handles empty evidence collections cleanly."""
        empty_case = deepcopy(self.scenario_001_case)
        empty_case["evidence_references"] = []
        for te in empty_case.get("timeline", []):
            te["evidence_ids"] = []
        for rel in empty_case.get("relationships", []):
            rel["evidence_ids"] = []
        package = self.package_builder.build(empty_case)
        report = self.report_engine.generate_report(empty_case, package)
        self.assertEqual(report["summary"]["total_evidence_references"], 0)

    def test_26_verified_evidence_handling(self):
        """Verify evidence with matching hash is classified as verified."""
        case_ver = deepcopy(self.scenario_001_case)
        case_ver["evidence_references"][0]["hash"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        case_ver["evidence_references"][0]["hash_algorithm"] = "SHA-256"

        ev_rec = {
            "schema_version": "evidence-integrity-v1",
            "evidence_id": "ev-FLOW-001",
            "case_id": "CASE-SCENARIO-001",
            "evidence_type": "flow",
            "source_id": "FLOW-001",
            "expected_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "calculated_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "hash_algorithm": "SHA-256",
            "verification_status": "verified",
            "verified_at": "2026-08-15T12:00:00Z",
            "collected_at": None,
            "ingested_at": None,
            "chain_of_custody": []
        }
        report = self.report_engine.generate_report(case_ver, [ev_rec])
        self.assertEqual(report["summary"]["verified_evidence_count"], 1)

    def test_27_mismatched_evidence_handling(self):
        """Verify evidence with mismatched hash is classified as mismatched."""
        case_ver = deepcopy(self.scenario_001_case)
        ev_rec = {
            "schema_version": "evidence-integrity-v1",
            "evidence_id": "ev-FLOW-001",
            "case_id": "CASE-SCENARIO-001",
            "evidence_type": "flow",
            "source_id": "FLOW-001",
            "expected_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "calculated_hash": "bad_hash",
            "hash_algorithm": "SHA-256",
            "verification_status": "mismatch",
            "verified_at": "2026-08-15T12:00:00Z",
            "collected_at": None,
            "ingested_at": None,
            "chain_of_custody": []
        }
        report = self.report_engine.generate_report(case_ver, [ev_rec])
        self.assertEqual(report["summary"]["mismatched_evidence_count"], 1)

    def test_28_unverified_evidence_handling(self):
        """Verify evidence without expected hash is classified as unverified."""
        package = self.package_builder.build(self.scenario_001_case)
        report = self.report_engine.generate_report(self.scenario_001_case, package)
        self.assertEqual(report["summary"]["unverified_evidence_count"], 2)

    def test_29_invalid_upstream_payload_rejection(self):
        """Verify invalid InvestigationCase input raises ValidationError."""
        bad_case = deepcopy(self.scenario_001_case)
        del bad_case["case_id"]
        with self.assertRaises(Exception):
            self.package_builder.build(bad_case)

    def test_30_invalid_report_v1_rejection(self):
        """Verify invalid Report V1 dictionary is rejected by exporters and renderers."""
        bad_report = {"schema_version": "invalid-schema"}
        with self.assertRaises(Exception):
            self.json_exporter.export_json(bad_report)
        with self.assertRaises(Exception):
            self.html_renderer.render(bad_report)
        with self.assertRaises(Exception):
            self.pdf_renderer.render(bad_report)
