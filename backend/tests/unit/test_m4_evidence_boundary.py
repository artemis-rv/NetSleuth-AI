import unittest
import json
from pathlib import Path
from copy import deepcopy
import jsonschema

from backend.app.shared.contract_validation import ContractValidator
from backend.app.engines.reporting.case_adapter import M3ToM4EvidenceAdapter
from backend.app.engines.reporting.evidence_model import M4CaseEvidencePackage, M4EvidenceReference

class TestM4EvidenceBoundary(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.adapter = M3ToM4EvidenceAdapter(self.validator)

        fixture_path = (
            Path(__file__).resolve().parent.parent.parent.parent / "fixtures"
            / "investigations"
            / "investigation-case-v1-valid.json"
        )
        with open(fixture_path, "r", encoding="utf-8") as f:
            self.valid_case_payload = json.load(f)

    def test_1_valid_investigation_case_accepted(self):
        """Valid InvestigationCase V1.1 payload is accepted."""
        pkg = self.adapter.adapt(self.valid_case_payload)
        self.assertIsInstance(pkg, M4CaseEvidencePackage)
        self.assertEqual(pkg.case_id, "CASE-12345")
        self.assertEqual(pkg.schema_version, "investigation-case-v1.1")

    def test_2_invalid_investigation_case_rejected(self):
        """Invalid InvestigationCase is rejected during contract validation."""
        invalid_payload = deepcopy(self.valid_case_payload)
        # Remove mandatory required field 'case_id'
        del invalid_payload["case_id"]

        with self.assertRaises(jsonschema.ValidationError):
            self.adapter.adapt(invalid_payload)

    def test_3_evidence_references_preserved_exactly(self):
        """Evidence references are extracted and preserved without alteration."""
        pkg = self.adapter.adapt(self.valid_case_payload)
        self.assertEqual(len(pkg.evidence_references), 1)
        ref = pkg.evidence_references[0]
        self.assertEqual(ref.evidence_id, "ev-001")
        self.assertEqual(ref.evidence_type, "flow")
        self.assertEqual(ref.source_id, "flow-001")

    def test_4_evidence_ids_not_changed(self):
        """Evidence IDs are preserved verbatim."""
        payload = deepcopy(self.valid_case_payload)
        payload["evidence_references"] = [
            {"evidence_id": "ev-custom-999", "evidence_type": "pcap", "source_id": "src-1"}
        ]
        pkg = self.adapter.adapt(payload)
        self.assertEqual(pkg.evidence_references[0].evidence_id, "ev-custom-999")

    def test_5_evidence_types_not_changed(self):
        """Evidence types are preserved verbatim."""
        payload = deepcopy(self.valid_case_payload)
        payload["evidence_references"] = [
            {"evidence_id": "ev-dns-001", "evidence_type": "dns", "source_id": "dns-log-1"}
        ]
        pkg = self.adapter.adapt(payload)
        self.assertEqual(pkg.evidence_references[0].evidence_type, "dns")

    def test_6_provenance_preserved(self):
        """Provenance details (source_id, hash, hash_algorithm) are preserved."""
        payload = deepcopy(self.valid_case_payload)
        payload["evidence_references"] = [
            {
                "evidence_id": "ev-sha-1",
                "evidence_type": "artifact",
                "source_id": "file.bin",
                "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "hash_algorithm": "SHA-256"
            }
        ]
        pkg = self.adapter.adapt(payload)
        ref = pkg.evidence_references[0]
        self.assertEqual(ref.source_id, "file.bin")
        self.assertEqual(ref.hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(ref.hash_algorithm, "SHA-256")

    def test_7_relationship_and_timeline_linkage_preserved(self):
        """Linkages between timeline events, relationships, assessment facts and evidence IDs are preserved."""
        payload = deepcopy(self.valid_case_payload)
        payload["relationships"] = [
            {
                "relationship_id": "rel-001",
                "source_entity_id": "ent-host-1",
                "relationship_type": "connected_to",
                "target_entity_id": "ent-ip-1",
                "confidence": 0.9,
                "evidence_ids": ["ev-001"]
            }
        ]
        pkg = self.adapter.adapt(payload)
        linkage = pkg.linkages["ev-001"]
        self.assertIn("evt-001", linkage.timeline_event_ids)
        self.assertIn("rel-001", linkage.relationship_ids)
        self.assertIn("Host transferred 850MB to 203.0.113.10.", linkage.assessment_fact_statements)

    def test_8_empty_evidence_collection_deterministic(self):
        """Empty evidence collection behaves deterministically without errors."""
        payload = deepcopy(self.valid_case_payload)
        payload["evidence_references"] = []
        payload["timeline"] = []
        payload["relationships"] = []
        payload["assessment"] = {"facts": []}

        pkg = self.adapter.adapt(payload)
        self.assertEqual(len(pkg.evidence_references), 0)
        self.assertEqual(len(pkg.linkages), 0)

    def test_9_duplicate_input_references_deterministic(self):
        """Duplicate evidence IDs in evidence_references are handled deterministically."""
        payload = deepcopy(self.valid_case_payload)
        payload["evidence_references"] = [
            {"evidence_id": "ev-dup-1", "evidence_type": "flow", "source_id": "flow-1"},
            {"evidence_id": "ev-dup-1", "evidence_type": "flow", "source_id": "flow-1"}
        ]
        pkg = self.adapter.adapt(payload)
        self.assertEqual(len(pkg.evidence_references), 1)
        self.assertEqual(pkg.evidence_references[0].evidence_id, "ev-dup-1")

    def test_10_no_evidence_invented(self):
        """Only explicitly declared evidence in input exists in extracted evidence references."""
        pkg = self.adapter.adapt(self.valid_case_payload)
        extracted_ids = [ref.evidence_id for ref in pkg.evidence_references]
        input_ids = [ref["evidence_id"] for ref in self.valid_case_payload["evidence_references"]]
        self.assertEqual(sorted(extracted_ids), sorted(input_ids))

    def test_11_output_deterministic_across_runs(self):
        """Repeated execution on identical input produces identical output."""
        run1 = self.adapter.adapt(self.valid_case_payload).to_dict()
        run2 = self.adapter.adapt(self.valid_case_payload).to_dict()
        self.assertEqual(run1, run2)

    def test_12_contract_validation_enforced(self):
        """Validation fails before processing if contract schema version is incorrect."""
        payload = deepcopy(self.valid_case_payload)
        payload["schema_version"] = "invalid-schema-version"

        with self.assertRaises(jsonschema.ValidationError):
            self.adapter.adapt(payload)
