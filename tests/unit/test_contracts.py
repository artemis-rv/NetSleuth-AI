import unittest
import json
from pathlib import Path
import jsonschema
from src.shared.contract_validation import ContractValidator

class TestContracts(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()

    def test_network_intelligence_v1_valid(self):
        valid_m1 = {
            "package_id": "nip-001",
            "contract_version": "1.0",
            "acquisition_id": "acq-001",
            "flows": [],
            "protocol_events": [],
            "artifacts": [],
            "packet_references": []
        }
        # Should not raise any exception
        self.validator.validate("network-intelligence-v1.json", valid_m1)

    def test_finding_v1_valid(self):
        valid_m2 = {
            "finding_id": "finding-001",
            "contract_version": "1.0",
            "acquisition_id": "acq-001",
            "finding_type": "data_exfiltration",
            "title": "Potential Data Exfiltration",
            "description": "...",
            "severity": "high",
            "risk_score": 87.0,
            "confidence_score": 0.91,
            "status": "new",
            "first_seen": "2026-08-15T12:00:00Z",
            "last_seen": "2026-08-15T12:05:00Z",
            "detection": {
                "methods": [],
                "explanation": [],
                "features": [],
                "model": {}
            },
            "entities": [],
            "evidence_references": [],
            "provenance": {}
        }
        self.validator.validate("finding-v1.json", valid_m2)

    def test_evidence_reference_v1_valid(self):
        valid_m4 = {
            "schema_version": "evidence-reference-v1",
            "evidence_id": "ev-001",
            "evidence_type": "pcap"
        }
        self.validator.validate("evidence-reference-v1.json", valid_m4)

    def test_invalid_m1_extra_property(self):
        invalid_m1 = {
            "package_id": "nip-001",
            "contract_version": "1.0",
            "acquisition_id": "acq-001",
            "flows": [],
            "protocol_events": [],
            "artifacts": [],
            "packet_references": [],
            "unknown_field": "should fail"
        }
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            self.validator.validate("network-intelligence-v1.json", invalid_m1)

    def test_invalid_m4_wrong_enum(self):
        invalid_m4 = {
            "schema_version": "evidence-reference-v1",
            "evidence_id": "ev-002",
            "evidence_type": "unknown_type"
        }
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            self.validator.validate("evidence-reference-v1.json", invalid_m4)

    def test_investigation_case_v1_valid(self):
        fixture_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "investigations" / "investigation-case-v1-valid.json"
        with open(fixture_path, 'r', encoding='utf-8') as f:
            valid_case = json.load(f)
        # Should not raise exception
        self.validator.validate("investigation-case-v1.1.json", valid_case)

    def test_invalid_investigation_case_extra_property(self):
        fixture_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "investigations" / "investigation-case-v1-valid.json"
        with open(fixture_path, 'r', encoding='utf-8') as f:
            invalid_case = json.load(f)
        
        invalid_case["unknown_property"] = "this should fail"
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            self.validator.validate("investigation-case-v1.1.json", invalid_case)

    def test_invalid_investigation_case_bad_enum(self):
        fixture_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "investigations" / "investigation-case-v1-valid.json"
        with open(fixture_path, 'r', encoding='utf-8') as f:
            invalid_case = json.load(f)
            
        invalid_case["status"] = "super_closed" # not in enum
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            self.validator.validate("investigation-case-v1.1.json", invalid_case)

    def test_scenario_001_m1_valid(self):
        fixture_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "network_intelligence" / "network-intelligence-v1-scenario-001.json"
        with open(fixture_path, 'r', encoding='utf-8') as f:
            valid_m1 = json.load(f)
        self.validator.validate("network-intelligence-v1.json", valid_m1)

    def test_scenario_001_m2_valid(self):
        fixture_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "findings" / "finding-v1-scenario-001.json"
        with open(fixture_path, 'r', encoding='utf-8') as f:
            valid_m2 = json.load(f)
        self.validator.validate("finding-v1.json", valid_m2)

    def test_scenario_001_m3_expected_valid(self):
        fixture_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "investigations" / "investigation-case-v1-scenario-001-expected.json"
        with open(fixture_path, 'r', encoding='utf-8') as f:
            valid_m3 = json.load(f)
        self.validator.validate("investigation-case-v1.1.json", valid_m3)


