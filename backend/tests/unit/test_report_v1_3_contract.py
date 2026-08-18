import pytest
import json
import os
from jsonschema import validate, ValidationError

CONTRACTS_DIR = os.path.join(os.path.dirname(__file__), "../../../docs/contracts")
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "../../../fixtures/reports")

def load_schema(version: str) -> dict:
    with open(os.path.join(CONTRACTS_DIR, f"{version}.json"), "r") as f:
        return json.load(f)

def load_fixture(name: str) -> dict:
    with open(os.path.join(FIXTURES_DIR, name), "r") as f:
        return json.load(f)

@pytest.fixture
def v1_3_schema():
    return load_schema("report-v1.3")

@pytest.fixture
def v1_2_schema():
    return load_schema("report-v1.2")

@pytest.fixture
def v1_1_schema():
    return load_schema("report-v1.1")

@pytest.fixture
def valid_v1_3_report():
    return load_fixture("report-v1.3-valid.json")

# 1. Valid V1.3 report.
def test_valid_v1_3_report(v1_3_schema, valid_v1_3_report):
    validate(instance=valid_v1_3_report, schema=v1_3_schema)

# 2. Hypothesis validates.
# 3. Hypothesis validation validates.
# 4. Root cause validates.
# 5. Impact assessment validates.
# All tested via full fixture validation.

# 6. Invalid hypothesis status fails.
def test_invalid_hypothesis_status_fails(v1_3_schema, valid_v1_3_report):
    valid_v1_3_report["assessment"]["hypotheses"][0]["status"] = "FAKE_STATUS"
    with pytest.raises(ValidationError, match="FAKE_STATUS"):
        validate(instance=valid_v1_3_report, schema=v1_3_schema)

# 7. Invalid validation status fails.
def test_invalid_validation_status_fails(v1_3_schema, valid_v1_3_report):
    valid_v1_3_report["assessment"]["hypothesis_validations"][0]["validation_status"] = "FAKE_STATUS"
    with pytest.raises(ValidationError, match="FAKE_STATUS"):
        validate(instance=valid_v1_3_report, schema=v1_3_schema)

# 8. Invalid root-cause status fails.
def test_invalid_root_cause_status_fails(v1_3_schema, valid_v1_3_report):
    valid_v1_3_report["assessment"]["root_causes"][0]["status"] = "REJECTED" # Not allowed in root cause
    with pytest.raises(ValidationError, match="REJECTED"):
        validate(instance=valid_v1_3_report, schema=v1_3_schema)

# 9. Invalid impact status fails.
def test_invalid_impact_status_fails(v1_3_schema, valid_v1_3_report):
    valid_v1_3_report["assessment"]["impact_assessments"][0]["status"] = "UNRESOLVED" # Not allowed
    with pytest.raises(ValidationError, match="UNRESOLVED"):
        validate(instance=valid_v1_3_report, schema=v1_3_schema)

# 10. Confidence outside 0..1 fails.
def test_confidence_outside_bounds_fails(v1_3_schema, valid_v1_3_report):
    valid_v1_3_report["assessment"]["hypotheses"][0]["confidence"] = 1.5
    with pytest.raises(ValidationError, match="1.5 is greater than the maximum of 1"):
        validate(instance=valid_v1_3_report, schema=v1_3_schema)
        
    valid_v1_3_report["assessment"]["hypotheses"][0]["confidence"] = -0.5
    with pytest.raises(ValidationError, match="-0.5 is less than the minimum of 0"):
        validate(instance=valid_v1_3_report, schema=v1_3_schema)

# 11. Missing required evidence fails.
def test_missing_required_evidence_fails(v1_3_schema, valid_v1_3_report):
    valid_v1_3_report["assessment"]["hypotheses"][0]["supporting_evidence_ids"] = []
    with pytest.raises(ValidationError, match="should be non-empty"):
        validate(instance=valid_v1_3_report, schema=v1_3_schema)

# 12. Unknown fields fail.
def test_unknown_fields_fail(v1_3_schema, valid_v1_3_report):
    valid_v1_3_report["assessment"]["hypotheses"][0]["unknown_field"] = "test"
    with pytest.raises(ValidationError, match="Additional properties are not allowed"):
        validate(instance=valid_v1_3_report, schema=v1_3_schema)

# 13. MITRE data remains valid.
def test_mitre_data_remains_valid(v1_3_schema, valid_v1_3_report):
    valid_v1_3_report["mitre_mappings"] = [{"technique_id": "T1071", "technique_name": "Web Protocols"}]
    validate(instance=valid_v1_3_report, schema=v1_3_schema)

# 14. Attack chain remains valid.
def test_attack_chain_remains_valid(v1_3_schema, valid_v1_3_report):
    valid_v1_3_report["attack_chain"] = {"status": "potential", "stages": []}
    validate(instance=valid_v1_3_report, schema=v1_3_schema)

# 15. LLM enrichment remains valid.
def test_llm_enrichment_remains_valid(v1_3_schema, valid_v1_3_report):
    # It's already in the fixture
    validate(instance=valid_v1_3_report, schema=v1_3_schema)

# 16. V1.2 legacy report still validates against V1.2.
def test_v1_2_legacy_validates(v1_2_schema):
    v1_2_fixture = load_fixture("report-v1.2-valid.json")
    validate(instance=v1_2_fixture, schema=v1_2_schema)

# 17. V1.1 legacy report still validates against V1.1.
def test_v1_1_legacy_validates(v1_1_schema):
    v1_1_fixture = load_fixture("report-v1.1-valid.json")
    validate(instance=v1_1_fixture, schema=v1_1_schema)

# 18. JSON round-trip preserves all V1.3 investigation data.
def test_json_round_trip_preserves_v1_3(v1_3_schema, valid_v1_3_report):
    dumped = json.dumps(valid_v1_3_report)
    loaded = json.loads(dumped)
    validate(instance=loaded, schema=v1_3_schema)
    assert len(loaded["assessment"]["hypotheses"]) == 1
    assert loaded["assessment"]["hypotheses"][0]["status"] == "POTENTIAL"

def test_no_investigation_fixture(v1_3_schema):
    fixture = load_fixture("report-v1.3-valid-no-investigation.json")
    validate(instance=fixture, schema=v1_3_schema)
