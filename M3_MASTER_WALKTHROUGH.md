# Master Walkthrough — M3 Correlation & Investigation Engine (MITRE Complete)

The **M3 Correlation & Investigation Engine** implementation is **100% Complete** for the MITRE Phase 1 integration. M3 successfully isolates upstream M1/M2 outputs, performs deterministic correlation, intelligently derives forensic MITRE STIX intelligence, and yields a complete `InvestigationCase V1.2` payload for downstream M4 reporting.

---

## Architecture Overview

```
    NetworkIntelligencePackage (M1)          FindingsPackage (M2)
                  │                                   │
                  └─────────────────┬─────────────────┘
                                    ▼
                     M3 Canonical Adapters (Phase 1)
                      (Sanitization & Normalization)
                                    │
                                    ▼
                        M3InvestigationInput
                                    │
                                    ▼
                      M3 Correlation Engine (Phase 2)
                 (Entity Merging, Timeline Construction)
                                    │
                                    ▼
                        Runtime MITRE Mapper (Phase 4)
                  (Powered by Curated Knowledge Profile)
                                    │
                                    ▼
                      Attack Chain Constructor (Phase 5)
                      (Strict sequential evidence linking)
                                    │
                                    ▼
                   InvestigationCaseBuilder (Phase 6)
             (Strict validation against V1.2 JSON Schema)
                                    │
                                    ▼
                       InvestigationCase V1.2
                                    │
                                    ▼
                        M4 Reporting Engine (Phase 7)
```

---

## Complete Phase-by-Phase Breakdown

### Phase 1: Canonical Input Isolation & Adapters
- **Location**: `backend/app/engines/correlation/domain/input.py`, `backend/app/engines/correlation/adapters/`
- **Key Artifacts**: `M3InvestigationInput`, `m1_adapter.py`, `m2_adapter.py`.
- **Constraint Enforcement**: Strictly segregates raw M1/M2 components behind canonical abstractions to prevent engine coupling. Discards redundant noise while perfectly preserving `evidence_ids` and `finding_ids`.

---

### Phase 2: M3 Correlation Engine
- **Location**: `backend/app/engines/correlation/correlation/`
- **Key Modules**: `correlation_engine.py`, `rules.py`.
- **Purpose**: Combines isolated finding events and physical network packets into a singular cohesive investigative timeline. Enforces deduplication and chronological sanity (`first_seen`, `last_seen`).

---

### Phase 3: MITRE Knowledge Profile (STIX 2.1) Curation
- **Location**: `backend/app/engines/correlation/mitre/knowledge/`
- **Key Modules**: `repository.py`, `network-evidence-v1.json` (Knowledge Profile).
- **ATT&CK Release**: 19.2
- **Curated Scope**: Strictly constrained to the 5 designated NetSleuth behaviors:
  1. `C2_MALWARE_COMMUNICATION`
  2. `DNS_ANOMALY_TUNNELING`
  3. `SCANNING_RECONNAISSANCE`
  4. `POSSIBLE_EXFILTRATION`
  5. `SUSPICIOUS_WEB_ACTIVITY`
- **Rule Engine**: Explicitly blocks non-relevant tactics and avoids hallucinating support for unsupported behavior families.

---

### Phase 4: Runtime MITRE Mapper
- **Location**: `backend/app/engines/correlation/mitre/mapper.py`, `models.py`
- **Key Artifact**: `MitreMapping`
- **Behavior Mapping Rules**: Dynamically derives candidate techniques based purely on verifiable evidence.
  - Generates `POTENTIAL` mappings for weak or incomplete telemetry (e.g. large volume alone does not prove Exfil).
  - Maintains traceability to raw M2 `finding_id`s and `evidence_id`s.

---

### Phase 5: Attack Chain Construction
- **Location**: `backend/app/engines/correlation/investigation/case_builder.py`
- **Key Artifact**: `attack_chain`
- **Rule Engine**: 
  - Generates forensic stages (`stage_id`, `technique_name`) derived directly from supported mappings.
  - Sorts stages deterministically chronologically.
  - Avoids "chain fabrication": Ensures overall status degrades gracefully to `POTENTIAL` if deterministic chain causality rules are not explicitly met. It NEVER automatically flags `CONFIRMED` merely because an individual finding exists.

---

### Phase 6: InvestigationCase V1.2 Contract
- **Location**: `docs/contracts/investigation-case-v1.2.json`, `backend/app/shared/contract_validation.py`
- **Schema Enhancements**: Explicitly expands upon `V1.1` to house a new `mitre_mappings` array, `mitre_provenance`, and `attack_chain` block.
- **Data Integrity**: Enforces strict `jsonschema` bounds, including restricting `Entity` representations to block undefined attributes (`value`) for downstream resilience.

---

### Phase 7: M3 → M4 Version Negotiation & Boundary
- **Location**: `backend/app/engines/reporting/case_adapter.py`
- **Seamless Upgrade**: M4 natively identifies the incoming payload's `schema_version`. It consumes `V1.2` forensic structures smoothly while simultaneously supporting backwards compatibility with legacy `V1.1` pipeline payloads.

---

## Verification Summary

All **71 focused MITRE/M3 unit & integration tests** pass 100% cleanly across the codebase.

```
============================= test session starts =============================
platform win32 -- Python 3.14
rootdir: D:\NetSleuth-AI

backend\tests\unit\test_mitre_knowledge.py ...........                  [ 15%]
backend\tests\unit\test_mitre_mapper.py ............                    [ 32%]
backend\tests\unit\test_attack_chain.py ...............                 [ 53%]
backend\tests\unit\test_mitre_case_contract.py .............            [ 71%]
backend\tests\unit\test_m3_input_adapter.py .............               [ 90%]
backend\tests\unit\test_m3_m4_integration.py .......                    [100%]

============================= 71 passed in 1.04s ==============================
```

M3 Correlation is fully operational, evidence-backed, deterministically reproducible, and ready for **M4 Report generation/visualization upgrades**.
