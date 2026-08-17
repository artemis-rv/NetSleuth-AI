# DB-0: ID Strategy

## 1. Engine Referencing
Engines reference one another **only through canonical IDs**. We do not duplicate entire records across engine boundaries.

## 2. Canonical ID Ownership
The IDs owned by each engine are frozen as follows:

### Pre-existing / Core
- `acquisition_id`
- `evidence_id`
- `flow_id`
- `event_id`
- `artifact_id`

### M2 (Analysis)
- `finding_id`
- `analysis_id`

### M3 (Correlation & Investigation)
- `investigation_id`
- `relationship_id`
- `behavior_id`
- `timeline_event_id`
- `mitre_mapping_id`
- `attack_chain_id`

### M4 (Evidence & Reporting)
- `report_id`
- `custody_event_id`
- `audit_event_id`
