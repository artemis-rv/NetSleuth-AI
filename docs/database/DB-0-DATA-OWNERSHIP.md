# DB-0: Data Ownership

## 1. M1 Ownership (Packet Intelligence)
M1 produces and owns the `NetworkIntelligencePackage` data. 
- **Persistence**: Relational (not as one giant JSONB blob).
- **Entities**: 
  - Acquisition
  - Flow
  - ProtocolEvent
  - Artifact
  - Provenance
- Relationships are maintained using foreign keys. This enables investigator queries (e.g., all flows for an acquisition, all events for a flow).

## 2. M2 Ownership (Analysis Engine)
M2 produces and owns the `FindingsPackage` and specific analytical outputs.
- **FindingsPackage**: Persisted in PostgreSQL (`analytics/findings`).
- **Feature Vectors**: Do not store every transient inference vector. Only persist feature vectors/snapshots when required for finding reproducibility, model audit, evaluation experiments, or case investigation.
- **Models**: The models themselves live in MinIO (`netsleuth-models/`). Metadata (model_id, version, metrics, etc.) lives in PostgreSQL. M3 does not need M2 to duplicate the entire M1 package inside the findings.

## 3. M3 Ownership (Correlation & Investigation)
M3 receives the `NetworkIntelligencePackage` + `FindingsPackage` and owns the investigation process.
- **Persistence**: PostgreSQL (`investigation/`).
- **Entities**:
  - cases
  - entities
  - relationships
  - behaviors
  - timeline_events
  - mitre_mappings
  - attack_chain
- **MITRE Knowledge**: M3 owns MITRE data. Versioned ATT&CK knowledge snapshots live in MinIO, while the mappings/metadata used by investigations are persisted in PostgreSQL. M1 and M2 are not dependent on the MITRE database.

## 4. M4 Ownership (Evidence & Reporting)
M4 owns final evidence packaging and report generation.
- **Persistence**: Metadata in PostgreSQL, actual files in MinIO.
- **Entities**: 
  - `report_id`, `case_id`, `version`, `object_key`, `sha256` (PostgreSQL)
  - `report.pdf`, exports (MinIO `netsleuth-reports/`)
