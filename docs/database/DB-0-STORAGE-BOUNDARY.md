# DB-0: Storage Boundary

## 1. Storage Technologies
For the V1 architecture, the storage footprint is strictly limited to:
- **PostgreSQL**: Structured system of record.
- **MinIO**: Object/file store.

> **IMPORTANT**
> Do NOT introduce MongoDB, Neo4j, OpenSearch, Elasticsearch, Redis, Kafka, RabbitMQ, or any vector database in V1 unless explicitly requested later. MinIO is NOT replacing PostgreSQL.

## 2. PostgreSQL Responsibilities
PostgreSQL stores structured, queryable, relationship-heavy, and audit-relevant data. This includes:
- Acquisition metadata
- Evidence metadata
- M1 canonical intelligence (Flow, ProtocolEvent, Artifact, Provenance)
- M2 findings
- M2 model-run metadata
- M3 entities
- M3 relationships
- M3 behaviors
- M3 timeline events
- M3 MITRE mappings
- M3 attack chain
- InvestigationCase
- M4 report metadata
- Chain-of-custody metadata
- Audit events

## 3. MinIO Responsibilities
MinIO stores large objects, files, and binary artifacts:
- Original PCAP / PCAPNG evidence
- Raw/derived Zeek logs (e.g., `netsleuth-zeek/{acquisition_id}/conn.log`)
- Large ML datasets and processed dataset artifacts
- Trained models (`netsleuth-models/`)
- Scalers/preprocessors and feature-schema artifacts
- PDF reports (`netsleuth-reports/`)
- Evidence exports

## 4. Usage of JSONB
JSONB will be used selectively. We do NOT use JSONB as an excuse to store the whole system as document blobs.
- **Relational Columns**: Use for stable/high-value fields (e.g., `flow_id`, `acquisition_id`, `timestamp`, `source_ip`, `destination_ip`, `protocol`, `finding_id`, `case_id`).
- **JSONB Columns**: Use for genuinely variable structures (e.g., protocol-specific payloads, classifier probability maps, model metadata, flexible evidence metadata).

## 5. Partitioning Strategy
Start with normal indexed PostgreSQL tables. Partitioning will only be introduced when actual data volume and query behavior justify it.
First likely candidates for future partitioning (DB-8+):
- `flows`
- `protocol_events`
- `audit_events`
- `timeline_events`
