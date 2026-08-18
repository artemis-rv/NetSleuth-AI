# NetSleuth-AI

A forensic network investigation system that ingests raw packet captures (PCAP/PCAPNG), runs them through automated analysis and correlation engines, and produces structured investigation findings and reports.

---

## What It Does

1. **Ingest** — accepts raw PCAP/PCAPNG evidence files
2. **Parse** — runs Zeek to extract flows, DNS, HTTP, TLS events
3. **Analyse** — detects anomalies, extracts behaviours, maps to MITRE ATT&CK
4. **Correlate** — links related events, builds attack chains, assembles investigation context
5. **Report** — produces structured forensic evidence packages and reports

---

## Architecture — Four Modules

| Module | Role | Status |
|--------|------|--------|
| **M1** — Input + Packet Intelligence | PCAP ingestion, Zeek runner, protocol adapters, artifact extraction | ✅ Complete |
| **M2** — Analysis Engine | Anomaly detection, behaviour extraction, findings production | ✅ Complete |
| **M3** — Correlation + Investigation | Context assembly, MITRE mapping, attack chain construction | ✅ Complete (Engine & KB ready; orchestrator injection pending) |
| **M4** — Evidence + Reporting | Evidence packaging, report generation, export | ✅ Complete (Report engine & DB persistence ready) |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.10+ / 3.12 |
| Packet analysis | [Zeek](https://zeek.org/) |
| Structured database | PostgreSQL + asyncpg + SQLAlchemy — **running locally via Docker** |
| Object storage | MinIO (S3-compatible) — **running locally via Docker** |
| Container runtime | Docker + Docker Compose |

---

## Data Storage Architecture

NetSleuth-AI uses a dual-storage pattern separating structured relational metadata from raw binary objects.

### 1. PostgreSQL Relational Database (`netsleuth`)
**Connection**: `postgresql://postgres:postgres@localhost:15432/netsleuth` (host `15432` → container `5432`)

| Schema | Role / Data Stored | Key Entities |
|--------|--------------------|--------------|
| `identity` | Users, authentication credentials, RBAC roles (`administrator`, `investigator`, `analyst`), case access control lists | `users`, `case_access` |
| `investigation` | Investigation cases, trigger events, goals, attack chain stages, timeline context, persistent `analysis_jobs` | `investigation_cases`, `analysis_jobs`, `case_acquisition_links` |
| `acquisition` | Acquisition file metadata, source type, format, SHA-256 hashes, status tracking | `acquisitions`, `evidence` |
| `packet_intel` | Normalized network flows, protocol events (DNS, HTTP, TLS), extracted indicators/artifacts | `flows`, `protocol_events`, `artifacts` |
| `analysis` | Statistical flow metrics, ML feature vectors, model predictions, generated findings packages | `feature_vectors`, `findings_packages` |
| `correlation` | Aggregated threat context, MITRE ATT&CK technique mappings, attack graph nodes/edges | `timeline_events`, `mitre_mappings`, `attack_graphs` |
| `evidence` | Cryptographic evidence metadata, integrity verification logs | `evidence_packages`, `verification_logs` |
| `audit` | Immutable security and operation audit trail | `audit_events` |

### 2. MinIO Object Storage (S3-Compatible)
**Connection**: `http://localhost:9000` (S3 API) \| `http://localhost:9001` (Web Console)

| Storage Bucket | Role / Data Stored | Object Key Structure |
|----------------|--------------------|----------------------|
| `netsleuth-evidence` (or `evidence`) | Authoritative original raw PCAP/PCAPNG capture files | `evidence/{acquisition_id}/{file_name}` |
| `netsleuth-zeek` | Intermediate raw Zeek log files (`conn.log`, `dns.log`, `http.log`, `ssl.log`) | `zeek/{acquisition_id}/conn.log` |
| `netsleuth-datasets` | Feature extraction & ML model evaluation datasets | `datasets/{dataset_id}/data.parquet` |
| `netsleuth-models` | Serialized ML model weights, scaler artifacts, and detection parameters | `models/{model_id}/model.pt` |
| `netsleuth-reports` | Generated forensic investigation reports (JSON/PDF) and exported evidence zip packages | `reports/{case_id}/{report_id}.json` / `.pdf` |

---

## What Is Already Implemented

### M1 — Packet Intelligence (Complete)
- Acquisition engine — validates and hashes PCAP input
- Zeek runner — executes Zeek against PCAP, captures raw logs
- Zeek reader — parses `conn.log`, `dns.log`, `http.log`, `ssl.log`
- Protocol adapters — normalises each log type into canonical models
- Artifact extractor — pulls observables (IPs, domains, hashes, certs)
- Provenance validator — enforces SHA-256 integrity across the pipeline
- M1 Persistence Service — transparent async persistence boundary (PostgreSQL DB-9 & MinIO)

### M2 — Analysis Engine (Complete)
- Feature extraction pipeline — evaluates flows/events for statistical anomalies
- ML Models — isolated prediction layer mapping behaviors
- Findings package generator — structures discoveries into standard contracts
- M2 Persistence Service — transparent async persistence boundary (PostgreSQL DB-10)

### M3 — Correlation & Investigation (Complete)
- Context assembly — aggregates M2 findings and builds timeline events
- MITRE ATT&CK Knowledge Base & Mapper — static repository (`network-evidence-v1.json`) and runtime `MitreMapper`
- Attack chain construction — builds chronological attack chain stages inside `InvestigationCase`
- M3 Persistence Service — transparent async persistence boundary (PostgreSQL DB-11)

### M4 — Evidence & Reporting (Complete)
- Evidence Integrity verification & packaging engine
- Report Engine — produces contract-compliant `Report V1` JSON documents
- M4 Persistence Service — transparent async persistence boundary (PostgreSQL DB-12 & MinIO)

### Orchestration & End-to-End Testing (Complete)
- `ForensicPipelineOrchestrator` (`backend/app/orchestrator/pipeline.py`) — unified pipeline connecting M1 -> M2 -> M3 -> M4
- Fast E2E integration test (`tests/integration/e2e/test_full_forensic_chain.py`) — primary CI test validating full cross-engine DB persistence using mock data
- Real-PCAP system integration test (`tests/integration/e2e/test_full_forensic_chain_real_pcap.py`) — full forensic path test requiring real PCAP + Zeek + MinIO

### Shared Infrastructure (Complete)
- MinIO object storage — running in Docker, all 5 buckets provisioned
- PostgreSQL DB — running in Docker, Alembic migrations defined and wired (DB-0 through DB-12 complete)
- Backend configuration contract — `backend/app/config.py`
- Environment variable convention — `.env` / `.env.example`

---

### Application Layer (Complete)
- **APP-0 (Application Foundation)**: FastAPI application core structure, SQLAlchemy async database initialization, and API router routing (`/api/v1`).
- **APP-1 (Authentication & RBAC)**: JWT authentication, password hashing (`passlib`/`bcrypt`), Role-Based Access Control (`administrator`, `investigator`, `analyst`), case-level access policies, and standard security auditing (`audit.audit_events`).
- **APP-2 (Case Management APIs)**: Investigation case management endpoints (`POST /cases`, `GET /cases`, `GET /cases/{case_id}`, `PATCH /cases/{case_id}`), Pydantic contracts, strict pagination, safe filter/sort options, and status transition workflows.
- **APP-3 (Acquisition & Evidence APIs)**: MinIO integration for original PCAP storage, explicit transactional coordination with PostgreSQL, streaming integrity checks (SHA-256), orchestration with M1 Acquisition Engine, orphaned object handling, and case-scoped authorization endpoints (`/api/v1/cases/{case_id}/acquisitions`, `/api/v1/evidence/{evidence_id}`).
- **APP-4 (Analysis & Orchestration APIs)**: Asynchronous end-to-end analysis orchestration (M1 → M2 → M3 → M4), persistent `analysis_jobs` database tracking, status polling, stage progress monitoring, idempotency guards (at most one active analysis per acquisition), and full integration testing (`/api/v1/cases/{case_id}/analysis`).

---

## Integration Status & Next Steps

- **Pipeline Orchestration**: Unified M1 -> M2 -> M3 -> M4 pipeline operational.
- **Application Layer**: APP-0, APP-1, APP-2, APP-3, and APP-4 completed with full integration test coverage.
- **Next Steps**: FE-0 — Frontend App Shell + Design System + Authenticated Routing.

---

## Local Setup

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose plugin)
- Python 3.10+ (for running application code)
- [Zeek](https://zeek.org/get-zeek/) (for packet analysis — M1)

### 1 — Clone the repo

```bash
git clone <repo-url>
cd NetSleuth-AI
```

### 2 — Create your `.env` file

```bash
cp .env.example .env
```

Then open `.env` and set your MinIO credentials:

```env
MINIO_ROOT_USER=pick_any_username
MINIO_ROOT_PASSWORD=pick_any_password_min8chars
```

Everything else in `.env` can stay as-is for local development.

> **Note:** `.env` is gitignored. Never commit it. `.env.example` is safe to commit — it has no real credentials.

### 3 — Start the infrastructure

```bash
docker compose up -d
```

This starts MinIO and automatically creates all five storage buckets. First run will pull the image (~100 MB).

### 4 — Verify it is running

```bash
docker compose ps
```

You should see `netsleuth-minio` with status `(healthy)`.

Open the MinIO Console in your browser: **http://localhost:9001**  
Log in with the credentials you set in `.env`.

### 5 — Stop the infrastructure

```bash
docker compose down          # stops containers, keeps your data
docker compose down -v       # stops containers AND deletes all stored data (careful)
```

---

## Storage Buckets

| Bucket | Purpose |
|--------|---------|
| `netsleuth-evidence` | Original PCAP/PCAPNG files — versioned, object-lock capable |
| `netsleuth-zeek` | Zeek-generated log files (derived from evidence) |
| `netsleuth-datasets` | ML training datasets |
| `netsleuth-models` | Trained ML model artifacts |
| `netsleuth-reports` | Generated forensic reports and exports |

Buckets are created automatically when you run `docker compose up`. You do not need to create them manually.

---

## Ports

| Port | Service |
|------|---------|
| `9000` | MinIO S3 API |
| `9001` | MinIO web console |
| `15432`| PostgreSQL Database |

---

## Project Structure

```
NetSleuth-AI/
├── backend/
│   └── app/
│       ├── config.py            ← environment-based configuration
│       ├── contracts/           ← canonical data models
│       └── engines/
│           └── packet_intelligence/   ← M1 implementation
├── src/
│   ├── m1_packet_intel/
│   ├── m2_analysis/
│   ├── m3_correlation/
│   ├── m4_reporting/
│   └── shared/
├── docs/
│   ├── contracts/               ← JSON schema contracts
│   └── infrastructure/
│       └── minio.md             ← full MinIO documentation
├── infra/
│   └── docker/minio/            ← Docker config notes
├── tests/
├── fixtures/
├── docker-compose.yml           ← local infrastructure (MinIO)
├── .env.example                 ← copy this to .env
└── pyproject.toml
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Start infrastructure | `docker compose up -d` |
| Stop infrastructure | `docker compose down` |
| View container status | `docker compose ps` |
| View MinIO logs | `docker compose logs minio` |
| Open MinIO console | http://localhost:9001 |
| Re-run bucket setup | `docker compose up minio-init` |

---

## Documentation

- [`docs/api/CASES_API_V1.md`](docs/api/CASES_API_V1.md) — Case Management API V1 contracts and authorization rules
- [`docs/infrastructure/minio.md`](docs/infrastructure/minio.md) — full MinIO setup, persistence, security notes
- [`docs/contracts/`](docs/contracts/) — JSON schema definitions for inter-module data contracts
- [`docs/M1_V1_IMPLEMENTATION_SUMMARY.md`](docs/M1_V1_IMPLEMENTATION_SUMMARY.md) — M1 implementation detail
- [`docs/M3_V1_IMPLEMENTATION_SUMMARY.md`](docs/M3_V1_IMPLEMENTATION_SUMMARY.md) — M3 implementation detail
