# MinIO Object Storage — Local Development Infrastructure

> **⚠️ LOCAL DEVELOPMENT ONLY**
>
> This configuration is **not production-ready**. It is designed exclusively
> for local developer machines. No TLS, no replication, no HA, no lifecycle
> policies, no production retention. Production hardening is a separate phase.

---

## 1. Purpose

MinIO is the S3-compatible object storage layer for NetSleuth-AI.

It stores large binary forensic artifacts that are inappropriate for a
relational database:

| Bucket                  | Contents                                                    |
|-------------------------|-------------------------------------------------------------|
| `netsleuth-evidence`    | Original PCAP/PCAPNG evidence files                         |
| `netsleuth-zeek`        | Zeek-generated log files (derived data)                     |
| `netsleuth-datasets`    | ML datasets (raw, processed, manifests)                     |
| `netsleuth-models`      | ML model artifacts (weights, scalers, metadata)             |
| `netsleuth-reports`     | Generated forensic reports and exports                      |

PostgreSQL stores metadata and references (evidence_id, sha256, object_key,
etc.). MinIO stores the actual binary objects.

---

## 2. Architecture

```
Developer machine
       |
       | localhost:9000 (S3 API)
       | localhost:9001 (Console)
       |
Docker Engine
       |
  +----+--------+       +------------------+
  |   minio     |       |   minio-init     |
  | (container) | <---- | (setup / exits)  |
  +----+--------+       +------------------+
       |
  Named Volume
  netsleuth_minio_data
       |
  /data (inside container)
```

Backend containers reach MinIO via Docker networking:

- Inside Docker: `http://minio:9000`
- From host:     `http://localhost:9000`

---

## 3. Local Setup

### Prerequisites

- Docker Desktop (or Docker Engine + Compose plugin) installed and running
- Repository cloned

### Steps

```bash
# 1. Copy the environment template
cp .env.example .env

# 2. Edit .env — set real credentials
#    MINIO_ROOT_USER and MINIO_ROOT_PASSWORD must not be the placeholders
nano .env

# 3. Start MinIO (detached)
docker compose up -d

# 4. Wait for MinIO to become healthy and minio-init to complete
docker compose logs -f minio-init

# 5. Verify buckets
docker compose exec minio mc ls netsleuth
```

---

## 4. Environment Variables

Defined in `.env` (not committed). Template: `.env.example`.

| Variable                  | Description                                           | Example value            |
|---------------------------|-------------------------------------------------------|--------------------------|
| `MINIO_ROOT_USER`         | MinIO admin username                                  | `netsleuth_dev`          |
| `MINIO_ROOT_PASSWORD`     | MinIO admin password (≥8 chars)                       | `changeme_local_dev`     |
| `MINIO_ENDPOINT`          | S3 endpoint (inside Docker: `minio:9000`)             | `minio:9000`             |
| `MINIO_REGION`            | Region string (S3 compat; MinIO is region-agnostic)   | `us-east-1`              |
| `MINIO_USE_SSL`           | Enable TLS (false for local dev)                      | `false`                  |
| `MINIO_BUCKET_EVIDENCE`   | Evidence bucket name                                  | `netsleuth-evidence`     |
| `MINIO_BUCKET_ZEEK`       | Zeek output bucket name                               | `netsleuth-zeek`         |
| `MINIO_BUCKET_DATASETS`   | Datasets bucket name                                  | `netsleuth-datasets`     |
| `MINIO_BUCKET_MODELS`     | Models bucket name                                    | `netsleuth-models`       |
| `MINIO_BUCKET_REPORTS`    | Reports bucket name                                   | `netsleuth-reports`      |

---

## 5. Ports

| Port  | Service       | Access                      |
|-------|---------------|-----------------------------|
| 9000  | S3 API        | http://localhost:9000        |
| 9001  | MinIO Console | http://localhost:9001        |

---

## 6. Buckets

### `netsleuth-evidence`
- **Purpose**: Original forensic evidence (PCAP/PCAPNG)
- **Versioning**: Enabled
- **Object Lock**: Capable (COMPLIANCE/GOVERNANCE retention configured later)
- **Access**: Private — no public access
- **Forensic note**: Original evidence must never be modified or overwritten.
  SHA-256 identity must be preserved.

### `netsleuth-zeek`
- **Purpose**: Zeek-generated logs (derived data — NOT original evidence)
- **Versioning**: Not required for local dev
- **Access**: Private

### `netsleuth-datasets`
- **Purpose**: ML training/evaluation datasets
- **Access**: Private
- **Note**: Do not commit large dataset files to Git

### `netsleuth-models`
- **Purpose**: Trained ML models, scalers, feature schemas, metrics
- **Access**: Private

### `netsleuth-reports`
- **Purpose**: Generated forensic reports (PDF, JSON)
- **Access**: Private

---

## 7. Persistence

MinIO data is stored in a named Docker volume:

```
netsleuth_minio_data
```

This volume:
- Survives `docker compose down` ✅
- Survives `docker compose restart minio` ✅
- Is destroyed by `docker compose down -v` ⚠️ (data loss)

**Never run `docker compose down -v` unless you intend to destroy all local
object storage data.**

---

## 8. How to Start

```bash
docker compose up -d
```

Check health:
```bash
docker compose ps
```

---

## 9. How to Stop

Stop, preserve data:
```bash
docker compose down
```

Stop and destroy all volumes (⚠️ permanent data loss):
```bash
docker compose down -v
```

---

## 10. How to Inspect the Console

1. Start MinIO: `docker compose up -d`
2. Open browser: http://localhost:9001
3. Login with `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` from your `.env`

---

## 11. How to Verify S3 Connectivity

Using curl (liveness):
```bash
curl http://localhost:9000/minio/health/live
```

Using mc from the host (if mc is installed):
```bash
mc alias set netsleuth http://localhost:9000 <MINIO_ROOT_USER> <MINIO_ROOT_PASSWORD>
mc ls netsleuth
```

Using mc inside the container:
```bash
docker compose exec minio mc alias set local http://localhost:9000 \
    $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD
docker compose exec minio mc ls local
```

---

## 12. How to Reset Local MinIO

**WARNING: This destroys all local MinIO data.**

```bash
docker compose down -v
docker compose up -d
```

This will:
1. Stop all containers
2. Delete the `netsleuth_minio_data` volume
3. Recreate MinIO fresh
4. Re-run minio-init to recreate buckets

---

## 13. Security Warnings

| Concern                  | Status for Local Dev                              |
|--------------------------|--------------------------------------------------|
| Authentication           | Required (MINIO_ROOT_USER/PASSWORD)              |
| Public bucket access     | Disabled (all buckets private)                   |
| Anonymous access         | Disabled                                         |
| Credentials in Git       | Forbidden (.env is gitignored)                   |
| TLS                      | Not configured (local only)                      |
| Network exposure         | localhost only (127.0.0.1 ports)                 |
| .env file                | Gitignored — never commit real credentials       |
| .env.example             | Safe to commit — contains only placeholders      |

---

## 14. Production Limitations

This local configuration is **NOT suitable for production** because:

- No TLS — data in transit is unencrypted
- Single-node — no replication or availability guarantees
- No lifecycle policies — data accumulates indefinitely
- No access policies — uses root credentials only
- No network ACLs — relies on Docker bridge isolation only
- No retention/legal-hold configuration
- No backup strategy

Production deployment requires:
- TLS/HTTPS with valid certificates
- Multi-node distributed MinIO or cloud S3-compatible storage
- IAM-style access policies (per-service credentials)
- Lifecycle policies for derived data buckets
- Backup and disaster recovery strategy
- Formal object lock + retention policy (legal custody)
- Network-level isolation and firewall rules
