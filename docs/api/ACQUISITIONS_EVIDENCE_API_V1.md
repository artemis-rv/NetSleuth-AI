# Acquisitions & Evidence API V1 (APP-3)

## Overview
This API manages the acquisition and evidence storage lifecycle for NetSleuth-AI cases. It coordinates Postgres metadata with authoritative MinIO object storage.

## Endpoints

### `POST /api/v1/cases/{case_id}/acquisitions`
Uploads a raw packet capture to be processed and stored.
- **Roles**: Administrator, Investigator
- **Scope**: Must have access to `case_id`
- **Body**: `multipart/form-data` with `file` field.
- **Workflow**:
  1. Temporary local save
  2. M1 Acquisition validation (format + sha256)
  3. Upload to MinIO bucket
  4. Persist `AcquisitionModel` and `EvidenceModel` in PostgreSQL
  5. Link to case via `case_acquisition_links`
  6. Return `AcquisitionUploadResponse`

### `GET /api/v1/cases/{case_id}/acquisitions`
Lists acquisitions linked to a case.
- **Roles**: Administrator, Investigator, Analyst
- **Scope**: Must have access to `case_id`
- **Returns**: `AcquisitionListResponse` with pagination.

### `GET /api/v1/evidence/{evidence_id}`
Retrieves metadata for a stored evidence object.
- **Roles**: Administrator, Investigator, Analyst
- **Scope**: Programmatic check via case linkages
- **Returns**: `EvidenceResponse`

### `POST /api/v1/evidence/{evidence_id}/verify`
Verifies the cryptographic integrity of a stored evidence object against its recorded hash.
- **Roles**: Administrator, Investigator, Analyst
- **Scope**: Programmatic check via case linkages
- **Returns**: `EvidenceVerificationResponse` indicating `integrity_status` (verified/mismatch/missing).

## Error Handling
- `InfrastructureError` (503): Raised if the MinIO storage backend is unavailable.
- Orphan Objects: If MinIO succeeds but Postgres fails, the object is left intact and an `EVIDENCE_ORPHANED` audit log is created for future reconciliation.
