# Analysis & Orchestration API V1 (APP-4)

## Overview
The Analysis API provides asynchronous orchestration for running the end-to-end forensic analysis pipeline across M1 (Packet Intelligence), M2 (Analysis Engine), M3 (Correlation), and M4 (Reporting).

Analysis jobs are tracked in the persistent `acquisition.analysis_jobs` PostgreSQL table to provide status polling, stage progress monitoring, failure recording, and idempotency protection.

---

## Endpoints

### `POST /api/v1/cases/{case_id}/analysis`
Triggers a new analysis job for an acquisition linked to a case.

- **Roles Allowed**: Administrator, Investigator
- **Scope Requirement**: Must have access to `case_id`
- **Request Body**:
  ```json
  {
    "acquisition_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
  }
  ```
- **Responses**:
  - `202 Accepted`: Returns initial job status (`queued`).
    ```json
    {
      "analysis_id": "e04f3c76-24ea-46c2-8f7f-67b673cd999a",
      "case_id": "c868cde8-fa46-4384-ae09-86dcd4943cf7",
      "acquisition_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "status": "queued",
      "current_stage": "QUEUED",
      "started_at": "2026-08-18T01:30:00Z",
      "completed_at": null,
      "progress": 0,
      "result_available": false,
      "error_code": null,
      "error_message": null
    }
    ```
  - `400 Bad Request`: If an active analysis job (`queued` or `running`) already exists for the given acquisition.
  - `403 Forbidden`: User does not have access to the specified case or lacks required role.
  - `404 Not Found`: Case or acquisition not found, or acquisition is not linked to the case.

---

### `GET /api/v1/cases/{case_id}/analysis`
Lists all analysis jobs created for an investigation case.

- **Roles Allowed**: Administrator, Investigator, Analyst
- **Scope Requirement**: Must have access to `case_id`
- **Query Parameters**:
  - `page` (default: 1)
  - `page_size` (default: 25, max: 100)
- **Responses**:
  - `200 OK`: `PaginatedResponse[AnalysisStatusResponse]`

---

### `GET /api/v1/cases/{case_id}/analysis/{analysis_id}`
Retrieves detailed lifecycle status for a specific analysis job.

- **Roles Allowed**: Administrator, Investigator, Analyst
- **Scope Requirement**: Must have access to `case_id`
- **Responses**:
  - `200 OK`: `AnalysisStatusResponse` with current stage (`M1_PACKET_INTELLIGENCE`, `M2_ANALYSIS_ENGINE`, `M3_CORRELATION`, `M4_REPORTING`, `COMPLETED`, `FAILED`) and overall progress percentage.
  - `404 Not Found`: Job not found.

---

## Idempotency & Single Active Job Rule
To prevent race conditions, duplicate processing, and resource exhaustion:
- At most **one** active analysis (`queued` or `running`) is permitted per `acquisition_id`.
- Subsequent execution attempts while a job is active are rejected with a `400 Bad Request` validation error.

---

## Orchestration Lifecycle

```
[ POST /analysis ]
       ↓
  1. Verify Case Access & Role
  2. Verify Acquisition Linkage
  3. Enforce Single Active Job
  4. Create analysis_jobs record (queued)
  5. Dispatch FastAPI BackgroundTask
       ↓
  Background Execution:
    Stage 1: M1 — Evidence Download + Packet Intelligence Ingestion (25%)
    Stage 2: M2 — Rule & Anomaly Analysis (50%)
    Stage 3: M3 — Threat Correlation & Graph Assembly (75%)
    Stage 4: M4 — Evidence Package & Report Compilation (100%)
       ↓
  Mark status = "completed", stage = "COMPLETED", result_available = true
```

---

## Architectural Decision: FastAPI BackgroundTasks & Crash-Durability

> [!WARNING]
> **Crash-Durability Limitation (V1 Implementation)**
>
> In APP-4 V1, background job execution is dispatched using FastAPI's standard `BackgroundTasks` runner within the application process space.
>
> - **State Persistence**: Job metadata, stage progress, timestamps, and error state are **durably stored** in the PostgreSQL `acquisition.analysis_jobs` table.
> - **Process Bound**: The execution task itself runs in an in-process thread pool. If the API server process encounters an unhandled crash or terminates abruptly during processing, queued/running tasks in memory will not automatically resume upon server restart.
> - **Production Recommendation**: For multi-node high-availability deployment, the orchestrator interface is designed to cleanly plug into a dedicated distributed worker queue (such as Celery + Redis / RabbitMQ or Temporal) without altering API contracts or database schema.
