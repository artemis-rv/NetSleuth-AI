# NetSleuth-AI: Application Layer Architecture (V1)

**Phase**: APP-0 — Application Architecture + Repository Foundation  
**Status**: ACTIVE / ESTABLISHED  
**Scope**: FastAPI Application Assembly, Boundary Definition, Router Hierarchy, Middleware, Error Handling, and Configuration.

---

## 1. Purpose

The NetSleuth-AI Application Layer sits between external API consumers (e.g. React Frontend, Analyst CLI) and the underlying domain/engine and persistence layers (M1, M2, M3, M4, PostgreSQL, MinIO).

Its primary responsibilities are:
- HTTP lifecycle, routing, and transport parsing
- DTO serialization/deserialization and payload validation
- Workflows and cross-engine transaction coordination (via Application Services)
- Centralized exception mapping and standard error envelopes
- Cross-cutting security, CORS, and request tracking (`X-Request-ID`)

```text
               ┌──────────────────────────────┐
               │    React Frontend / CLI      │
               └──────────────┬───────────────┘
                              │ HTTPS / JSON
                              ▼
               ┌──────────────────────────────┐
               │         FastAPI App          │
               │  (/api/v1/..., Middleware)   │
               └──────────────┬───────────────┘
                              │
                              ▼
               ┌──────────────────────────────┐
               │  Application Service Layer   │
               │ (Workflows, Auth, Pipelines) │
               └──────────────┬───────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
┌───────────────────────┐           ┌───────────────────────┐
│ Domain Engines        │           │ Persistence Layer     │
│ (M1, M2, M3, M4)      │           │ (UOW, Repositories)   │
└───────────────────────┘           └───────────┬───────────┘
                                                │
                                    ┌───────────┴───────────┐
                                    ▼                       ▼
                        ┌───────────────────────┐ ┌───────────────────┐
                        │   PostgreSQL DB       │ │   MinIO Storage   │
                        │ (System of Record)    │ │ (Evidence Objects)│
                        └───────────────────────┘ └───────────────────┘
```

---

## 2. Layer Boundaries & Responsibilities

| Layer | Path | Responsibility | Prohibitions |
|---|---|---|---|
| **API Layer** | `backend/app/api/` | Route registration, HTTP verbs, status codes, query/body parsing. | No raw SQL, no direct engine internals, no business rules. |
| **App Service Layer** | `backend/app/services/` | Workflow orchestration, transaction scoping (UOW), authorization hooks, cross-engine data passing. | No HTTP request/response objects, no direct DB table manipulation. |
| **Domain / Engine** | `backend/app/engines/` | M1 (Packet Intel), M2 (Analysis), M3 (Correlation), M4 (Reporting). Pure business logic and analytics. | No knowledge of FastAPI, HTTP headers, or web sessions. |
| **Persistence Layer** | `backend/app/persistence/` | Concrete repositories, SQLAlchemy models, UnitOfWork, atomic DB transactions, MinIO client abstractions. | No HTTP transport concerns, no domain-level inference. |
| **Infrastructure** | `backend/app/config.py`, `backend/app/middleware/` | Environment config, logging, middleware, security headers, request tracking. | No business logic. |

---

## 3. Dependency Direction

Dependencies flow strictly top-to-bottom:

$$\text{HTTP / API Layer} \longrightarrow \text{Application Services} \longrightarrow \text{Domain Engines / Persistence} \longrightarrow \text{PostgreSQL / MinIO}$$

**Strict Invariants**:
- Routers must **never** execute raw SQL queries.
- Routers must **never** directly invoke private engine internals.
- Frontend must **never** connect directly to PostgreSQL or MinIO.
- Domain engines must **never** import FastAPI or Starlette modules.

---

## 4. API Versioning

All public business endpoints are strictly versioned under:
```text
/api/v1/...
```

Top-level unversioned endpoints are reserved strictly for platform health probes (`/health`, `/ready`).

---

## 5. Router Hierarchy

The v1 API router (`backend/app/api/v1/`) mounts the following 15 domain routers:

| Domain | Route Prefix | Responsibility |
|---|---|---|
| **Auth** | `/api/v1/auth` | User authentication, token issuance, session control (APP-1). |
| **Users** | `/api/v1/users` | User management and profile administration (APP-1/APP-2). |
| **Cases** | `/api/v1/cases` | Forensic investigation case lifecycle management. |
| **Acquisitions** | `/api/v1/acquisitions` | PCAP/PCAPNG evidence intake, hashing, metadata registration. |
| **Analysis** | `/api/v1/analysis` | Analysis engine runs and ML model scoring requests. |
| **Findings** | `/api/v1/findings` | M2 anomaly/threat findings retrieval and querying. |
| **Network** | `/api/v1/network` | Flow and protocol event intelligence retrieval. |
| **Timeline** | `/api/v1/timeline` | Chronological event stream and milestone queries. |
| **Graph** | `/api/v1/graph` | Entity relationship and attack topology graph endpoints. |
| **MITRE** | `/api/v1/mitre` | MITRE ATT&CK technique mappings and coverage matrices. |
| **Evidence** | `/api/v1/evidence` | Evidence index, artifact records, and verification status. |
| **Custody** | `/api/v1/custody` | Chain-of-custody tracking, audit log, and transfer ledger. |
| **Reports** | `/api/v1/reports` | M4 forensic report generation and export access. |
| **Copilot** | `/api/v1/copilot` | Forensic assistant and copilot query endpoints (future). |
| **Admin** | `/api/v1/admin` | System health diagnostics, engine configuration, model registry. |

---

## 6. Application Service Responsibility

Application Services (`backend/app/services/`) serve as the orchestrators of business use cases:
- Open and manage `UnitOfWork` transaction contexts.
- Translate API DTOs into domain objects.
- Invoke engine interfaces (`M1PersistenceService`, `M2AnalysisEngine`, `InvestigationCaseBuilder`, `ReportEngine`).
- Coordinate custody record creation upon evidence mutations.
- Enforce authorization policies before dispatching engine jobs.

---

## 7. Persistence Responsibility

Persistence components (`backend/app/persistence/`):
- Ensure atomic operations across PostgreSQL tables (`analytics.*`, `investigation.*`, `custody.*`, `auth.*`).
- Guarantee referential integrity via SQLAlchemy 2.0 Async mappings.
- Abstract object storage operations against MinIO buckets.

---

## 8. Middleware & Cross-Cutting Concerns

The middleware stack (`backend/app/middleware/`) handles HTTP-level concerns:
1. **Security Headers**: Injects `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`.
2. **CORS Middleware**: Configuration-driven via `CORS_ORIGINS`. Wildcards are disallowed in production.
3. **Request ID Middleware**: Injects `X-Request-ID` into every request state and response header.

*Rule*: Business authorization, RBAC, and case access control are **not** placed in middleware; they are enforced via FastAPI dependencies in subsequent phases.

---

## 9. Error Handling Boundary & Error Envelope

All application errors return a uniform error envelope:

```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested case does not exist.",
    "request_id": "c56a4180-65aa-42ec-a945-5fd21dec0538",
    "details": {}
  }
}
```

### Standard Exception Hierarchy (`backend/app/exceptions.py`):
- `ApplicationError` (base, 500 `INTERNAL_SERVER_ERROR`)
- `ValidationError` (422 `VALIDATION_ERROR`)
- `NotFoundError` (404 `RESOURCE_NOT_FOUND`)
- `ConflictError` (409 `RESOURCE_CONFLICT`)
- `UnauthorizedError` (401 `UNAUTHORIZED`)
- `ForbiddenError` (403 `FORBIDDEN`)
- `InfrastructureError` (503 `INFRASTRUCTURE_UNAVAILABLE`)

Internal stack traces are logged on the server and masked from external HTTP responses.

---

## 10. Request ID / Correlation Strategy

- Header convention: `X-Request-ID`.
- If a client supplies `X-Request-ID`, it is validated and preserved.
- If missing, a new `uuid4` is generated.
- Attached to `request.state.request_id` and included in all log messages and error payloads.

---

## 11. Configuration Strategy

- Unified in `backend/app/config.py` via `settings`.
- Environment-driven (via `os.environ` / `.env`).
- Supports runtime overrides during testing.
- No credentials or secrets are hardcoded.

---

## 12. What APP-0 Does NOT Implement

To preserve architectural focus and integrity, the following are explicitly out of scope for APP-0:
- JWT authentication and user token issuance (belongs to APP-1)
- Password hashing and user registration endpoints (belongs to APP-1)
- RBAC permission checking and case-level authorization (belongs to APP-1)
- PCAP upload processing endpoints (belongs to APP-2)
- Engine execution endpoints (belongs to APP-2+)
- Frontend UI components or pages
- Database schema changes or migrations
- Copilot integrations or LLM wrappers
