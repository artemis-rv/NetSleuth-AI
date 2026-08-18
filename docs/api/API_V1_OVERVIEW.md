# NetSleuth-AI API V1 Overview

Welcome to the NetSleuth-AI Application API (v1). This is the canonical API contract that the frontend shell (`FE-0`) and external integrations will consume.

## Base URL
All API requests in this version must be prefixed with:
`/api/v1`

## Investigator Workflow

The standard investigative process maps to these API domains:
1. **Authentication**: `POST /api/v1/auth/login` to receive a Bearer Token.
2. **Case Management**: `POST /api/v1/cases` to start a new investigation.
3. **Acquisition**: `POST /api/v1/cases/{case_id}/acquisitions` to upload evidence (PCAPs).
4. **Analysis Orchestration**: `POST /api/v1/cases/{case_id}/analysis` to start the M1-M4 pipeline.
5. **Findings & Network Intelligence**: `GET /api/v1/cases/{case_id}/findings` and `/network/*`
6. **Investigation Timeline & Graph**: `GET /api/v1/cases/{case_id}/investigation/timeline`
7. **Evidence & Custody**: `GET /api/v1/cases/{case_id}/custody`
8. **Reporting**: `POST /api/v1/cases/{case_id}/reports`

## Authentication
Authentication is enforced via JWT (JSON Web Tokens).

**Header Requirement:**
`Authorization: Bearer <your_jwt_token>`

Tokens are valid for the duration specified by `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` in the deployment environment.

## Role-Based Access Control (RBAC) & Case Authorization

Access is controlled at two layers:
1. **Role Scope**: (`administrator`, `investigator`, `analyst`).
2. **Case Scope**: Investigators and Analysts are strictly bound to cases they have been assigned to. 

If you attempt to access an endpoint for a case you are not assigned to, you will receive a `403 FORBIDDEN` and an `UNAUTHORIZED_ACCESS` audit event will be logged.

## Standardized Responses

### Pagination Contract
Any endpoint that returns a list of items will strictly follow this pagination envelope:

```json
{
  "items": [...],
  "total": 105,
  "page": 1,
  "page_size": 25
}
```
Query parameters for filtering generally follow: `?page=1&page_size=25&status=completed`.

### Error Contract
Failed requests will NEVER return Python tracebacks, database exceptions, or leaked internal state.
All errors follow this envelope:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request payload validation failed.",
    "request_id": "req-1234abcd",
    "details": [...]
  }
}
```

Common Error Codes:
* `UNAUTHORIZED` (401)
* `FORBIDDEN` (403)
* `RESOURCE_NOT_FOUND` (404)
* `VALIDATION_ERROR` (422)
* `INTERNAL_SERVER_ERROR` (500)

## Versioning Policy
This API is contractually frozen at `v1`. 
* **Non-breaking changes**: Adding optional fields or new endpoints will occur without version bumps.
* **Breaking changes**: Modifying existing response schemas, deleting fields, or changing authentication paradigms will require `/api/v2/`.

For complete programmatic specifications, please refer to the `openapi-v1.json` artifact generated alongside this documentation.
