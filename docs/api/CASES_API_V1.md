# Cases API V1

The Cases API provides endpoints for managing Forensic Investigation Cases in NetSleuth-AI.

## Endpoints

### 1. Create Case
**POST** `/api/v1/cases`

Creates a new investigation case. The user creating the case is automatically assigned as the case `owner`.

- **Authorization:** Requires valid JWT. User role must be `administrator` or `investigator`. Analysts are forbidden.
- **Request Body (CreateCaseRequest):**
  ```json
  {
    "title": "Suspected Malware Activity",
    "description": "User reported abnormal outbound traffic.",
    "trigger_type": "USER_REPORT",
    "trigger_description": "Unexpected outbound traffic from workstation 10.0.0.25.",
    "investigation_goals": [
      "Identify possible infection source",
      "Identify external communications",
      "Determine possible self-propagation"
    ],
    "priority": "high",
    "external_case_id": "INC-1234",
    "external_system": "ServiceNow",
    "reported_by": "jdoe"
  }
  ```
- **Responses:**
  - `201 Created`: Returns `CaseResponse`
  - `401 Unauthorized`: Missing or invalid JWT
  - `403 Forbidden`: User is an analyst
  - `422 Unprocessable Entity`: Validation error

---

### 2. List Cases
**GET** `/api/v1/cases`

Returns a paginated list of cases. 
- **Administrators:** Can see all cases.
- **Investigators / Analysts:** Can only see cases they are explicitly assigned to (via `identity.case_access`).

- **Authorization:** Requires valid JWT.
- **Query Parameters:**
  - `page` (int): Page number, defaults to 1.
  - `page_size` (int): Items per page, defaults to 25 (max 100).
  - `status` (string, optional): Filter by case status.
  - `priority` (string, optional): Filter by case priority.
  - `sort_by` (string): Field to sort by. Allowed: `created_at`, `updated_at`, `priority`, `status`. Defaults to `created_at`.
- **Responses:**
  - `200 OK`: Returns `CaseListResponse`
  ```json
  {
    "items": [...],
    "total": 42,
    "page": 1,
    "page_size": 25
  }
  ```

---

### 3. Get Case
**GET** `/api/v1/cases/{case_id}`

Retrieves full details of a specific case.

- **Authorization:** Requires valid JWT. Must have explicit read access to the case (or be an Administrator).
- **Responses:**
  - `200 OK`: Returns `CaseResponse`
  - `403 Forbidden`: No access to this case (IDOR prevention)
  - `404 Not Found`: Case does not exist

---

### 4. Update Case
**PATCH** `/api/v1/cases/{case_id}`

Modifies permitted fields of a case. Immutable forensic fields cannot be updated through this endpoint.

- **Authorization:** Requires valid JWT. Must have explicit write access to the case.
- **Request Body (UpdateCaseRequest):** (All fields optional)
  - `title`, `description`, `priority`, `trigger_type`, `trigger_description`, `investigation_goals`, `external_case_id`, `external_system`, `reported_by`, `status`.
- **Status Transitions:** If updating `status`, it must follow the allowed workflow: `open` -> `investigating` -> `review` -> `closed` -> `open`.
- **Responses:**
  - `200 OK`: Returns updated `CaseResponse`
  - `403 Forbidden`: No write access to this case
  - `404 Not Found`: Case does not exist
  - `409 Conflict`: Invalid status transition attempted

## Audit Behavior
The following operations generate events in the `audit.audit_events` schema:
- `CASE_CREATED`: When a case is successfully created.
- `CASE_VIEWED`: When a case is accessed directly via GET.
- `CASE_UPDATED`: When a case is patched, tracking `updated_fields`.
- `case_access_denied`: Handled natively by the auth dependency when a user fails the IDOR checks.
