# FE-1 — Investigator Dashboard & Case Management Workflow

## Overview
FE-1 implements the initial complete investigator workflow connecting the React frontend to the frozen `/api/v1` backend endpoints.

## Route Architecture
| Route | Component | Purpose | Access Control |
|---|---|---|---|
| `/` | `DashboardPage` | Top-level summary metrics and recent investigations | All authenticated roles |
| `/investigations` | `InvestigationsPage` | Paginated, filterable, and sortable case list | All authenticated roles |
| `/investigations/new` | `CreateInvestigationPage` | Multi-section case creation form | Investigator, Administrator |
| `/investigations/:caseId` | `CaseDetailPage` | Case overview, trigger event, goals, and inline editor | Case access-controlled |

## Consumed OpenAPI v1.0 Endpoints
| HTTP Method | Endpoint | Query / Body Payload | Response Model |
|---|---|---|---|
| `GET` | `/api/v1/auth/me` | None (Bearer token header) | `User` |
| `GET` | `/api/v1/cases` | `page`, `page_size`, `status`, `priority`, `sort_by` | `PaginatedResponse[CaseResponse]` |
| `POST` | `/api/v1/cases` | `CreateCaseRequest` (JSON) | `CaseResponse` (201 Created) |
| `GET` | `/api/v1/cases/{case_id}` | Path parameter `case_id` (UUID) | `CaseResponse` (200 OK) |
| `PATCH` | `/api/v1/cases/{case_id}` | `UpdateCaseRequest` (JSON) | `CaseResponse` (200 OK) |

## Query Keys Structure
Query key factory in `src/features/cases/query-keys.ts`:
```typescript
caseKeys.all              // ['cases']
caseKeys.lists()          // ['cases', 'list']
caseKeys.list(filters)    // ['cases', 'list', filters]
caseKeys.details()        // ['cases', 'detail']
caseKeys.detail(caseId)   // ['cases', 'detail', caseId]
```

### Invalidation Rules
- **Case Creation**: Invalidates `caseKeys.lists()`.
- **Case Modification (PATCH)**: Invalidates `caseKeys.detail(caseId)` and `caseKeys.lists()`.

## Component & State Hierarchy
- **Server State**: Managed exclusively by TanStack Query (`useCasesQuery`, `useCaseQuery`, `useCreateCaseMutation`, `useUpdateCaseMutation`).
- **Auth State**: Abstracted in `AuthTokenStore` via `AuthProvider` React Context.
- **Local State**: Managed inside controlled components (`CreateCaseForm`, `EditCaseForm`).

## Form & Validation Rules
- **CreateCaseForm**:
  - Requires `title` and `trigger_type`.
  - Preserves exact investigator-entered wording for `trigger_description` and `investigation_goals`.
  - Supports dynamic additions and removals of repeatable goal items.
  - Maps backend 422 `ValidationError` arrays directly to corresponding input field errors.
- **EditCaseForm**:
  - Exposes only fields permitted by the OpenAPI `UpdateCaseRequest` schema.

## Role-Based Access Control (RBAC)
- **Investigator / Administrator**: Render "New Investigation" CTA buttons on the Dashboard and Case List.
- **Analyst**: "New Investigation" actions are hidden in the UI; backend enforces 403 on API invocation.

## Error Handling Matrix
- `401 Unauthorized`: Triggers token eviction and redirect to `/login` via `AuthProvider`.
- `403 Forbidden`: Displays descriptive Access Denied state (UI empty state or inline alert).
- `404 Not Found`: Displays "Investigation Not Found" state with a return navigation action.
- `422 Unprocessable Entity`: Maps field-level error messages to form inputs.
- `500+ / Network Error`: Normalized to `ApiError` with retry actions in `ErrorState`.
