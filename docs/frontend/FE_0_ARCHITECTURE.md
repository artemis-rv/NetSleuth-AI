# FE-0 Frontend Architecture

## Foundation
The frontend application uses `React 18`, `TypeScript`, `Vite`, `React Router 6`, `TanStack Query v5`, and `Tailwind CSS 3`. The core philosophy enforces that the backend remains the true source of authority.

## Directory Structure
- `src/api`: Centralized HTTP fetch client handling normalized error responses and API types synced strictly from the OpenAPI contract.
- `src/auth`: Manages the application's authentication lifecycle and abstractions. Contains the `AuthProvider`, token persistence logic, and route guards.
- `src/components`: UI primitive building blocks, split into `ui`, `layout`, and `feedback` segments. 
- `src/layouts`: Composes application shells, like `AppLayout` representing the protected dashboard view.
- `src/pages`: Distinct route views like `LoginPage` and `NotFoundPage`.

## Authentication and Routing
- Token storage is abstracted behind an `AuthTokenStore` interface. Currently implemented with `localStorage`, but safely swappable for Secure Cookies/Session APIs in the future.
- The `apiClient` automatically injects the active token into headers, and transforms raw responses/errors into typed payload data or the structured `ApiError` class.
- The UI layer exclusively handles redirect and navigation logic to keep the HTTP transport unopinionated.

## Design System & Tailwind
The application employs semantic design tokens targeting a "dark security-console" aesthetic. Instead of hard-coded colors scattered through components, styles rely on defined variables such as:
- `bg-surface`, `bg-surface-elevated`
- `text-primary`, `text-secondary`, `text-muted`
- Status intents like `success`, `warning`, `danger`, `info`

## Security Assumptions
- The frontend operates as a UX boundary, not a primary security mechanism.
- 401 Unauthorized API responses are intercepted by components/route context, clearing local states and pushing to `/login`.
- 403 Forbidden responses signify authenticated but unauthorized access (managed natively without triggering a hard logout).
- Input variables and user data rendered to the DOM are natively escaped by React. `dangerouslySetInnerHTML` is explicitly forbidden unless explicitly mandated and sanitized in a subsequent phase. 

## Boundary Exceptions
This phase deliberately excludes:
- Any implementation of investigator/analyst dashboard logic or components.
- Direct visualization libraries (e.g. for graphs or timeline tools).
- The automatic polling architecture for real-time log ingestion.
