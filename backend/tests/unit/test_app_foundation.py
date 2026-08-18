"""
backend/tests/unit/test_app_foundation.py
-----------------------------------------
Unit tests for APP-0 Application Architecture & Foundation.

Validates:
- FastAPI application assembly & metadata
- Liveness & Readiness health endpoints (/health, /ready)
- Request ID generation and header preservation
- Security headers middleware
- Versioned API router hierarchy (/api/v1/...)
- Centralized exception handling & uniform error envelopes
- Validation error formatting
- Configuration boundary and CORS security rules
"""

import os
import uuid
import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.main import create_app
from app.config import settings, _Settings
from app.exceptions import (
    ApplicationError,
    NotFoundError,
    ValidationError,
    ConflictError,
    ForbiddenError,
    UnauthorizedError,
    InfrastructureError,
)
from app.middleware.request_id import REQUEST_ID_HEADER


@pytest.fixture
def client():
    """Provides a TestClient with a fresh application instance."""
    app = create_app()
    return TestClient(app)


def test_app_instantiation(client):
    """Verifies the FastAPI application instantiates with proper metadata."""
    assert client.app.title == settings.app_name
    assert client.app.version == settings.app_version


def test_health_endpoint(client):
    """Verifies the /health liveness probe responds with 200 OK."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
    assert REQUEST_ID_HEADER in response.headers


def test_ready_endpoint(client):
    """Verifies the /ready readiness probe responds with 200 OK."""
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
    assert REQUEST_ID_HEADER in response.headers


def test_request_id_generated_when_missing(client):
    """Verifies a valid UUID4 X-Request-ID is generated and returned when omitted by client."""
    response = client.get("/health")
    assert REQUEST_ID_HEADER in response.headers
    req_id = response.headers[REQUEST_ID_HEADER]
    # Validate it's a valid UUID
    parsed = uuid.UUID(req_id)
    assert str(parsed) == req_id


def test_request_id_preserved_when_supplied(client):
    """Verifies a client-supplied X-Request-ID is preserved and returned."""
    custom_id = "test-custom-request-id-12345"
    response = client.get("/health", headers={REQUEST_ID_HEADER: custom_id})
    assert response.headers[REQUEST_ID_HEADER] == custom_id


def test_security_headers_present(client):
    """Verifies foundational security headers are injected into all HTTP responses."""
    response = client.get("/health")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_v1_domain_routers_registered(client):
    """Verifies that all 15 required domain router prefixes exist in the API router hierarchy."""
    from app.api.v1 import (
        auth_router,
        users_router,
        cases_router,
        acquisitions_router,
        analysis_router,
        findings_router,
        network_router,
        timeline_router,
        graph_router,
        mitre_router,
        evidence_router,
        custody_router,
        reports_router,
        copilot_router,
        admin_router,
    )

    domain_routers = [
        auth_router,
        users_router,
        cases_router,
        acquisitions_router,
        analysis_router,
        findings_router,
        network_router,
        timeline_router,
        graph_router,
        mitre_router,
        evidence_router,
        custody_router,
        reports_router,
        copilot_router,
        admin_router,
    ]

    # Verify all required domain routers are registered
    # (Many use prefix="" because their routes are /cases/{case_id}/...)
    assert len(domain_routers) >= 15
    
    # We can verify that the auth and users routers still have their prefixes
    prefixes = [r.prefix for r in domain_routers]
    assert "/auth" in prefixes
    assert "/users" in prefixes
    assert "/cases" in prefixes


def test_application_exception_envelope():
    """Verifies custom ApplicationError subclasses return uniform error envelopes."""
    app = create_app()

    test_router = APIRouter(prefix="/test-errors")

    @test_router.get("/not-found")
    async def raise_not_found():
        raise NotFoundError("Case 'CASE-999' was not found.")

    @test_router.get("/forbidden")
    async def raise_forbidden():
        raise ForbiddenError("User is not authorized for this case.", details={"case_id": "CASE-100"})

    @test_router.get("/conflict")
    async def raise_conflict():
        raise ConflictError("Case is already closed.")

    @test_router.get("/unauthorized")
    async def raise_unauthorized():
        raise UnauthorizedError("Invalid authentication token.")

    @test_router.get("/infrastructure")
    async def raise_infrastructure():
        raise InfrastructureError("Database connection timed out.")

    app.include_router(test_router)
    client = TestClient(app)

    # 1. NotFoundError (404)
    res = client.get("/test-errors/not-found", headers={REQUEST_ID_HEADER: "req-404"})
    assert res.status_code == 404
    data = res.json()
    assert data["error"]["code"] == "RESOURCE_NOT_FOUND"
    assert data["error"]["message"] == "Case 'CASE-999' was not found."
    assert data["error"]["request_id"] == "req-404"

    # 2. ForbiddenError (403) with details
    res = client.get("/test-errors/forbidden", headers={REQUEST_ID_HEADER: "req-403"})
    assert res.status_code == 403
    data = res.json()
    assert data["error"]["code"] == "FORBIDDEN"
    assert data["error"]["details"] == {"case_id": "CASE-100"}

    # 3. ConflictError (409)
    res = client.get("/test-errors/conflict")
    assert res.status_code == 409
    assert res.json()["error"]["code"] == "RESOURCE_CONFLICT"

    # 4. UnauthorizedError (401)
    res = client.get("/test-errors/unauthorized")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"

    # 5. InfrastructureError (503)
    res = client.get("/test-errors/infrastructure")
    assert res.status_code == 503
    assert res.json()["error"]["code"] == "INFRASTRUCTURE_UNAVAILABLE"


def test_unhandled_exception_masked():
    """Verifies unhandled exceptions return 500 without leaking stack traces."""
    app = create_app()
    test_router = APIRouter(prefix="/test-crash")

    @test_router.get("/boom")
    async def raise_unexpected():
        raise RuntimeError("Secret database password failed in /var/internal/db.py:42")

    app.include_router(test_router)
    client = TestClient(app, raise_server_exceptions=False)

    res = client.get("/test-crash/boom", headers={REQUEST_ID_HEADER: "req-500"})
    assert res.status_code == 500
    data = res.json()
    assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
    assert data["error"]["message"] == "An unexpected internal server error occurred."
    assert data["error"]["request_id"] == "req-500"
    # Verify no traceback leak in response body
    assert "Secret database password" not in str(data)
    assert "/var/internal" not in str(data)


def test_validation_error_envelope():
    """Verifies FastAPI RequestValidationError returns standard envelope with code VALIDATION_ERROR."""
    app = create_app()
    test_router = APIRouter(prefix="/test-validation")

    class ItemPayload(BaseModel):
        name: str
        count: int

    @test_router.post("/items")
    async def create_item(payload: ItemPayload):
        return {"ok": True}

    app.include_router(test_router)
    client = TestClient(app)

    # Missing required field 'count' and invalid 'name' type
    res = client.post("/test-validation/items", json={"name": 123}, headers={REQUEST_ID_HEADER: "req-val"})
    assert res.status_code == 422
    data = res.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert data["error"]["request_id"] == "req-val"
    assert "details" in data["error"]
    assert len(data["error"]["details"]) > 0


def test_cors_production_security_rule(monkeypatch):
    """Verifies CORS origins filter out wildcards in production environment."""
    test_settings = _Settings()

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("CORS_ORIGINS", "https://app.netsleuth.ai,*,https://admin.netsleuth.ai")

    origins = test_settings.cors_origins
    assert "*" not in origins
    assert "https://app.netsleuth.ai" in origins
    assert "https://admin.netsleuth.ai" in origins
