"""
backend/tests/integration/test_app_endpoints.py
-----------------------------------------------
Integration tests for base application endpoints and router integration.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.middleware.request_id import REQUEST_ID_HEADER


@pytest.mark.asyncio
async def test_async_health_endpoint():
    """Validates async transport against /health."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}
        assert REQUEST_ID_HEADER in response.headers


@pytest.mark.asyncio
async def test_async_ready_endpoint():
    """Validates async transport against /ready."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/ready")
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}
        assert REQUEST_ID_HEADER in response.headers


@pytest.mark.asyncio
async def test_async_unversioned_404_error_envelope():
    """Validates unmapped route returns uniform 404 error envelope."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/non-existent-endpoint")
        assert response.status_code == 404
        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == "RESOURCE_NOT_FOUND"
        assert REQUEST_ID_HEADER in response.headers
