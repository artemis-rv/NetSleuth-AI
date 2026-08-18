import pytest
from httpx import AsyncClient
from uuid import uuid4
from fastapi.testclient import TestClient

from .test_app2_cases import setup_users_cases, client, db_session

@pytest.fixture
def get_admin_token(setup_users_cases):
    from app.auth.jwt import create_access_token
    async def _get_token():
        return create_access_token(subject=str(setup_users_cases["admin"].user_id))
    return _get_token

@pytest.mark.asyncio
async def test_app5_findings_empty_case(client: TestClient, get_admin_token):
    token = await get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1. Create a case
    case_data = {
        "title": "APP-5 Test Case",
        "description": "Testing Findings API",
        "priority": "high",
        "trigger_type": "alert"
    }
    case_resp = client.post("/api/v1/cases", json=case_data, headers=headers)
    assert case_resp.status_code == 201
    case_id = case_resp.json()["case_id"]

    # 2. Get findings for empty case
    find_resp = client.get(f"/api/v1/cases/{case_id}/findings", headers=headers)
    assert find_resp.status_code == 200
    assert find_resp.json()["total"] == 0

@pytest.mark.asyncio
async def test_app5_flows_empty_case(client: TestClient, get_admin_token):
    token = await get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1. Create a case
    case_data = {
        "title": "APP-5 Flow Test Case",
        "description": "Testing Flow API",
        "priority": "medium",
        "trigger_type": "alert"
    }
    case_resp = client.post("/api/v1/cases", json=case_data, headers=headers)
    assert case_resp.status_code == 201
    case_id = case_resp.json()["case_id"]

    # 2. Get flows for empty case
    flow_resp = client.get(f"/api/v1/cases/{case_id}/flows", headers=headers)
    assert flow_resp.status_code == 200
    assert flow_resp.json()["total"] == 0

@pytest.mark.asyncio
async def test_app5_unauthorized_finding_access(client: TestClient, get_admin_token):
    token = await get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    # Try to access a non-existent finding, should return 404
    fake_finding_id = str(uuid4())
    resp = client.get(f"/api/v1/findings/{fake_finding_id}", headers=headers)
    assert resp.status_code == 404
