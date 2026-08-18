import pytest
from fastapi.testclient import TestClient
from uuid import uuid4

from .test_app2_cases import setup_users_cases, client, db_session

@pytest.fixture
def get_admin_token(setup_users_cases):
    from app.auth.jwt import create_access_token
    async def _get_token():
        return create_access_token(subject=str(setup_users_cases["admin"].user_id))
    return _get_token

@pytest.mark.asyncio
async def test_app6_entities_empty_case(client: TestClient, get_admin_token):
    token = await get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1. Create a case
    case_data = {
        "title": "APP-6 Test Case",
        "description": "Testing Investigation API",
        "priority": "high",
        "trigger_type": "alert"
    }
    case_resp = client.post("/api/v1/cases", json=case_data, headers=headers)
    assert case_resp.status_code == 201
    case_id = case_resp.json()["case_id"]

    # 2. Get entities for empty case
    ent_resp = client.get(f"/api/v1/cases/{case_id}/entities", headers=headers)
    assert ent_resp.status_code == 200
    assert ent_resp.json()["total"] == 0

@pytest.mark.asyncio
async def test_app6_timeline_empty_case(client: TestClient, get_admin_token):
    token = await get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1. Create a case
    case_data = {
        "title": "APP-6 Timeline Test Case",
        "description": "Testing Investigation API",
        "priority": "medium",
        "trigger_type": "alert"
    }
    case_resp = client.post("/api/v1/cases", json=case_data, headers=headers)
    assert case_resp.status_code == 201
    case_id = case_resp.json()["case_id"]

    # 2. Get timeline for empty case
    time_resp = client.get(f"/api/v1/cases/{case_id}/timeline", headers=headers)
    assert time_resp.status_code == 200
    assert time_resp.json()["total"] == 0

@pytest.mark.asyncio
async def test_app6_unauthorized_entity_access(client: TestClient, get_admin_token):
    token = await get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    # Try to access a non-existent entity, should return 404
    fake_id = str(uuid4())
    resp = client.get(f"/api/v1/entities/{fake_id}", headers=headers)
    assert resp.status_code == 404
