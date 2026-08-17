import pytest
import uuid
from fastapi.testclient import TestClient
from fastapi import status
from app.auth.jwt import create_access_token

# Import fixtures from app2 tests for reuse
from .test_app2_cases import setup_users_cases, client, db_session

@pytest.mark.asyncio
async def test_list_evidence(client: TestClient, setup_users_cases):
    inv1_token = create_access_token(subject=str(setup_users_cases["inv1"].user_id))
    headers = {"Authorization": f"Bearer {inv1_token}"}
    test_case_id = str(setup_users_cases["case_inv1"].case_id)
    
    response = client.get(f"/api/v1/cases/{test_case_id}/evidence", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert "items" in response.json()
    assert "total" in response.json()

@pytest.mark.asyncio
async def test_upload_and_verify_evidence(client: TestClient, setup_users_cases):
    inv1_token = create_access_token(subject=str(setup_users_cases["inv1"].user_id))
    headers = {"Authorization": f"Bearer {inv1_token}"}
    test_case_id = str(setup_users_cases["case_inv1"].case_id)
    
    # 1. Upload
    file_content = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00" 
    files = {"file": ("test_verify.pcap", file_content, "application/vnd.tcpdump.pcap")}
    
    resp1 = client.post(f"/api/v1/cases/{test_case_id}/acquisitions", headers=headers, files=files)
    if resp1.status_code != status.HTTP_201_CREATED:
        print(f"FAILED: {resp1.status_code} - {resp1.text}")
    assert resp1.status_code == status.HTTP_201_CREATED
    ev_id = resp1.json()["evidence_id"]
    
    # 2. Get Evidence
    resp2 = client.get(f"/api/v1/evidence/{ev_id}", headers=headers)
    assert resp2.status_code == status.HTTP_200_OK
    assert resp2.json()["evidence_id"] == ev_id
    
    # 3. Verify
    resp3 = client.post(f"/api/v1/evidence/{ev_id}/verify", headers=headers)
    assert resp3.status_code == status.HTTP_200_OK
    data = resp3.json()
    assert data["integrity_status"] == "verified"
    assert data["observed_sha256"] == data["expected_sha256"]
