import pytest
import uuid
from fastapi.testclient import TestClient
from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.persistence.models.acquisition_models import AcquisitionModel
from app.persistence.models.investigation_models import case_acquisition_links
from app.auth.jwt import create_access_token

# Import fixtures from app2 tests for reuse
from .test_app2_cases import setup_users_cases, client, db_session

@pytest.mark.asyncio
async def test_upload_acquisition_success(client: TestClient, setup_users_cases, db_session: AsyncSession):
    inv1_token = create_access_token(subject=str(setup_users_cases["inv1"].user_id))
    headers = {"Authorization": f"Bearer {inv1_token}"}
    test_case_id = str(setup_users_cases["case_inv1"].case_id)
    
    file_content = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00" + uuid.uuid4().bytes
    files = {"file": ("test.pcap", file_content, "application/vnd.tcpdump.pcap")}
    
    response = client.post(f"/api/v1/cases/{test_case_id}/acquisitions", headers=headers, files=files)
    
    if response.status_code != status.HTTP_201_CREATED:
        print(f"FAILED: {response.status_code} - {response.text}")
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "acquisition_id" in data
    assert "evidence_id" in data
    assert data["file_name"] == "test.pcap"
    assert data["format"] == "pcap"
    assert data["status"] == "complete"
    
    acq_id = uuid.UUID(data["acquisition_id"])
    
    # Verify DB
    stmt = select(AcquisitionModel).where(AcquisitionModel.acquisition_id == acq_id)
    acq = (await db_session.execute(stmt)).scalar_one_or_none()
    assert acq is not None
    assert acq.status == "complete"
    
    stmt2 = select(case_acquisition_links).where(case_acquisition_links.c.acquisition_id == acq_id)
    link = (await db_session.execute(stmt2)).first()
    assert link is not None
    assert str(link.case_id) == test_case_id

@pytest.mark.asyncio
async def test_upload_acquisition_analyst_forbidden(client: TestClient, setup_users_cases):
    analyst_token = create_access_token(subject=str(setup_users_cases["analyst"].user_id))
    headers = {"Authorization": f"Bearer {analyst_token}"}
    test_case_id = str(setup_users_cases["case_inv1"].case_id)
    
    file_content = b"dummy"
    files = {"file": ("test.pcap", file_content, "application/vnd.tcpdump.pcap")}
    
    response = client.post(f"/api/v1/cases/{test_case_id}/acquisitions", headers=headers, files=files)
    assert response.status_code == status.HTTP_403_FORBIDDEN

@pytest.mark.asyncio
async def test_upload_invalid_file(client: TestClient, setup_users_cases):
    inv1_token = create_access_token(subject=str(setup_users_cases["inv1"].user_id))
    headers = {"Authorization": f"Bearer {inv1_token}"}
    test_case_id = str(setup_users_cases["case_inv1"].case_id)
    
    file_content = b"not a pcap"
    files = {"file": ("test.txt", file_content, "text/plain")}
    
    response = client.post(f"/api/v1/cases/{test_case_id}/acquisitions", headers=headers, files=files)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

@pytest.mark.asyncio
async def test_list_acquisitions(client: TestClient, setup_users_cases):
    inv1_token = create_access_token(subject=str(setup_users_cases["inv1"].user_id))
    headers = {"Authorization": f"Bearer {inv1_token}"}
    test_case_id = str(setup_users_cases["case_inv1"].case_id)
    
    response = client.get(f"/api/v1/cases/{test_case_id}/acquisitions", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert "items" in response.json()
    assert "total" in response.json()
