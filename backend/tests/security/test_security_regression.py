import pytest
import pytest_asyncio
from uuid import uuid4
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.main import create_app
from app.persistence.database import async_session_factory
from app.persistence.models.identity_models import UserModel, CaseAccessModel
from app.persistence.models.investigation_models import InvestigationCaseModel
from app.auth.passwords import get_password_hash
from app.auth.jwt import create_access_token

@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as client:
        yield client

@pytest_asyncio.fixture
async def db_session():
    async with async_session_factory() as session:
        yield session

@pytest_asyncio.fixture
async def security_setup(db_session: AsyncSession):
    # Setup users and cases
    inv1_uname = f"sec_inv1_{uuid4().hex[:8]}"
    inv2_uname = f"sec_inv2_{uuid4().hex[:8]}"
    
    inv1 = UserModel(
        user_id=uuid4(),
        username=inv1_uname,
        email=f"{inv1_uname}@test.com",
        full_name="Inv One",
        role="investigator",
        hashed_password=get_password_hash("testpass")
    )
    inv2 = UserModel(
        user_id=uuid4(),
        username=inv2_uname,
        email=f"{inv2_uname}@test.com",
        full_name="Inv Two",
        role="investigator",
        hashed_password=get_password_hash("testpass")
    )
    
    db_session.add_all([inv1, inv2])
    await db_session.flush()
    
    case1 = InvestigationCaseModel(
        case_id=uuid4(),
        title="Case 1 Security",
        status="open",
        trigger_type="manual"
    )
    case2 = InvestigationCaseModel(
        case_id=uuid4(),
        title="Case 2 Security",
        status="open",
        trigger_type="manual"
    )
    
    db_session.add_all([case1, case2])
    await db_session.flush()
    
    acc1 = CaseAccessModel(
        user_id=inv1.user_id,
        case_id=case1.case_id,
        access_level="read",
        granted_by=inv1.user_id
    )
    acc2 = CaseAccessModel(
        user_id=inv2.user_id,
        case_id=case2.case_id,
        access_level="read",
        granted_by=inv2.user_id
    )
    
    db_session.add_all([acc1, acc2])
    await db_session.commit()
    
    return {"inv1": inv1, "inv2": inv2, "case1": case1, "case2": case2}


@pytest.mark.asyncio
async def test_jwt_malformed_token(client: TestClient):
    response = client.get("/api/v1/cases", headers={"Authorization": "Bearer not.a.valid.jwt"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"

@pytest.mark.asyncio
async def test_jwt_missing_header(client: TestClient):
    response = client.get("/api/v1/cases")
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_case_idor_matrix(client: TestClient, security_setup):
    """Verify User A cannot access User B's case resources."""
    inv1_token = create_access_token(subject=str(security_setup["inv1"].user_id))
    case2_id = str(security_setup["case2"].case_id)

    # Base case IDOR
    resp1 = client.get(f"/api/v1/cases/{case2_id}", headers={"Authorization": f"Bearer {inv1_token}"})
    assert resp1.status_code == 403

    # Sub-resource IDOR (Acquisitions)
    resp2 = client.get(f"/api/v1/cases/{case2_id}/acquisitions", headers={"Authorization": f"Bearer {inv1_token}"})
    assert resp2.status_code == 403

    # Sub-resource IDOR (Analysis)
    resp3 = client.get(f"/api/v1/cases/{case2_id}/analysis", headers={"Authorization": f"Bearer {inv1_token}"})
    assert resp3.status_code == 403

@pytest.mark.asyncio
async def test_pagination_bounds(client: TestClient, security_setup):
    """Verify pagination cannot request unbounded memory."""
    inv1_token = create_access_token(subject=str(security_setup["inv1"].user_id))
    case1_id = str(security_setup["case1"].case_id)
    
    # page_size > 100 should throw a 422 validation error
    response = client.get(f"/api/v1/cases/{case1_id}/acquisitions?page_size=1000", headers={"Authorization": f"Bearer {inv1_token}"})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"

@pytest.mark.asyncio
async def test_error_envelope_leakage(client: TestClient):
    """Verify an invalid route returns standard envelope, not HTML or stacktrace."""
    response = client.get("/api/v1/does_not_exist")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "RESOURCE_NOT_FOUND"
