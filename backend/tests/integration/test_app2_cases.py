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
from app.persistence.models.audit_models import AuditEventModel
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
async def setup_users_cases(db_session: AsyncSession):
    admin_uname = f"admin_c_{uuid4().hex[:8]}"
    inv1_uname = f"inv1_c_{uuid4().hex[:8]}"
    analyst_uname = f"ana1_c_{uuid4().hex[:8]}"
    
    admin = UserModel(
        user_id=uuid4(),
        username=admin_uname,
        email=f"{admin_uname}@test.com",
        full_name="Admin User",
        role="administrator",
        hashed_password=get_password_hash("testpass")
    )
    inv1 = UserModel(
        user_id=uuid4(),
        username=inv1_uname,
        email=f"{inv1_uname}@test.com",
        full_name="Inv One",
        role="investigator",
        hashed_password=get_password_hash("testpass")
    )
    analyst = UserModel(
        user_id=uuid4(),
        username=analyst_uname,
        email=f"{analyst_uname}@test.com",
        full_name="Analyst One",
        role="analyst",
        hashed_password=get_password_hash("testpass")
    )
    
    db_session.add_all([admin, inv1, analyst])
    await db_session.flush()
    
    case_admin = InvestigationCaseModel(
        case_id=uuid4(),
        title="Admin Case",
        status="open",
        trigger_type="manual",
        created_by=admin.user_id
    )
    case_inv1 = InvestigationCaseModel(
        case_id=uuid4(),
        title="Inv Case",
        status="open",
        trigger_type="automated",
        created_by=inv1.user_id
    )
    
    db_session.add_all([case_admin, case_inv1])
    await db_session.flush()
    
    acc1 = CaseAccessModel(
        user_id=inv1.user_id,
        case_id=case_inv1.case_id,
        access_level="admin",
        granted_by=admin.user_id
    )
    acc2 = CaseAccessModel(
        user_id=analyst.user_id,
        case_id=case_inv1.case_id,
        access_level="read",
        granted_by=admin.user_id
    )
    
    db_session.add_all([acc1, acc2])
    await db_session.commit()
    
    return {
        "admin": admin, "inv1": inv1, "analyst": analyst,
        "case_admin": case_admin, "case_inv1": case_inv1
    }

@pytest.mark.asyncio
async def test_create_case_investigator(client: TestClient, setup_users_cases):
    inv1_token = create_access_token(subject=str(setup_users_cases["inv1"].user_id))
    payload = {
        "title": "New Suspected Malware",
        "description": "Observed unusual outbound connections.",
        "trigger_type": "USER_REPORT",
        "investigation_goals": ["Identify C2", "Determine root cause"],
        "priority": "high"
    }
    response = client.post("/api/v1/cases", json=payload, headers={"Authorization": f"Bearer {inv1_token}"})
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == payload["title"]
    assert data["status"] == "open"
    assert "case_id" in data

@pytest.mark.asyncio
async def test_create_case_analyst_forbidden(client: TestClient, setup_users_cases):
    analyst_token = create_access_token(subject=str(setup_users_cases["analyst"].user_id))
    payload = {
        "title": "Analyst created case",
        "trigger_type": "USER_REPORT"
    }
    response = client.post("/api/v1/cases", json=payload, headers={"Authorization": f"Bearer {analyst_token}"})
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_list_cases_admin_sees_all(client: TestClient, setup_users_cases):
    admin_token = create_access_token(subject=str(setup_users_cases["admin"].user_id))
    response = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 2  # Sees both cases created in setup

@pytest.mark.asyncio
async def test_list_cases_investigator_scoping(client: TestClient, setup_users_cases):
    inv1_token = create_access_token(subject=str(setup_users_cases["inv1"].user_id))
    response = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {inv1_token}"})
    assert response.status_code == 200
    data = response.json()
    # Should only see case_inv1
    case_ids = [item["case_id"] for item in data["items"]]
    assert str(setup_users_cases["case_inv1"].case_id) in case_ids
    assert str(setup_users_cases["case_admin"].case_id) not in case_ids

@pytest.mark.asyncio
async def test_get_case_authorized(client: TestClient, setup_users_cases):
    inv1_token = create_access_token(subject=str(setup_users_cases["inv1"].user_id))
    case_id = str(setup_users_cases["case_inv1"].case_id)
    response = client.get(f"/api/v1/cases/{case_id}", headers={"Authorization": f"Bearer {inv1_token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["case_id"] == case_id

@pytest.mark.asyncio
async def test_update_case_status_transition(client: TestClient, setup_users_cases, db_session: AsyncSession):
    inv1_token = create_access_token(subject=str(setup_users_cases["inv1"].user_id))
    case_id = str(setup_users_cases["case_inv1"].case_id)
    
    # Update to investigating
    response = client.patch(f"/api/v1/cases/{case_id}", json={"status": "investigating"}, headers={"Authorization": f"Bearer {inv1_token}"})
    assert response.status_code == 200
    assert response.json()["status"] == "investigating"
    
    # Try invalid transition: investigating -> open
    response = client.patch(f"/api/v1/cases/{case_id}", json={"status": "open"}, headers={"Authorization": f"Bearer {inv1_token}"})
    assert response.status_code == 409
    
    # Validate audit event was created for the successful update
    stmt = select(AuditEventModel).where(
        AuditEventModel.action == "CASE_UPDATED",
        AuditEventModel.target_entity_id == case_id
    )
    result = await db_session.execute(stmt)
    audit = result.scalars().first()
    assert audit is not None
    assert "status" in audit.metadata_["updated_fields"]
