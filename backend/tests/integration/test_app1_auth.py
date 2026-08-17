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
async def setup_users(db_session: AsyncSession):
    # Create an admin, investigator 1, investigator 2
    admin_uname = f"admin_{uuid4().hex[:8]}"
    inv1_uname = f"inv1_{uuid4().hex[:8]}"
    inv2_uname = f"inv2_{uuid4().hex[:8]}"
    
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
    inv2 = UserModel(
        user_id=uuid4(),
        username=inv2_uname,
        email=f"{inv2_uname}@test.com",
        full_name="Inv Two",
        role="investigator",
        hashed_password=get_password_hash("testpass")
    )
    
    db_session.add_all([admin, inv1, inv2])
    await db_session.flush()
    
    # Create two cases
    case1 = InvestigationCaseModel(
        case_id=uuid4(),
        title="Case 1",
        status="open",
        trigger_type="manual"
    )
    case2 = InvestigationCaseModel(
        case_id=uuid4(),
        title="Case 2",
        status="open",
        trigger_type="manual"
    )
    
    db_session.add_all([case1, case2])
    await db_session.flush()
    
    # Grant inv1 access to case1 ONLY
    acc1 = CaseAccessModel(
        user_id=inv1.user_id,
        case_id=case1.case_id,
        access_level="read",
        granted_by=admin.user_id
    )
    # Grant inv2 access to case2 ONLY
    acc2 = CaseAccessModel(
        user_id=inv2.user_id,
        case_id=case2.case_id,
        access_level="read",
        granted_by=admin.user_id
    )
    
    db_session.add_all([acc1, acc2])
    await db_session.commit()
    
    return {"admin": admin, "inv1": inv1, "inv2": inv2, "case1": case1, "case2": case2}

@pytest.mark.asyncio
async def test_login_success(client: TestClient, setup_users):
    response = client.post("/api/v1/auth/login", data={
        "username": setup_users["admin"].username,
        "password": "testpass"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

@pytest.mark.asyncio
async def test_login_failure(client: TestClient, setup_users):
    response = client.post("/api/v1/auth/login", data={
        "username": setup_users["admin"].username,
        "password": "wrongpassword"
    })
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_rbac_admin_only_endpoint(client: TestClient, setup_users):
    admin_token = create_access_token(subject=str(setup_users["admin"].user_id))
    inv1_token = create_access_token(subject=str(setup_users["inv1"].user_id))
    
    # Admin should access
    response = client.get("/api/v1/admin/system-status", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    
    # Investigator should be rejected
    response = client.get("/api/v1/admin/system-status", headers={"Authorization": f"Bearer {inv1_token}"})
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_case_idor_prevention(client: TestClient, setup_users, db_session: AsyncSession):
    inv1_token = create_access_token(subject=str(setup_users["inv1"].user_id))
    case1_id = str(setup_users["case1"].case_id)
    case2_id = str(setup_users["case2"].case_id)
    
    # inv1 should access case 1
    response = client.get(f"/api/v1/cases/{case1_id}", headers={"Authorization": f"Bearer {inv1_token}"})
    assert response.status_code == 200
    
    # inv1 should be blocked from case 2
    response = client.get(f"/api/v1/cases/{case2_id}", headers={"Authorization": f"Bearer {inv1_token}"})
    assert response.status_code == 403
    
    # Validate audit log was written for the denial
    stmt = select(AuditEventModel).where(
        AuditEventModel.action == "case_access_denied",
        AuditEventModel.target_entity_id == case2_id,
        AuditEventModel.actor_id == setup_users["inv1"].user_id
    )
    result = await db_session.execute(stmt)
    audit_event = result.scalars().first()
    assert audit_event is not None
    assert audit_event.result == "denied"
