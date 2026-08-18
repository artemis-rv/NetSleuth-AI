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


@pytest_asyncio.fixture
async def analyst_rbac_setup(db_session: AsyncSession):
    """Setup Analyst, Investigator, Admin, assigned case, and foreign case."""
    analyst_uname = f"sec_analyst_{uuid4().hex[:8]}"
    inv_uname = f"sec_inv_{uuid4().hex[:8]}"
    admin_uname = f"sec_admin_{uuid4().hex[:8]}"

    analyst = UserModel(
        user_id=uuid4(),
        username=analyst_uname,
        email=f"{analyst_uname}@test.com",
        full_name="Analyst One",
        role="analyst",
        hashed_password=get_password_hash("testpass")
    )
    inv = UserModel(
        user_id=uuid4(),
        username=inv_uname,
        email=f"{inv_uname}@test.com",
        full_name="Investigator One",
        role="investigator",
        hashed_password=get_password_hash("testpass")
    )
    admin = UserModel(
        user_id=uuid4(),
        username=admin_uname,
        email=f"{admin_uname}@test.com",
        full_name="Admin One",
        role="administrator",
        hashed_password=get_password_hash("testpass")
    )

    db_session.add_all([analyst, inv, admin])
    await db_session.flush()

    assigned_case = InvestigationCaseModel(
        case_id=uuid4(),
        title="Assigned Case for Analyst",
        description="Original description",
        status="open",
        trigger_type="manual"
    )
    unassigned_case = InvestigationCaseModel(
        case_id=uuid4(),
        title="Unassigned Foreign Case",
        description="Foreign description",
        status="open",
        trigger_type="manual"
    )

    db_session.add_all([assigned_case, unassigned_case])
    await db_session.flush()

    # Grant analyst read access to assigned_case only
    access = CaseAccessModel(
        user_id=analyst.user_id,
        case_id=assigned_case.case_id,
        access_level="read",
        granted_by=admin.user_id
    )
    # Grant inv access to assigned_case
    access_inv = CaseAccessModel(
        user_id=inv.user_id,
        case_id=assigned_case.case_id,
        access_level="admin",
        granted_by=admin.user_id
    )

    db_session.add_all([access, access_inv])
    await db_session.commit()

    return {
        "analyst": analyst,
        "inv": inv,
        "admin": admin,
        "assigned_case": assigned_case,
        "unassigned_case": unassigned_case
    }


@pytest.mark.asyncio
async def test_analyst_can_read_assigned_case(client: TestClient, analyst_rbac_setup):
    """Analyst can GET assigned case details."""
    analyst_token = create_access_token(subject=str(analyst_rbac_setup["analyst"].user_id))
    case_id = str(analyst_rbac_setup["assigned_case"].case_id)

    response = client.get(f"/api/v1/cases/{case_id}", headers={"Authorization": f"Bearer {analyst_token}"})
    assert response.status_code == 200
    assert response.json()["title"] == "Assigned Case for Analyst"


@pytest.mark.asyncio
async def test_analyst_can_patch_non_status_fields(client: TestClient, analyst_rbac_setup):
    """Analyst can update allowed non-status metadata fields."""
    analyst_token = create_access_token(subject=str(analyst_rbac_setup["analyst"].user_id))
    case_id = str(analyst_rbac_setup["assigned_case"].case_id)

    response = client.patch(
        f"/api/v1/cases/{case_id}",
        json={"description": "Updated analyst notes"},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert response.status_code == 200
    assert response.json()["description"] == "Updated analyst notes"


@pytest.mark.asyncio
async def test_analyst_cannot_change_status_to_closed(client: TestClient, analyst_rbac_setup):
    """Analyst is DENIED (403) when attempting to close a case."""
    analyst_token = create_access_token(subject=str(analyst_rbac_setup["analyst"].user_id))
    case_id = str(analyst_rbac_setup["assigned_case"].case_id)

    response = client.patch(
        f"/api/v1/cases/{case_id}",
        json={"status": "closed"},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_analyst_cannot_change_status_to_investigating(client: TestClient, analyst_rbac_setup):
    """Analyst is DENIED (403) when attempting any status transition."""
    analyst_token = create_access_token(subject=str(analyst_rbac_setup["analyst"].user_id))
    case_id = str(analyst_rbac_setup["assigned_case"].case_id)

    response = client.patch(
        f"/api/v1/cases/{case_id}",
        json={"status": "investigating"},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_investigator_can_close_case(client: TestClient, analyst_rbac_setup):
    """Investigator CAN close an assigned case."""
    inv_token = create_access_token(subject=str(analyst_rbac_setup["inv"].user_id))
    case_id = str(analyst_rbac_setup["assigned_case"].case_id)

    response = client.patch(
        f"/api/v1/cases/{case_id}",
        json={"status": "closed"},
        headers={"Authorization": f"Bearer {inv_token}"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "closed"


@pytest.mark.asyncio
async def test_admin_can_close_case(client: TestClient, analyst_rbac_setup):
    """Administrator CAN close any case."""
    admin_token = create_access_token(subject=str(analyst_rbac_setup["admin"].user_id))
    case_id = str(analyst_rbac_setup["unassigned_case"].case_id)

    response = client.patch(
        f"/api/v1/cases/{case_id}",
        json={"status": "closed"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "closed"


@pytest.mark.asyncio
async def test_service_direct_analyst_status_change_rejected(db_session: AsyncSession, analyst_rbac_setup):
    """Direct CaseService invocation with analyst role and status update raises ForbiddenError."""
    from app.services.case_service import CaseService
    from app.contracts.api.cases import UpdateCaseRequest
    from app.exceptions import ForbiddenError
    from unittest.mock import MagicMock

    service = CaseService(db_session)
    mock_request = MagicMock()
    req = UpdateCaseRequest(status="closed")

    with pytest.raises(ForbiddenError):
        await service.update_case(
            case_id=analyst_rbac_setup["assigned_case"].case_id,
            update_data=req,
            current_user=analyst_rbac_setup["analyst"],
            http_request=mock_request
        )


@pytest.mark.asyncio
async def test_analyst_cannot_close_unassigned_case(client: TestClient, analyst_rbac_setup):
    """Analyst cannot modify unassigned case (403 Forbidden)."""
    analyst_token = create_access_token(subject=str(analyst_rbac_setup["analyst"].user_id))
    unassigned_id = str(analyst_rbac_setup["unassigned_case"].case_id)

    response = client.patch(
        f"/api/v1/cases/{unassigned_id}",
        json={"description": "Attempt unassigned edit"},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_timeline_router_endpoint_authorized(client: TestClient, analyst_rbac_setup):
    """Verify GET /api/v1/cases/{case_id}/timeline works and enforces case access."""
    analyst_token = create_access_token(subject=str(analyst_rbac_setup["analyst"].user_id))
    assigned_id = str(analyst_rbac_setup["assigned_case"].case_id)
    unassigned_id = str(analyst_rbac_setup["unassigned_case"].case_id)

    # Assigned case timeline: 200 OK
    res1 = client.get(f"/api/v1/cases/{assigned_id}/timeline", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res1.status_code == 200

    # Unassigned case timeline: 403 Forbidden
    res2 = client.get(f"/api/v1/cases/{unassigned_id}/timeline", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res2.status_code == 403


@pytest.mark.asyncio
async def test_graph_router_endpoint_authorized(client: TestClient, analyst_rbac_setup):
    """Verify GET /api/v1/cases/{case_id}/graph works and enforces case access."""
    analyst_token = create_access_token(subject=str(analyst_rbac_setup["analyst"].user_id))
    assigned_id = str(analyst_rbac_setup["assigned_case"].case_id)
    unassigned_id = str(analyst_rbac_setup["unassigned_case"].case_id)

    # Assigned case graph: 200 OK
    res1 = client.get(f"/api/v1/cases/{assigned_id}/graph", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res1.status_code == 200

    # Unassigned case graph: 403 Forbidden
    res2 = client.get(f"/api/v1/cases/{unassigned_id}/graph", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res2.status_code == 403


@pytest.mark.asyncio
async def test_report_lifecycle_and_security(client: TestClient, analyst_rbac_setup, db_session: AsyncSession):
    """Test full report lifecycle: generate (draft), analyst finalization denial, investigator finalization, analyst export denial, investigator export, integrity hash match."""
    analyst_token = create_access_token(subject=str(analyst_rbac_setup["analyst"].user_id))
    inv_token = create_access_token(subject=str(analyst_rbac_setup["inv"].user_id))
    admin_token = create_access_token(subject=str(analyst_rbac_setup["admin"].user_id))

    # Create a valid user in DB who has no access to assigned_case
    unassigned_user_id = uuid4()
    unassigned_user = UserModel(
        user_id=unassigned_user_id,
        username=f"unassigned_{unassigned_user_id.hex[:8]}",
        email=f"unassigned_{unassigned_user_id.hex[:8]}@test.com",
        full_name="Unassigned User",
        role="analyst",
        hashed_password=get_password_hash("testpass")
    )
    db_session.add(unassigned_user)
    await db_session.commit()

    no_access_token = create_access_token(subject=str(unassigned_user.user_id))

    assigned_id = str(analyst_rbac_setup["assigned_case"].case_id)
    unassigned_id = str(analyst_rbac_setup["unassigned_case"].case_id)

    # 1. Investigator generates a draft report
    gen_res = client.post(
        f"/api/v1/reports/cases/{assigned_id}/reports/generate",
        json={"format": "pdf", "title": "Forensic Investigation Report"},
        headers={"Authorization": f"Bearer {inv_token}"}
    )
    assert gen_res.status_code == 200
    report_data = gen_res.json()
    report_id = report_data["report_id"]
    assert report_data["report_type"] == "draft"
    assert report_data["sha256"] is not None

    # 2. Analyst can view authorized report metadata
    view_res = client.get(f"/api/v1/reports/{report_id}", headers={"Authorization": f"Bearer {analyst_token}"})
    assert view_res.status_code == 200
    assert view_res.json()["report_id"] == report_id

    # 3. Analyst CANNOT finalize report (403 Forbidden)
    fin_analyst = client.post(f"/api/v1/reports/{report_id}/finalize", headers={"Authorization": f"Bearer {analyst_token}"})
    assert fin_analyst.status_code == 403

    # 4. Analyst CANNOT export draft/unfinalized report as court report (403 Forbidden)
    exp_analyst = client.get(f"/api/v1/reports/{report_id}/export", headers={"Authorization": f"Bearer {analyst_token}"})
    assert exp_analyst.status_code == 403

    # 5. Investigator CANNOT export draft/unfinalized report (409 Conflict)
    exp_draft = client.get(f"/api/v1/reports/{report_id}/export", headers={"Authorization": f"Bearer {inv_token}"})
    assert exp_draft.status_code == 409

    # 6. User without case access CANNOT view report (403 Forbidden)
    no_access_res = client.get(f"/api/v1/reports/{report_id}", headers={"Authorization": f"Bearer {no_access_token}"})
    assert no_access_res.status_code == 403

    # 7. Investigator finalizes report
    fin_res = client.post(f"/api/v1/reports/{report_id}/finalize", headers={"Authorization": f"Bearer {inv_token}"})
    assert fin_res.status_code == 200
    fin_data = fin_res.json()
    assert fin_data["report_type"] == "final"

    # 8. Finalized report CANNOT be re-finalized (409 Conflict - immutability)
    re_fin = client.post(f"/api/v1/reports/{report_id}/finalize", headers={"Authorization": f"Bearer {inv_token}"})
    assert re_fin.status_code == 409

    # 9. Investigator exports finalized court report
    exp_res = client.get(f"/api/v1/reports/{report_id}/export", headers={"Authorization": f"Bearer {inv_token}"})
    assert exp_res.status_code == 200
    assert exp_res.headers["content-type"] == "application/pdf"
    exported_bytes = exp_res.content

    # 10. Recomputed SHA-256 matches stored hash
    import hashlib
    recomputed_hash = hashlib.sha256(exported_bytes).hexdigest()
    assert recomputed_hash.lower() == fin_data["sha256"].lower()



