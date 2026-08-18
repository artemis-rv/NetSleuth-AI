from typing import Optional, Tuple, List
from uuid import UUID
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.contracts.api.cases import CreateCaseRequest, UpdateCaseRequest, CaseResponse, CaseListResponse
from app.persistence.repositories.investigation_repository import InvestigationCaseRepository
from app.persistence.repositories.identity_repository import CaseAccessRepository
from app.persistence.models.investigation_models import InvestigationCaseModel
from app.persistence.models.identity_models import UserModel, CaseAccessModel
from app.services.audit_service import log_audit_event, get_client_ip
from app.exceptions import NotFoundError, ForbiddenError, ValidationError, ConflictError

class CaseService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo = InvestigationCaseRepository(db)
        self.access_repo = CaseAccessRepository(db)

    async def create_case(self, current_user: UserModel, request_data: CreateCaseRequest, http_request: Request) -> CaseResponse:
        """Create a new investigation case and assign creator as owner."""
        if current_user.role == "analyst":
            # Analysts are not allowed to create cases according to requirements
            raise ForbiddenError("Analysts are not permitted to create investigation cases.")

        new_case = InvestigationCaseModel(
            title=request_data.title,
            description=request_data.description,
            trigger_type=request_data.trigger_type,
            trigger_description=request_data.trigger_description,
            investigation_goals=request_data.investigation_goals,
            external_case_id=request_data.external_case_id,
            external_system=request_data.external_system,
            reported_by=request_data.reported_by,
            priority=request_data.priority,
            created_by=current_user.user_id,
            status="open"
        )
        
        await self.repo.create(new_case)
        
        # Grant access to creator
        access = CaseAccessModel(
            user_id=current_user.user_id,
            case_id=new_case.case_id,
            access_level="admin",
            granted_by=current_user.user_id
        )
        await self.access_repo.create(access)
        
        # Audit
        await log_audit_event(
            db=self.db,
            action="CASE_CREATED",
            target_entity_type="investigation_case",
            target_entity_id=str(new_case.case_id),
            result="success",
            actor_id=current_user.user_id,
            actor_name=current_user.username,
            source_ip=get_client_ip(http_request),
            metadata={"title": new_case.title, "trigger_type": new_case.trigger_type}
        )
        
        await self.db.commit()
        
        return CaseResponse.model_validate(new_case)

    async def list_cases(
        self, 
        current_user: UserModel, 
        page: int = 1, 
        page_size: int = 25, 
        status: Optional[str] = None, 
        priority: Optional[str] = None,
        sort_by: str = "created_at"
    ) -> CaseListResponse:
        """List accessible cases for the current user."""
        # Hard limits
        page = max(1, page)
        page_size = min(max(1, page_size), 100)
        skip = (page - 1) * page_size
        
        allowed_sort_fields = {"created_at", "updated_at", "priority", "status"}
        if sort_by not in allowed_sort_fields:
            raise ValidationError(f"Invalid sort field. Allowed fields: {allowed_sort_fields}")

        items, total = await self.repo.list_cases(
            user_id=current_user.user_id,
            role=current_user.role,
            skip=skip,
            limit=page_size,
            status=status,
            priority=priority,
            sort_by=sort_by
        )
        
        return CaseListResponse(
            items=[CaseResponse.model_validate(item) for item in items],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_case(self, case_id: UUID, current_user: UserModel, http_request: Request) -> CaseResponse:
        """Get a specific case."""
        case = await self.repo.get(case_id)
        if not case:
            raise NotFoundError("Investigation case not found")
            
        await log_audit_event(
            db=self.db,
            action="CASE_VIEWED",
            target_entity_type="investigation_case",
            target_entity_id=str(case.case_id),
            result="success",
            actor_id=current_user.user_id,
            actor_name=current_user.username,
            source_ip=get_client_ip(http_request)
        )
        await self.db.commit()
        
        return CaseResponse.model_validate(case)

    async def update_case(self, case_id: UUID, update_data: UpdateCaseRequest, current_user: UserModel, http_request: Request) -> CaseResponse:
        """Update a specific case."""
        case = await self.repo.get(case_id)
        if not case:
            raise NotFoundError("Investigation case not found")
            
        update_dict = update_data.model_dump(exclude_unset=True)
        
        if not update_dict:
            return CaseResponse.model_validate(case)

        # Enforce status transitions
        if "status" in update_dict:
            if current_user.role == "analyst":
                raise ForbiddenError("Analysts are not permitted to modify case status or close investigation cases.")
            new_status = update_dict["status"]
            allowed_transitions = {
                "open": ["investigating", "closed"],
                "investigating": ["review", "closed"],
                "review": ["closed", "investigating"],
                "closed": ["open"]
            }
            if new_status not in allowed_transitions.get(case.status, []):
                raise ConflictError(f"Invalid status transition from {case.status} to {new_status}")
            
            if new_status == "closed":
                from datetime import datetime, timezone
                update_dict["closed_at"] = datetime.now(timezone.utc)

        updated_case = await self.repo.update(case_id, update_dict)
        
        await log_audit_event(
            db=self.db,
            action="CASE_UPDATED",
            target_entity_type="investigation_case",
            target_entity_id=str(updated_case.case_id),
            result="success",
            actor_id=current_user.user_id,
            actor_name=current_user.username,
            source_ip=get_client_ip(http_request),
            metadata={"updated_fields": list(update_dict.keys())}
        )
        await self.db.commit()
        
        return CaseResponse.model_validate(updated_case)
