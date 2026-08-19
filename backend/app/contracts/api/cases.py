from typing import Optional, List
from uuid import UUID, uuid4
from datetime import datetime
from pydantic import BaseModel, Field

class InvestigationGoal(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    description: str
    completed: bool = False
    note: Optional[str] = None

class CreateCaseRequest(BaseModel):
    title: str = Field(..., min_length=1, description="The title of the investigation case")
    description: Optional[str] = Field(None, description="Detailed description of the case context")
    trigger_type: str = Field(..., description="The type of event that triggered the case (e.g., USER_REPORT)")
    trigger_description: Optional[str] = Field(None, description="Detailed description of the trigger")
    investigation_goals: Optional[List[InvestigationGoal]] = Field(None, description="Specific goals for the investigation")
    external_case_id: Optional[str] = Field(None, description="ID of a related case in an external system")
    external_system: Optional[str] = Field(None, description="Name of the external system (e.g., Jira, ServiceNow)")
    reported_by: Optional[str] = Field(None, description="User or entity that reported the issue")
    priority: Optional[str] = Field(None, description="Priority level of the case")

class UpdateCaseRequest(BaseModel):
    title: Optional[str] = Field(None, min_length=1)
    description: Optional[str] = Field(None)
    priority: Optional[str] = Field(None)
    trigger_type: Optional[str] = Field(None)
    trigger_description: Optional[str] = Field(None)
    investigation_goals: Optional[List[InvestigationGoal]] = Field(None)
    external_case_id: Optional[str] = Field(None)
    external_system: Optional[str] = Field(None)
    reported_by: Optional[str] = Field(None)
    status: Optional[str] = Field(None, description="Case status, must be one of the allowed transitions")

class CaseResponse(BaseModel):
    case_id: UUID
    title: str
    description: Optional[str] = None
    status: str
    priority: Optional[str] = None
    trigger_type: str
    trigger_description: Optional[str] = None
    external_case_id: Optional[str] = None
    external_system: Optional[str] = None
    reported_by: Optional[str] = None
    investigation_goals: Optional[List[InvestigationGoal]] = None
    opened_at: datetime
    closed_at: Optional[datetime] = None
    created_by: Optional[UUID] = None
    updated_at: datetime

    class Config:
        from_attributes = True

from app.contracts.api.common import PaginatedResponse
CaseListResponse = PaginatedResponse[CaseResponse]
