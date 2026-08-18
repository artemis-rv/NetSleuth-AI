"""
backend/app/api/v1/copilot.py
-----------------------------
Forensic Copilot API Router boundary (APP-0 structural placeholder).
"""

from uuid import UUID
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import verify_case_access, get_current_user, get_db
from app.persistence.models.identity_models import UserModel
from app.engines.llm_assistant.models import LLMInvestigationResponse
from app.services.copilot_service import CopilotOrchestrator

router = APIRouter(prefix="/copilot", tags=["Forensic Copilot"])

class QARequest(BaseModel):
    question: str

@router.post("/{case_id}/summary", response_model=LLMInvestigationResponse)
async def generate_summary(
    case_id: UUID,
    http_request: Request,
    verified_case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    orchestrator = CopilotOrchestrator(db)
    return await orchestrator.generate_summary(verified_case_id, current_user, http_request)

@router.post("/{case_id}/mitre/{technique_id}", response_model=LLMInvestigationResponse)
async def generate_mitre_explanation(
    case_id: UUID,
    technique_id: str,
    http_request: Request,
    verified_case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    orchestrator = CopilotOrchestrator(db)
    return await orchestrator.generate_mitre_explanation(verified_case_id, technique_id, current_user, http_request)

@router.post("/{case_id}/qa", response_model=LLMInvestigationResponse)
async def generate_qa(
    case_id: UUID,
    payload: QARequest,
    http_request: Request,
    verified_case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    orchestrator = CopilotOrchestrator(db)
    return await orchestrator.generate_qa(verified_case_id, payload.question, current_user, http_request)
