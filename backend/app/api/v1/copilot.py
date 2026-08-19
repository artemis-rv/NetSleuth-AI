"""
backend/app/api/v1/copilot.py
-----------------------------
Forensic Copilot API Router boundary.
"""

from uuid import UUID
from typing import Optional
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
    finding_id: Optional[str] = None
    technique_id: Optional[str] = None
    hypothesis_id: Optional[str] = None
    root_cause_id: Optional[str] = None
    impact_id: Optional[str] = None

class FindingExplanationRequest(BaseModel):
    finding_id: str

class HypothesisExplanationRequest(BaseModel):
    hypothesis_id: str

class RootCauseExplanationRequest(BaseModel):
    root_cause_id: str

class ImpactExplanationRequest(BaseModel):
    impact_id: str

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

@router.post("/{case_id}/finding-explanation", response_model=LLMInvestigationResponse)
@router.post("/{case_id}/finding/{finding_id}", response_model=LLMInvestigationResponse)
async def generate_finding_explanation(
    case_id: UUID,
    finding_id: str,
    http_request: Request,
    verified_case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    orchestrator = CopilotOrchestrator(db)
    return await orchestrator.generate_finding_explanation(verified_case_id, finding_id, current_user, http_request)

@router.post("/{case_id}/mitre-explanation", response_model=LLMInvestigationResponse)
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

@router.post("/{case_id}/hypothesis-explanation", response_model=LLMInvestigationResponse)
@router.post("/{case_id}/hypothesis/{hypothesis_id}", response_model=LLMInvestigationResponse)
async def generate_hypothesis_explanation(
    case_id: UUID,
    hypothesis_id: str,
    http_request: Request,
    verified_case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    orchestrator = CopilotOrchestrator(db)
    return await orchestrator.generate_hypothesis_explanation(verified_case_id, hypothesis_id, current_user, http_request)

@router.post("/{case_id}/root-cause-explanation", response_model=LLMInvestigationResponse)
@router.post("/{case_id}/root-cause/{root_cause_id}", response_model=LLMInvestigationResponse)
async def generate_root_cause_explanation(
    case_id: UUID,
    root_cause_id: str,
    http_request: Request,
    verified_case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    orchestrator = CopilotOrchestrator(db)
    return await orchestrator.generate_root_cause_explanation(verified_case_id, root_cause_id, current_user, http_request)

@router.post("/{case_id}/impact-explanation", response_model=LLMInvestigationResponse)
@router.post("/{case_id}/impact/{impact_id}", response_model=LLMInvestigationResponse)
async def generate_impact_explanation(
    case_id: UUID,
    impact_id: str,
    http_request: Request,
    verified_case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    orchestrator = CopilotOrchestrator(db)
    return await orchestrator.generate_impact_explanation(verified_case_id, impact_id, current_user, http_request)

@router.post("/{case_id}/ask", response_model=LLMInvestigationResponse)
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
