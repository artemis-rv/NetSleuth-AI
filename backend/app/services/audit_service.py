import logging
from typing import Any, Dict, Optional
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Request

from app.persistence.models.audit_models import AuditEventModel
from app.persistence.repositories.identity_repository import AuditRepository

logger = logging.getLogger(__name__)

async def log_audit_event(
    db: AsyncSession,
    action: str,
    target_entity_type: str,
    target_entity_id: str,
    result: str,
    actor_id: Optional[UUID] = None,
    actor_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    session_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
):
    """
    Standardized function to log audit events to the audit.audit_events table.
    """
    try:
        repo = AuditRepository(db)
        event = AuditEventModel(
            actor_id=actor_id,
            actor_name=actor_name,
            action=action,
            target_entity_type=target_entity_type,
            target_entity_id=target_entity_id,
            result=result,
            source_ip=source_ip,
            session_id=session_id,
            metadata_=metadata or {}
        )
        await repo.create(event)
    except Exception as e:
        # We don't want audit logging failures to crash the request necessarily, 
        # but we must log it loudly
        logger.error(f"Failed to write audit log: {e}")

def get_client_ip(request: Request) -> str:
    """Helper to safely extract IP from FastAPI request."""
    if request.client and request.client.host:
        host = request.client.host
        if host == "testclient":
            return "127.0.0.1"
        return host
    return "127.0.0.1"
