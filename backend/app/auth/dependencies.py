from typing import Optional, List
from fastapi import Depends, HTTPException, status, Request, Path
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.persistence.database import async_session_factory
from app.persistence.repositories.identity_repository import UserRepository, CaseAccessRepository
from app.persistence.models.identity_models import UserModel
from app.auth.jwt import verify_token
from app.services.audit_service import log_audit_event, get_client_ip

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

async def get_db() -> AsyncSession:
    async with async_session_factory() as session:
        yield session

async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> UserModel:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    user_id = verify_token(token)
    if user_id is None:
        raise credentials_exception
    
    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise credentials_exception
        
    repo = UserRepository(db)
    # wait, the identity repository created has get_by_username but not get_by_id?
    # Let's add get_by_id to UserRepository
    from sqlalchemy import select
    stmt = select(UserModel).where(UserModel.user_id == user_uuid)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if user is None or not user.is_active:
        raise credentials_exception
        
    return user

class RequireRole:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    async def __call__(
        self,
        request: Request,
        current_user: UserModel = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
    ) -> UserModel:
        if current_user.role not in self.allowed_roles:
            await log_audit_event(
                db=db,
                action="access_denied",
                target_entity_type="system",
                target_entity_id="rbac",
                result="denied",
                actor_id=current_user.user_id,
                actor_name=current_user.username,
                source_ip=get_client_ip(request),
                metadata={"reason": "insufficient_role", "required": self.allowed_roles, "actual": current_user.role}
            )
            # commit audit event because exception stops normal flow if not committed
            await db.commit()
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user

async def verify_case_access_direct(
    case_id: UUID,
    current_user: UserModel,
    db: AsyncSession,
    request: Request = None
) -> UUID:
    """Core logic for verifying case access."""
    if current_user.role == "administrator":
        return case_id
        
    repo = CaseAccessRepository(db)
    access = await repo.get_by_user_and_case(current_user.user_id, case_id)
    
    if not access:
        if request:
            await log_audit_event(
                db=db,
                action="case_access_denied",
                target_entity_type="investigation_case",
                target_entity_id=str(case_id),
                result="denied",
                actor_id=current_user.user_id,
                actor_name=current_user.username,
                source_ip=get_client_ip(request),
                metadata={"reason": "case_not_assigned"}
            )
            await db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access to this case is forbidden"
        )
        
    return case_id

async def verify_case_access(
    request: Request,
    case_id: UUID = Path(...),
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> UUID:
    """
    Dependency to verify that the current user has access to the specified case.
    Administrators have implicit access to all cases.
    """
    return await verify_case_access_direct(case_id, current_user, db, request)
