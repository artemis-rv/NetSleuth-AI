from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.persistence.database import async_session_factory
from app.persistence.models.identity_models import UserModel
from app.persistence.repositories.identity_repository import UserRepository
from app.auth.passwords import verify_password
from app.auth.jwt import create_access_token
from app.auth.dependencies import get_current_user, get_db
from app.services.audit_service import log_audit_event, get_client_ip

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/login")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    repo = UserRepository(db)
    user = await repo.get_by_username(form_data.username)
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        await log_audit_event(
            db=db,
            action="login_attempt",
            target_entity_type="system",
            target_entity_id="auth",
            result="failure",
            source_ip=get_client_ip(request),
            metadata={"username_attempted": form_data.username}
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    if not user.is_active:
        await log_audit_event(
            db=db,
            action="login_attempt",
            target_entity_type="system",
            target_entity_id="auth",
            result="denied",
            actor_id=user.user_id,
            actor_name=user.username,
            source_ip=get_client_ip(request),
            metadata={"reason": "account_inactive"}
        )
        await db.commit()
        raise HTTPException(status_code=400, detail="Inactive user")

    # Update last login
    user.last_login_at = datetime.now(timezone.utc)
    
    # Audit log success
    await log_audit_event(
        db=db,
        action="login",
        target_entity_type="system",
        target_entity_id="auth",
        result="success",
        actor_id=user.user_id,
        actor_name=user.username,
        source_ip=get_client_ip(request)
    )
    
    await db.commit()

    access_token = create_access_token(subject=str(user.user_id))
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me")
async def read_users_me(current_user: UserModel = Depends(get_current_user)):
    return {
        "user_id": current_user.user_id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "is_active": current_user.is_active,
        "last_login_at": current_user.last_login_at
    }
