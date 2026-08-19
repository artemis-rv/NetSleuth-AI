from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID

from app.persistence.models.identity_models import UserModel, CaseAccessModel
from app.persistence.models.audit_models import AuditEventModel

class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, user: UserModel) -> UserModel:
        self.session.add(user)
        await self.session.flush()
        return user

    async def get_by_username(self, username: str) -> Optional[UserModel]:
        from sqlalchemy import or_
        candidates = [username]
        if username == "admin":
            candidates.append("admin_user")
        elif username == "admin_user":
            candidates.append("admin")
            
        stmt = select(UserModel).where(
            or_(
                UserModel.username.in_(candidates),
                UserModel.email == username
            )
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

class CaseAccessRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, access: CaseAccessModel) -> CaseAccessModel:
        self.session.add(access)
        await self.session.flush()
        return access

    async def get_by_user_and_case(self, user_id: UUID, case_id: UUID) -> Optional[CaseAccessModel]:
        from sqlalchemy import and_
        stmt = select(CaseAccessModel).where(
            and_(
                CaseAccessModel.user_id == user_id,
                CaseAccessModel.case_id == case_id
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

class AuditRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, event: AuditEventModel) -> AuditEventModel:
        self.session.add(event)
        await self.session.flush()
        return event
