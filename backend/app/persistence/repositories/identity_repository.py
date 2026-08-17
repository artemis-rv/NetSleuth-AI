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
        stmt = select(UserModel).where(UserModel.username == username)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

class CaseAccessRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, access: CaseAccessModel) -> CaseAccessModel:
        self.session.add(access)
        await self.session.flush()
        return access

class AuditRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, event: AuditEventModel) -> AuditEventModel:
        self.session.add(event)
        await self.session.flush()
        return event
