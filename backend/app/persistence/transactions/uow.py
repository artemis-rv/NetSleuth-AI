from typing import Any, Dict, Type
from sqlalchemy.ext.asyncio import AsyncSession
from app.persistence.database import async_session_factory

class UnitOfWork:
    """
    Unit of Work Context Manager.
    Enforces the single logical transaction rule across repositories.
    """
    
    def __init__(self, session_factory=None):
        self._session: AsyncSession | None = None
        self._repositories: Dict[str, Any] = {}
        self._session_factory = session_factory or async_session_factory

    async def __aenter__(self):
        self._session = self._session_factory()
        # Initialize repositories dynamically as requested, or explicitly if preferred.
        # For this design, we will require the caller to inject the session into repositories,
        # or we will expose a method to get a repository attached to this session.
        return self

    async def __aexit__(self, exc_type, exc_val, traceback):
        try:
            if exc_type is not None:
                await self._session.rollback()
            else:
                await self._session.commit()
        finally:
            await self._session.close()
            self._session = None

    @property
    def session(self) -> AsyncSession:
        if self._session is None:
            raise RuntimeError("Session accessed outside of UnitOfWork context")
        return self._session

    def get_repository(self, repo_class: Type) -> Any:
        """
        Instantiate a concrete repository tied to the current active transaction.
        """
        return repo_class(self.session)
