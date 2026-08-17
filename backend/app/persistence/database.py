import os
from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@127.0.0.1:15432/netsleuth"
)

# 1. AsyncEngine
# Configured with NullPool for testing isolated transactions
engine = create_async_engine(
    DATABASE_URL,
    echo=False,  
    poolclass=NullPool
)

# 2. SessionFactory
async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)

async def check_health() -> bool:
    """Verify the database is reachable."""
    try:
        async with engine.connect() as conn:
            from sqlalchemy import text
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

async def close_db():
    """Dispose the engine cleanly on shutdown."""
    await engine.dispose()
