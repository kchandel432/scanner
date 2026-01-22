"""
Database connection and session management
"""
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool
from urllib.parse import urlparse

from backend.core.settings import settings
from backend.core.logger import logger


def _convert_to_async_url(url: str) -> str:
    """Convert sync DB URL to async URL"""
    if url.startswith("sqlite://"):
        # Replace sqlite:// with sqlite+aiosqlite://
        return url.replace("sqlite://", "sqlite+aiosqlite://", 1)
    return url


# Convert to async URL
ASYNC_DATABASE_URL = _convert_to_async_url(settings.DATABASE_URL)

# Create async engine
engine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
    pool_pre_ping=True,
    pool_recycle=3600,
    poolclass=NullPool if settings.DEBUG else None,
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Base model
Base = declarative_base()

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session dependency
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()

async def init_db():
    """
    Initialize database tables
    """
    async with engine.begin() as conn:
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Database tables created")

async def close_db():
    """
    Close database connections
    """
    await engine.dispose()
    logger.info("✅ Database connections closed")
