"""Shared fixtures for integration tests."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from neozen.storage.sqlalchemy.base import Base


def create_test_database(db_path: str) -> tuple[AsyncEngine, async_sessionmaker]:
    """Create async SQLAlchemy engine and session factory for tests.

    Uses NullPool to avoid thread cleanup issues with aiosqlite.
    """
    db_url = f"sqlite+aiosqlite:///{db_path}"
    engine = create_async_engine(db_url, echo=False, poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, session_factory


async def init_test_database(engine: AsyncEngine) -> None:
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# Note: Individual test files define their own fixtures (async_engine, session, db_session).
# For in-memory SQLite, use StaticPool to maintain a single connection.
# For file-based SQLite, use NullPool to avoid thread cleanup issues.
# The helper functions create_test_database and init_test_database are provided
# for tests that need file-based databases with NullPool.
