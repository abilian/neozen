"""Shared database utilities for NeoZen demo applications."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from neozen.storage.sqlalchemy.base import Base


def create_database(db_path: str) -> tuple[AsyncEngine, async_sessionmaker]:
    """Create async SQLAlchemy engine and session factory.

    Args:
        db_path: Path to SQLite database file.

    Returns:
        Tuple of (engine, session_factory).
    """
    db_url = f"sqlite+aiosqlite:///{db_path}"
    engine = create_async_engine(db_url, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, session_factory


async def init_database(engine: AsyncEngine) -> None:
    """Initialize database tables.

    Args:
        engine: SQLAlchemy async engine.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


__all__ = ["create_database", "init_database"]
