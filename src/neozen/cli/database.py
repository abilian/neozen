"""Database management for NeoZen CLI.

Provides SQLite database initialization and access for CLI commands.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Coroutine
from functools import wraps
from pathlib import Path
from typing import Any, Concatenate, ParamSpec, TypeVar

from sqlalchemy import Result, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from neozen.storage.sqlalchemy import Base

# Default database location (relative to current working directory)
DEFAULT_DB_PATH = Path("data") / "neozen.db"

P = ParamSpec("P")
R = TypeVar("R")


def get_database_url(db_path: Path | str | None = None) -> str:
    """Get the database URL.

    Args:
        db_path: Optional path to database file. If None, uses default location.
                 Can also be a full SQLAlchemy URL for other databases.

    Returns:
        SQLAlchemy database URL.
    """
    # Check environment variable first
    env_url = os.environ.get("NEOZEN_DATABASE_URL")
    if env_url:
        return env_url

    if db_path is None:
        db_path = DEFAULT_DB_PATH

    if isinstance(db_path, str):
        # If it looks like a URL, use it directly
        if "://" in db_path:
            return db_path
        db_path = Path(db_path)

    # Ensure parent directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)

    return f"sqlite+aiosqlite:///{db_path}"


async def init_database(db_url: str | None = None) -> AsyncEngine:
    """Initialize the database and create tables.

    Args:
        db_url: Optional database URL. If None, uses default SQLite.

    Returns:
        The database engine.
    """
    if db_url is None:
        db_url = get_database_url()

    engine = create_async_engine(db_url, echo=False)

    # Import models to register them with Base
    from neozen.storage.sqlalchemy import (  # noqa: F401, PLC0415
        EmailVerificationToken,
        Session,
        Subject,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    return engine


async def get_session(engine: AsyncEngine) -> AsyncSession:
    """Get a new database session.

    Args:
        engine: The database engine.

    Returns:
        A new async session.
    """
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return session_factory()


class DatabaseContext:
    """Context manager for database operations."""

    def __init__(self, db_url: str | None = None) -> None:
        self.db_url = db_url or get_database_url()
        self.engine: AsyncEngine | None = None
        self.session: AsyncSession | None = None

    async def __aenter__(self) -> AsyncSession:
        self.engine = await init_database(self.db_url)
        self.session = await get_session(self.engine)
        return self.session

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.session:
            if exc_type is None:
                await self.session.commit()
            else:
                await self.session.rollback()
            await self.session.close()
        if self.engine:
            await self.engine.dispose()


def with_database(
    func: Callable[Concatenate[AsyncSession, P], Coroutine[Any, Any, R]],
) -> Callable[P, R]:
    """Decorator to run async function with database context.

    Wraps an async function to run in an event loop with database session.
    The wrapped function should accept 'session' as its first argument.
    """

    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        async def run() -> R:
            async with DatabaseContext() as session:
                return await func(session, *args, **kwargs)

        return asyncio.run(run())

    return wrapper


async def list_all(session: AsyncSession, model: type) -> list:
    """List all records of a model.

    Args:
        session: Database session.
        model: SQLAlchemy model class.

    Returns:
        List of all records.
    """
    result: Result[tuple[Any, ...]] = await session.execute(select(model))
    return list(result.scalars().all())


__all__ = [
    "DEFAULT_DB_PATH",
    "DatabaseContext",
    "get_database_url",
    "get_session",
    "init_database",
    "list_all",
    "with_database",
]
