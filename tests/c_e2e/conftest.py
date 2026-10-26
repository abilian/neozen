"""Shared fixtures for e2e tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from neozen.storage.sqlalchemy.base import Base

# Add project root to path for demos package
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


def create_test_database(db_path: str) -> tuple[AsyncEngine, async_sessionmaker]:
    """Create async SQLAlchemy engine and session factory for tests.

    No pool: tests run each coroutine on a fresh event loop, and a pooled
    aiosqlite connection stays bound to the loop that opened it.
    """
    db_url = f"sqlite+aiosqlite:///{db_path}"
    engine = create_async_engine(db_url, poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, session_factory


async def init_test_database(engine: AsyncEngine) -> None:
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@pytest.fixture
def test_db_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for test databases."""
    db_dir = tmp_path / "data"
    db_dir.mkdir()
    return db_dir


def pytest_sessionfinish(session, exitstatus):
    """Clean up demo app engines after all tests complete."""
    import asyncio
    import sys

    async def cleanup_engines():
        """Dispose all demo app engines that were created at import time."""
        # Only clean up if demos were imported
        if "demos.flask.app" in sys.modules:
            import demos.flask.app as flask_module

            if hasattr(flask_module, "engine") and flask_module.engine is not None:
                await flask_module.engine.dispose()

        if "demos.starlette.app" in sys.modules:
            import demos.starlette.app as starlette_module

            if (
                hasattr(starlette_module, "engine")
                and starlette_module.engine is not None
            ):
                await starlette_module.engine.dispose()

        if "demos.litestar.app" in sys.modules:
            import demos.litestar.app as litestar_module

            if (
                hasattr(litestar_module, "engine")
                and litestar_module.engine is not None
            ):
                await litestar_module.engine.dispose()

    asyncio.run(cleanup_engines())
