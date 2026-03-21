"""Integration tests for SQLAlchemy repository implementation.

Tests that NeoZenRepository properly implements the RepositoryProtocol
using a real SQLAlchemy database (in-memory SQLite).
"""

from __future__ import annotations

import pytest
from sqlalchemy import String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from neozen.core.repository import DoesNotExist
from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.repositories import NeoZenRepository


class SampleModel(Base):
    """Sample SQLAlchemy model for testing."""

    __tablename__ = "sample_entity"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    value: Mapped[int]


class SampleRepository(NeoZenRepository[SampleModel]):
    """Repository for SampleModel."""

    model_type = SampleModel


@pytest.fixture
async def db_session():
    """Create an in-memory SQLite database and session."""
    from sqlalchemy.pool import StaticPool

    # Use StaticPool for in-memory SQLite to maintain single connection
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session_maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session_maker() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def sqlalchemy_repository(db_session: AsyncSession) -> SampleRepository:
    """Provide a SQLAlchemy repository instance."""
    return SampleRepository(session=db_session)


# -----------------------------------------------------------------------------
# SQLAlchemy-specific repository tests
# -----------------------------------------------------------------------------


@pytest.mark.anyio
class TestSQLAlchemyRepositoryProtocol:
    """Tests that verify SQLAlchemy repository implements RepositoryProtocol."""

    # -------------------------------------------------------------------------
    # create() tests
    # -------------------------------------------------------------------------

    async def test_create_returns_object(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        obj = await sqlalchemy_repository.create(id="1", name="test", value=42)

        assert obj.id == "1"
        assert obj.name == "test"
        assert obj.value == 42

    async def test_create_persists_object(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        await sqlalchemy_repository.create(id="1", name="test", value=42)

        obj = await sqlalchemy_repository.get_one_by(id="1")
        assert obj.id == "1"

    # -------------------------------------------------------------------------
    # get_one_by() tests
    # -------------------------------------------------------------------------

    async def test_get_one_by_returns_matching_object(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        await sqlalchemy_repository.create(id="1", name="test", value=42)

        obj = await sqlalchemy_repository.get_one_by(id="1")

        assert obj.id == "1"
        assert obj.name == "test"

    async def test_get_one_by_raises_does_not_exist(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        with pytest.raises(DoesNotExist):
            await sqlalchemy_repository.get_one_by(id="nonexistent")

    async def test_get_one_by_multiple_filters(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        await sqlalchemy_repository.create(id="1", name="test", value=42)
        await sqlalchemy_repository.create(id="2", name="test", value=100)

        obj = await sqlalchemy_repository.get_one_by(name="test", value=42)

        assert obj.id == "1"

    # -------------------------------------------------------------------------
    # get_many_by() tests
    # -------------------------------------------------------------------------

    async def test_get_many_by_returns_all_matching(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        await sqlalchemy_repository.create(id="1", name="alpha", value=10)
        await sqlalchemy_repository.create(id="2", name="alpha", value=20)
        await sqlalchemy_repository.create(id="3", name="beta", value=30)

        results = await sqlalchemy_repository.get_many_by(name="alpha")

        assert len(results) == 2
        assert all(obj.name == "alpha" for obj in results)

    async def test_get_many_by_returns_empty_list_when_no_match(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        await sqlalchemy_repository.create(id="1", name="test", value=42)

        results = await sqlalchemy_repository.get_many_by(name="nonexistent")

        assert results == []

    async def test_get_many_by_with_limit(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        await sqlalchemy_repository.create(id="1", name="test", value=1)
        await sqlalchemy_repository.create(id="2", name="test", value=2)
        await sqlalchemy_repository.create(id="3", name="test", value=3)

        results = await sqlalchemy_repository.get_many_by(name="test", limit=2)

        assert len(results) == 2

    async def test_get_many_by_with_offset(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        await sqlalchemy_repository.create(id="1", name="test", value=1)
        await sqlalchemy_repository.create(id="2", name="test", value=2)
        await sqlalchemy_repository.create(id="3", name="test", value=3)

        results = await sqlalchemy_repository.get_many_by(name="test", offset=1)

        assert len(results) == 2

    # -------------------------------------------------------------------------
    # count() tests
    # -------------------------------------------------------------------------

    async def test_count_returns_zero_when_empty(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        result = await sqlalchemy_repository.count()

        assert result == 0

    async def test_count_returns_total_without_filters(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        await sqlalchemy_repository.create(id="1", name="first", value=1)
        await sqlalchemy_repository.create(id="2", name="second", value=2)

        result = await sqlalchemy_repository.count()

        assert result == 2

    async def test_count_with_filters(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        await sqlalchemy_repository.create(id="1", name="alpha", value=10)
        await sqlalchemy_repository.create(id="2", name="alpha", value=20)
        await sqlalchemy_repository.create(id="3", name="beta", value=30)

        result = await sqlalchemy_repository.count(name="alpha")

        assert result == 2

    # -------------------------------------------------------------------------
    # exists() tests
    # -------------------------------------------------------------------------

    async def test_exists_returns_true_when_match_found(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        await sqlalchemy_repository.create(id="1", name="test", value=42)

        result = await sqlalchemy_repository.exists(id="1")

        assert result is True

    async def test_exists_returns_false_when_no_match(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        await sqlalchemy_repository.create(id="1", name="test", value=42)

        result = await sqlalchemy_repository.exists(id="nonexistent")

        assert result is False

    # -------------------------------------------------------------------------
    # update_obj() tests
    # -------------------------------------------------------------------------

    async def test_update_obj_modifies_object(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        obj = await sqlalchemy_repository.create(id="1", name="original", value=10)

        updated = await sqlalchemy_repository.update_obj(obj, name="updated", value=20)

        assert updated.name == "updated"
        assert updated.value == 20

    async def test_update_obj_persists_changes(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        obj = await sqlalchemy_repository.create(id="1", name="original", value=10)

        await sqlalchemy_repository.update_obj(obj, name="updated")

        retrieved = await sqlalchemy_repository.get_one_by(id="1")
        assert retrieved.name == "updated"

    # -------------------------------------------------------------------------
    # delete() tests
    # -------------------------------------------------------------------------

    async def test_delete_removes_object(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        obj = await sqlalchemy_repository.create(id="1", name="test", value=42)

        await sqlalchemy_repository.delete(obj)

        with pytest.raises(DoesNotExist):
            await sqlalchemy_repository.get_one_by(id="1")

    async def test_delete_reduces_count(
        self, sqlalchemy_repository: SampleRepository
    ) -> None:
        obj = await sqlalchemy_repository.create(id="1", name="test", value=42)
        await sqlalchemy_repository.create(id="2", name="test2", value=43)

        assert await sqlalchemy_repository.count() == 2

        await sqlalchemy_repository.delete(obj)

        assert await sqlalchemy_repository.count() == 1
