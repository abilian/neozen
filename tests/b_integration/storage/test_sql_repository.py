"""Integration tests for raw SQL repository implementation.

Tests that SQLRepository properly implements the RepositoryProtocol
using a real database (in-memory SQLite via databases library).
"""

from __future__ import annotations

import dataclasses

import pytest
from databases import Database

from neozen.core.repository import DoesNotExist
from neozen.storage.sql import SQLRepository


@dataclasses.dataclass
class SampleModel:
    """Sample dataclass model for testing."""

    id: str
    name: str
    value: int


class SampleRepository(SQLRepository[SampleModel]):
    """Repository for SampleModel."""

    model_type = SampleModel
    table_name = "sample_entity"
    primary_key = "id"


@pytest.fixture
async def sql_repository(tmp_path):
    """Provide a SQL repository instance with fresh database."""
    db_path = tmp_path / "test.db"
    database = Database(f"sqlite+aiosqlite:///{db_path}")
    await database.connect()

    # Create the table
    await database.execute("""
        CREATE TABLE sample_entity (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            value INTEGER NOT NULL
        )
    """)

    yield SampleRepository(database)

    await database.disconnect()


# -----------------------------------------------------------------------------
# SQL-specific repository tests
# -----------------------------------------------------------------------------


@pytest.mark.anyio
class TestSQLRepositoryProtocol:
    """Tests that verify SQL repository implements RepositoryProtocol."""

    # -------------------------------------------------------------------------
    # create() tests
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize(
        "filters", [{"name = '' OR 1=1 --": "x"}, {"missing": "x"}]
    )
    async def test_unknown_column_names_never_reach_the_sql(
        self, sql_repository: SampleRepository, filters: dict[str, str]
    ) -> None:
        with pytest.raises(ValueError, match="Not a column"):
            await sql_repository.get_many_by(**filters)
        with pytest.raises(ValueError, match="Not a column"):
            await sql_repository.create(id="1", **filters)

    async def test_create_returns_object(
        self, sql_repository: SampleRepository
    ) -> None:
        obj = await sql_repository.create(id="1", name="test", value=42)

        assert obj.id == "1"
        assert obj.name == "test"
        assert obj.value == 42

    async def test_create_persists_object(
        self, sql_repository: SampleRepository
    ) -> None:
        await sql_repository.create(id="1", name="test", value=42)

        obj = await sql_repository.get_one_by(id="1")
        assert obj.id == "1"

    # -------------------------------------------------------------------------
    # get_one_by() tests
    # -------------------------------------------------------------------------

    async def test_get_one_by_returns_matching_object(
        self, sql_repository: SampleRepository
    ) -> None:
        await sql_repository.create(id="1", name="test", value=42)

        obj = await sql_repository.get_one_by(id="1")

        assert obj.id == "1"
        assert obj.name == "test"

    async def test_get_one_by_raises_does_not_exist(
        self, sql_repository: SampleRepository
    ) -> None:
        with pytest.raises(DoesNotExist):
            await sql_repository.get_one_by(id="nonexistent")

    async def test_get_one_by_multiple_filters(
        self, sql_repository: SampleRepository
    ) -> None:
        await sql_repository.create(id="1", name="test", value=42)
        await sql_repository.create(id="2", name="test", value=100)

        obj = await sql_repository.get_one_by(name="test", value=42)

        assert obj.id == "1"

    # -------------------------------------------------------------------------
    # get_many_by() tests
    # -------------------------------------------------------------------------

    async def test_get_many_by_returns_all_matching(
        self, sql_repository: SampleRepository
    ) -> None:
        await sql_repository.create(id="1", name="alpha", value=10)
        await sql_repository.create(id="2", name="alpha", value=20)
        await sql_repository.create(id="3", name="beta", value=30)

        results = await sql_repository.get_many_by(name="alpha")

        assert len(results) == 2
        assert all(obj.name == "alpha" for obj in results)

    async def test_get_many_by_returns_empty_list_when_no_match(
        self, sql_repository: SampleRepository
    ) -> None:
        await sql_repository.create(id="1", name="test", value=42)

        results = await sql_repository.get_many_by(name="nonexistent")

        assert results == []

    async def test_get_many_by_with_limit(
        self, sql_repository: SampleRepository
    ) -> None:
        await sql_repository.create(id="1", name="test", value=1)
        await sql_repository.create(id="2", name="test", value=2)
        await sql_repository.create(id="3", name="test", value=3)

        results = await sql_repository.get_many_by(name="test", limit=2)

        assert len(results) == 2

    async def test_get_many_by_with_offset(
        self, sql_repository: SampleRepository
    ) -> None:
        await sql_repository.create(id="1", name="test", value=1)
        await sql_repository.create(id="2", name="test", value=2)
        await sql_repository.create(id="3", name="test", value=3)

        results = await sql_repository.get_many_by(name="test", offset=1)

        assert len(results) == 2

    # -------------------------------------------------------------------------
    # count() tests
    # -------------------------------------------------------------------------

    async def test_count_returns_zero_when_empty(
        self, sql_repository: SampleRepository
    ) -> None:
        result = await sql_repository.count()

        assert result == 0

    async def test_count_returns_total_without_filters(
        self, sql_repository: SampleRepository
    ) -> None:
        await sql_repository.create(id="1", name="first", value=1)
        await sql_repository.create(id="2", name="second", value=2)

        result = await sql_repository.count()

        assert result == 2

    async def test_count_with_filters(self, sql_repository: SampleRepository) -> None:
        await sql_repository.create(id="1", name="alpha", value=10)
        await sql_repository.create(id="2", name="alpha", value=20)
        await sql_repository.create(id="3", name="beta", value=30)

        result = await sql_repository.count(name="alpha")

        assert result == 2

    # -------------------------------------------------------------------------
    # exists() tests
    # -------------------------------------------------------------------------

    async def test_exists_returns_true_when_match_found(
        self, sql_repository: SampleRepository
    ) -> None:
        await sql_repository.create(id="1", name="test", value=42)

        result = await sql_repository.exists(id="1")

        assert result is True

    async def test_exists_returns_false_when_no_match(
        self, sql_repository: SampleRepository
    ) -> None:
        await sql_repository.create(id="1", name="test", value=42)

        result = await sql_repository.exists(id="nonexistent")

        assert result is False

    # -------------------------------------------------------------------------
    # update_obj() tests
    # -------------------------------------------------------------------------

    async def test_update_obj_modifies_object(
        self, sql_repository: SampleRepository
    ) -> None:
        obj = await sql_repository.create(id="1", name="original", value=10)

        updated = await sql_repository.update_obj(obj, name="updated", value=20)

        assert updated.name == "updated"
        assert updated.value == 20

    async def test_update_obj_persists_changes(
        self, sql_repository: SampleRepository
    ) -> None:
        obj = await sql_repository.create(id="1", name="original", value=10)

        await sql_repository.update_obj(obj, name="updated")

        retrieved = await sql_repository.get_one_by(id="1")
        assert retrieved.name == "updated"

    # -------------------------------------------------------------------------
    # delete() tests
    # -------------------------------------------------------------------------

    async def test_delete_removes_object(
        self, sql_repository: SampleRepository
    ) -> None:
        obj = await sql_repository.create(id="1", name="test", value=42)

        await sql_repository.delete(obj)

        with pytest.raises(DoesNotExist):
            await sql_repository.get_one_by(id="1")

    async def test_delete_reduces_count(self, sql_repository: SampleRepository) -> None:
        obj = await sql_repository.create(id="1", name="test", value=42)
        await sql_repository.create(id="2", name="test2", value=43)

        assert await sql_repository.count() == 2

        await sql_repository.delete(obj)

        assert await sql_repository.count() == 1
