"""Integration tests for Peewee repository implementation.

Tests that PeeweeRepository properly implements the RepositoryProtocol
using a real Peewee database (file-based SQLite for thread safety).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import peewee
import pytest

from neozen.core.repository import DoesNotExist
from neozen.storage.peewee import PeeweeRepository


# Use a deferred database that gets bound per test
_proxy_db = peewee.Proxy()


class SampleModel(peewee.Model):
    """Sample Peewee model for testing."""

    id = peewee.CharField(primary_key=True, max_length=64)
    name = peewee.CharField(max_length=128)
    value = peewee.IntegerField()

    class Meta:
        database = _proxy_db
        table_name = "sample_entity"


class SampleRepository(PeeweeRepository[SampleModel]):
    """Repository for SampleModel."""

    model_type = SampleModel


@pytest.fixture
def peewee_repository(tmp_path: Path):
    """Provide a Peewee repository instance with fresh database."""
    # Use a file-based database for thread safety
    db_path = tmp_path / "test.db"
    db = peewee.SqliteDatabase(str(db_path))
    _proxy_db.initialize(db)

    db.connect()
    db.create_tables([SampleModel])

    yield SampleRepository(db)

    db.close()


# -----------------------------------------------------------------------------
# Peewee-specific repository tests
# -----------------------------------------------------------------------------


@pytest.mark.anyio
class TestPeeweeRepositoryProtocol:
    """Tests that verify Peewee repository implements RepositoryProtocol."""

    # -------------------------------------------------------------------------
    # create() tests
    # -------------------------------------------------------------------------

    async def test_create_returns_object(
        self, peewee_repository: SampleRepository
    ) -> None:
        obj = await peewee_repository.create(id="1", name="test", value=42)

        assert obj.id == "1"
        assert obj.name == "test"
        assert obj.value == 42

    async def test_create_persists_object(
        self, peewee_repository: SampleRepository
    ) -> None:
        await peewee_repository.create(id="1", name="test", value=42)

        obj = await peewee_repository.get_one_by(id="1")
        assert obj.id == "1"

    # -------------------------------------------------------------------------
    # get_one_by() tests
    # -------------------------------------------------------------------------

    async def test_get_one_by_returns_matching_object(
        self, peewee_repository: SampleRepository
    ) -> None:
        await peewee_repository.create(id="1", name="test", value=42)

        obj = await peewee_repository.get_one_by(id="1")

        assert obj.id == "1"
        assert obj.name == "test"

    async def test_get_one_by_raises_does_not_exist(
        self, peewee_repository: SampleRepository
    ) -> None:
        with pytest.raises(DoesNotExist):
            await peewee_repository.get_one_by(id="nonexistent")

    async def test_get_one_by_multiple_filters(
        self, peewee_repository: SampleRepository
    ) -> None:
        await peewee_repository.create(id="1", name="test", value=42)
        await peewee_repository.create(id="2", name="test", value=100)

        obj = await peewee_repository.get_one_by(name="test", value=42)

        assert obj.id == "1"

    # -------------------------------------------------------------------------
    # get_many_by() tests
    # -------------------------------------------------------------------------

    async def test_get_many_by_returns_all_matching(
        self, peewee_repository: SampleRepository
    ) -> None:
        await peewee_repository.create(id="1", name="alpha", value=10)
        await peewee_repository.create(id="2", name="alpha", value=20)
        await peewee_repository.create(id="3", name="beta", value=30)

        results = await peewee_repository.get_many_by(name="alpha")

        assert len(results) == 2
        assert all(obj.name == "alpha" for obj in results)

    async def test_get_many_by_returns_empty_list_when_no_match(
        self, peewee_repository: SampleRepository
    ) -> None:
        await peewee_repository.create(id="1", name="test", value=42)

        results = await peewee_repository.get_many_by(name="nonexistent")

        assert results == []

    async def test_get_many_by_with_limit(
        self, peewee_repository: SampleRepository
    ) -> None:
        await peewee_repository.create(id="1", name="test", value=1)
        await peewee_repository.create(id="2", name="test", value=2)
        await peewee_repository.create(id="3", name="test", value=3)

        results = await peewee_repository.get_many_by(name="test", limit=2)

        assert len(results) == 2

    async def test_get_many_by_with_offset(
        self, peewee_repository: SampleRepository
    ) -> None:
        await peewee_repository.create(id="1", name="test", value=1)
        await peewee_repository.create(id="2", name="test", value=2)
        await peewee_repository.create(id="3", name="test", value=3)

        results = await peewee_repository.get_many_by(name="test", offset=1)

        assert len(results) == 2

    # -------------------------------------------------------------------------
    # count() tests
    # -------------------------------------------------------------------------

    async def test_count_returns_zero_when_empty(
        self, peewee_repository: SampleRepository
    ) -> None:
        result = await peewee_repository.count()

        assert result == 0

    async def test_count_returns_total_without_filters(
        self, peewee_repository: SampleRepository
    ) -> None:
        await peewee_repository.create(id="1", name="first", value=1)
        await peewee_repository.create(id="2", name="second", value=2)

        result = await peewee_repository.count()

        assert result == 2

    async def test_count_with_filters(
        self, peewee_repository: SampleRepository
    ) -> None:
        await peewee_repository.create(id="1", name="alpha", value=10)
        await peewee_repository.create(id="2", name="alpha", value=20)
        await peewee_repository.create(id="3", name="beta", value=30)

        result = await peewee_repository.count(name="alpha")

        assert result == 2

    # -------------------------------------------------------------------------
    # exists() tests
    # -------------------------------------------------------------------------

    async def test_exists_returns_true_when_match_found(
        self, peewee_repository: SampleRepository
    ) -> None:
        await peewee_repository.create(id="1", name="test", value=42)

        result = await peewee_repository.exists(id="1")

        assert result is True

    async def test_exists_returns_false_when_no_match(
        self, peewee_repository: SampleRepository
    ) -> None:
        await peewee_repository.create(id="1", name="test", value=42)

        result = await peewee_repository.exists(id="nonexistent")

        assert result is False

    # -------------------------------------------------------------------------
    # update_obj() tests
    # -------------------------------------------------------------------------

    async def test_update_obj_modifies_object(
        self, peewee_repository: SampleRepository
    ) -> None:
        obj = await peewee_repository.create(id="1", name="original", value=10)

        updated = await peewee_repository.update_obj(obj, name="updated", value=20)

        assert updated.name == "updated"
        assert updated.value == 20

    async def test_update_obj_persists_changes(
        self, peewee_repository: SampleRepository
    ) -> None:
        obj = await peewee_repository.create(id="1", name="original", value=10)

        await peewee_repository.update_obj(obj, name="updated")

        retrieved = await peewee_repository.get_one_by(id="1")
        assert retrieved.name == "updated"

    # -------------------------------------------------------------------------
    # delete() tests
    # -------------------------------------------------------------------------

    async def test_delete_removes_object(
        self, peewee_repository: SampleRepository
    ) -> None:
        obj = await peewee_repository.create(id="1", name="test", value=42)

        await peewee_repository.delete(obj)

        with pytest.raises(DoesNotExist):
            await peewee_repository.get_one_by(id="1")

    async def test_delete_reduces_count(
        self, peewee_repository: SampleRepository
    ) -> None:
        obj = await peewee_repository.create(id="1", name="test", value=42)
        await peewee_repository.create(id="2", name="test2", value=43)

        assert await peewee_repository.count() == 2

        await peewee_repository.delete(obj)

        assert await peewee_repository.count() == 1
