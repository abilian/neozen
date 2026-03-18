"""Test suite for RepositoryProtocol compliance.

This test suite defines the contract that all storage backends must satisfy.
Each backend should provide a fixture that yields a repository instance
implementing RepositoryProtocol.

To test a new backend:
1. Create a conftest.py in the backend's test directory
2. Define a fixture named `repository` that yields your repository
3. Import or run these tests

Example:
    @pytest.fixture
    async def repository():
        # Setup your backend
        yield YourRepository(session=db_session)
        # Cleanup
"""

from __future__ import annotations

import dataclasses

import pytest

from neozen.core.repository import DoesNotExist


@dataclasses.dataclass
class SampleEntity:
    """Sample entity for repository protocol tests."""

    id: str
    name: str
    value: int


# -----------------------------------------------------------------------------
# Protocol Compliance Test Suite
# -----------------------------------------------------------------------------


@pytest.mark.anyio
class TestRepositoryProtocolCompliance:
    """Tests that verify RepositoryProtocol compliance.

    These tests can be run against any repository implementation by providing
    a fixture named `mock_repository` that yields a repository for TestEntity.
    """

    # -------------------------------------------------------------------------
    # create() tests
    # -------------------------------------------------------------------------

    async def test_create_returns_object(self, mock_repository) -> None:
        """create() should return the created object."""
        obj = await mock_repository.create(id="1", name="test", value=42)

        assert obj.id == "1"
        assert obj.name == "test"
        assert obj.value == 42

    async def test_create_persists_object(self, mock_repository) -> None:
        """create() should persist the object so it can be retrieved."""
        await mock_repository.create(id="1", name="test", value=42)

        obj = await mock_repository.get_one_by(id="1")
        assert obj.id == "1"

    async def test_create_multiple_objects(self, mock_repository) -> None:
        """create() should allow creating multiple objects."""
        await mock_repository.create(id="1", name="first", value=1)
        await mock_repository.create(id="2", name="second", value=2)

        obj1 = await mock_repository.get_one_by(id="1")
        obj2 = await mock_repository.get_one_by(id="2")

        assert obj1.name == "first"
        assert obj2.name == "second"

    # -------------------------------------------------------------------------
    # get_one_by() tests
    # -------------------------------------------------------------------------

    async def test_get_one_by_returns_matching_object(self, mock_repository) -> None:
        """get_one_by() should return the object matching the filters."""
        await mock_repository.create(id="1", name="test", value=42)

        obj = await mock_repository.get_one_by(id="1")

        assert obj.id == "1"
        assert obj.name == "test"

    async def test_get_one_by_raises_does_not_exist(self, mock_repository) -> None:
        """get_one_by() should raise DoesNotExist when no match is found."""
        with pytest.raises(DoesNotExist):
            await mock_repository.get_one_by(id="nonexistent")

    async def test_get_one_by_multiple_filters(self, mock_repository) -> None:
        """get_one_by() should match on multiple filters."""
        await mock_repository.create(id="1", name="test", value=42)
        await mock_repository.create(id="2", name="test", value=100)

        obj = await mock_repository.get_one_by(name="test", value=42)

        assert obj.id == "1"

    async def test_get_one_by_no_match_with_partial_filters(
        self, mock_repository
    ) -> None:
        """get_one_by() should not match when only some filters match."""
        await mock_repository.create(id="1", name="test", value=42)

        with pytest.raises(DoesNotExist):
            await mock_repository.get_one_by(name="test", value=999)

    # -------------------------------------------------------------------------
    # get_many_by() tests
    # -------------------------------------------------------------------------

    async def test_get_many_by_returns_all_matching(self, mock_repository) -> None:
        """get_many_by() should return all objects matching the filters."""
        await mock_repository.create(id="1", name="alpha", value=10)
        await mock_repository.create(id="2", name="alpha", value=20)
        await mock_repository.create(id="3", name="beta", value=30)

        results = await mock_repository.get_many_by(name="alpha")

        assert len(results) == 2
        assert all(obj.name == "alpha" for obj in results)

    async def test_get_many_by_returns_empty_list_when_no_match(
        self, mock_repository
    ) -> None:
        """get_many_by() should return empty list when no matches."""
        await mock_repository.create(id="1", name="test", value=42)

        results = await mock_repository.get_many_by(name="nonexistent")

        assert results == []

    async def test_get_many_by_with_no_filters_returns_all(
        self, mock_repository
    ) -> None:
        """get_many_by() with no filters should return all objects."""
        await mock_repository.create(id="1", name="first", value=1)
        await mock_repository.create(id="2", name="second", value=2)

        results = await mock_repository.get_many_by()

        assert len(results) == 2

    async def test_get_many_by_with_limit(self, mock_repository) -> None:
        """get_many_by() should respect the limit parameter."""
        await mock_repository.create(id="1", name="test", value=1)
        await mock_repository.create(id="2", name="test", value=2)
        await mock_repository.create(id="3", name="test", value=3)

        results = await mock_repository.get_many_by(name="test", limit=2)

        assert len(results) == 2

    async def test_get_many_by_with_offset(self, mock_repository) -> None:
        """get_many_by() should respect the offset parameter."""
        await mock_repository.create(id="1", name="test", value=1)
        await mock_repository.create(id="2", name="test", value=2)
        await mock_repository.create(id="3", name="test", value=3)

        results = await mock_repository.get_many_by(name="test", offset=1)

        assert len(results) == 2

    async def test_get_many_by_with_offset_and_limit(self, mock_repository) -> None:
        """get_many_by() should combine offset and limit correctly."""
        await mock_repository.create(id="1", name="test", value=1)
        await mock_repository.create(id="2", name="test", value=2)
        await mock_repository.create(id="3", name="test", value=3)
        await mock_repository.create(id="4", name="test", value=4)

        results = await mock_repository.get_many_by(name="test", offset=1, limit=2)

        assert len(results) == 2

    # -------------------------------------------------------------------------
    # count() tests
    # -------------------------------------------------------------------------

    async def test_count_returns_zero_when_empty(self, mock_repository) -> None:
        """count() should return 0 for empty repository."""
        result = await mock_repository.count()

        assert result == 0

    async def test_count_returns_total_without_filters(self, mock_repository) -> None:
        """count() without filters should return total count."""
        await mock_repository.create(id="1", name="first", value=1)
        await mock_repository.create(id="2", name="second", value=2)

        result = await mock_repository.count()

        assert result == 2

    async def test_count_with_filters(self, mock_repository) -> None:
        """count() should count only matching objects."""
        await mock_repository.create(id="1", name="alpha", value=10)
        await mock_repository.create(id="2", name="alpha", value=20)
        await mock_repository.create(id="3", name="beta", value=30)

        result = await mock_repository.count(name="alpha")

        assert result == 2

    async def test_count_returns_zero_when_no_match(self, mock_repository) -> None:
        """count() should return 0 when no objects match."""
        await mock_repository.create(id="1", name="test", value=42)

        result = await mock_repository.count(name="nonexistent")

        assert result == 0

    # -------------------------------------------------------------------------
    # exists() tests
    # -------------------------------------------------------------------------

    async def test_exists_returns_true_when_match_found(self, mock_repository) -> None:
        """exists() should return True when matching object exists."""
        await mock_repository.create(id="1", name="test", value=42)

        result = await mock_repository.exists(id="1")

        assert result is True

    async def test_exists_returns_false_when_no_match(self, mock_repository) -> None:
        """exists() should return False when no matching object exists."""
        await mock_repository.create(id="1", name="test", value=42)

        result = await mock_repository.exists(id="nonexistent")

        assert result is False

    async def test_exists_returns_false_when_empty(self, mock_repository) -> None:
        """exists() should return False for empty repository."""
        result = await mock_repository.exists(id="1")

        assert result is False

    async def test_exists_with_multiple_filters(self, mock_repository) -> None:
        """exists() should check all filters."""
        await mock_repository.create(id="1", name="test", value=42)

        assert await mock_repository.exists(name="test", value=42) is True
        assert await mock_repository.exists(name="test", value=999) is False

    # -------------------------------------------------------------------------
    # update_obj() tests
    # -------------------------------------------------------------------------

    async def test_update_obj_modifies_object(self, mock_repository) -> None:
        """update_obj() should modify the object's attributes."""
        obj = await mock_repository.create(id="1", name="original", value=10)

        updated = await mock_repository.update_obj(obj, name="updated", value=20)

        assert updated.name == "updated"
        assert updated.value == 20
        assert updated.id == "1"  # Unchanged

    async def test_update_obj_persists_changes(self, mock_repository) -> None:
        """update_obj() should persist changes so they can be retrieved."""
        obj = await mock_repository.create(id="1", name="original", value=10)

        await mock_repository.update_obj(obj, name="updated")

        retrieved = await mock_repository.get_one_by(id="1")
        assert retrieved.name == "updated"

    async def test_update_obj_partial_update(self, mock_repository) -> None:
        """update_obj() should only modify specified attributes."""
        obj = await mock_repository.create(id="1", name="original", value=10)

        await mock_repository.update_obj(obj, value=20)

        assert obj.name == "original"  # Unchanged
        assert obj.value == 20  # Changed

    # -------------------------------------------------------------------------
    # delete() tests
    # -------------------------------------------------------------------------

    async def test_delete_removes_object(self, mock_repository) -> None:
        """delete() should remove the object from the repository."""
        obj = await mock_repository.create(id="1", name="test", value=42)

        await mock_repository.delete(obj)

        with pytest.raises(DoesNotExist):
            await mock_repository.get_one_by(id="1")

    async def test_delete_does_not_affect_other_objects(self, mock_repository) -> None:
        """delete() should only remove the specified object."""
        obj1 = await mock_repository.create(id="1", name="first", value=1)
        await mock_repository.create(id="2", name="second", value=2)

        await mock_repository.delete(obj1)

        # Second object should still exist
        obj2 = await mock_repository.get_one_by(id="2")
        assert obj2.name == "second"

    async def test_delete_reduces_count(self, mock_repository) -> None:
        """delete() should reduce the count."""
        obj = await mock_repository.create(id="1", name="test", value=42)
        await mock_repository.create(id="2", name="test2", value=43)

        assert await mock_repository.count() == 2

        await mock_repository.delete(obj)

        assert await mock_repository.count() == 1
