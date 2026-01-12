"""Tests for storage abstraction."""

from __future__ import annotations

import dataclasses

import pytest

from neozen.core.storage import DoesNotExist
from tests.conftest import MockModel, MockStorage


@pytest.fixture
def storage() -> MockStorage[MockModel]:
    return MockStorage(MockModel, [])


@pytest.mark.anyio
class TestMockStorage:
    async def test_create(self, storage: MockStorage[MockModel]) -> None:
        obj = await storage.create(id="1")
        assert obj.id == "1"

    async def test_get_one_by_exists(self, storage: MockStorage[MockModel]) -> None:
        await storage.create(id="1")
        obj = await storage.get_one_by(id="1")
        assert obj.id == "1"

    async def test_get_one_by_not_exists(self, storage: MockStorage[MockModel]) -> None:
        with pytest.raises(DoesNotExist):
            await storage.get_one_by(id="nonexistent")

    async def test_update(self, storage: MockStorage[MockModel]) -> None:
        obj = await storage.create(id="1")
        updated = await storage.update(obj, id="2")
        assert updated.id == "2"


@dataclasses.dataclass
class ExtendedModel:
    id: str
    name: str
    value: int


@pytest.fixture
def extended_storage() -> MockStorage[ExtendedModel]:
    return MockStorage(ExtendedModel, [])


@pytest.mark.anyio
class TestMockStorageExtended:
    async def test_create_with_multiple_fields(
        self, extended_storage: MockStorage[ExtendedModel]
    ) -> None:
        obj = await extended_storage.create(id="1", name="test", value=42)
        assert obj.id == "1"
        assert obj.name == "test"
        assert obj.value == 42

    async def test_get_one_by_multiple_filters(
        self, extended_storage: MockStorage[ExtendedModel]
    ) -> None:
        await extended_storage.create(id="1", name="test", value=42)
        await extended_storage.create(id="2", name="test", value=100)

        obj = await extended_storage.get_one_by(name="test", value=42)
        assert obj.id == "1"

    async def test_update_partial(
        self, extended_storage: MockStorage[ExtendedModel]
    ) -> None:
        obj = await extended_storage.create(id="1", name="test", value=42)
        updated = await extended_storage.update(obj, value=100)
        assert updated.id == "1"
        assert updated.name == "test"
        assert updated.value == 100
