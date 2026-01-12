"""Shared pytest fixtures and configuration for Prezo tests.

Test Pyramid Structure:
- tests/a_unit/        - Unit tests (fast, isolated, no I/O)
- tests/b_integration/ - Integration tests (component interactions, file I/O)
- tests/c_e2e/         - End-to-end tests (full app/CLI workflows)

Run specific test types:
    uv run pytest -m unit              # Run only unit tests
    uv run pytest -m integration       # Run only integration tests
    uv run pytest -m e2e               # Run only e2e tests
    uv run pytest tests/a_unit/        # Run by directory
"""

from __future__ import annotations

from pathlib import Path

import pytest


def pytest_collection_modifyitems(config, items):
    """Automatically apply markers based on test directory."""
    for item in items:
        # Get the path relative to tests/
        test_path = Path(item.fspath)
        parts = test_path.parts

        # Apply markers based on directory
        if "a_unit" in parts:
            item.add_marker(pytest.mark.unit)
        elif "b_integration" in parts:
            item.add_marker(pytest.mark.integration)
        elif "c_e2e" in parts:
            item.add_marker(pytest.mark.e2e)


# -----------------------------------------------------------------------------
# Shared Fixtures
# -----------------------------------------------------------------------------

import dataclasses
import typing
from collections.abc import Callable, Coroutine, Iterable

from neozen.core.storage import DoesNotExist, StorageProtocol, StorageProvider


@dataclasses.dataclass
class MockModel:
    """Simple mock model for testing."""

    id: str


class MockStorage[Model](StorageProtocol[Model]):
    """In-memory mock storage for testing."""

    def __init__(self, model: type[Model], data: list[Model]) -> None:
        self.model = model
        self._data = data

    async def get_one_by(self, **filters: typing.Any) -> Model:
        for obj in self._data:
            if all(getattr(obj, key) == value for key, value in filters.items()):
                return obj
        raise DoesNotExist()

    async def create(self, **data: typing.Any) -> Model:
        obj = self.model(**data)
        self._data.append(obj)
        return obj

    async def update(self, obj: Model, **data: typing.Any) -> Model:
        for key, value in data.items():
            setattr(obj, key, value)
        return obj


class MockStorageProvider(StorageProvider):
    """Mock storage provider for testing."""

    def __init__[Model](
        self,
        data: dict[typing.Any, list[typing.Any]],
        models: Iterable[type[Model]] | None = None,
        storage_class: type[MockStorage[typing.Any]] = MockStorage,
    ) -> None:
        super().__init__(models=models)
        self.data = data
        self.storage_class = storage_class

    def _get_storage_factory(
        self,
    ) -> Callable[..., Coroutine[None, None, StorageProtocol[typing.Any]]]:
        async def _get_storage[Model](model: type[Model]) -> StorageProtocol[Model]:
            return self.storage_class(model, self.data.get(model, []))

        return _get_storage


@pytest.fixture
def anyio_backend() -> str:
    """Configure anyio to use asyncio backend."""
    return "asyncio"
