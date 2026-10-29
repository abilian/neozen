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

import importlib.util
import logging
import sysconfig
from collections.abc import Generator
from pathlib import Path

import pytest
from _pytest._code.code import ExceptionInfo, Traceback

# Playwright has no musl wheels, so Alpine CI syncs without it.
collect_ignore = [] if importlib.util.find_spec("playwright") else ["d_playwright"]

# Quiet INFO-level lifecycle logs from `tortoise` and `databases`.
#
# Both libraries emit INFO-level startup/shutdown messages from background
# threads during fixture teardown ("Tortoise-ORM shutdown", "Connected to
# database ...", "Disconnected from database ..."). Those emissions race
# with pytest's capture teardown: when the captured stderr stream is closed
# before the thread's log record reaches its StreamHandler, we get a
# spurious `ValueError: I/O operation on closed file` traceback printed to
# the terminal. The log records themselves carry no diagnostic value for
# test runs, so raising the level eliminates both the noise and the race at
# the source.
logging.getLogger("tortoise").setLevel(logging.WARNING)
logging.getLogger("databases").setLevel(logging.WARNING)


# Failure reports show only frames from this repository: a SQLAlchemy or
# Werkzeug error otherwise runs to hundreds of lines, once per chained
# exception. `--full-trace` shows everything.
_LIBRARY_PATHS = tuple({
    sysconfig.get_path(name) for name in ("stdlib", "purelib", "platlib")
})


def _own_frames(excinfo: ExceptionInfo[BaseException]) -> Traceback:
    traceback = excinfo.traceback
    own = traceback.filter(lambda entry: not str(entry.path).startswith(_LIBRARY_PATHS))
    # An exception raised entirely inside a library: keep where it was raised.
    return own or traceback[-1:]


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    report = yield
    excinfo = call.excinfo
    if (
        report.failed
        and excinfo is not None
        and not item.config.getoption("fulltrace")
        and not excinfo.errisinstance(pytest.fail.Exception)
    ):
        style = item.config.getoption("tbstyle")
        report.longrepr = excinfo.getrepr(
            style="long" if style == "auto" else style,
            tbfilter=_own_frames,
        )
    return report


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

from neozen.core.repository import DoesNotExist, RepositoryProtocol


@dataclasses.dataclass
class MockModel:
    """Simple mock model for testing."""

    id: str


class MockStorage[Model](RepositoryProtocol[Model]):
    """In-memory mock storage for testing."""

    def __init__(self, model: type[Model], data: list[Model] | None = None) -> None:
        self.model_type = model
        self._data = data if data is not None else []

    def _filter(self, **filters: typing.Any) -> list[Model]:
        """Filter data by the given filters."""
        return [
            obj
            for obj in self._data
            if all(getattr(obj, key) == value for key, value in filters.items())
        ]

    async def get_one_by(self, **filters: typing.Any) -> Model:
        results = self._filter(**filters)
        if not results:
            raise DoesNotExist
        if len(results) > 1:
            # The SQL repositories raise too: use get_many_by.
            msg = f"get_one_by({filters}) matched {len(results)} rows"
            raise LookupError(msg)
        return results[0]

    async def get_many_by(
        self,
        *,
        offset: int = 0,
        limit: int | None = None,
        **filters: typing.Any,
    ) -> list[Model]:
        results = self._filter(**filters)
        if limit is not None:
            return results[offset : offset + limit]
        return results[offset:]

    async def count(self, **filters: typing.Any) -> int:
        return len(self._filter(**filters))

    async def exists(self, **filters: typing.Any) -> bool:
        return len(self._filter(**filters)) > 0

    async def create(self, **data: typing.Any) -> Model:
        obj = self.model_type(**data)
        self._data.append(obj)
        return obj

    async def update_obj(self, obj: Model, **data: typing.Any) -> Model:
        for key, value in data.items():
            setattr(obj, key, value)
        return obj

    async def delete(self, obj: Model) -> None:
        if obj not in self._data:
            raise DoesNotExist
        self._data.remove(obj)


@pytest.fixture
def anyio_backend() -> str:
    """Configure anyio to use asyncio backend."""
    return "asyncio"
