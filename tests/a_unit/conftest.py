"""Unit test fixtures."""

from __future__ import annotations

import pytest

from tests.conftest import MockStorage


@pytest.fixture
def mock_repository():
    """Provide a MockStorage instance for TestEntity.

    This fixture is used by test_repository_protocol.py to test
    the RepositoryProtocol contract using an in-memory mock.
    """
    # Import here to avoid circular import
    from tests.a_unit.core.test_repository_protocol import SampleEntity

    return MockStorage(SampleEntity, [])
