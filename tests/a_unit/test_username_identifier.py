"""Tests for username identifier."""

from __future__ import annotations

import dataclasses

import pytest

from neozen.core.identifiers.base import (
    IdentifierVerificationError,
    InvalidIdentifierFormat,
)
from neozen.core.identifiers.username import (
    DEFAULT_RESERVED_USERNAMES,
    UsernameIdentifier,
    UsernameSubjectModel,
)
from neozen.storage import DoesNotExist
from tests.conftest import MockStorage


@dataclasses.dataclass
class MockUsernameSubject(UsernameSubjectModel):
    id: str
    username: str


@pytest.fixture
def username_storage() -> MockStorage[MockUsernameSubject]:
    return MockStorage(MockUsernameSubject, [])


@pytest.fixture
def username_identifier(
    username_storage: MockStorage[MockUsernameSubject],
) -> UsernameIdentifier[MockUsernameSubject]:
    return UsernameIdentifier(username_storage)


@pytest.mark.anyio
class TestUsernameIdentifier:
    async def test_parse_valid_identifier(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        result = await username_identifier.parse_identifier("john_doe")
        assert result == "john_doe"

    async def test_parse_invalid_identifier_type(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        with pytest.raises(InvalidIdentifierFormat):
            await username_identifier.parse_identifier(12345)

    async def test_verify_valid_username(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        result = await username_identifier.verify_identifier("john_doe")
        assert result == "john_doe"

    async def test_verify_uppercase_normalized_to_lowercase(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        result = await username_identifier.verify_identifier("John_Doe")
        assert result == "john_doe"

    async def test_verify_username_with_numbers(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        result = await username_identifier.verify_identifier("user123")
        assert result == "user123"

    async def test_verify_username_with_hyphen(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        result = await username_identifier.verify_identifier("john-doe")
        assert result == "john-doe"

    async def test_verify_too_short(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        with pytest.raises(IdentifierVerificationError) as exc_info:
            await username_identifier.verify_identifier("ab")
        assert "at least 3 characters" in str(exc_info.value)

    async def test_verify_too_long(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        with pytest.raises(IdentifierVerificationError) as exc_info:
            await username_identifier.verify_identifier("a" * 33)
        assert "at most 32 characters" in str(exc_info.value)

    async def test_verify_starts_with_underscore(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        with pytest.raises(IdentifierVerificationError) as exc_info:
            await username_identifier.verify_identifier("_invalid")
        assert "must start with" in str(exc_info.value)

    async def test_verify_starts_with_hyphen(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        with pytest.raises(IdentifierVerificationError) as exc_info:
            await username_identifier.verify_identifier("-invalid")
        assert "must start with" in str(exc_info.value)

    async def test_verify_invalid_characters(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        with pytest.raises(IdentifierVerificationError):
            await username_identifier.verify_identifier("john@doe")

    async def test_verify_reserved_username(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        with pytest.raises(IdentifierVerificationError) as exc_info:
            await username_identifier.verify_identifier("admin")
        assert "reserved" in str(exc_info.value)

    async def test_verify_reserved_username_case_insensitive(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        with pytest.raises(IdentifierVerificationError) as exc_info:
            await username_identifier.verify_identifier("ADMIN")
        assert "reserved" in str(exc_info.value)

    async def test_get_by_identifier_exists(
        self,
        username_storage: MockStorage[MockUsernameSubject],
        username_identifier: UsernameIdentifier[MockUsernameSubject],
    ) -> None:
        await username_storage.create(id="1", username="john_doe")
        result = await username_identifier.get_by_identifier("john_doe")
        assert result.id == "1"
        assert result.username == "john_doe"

    async def test_get_by_identifier_case_insensitive(
        self,
        username_storage: MockStorage[MockUsernameSubject],
        username_identifier: UsernameIdentifier[MockUsernameSubject],
    ) -> None:
        await username_storage.create(id="1", username="john_doe")
        result = await username_identifier.get_by_identifier("JOHN_DOE")
        assert result.id == "1"

    async def test_get_by_identifier_not_exists(
        self, username_identifier: UsernameIdentifier[MockUsernameSubject]
    ) -> None:
        with pytest.raises(DoesNotExist):
            await username_identifier.get_by_identifier("nonexistent")

    async def test_custom_reserved_usernames(
        self, username_storage: MockStorage[MockUsernameSubject]
    ) -> None:
        custom_reserved = frozenset({"forbidden", "blocked"})
        identifier = UsernameIdentifier(
            username_storage, reserved_usernames=custom_reserved
        )

        # Default reserved username should now be allowed
        result = await identifier.verify_identifier("admin")
        assert result == "admin"

        # Custom reserved username should be blocked
        with pytest.raises(IdentifierVerificationError):
            await identifier.verify_identifier("forbidden")


class TestDefaultReservedUsernames:
    def test_contains_common_reserved_names(self) -> None:
        assert "admin" in DEFAULT_RESERVED_USERNAMES
        assert "root" in DEFAULT_RESERVED_USERNAMES
        assert "system" in DEFAULT_RESERVED_USERNAMES
        assert "support" in DEFAULT_RESERVED_USERNAMES
