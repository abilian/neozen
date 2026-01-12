"""Tests for identifier implementations."""

from __future__ import annotations

import dataclasses

import pytest

from neozen.core.identifiers.base import (
    IdentifierVerificationError,
    InvalidIdentifierFormat,
)
from neozen.core.identifiers.email import EmailIdentifier, EmailSubjectModel
from neozen.storage import DoesNotExist
from tests.conftest import MockStorage


@dataclasses.dataclass
class MockEmailSubject(EmailSubjectModel):
    id: str
    email: str


@pytest.fixture
def email_storage() -> MockStorage[MockEmailSubject]:
    return MockStorage(MockEmailSubject, [])


@pytest.fixture
def email_identifier(
    email_storage: MockStorage[MockEmailSubject],
) -> EmailIdentifier[MockEmailSubject]:
    return EmailIdentifier(email_storage)


@pytest.mark.anyio
class TestEmailIdentifier:
    async def test_parse_valid_identifier(
        self, email_identifier: EmailIdentifier[MockEmailSubject]
    ) -> None:
        result = await email_identifier.parse_identifier("test@example.com")
        assert result == "test@example.com"

    async def test_parse_invalid_identifier_type(
        self, email_identifier: EmailIdentifier[MockEmailSubject]
    ) -> None:
        with pytest.raises(InvalidIdentifierFormat):
            await email_identifier.parse_identifier(12345)

    async def test_verify_valid_email(
        self, email_identifier: EmailIdentifier[MockEmailSubject]
    ) -> None:
        result = await email_identifier.verify_identifier("test@example.com")
        assert result == "test@example.com"

    async def test_verify_valid_email_normalization(
        self, email_identifier: EmailIdentifier[MockEmailSubject]
    ) -> None:
        # Email normalization lowercases the domain part only
        # (local part is technically case-sensitive per RFC 5321)
        result = await email_identifier.verify_identifier("TEST@EXAMPLE.COM")
        assert result == "TEST@example.com"

    async def test_verify_invalid_email(
        self, email_identifier: EmailIdentifier[MockEmailSubject]
    ) -> None:
        with pytest.raises(IdentifierVerificationError):
            await email_identifier.verify_identifier("not-an-email")

    async def test_get_by_identifier_exists(
        self,
        email_storage: MockStorage[MockEmailSubject],
        email_identifier: EmailIdentifier[MockEmailSubject],
    ) -> None:
        await email_storage.create(id="1", email="test@example.com")

        result = await email_identifier.get_by_identifier("test@example.com")

        assert result.id == "1"
        assert result.email == "test@example.com"

    async def test_get_by_identifier_not_exists(
        self, email_identifier: EmailIdentifier[MockEmailSubject]
    ) -> None:
        with pytest.raises(DoesNotExist):
            await email_identifier.get_by_identifier("nonexistent@example.com")
