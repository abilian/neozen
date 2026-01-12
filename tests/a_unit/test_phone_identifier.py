"""Tests for phone identifier."""

from __future__ import annotations

import dataclasses

import pytest

from neozen.core.identifiers.base import (
    IdentifierVerificationError,
    InvalidIdentifierFormat,
)
from neozen.core.identifiers.phone import PhoneIdentifier, PhoneSubjectModel
from neozen.core.storage import DoesNotExist
from tests.conftest import MockStorage


@dataclasses.dataclass
class MockPhoneSubject(PhoneSubjectModel):
    id: str
    phone: str


@pytest.fixture
def phone_storage() -> MockStorage[MockPhoneSubject]:
    return MockStorage(MockPhoneSubject, [])


@pytest.fixture
def phone_identifier(
    phone_storage: MockStorage[MockPhoneSubject],
) -> PhoneIdentifier[MockPhoneSubject]:
    return PhoneIdentifier(phone_storage)


@pytest.fixture
def us_phone_identifier(
    phone_storage: MockStorage[MockPhoneSubject],
) -> PhoneIdentifier[MockPhoneSubject]:
    return PhoneIdentifier(phone_storage, default_region="US")


@pytest.mark.anyio
class TestPhoneIdentifier:
    async def test_parse_valid_identifier(
        self, phone_identifier: PhoneIdentifier[MockPhoneSubject]
    ) -> None:
        result = await phone_identifier.parse_identifier("+14155551234")
        assert result == "+14155551234"

    async def test_parse_invalid_identifier_type(
        self, phone_identifier: PhoneIdentifier[MockPhoneSubject]
    ) -> None:
        with pytest.raises(InvalidIdentifierFormat):
            await phone_identifier.parse_identifier(14155551234)

    async def test_verify_valid_e164(
        self, phone_identifier: PhoneIdentifier[MockPhoneSubject]
    ) -> None:
        result = await phone_identifier.verify_identifier("+14155551234")
        assert result == "+14155551234"

    async def test_verify_valid_international_format(
        self, phone_identifier: PhoneIdentifier[MockPhoneSubject]
    ) -> None:
        result = await phone_identifier.verify_identifier("+44 20 7946 0958")
        assert result == "+442079460958"

    async def test_verify_valid_with_spaces_and_dashes(
        self, phone_identifier: PhoneIdentifier[MockPhoneSubject]
    ) -> None:
        result = await phone_identifier.verify_identifier("+1 415-555-1234")
        assert result == "+14155551234"

    async def test_verify_with_default_region(
        self, us_phone_identifier: PhoneIdentifier[MockPhoneSubject]
    ) -> None:
        # US number without country code
        result = await us_phone_identifier.verify_identifier("(415) 555-1234")
        assert result == "+14155551234"

    async def test_verify_invalid_number(
        self, phone_identifier: PhoneIdentifier[MockPhoneSubject]
    ) -> None:
        with pytest.raises(IdentifierVerificationError):
            await phone_identifier.verify_identifier("not-a-phone-number")

    async def test_verify_invalid_country_code(
        self, phone_identifier: PhoneIdentifier[MockPhoneSubject]
    ) -> None:
        with pytest.raises(IdentifierVerificationError):
            await phone_identifier.verify_identifier("+999123456789")

    async def test_verify_too_short(
        self, phone_identifier: PhoneIdentifier[MockPhoneSubject]
    ) -> None:
        with pytest.raises(IdentifierVerificationError):
            await phone_identifier.verify_identifier("+1234")

    async def test_get_by_identifier_exists(
        self,
        phone_storage: MockStorage[MockPhoneSubject],
        phone_identifier: PhoneIdentifier[MockPhoneSubject],
    ) -> None:
        await phone_storage.create(id="1", phone="+14155551234")
        result = await phone_identifier.get_by_identifier("+14155551234")
        assert result.id == "1"
        assert result.phone == "+14155551234"

    async def test_get_by_identifier_not_exists(
        self, phone_identifier: PhoneIdentifier[MockPhoneSubject]
    ) -> None:
        with pytest.raises(DoesNotExist):
            await phone_identifier.get_by_identifier("+14155551234")


@pytest.mark.anyio
class TestPhoneIdentifierRegionRestriction:
    async def test_allowed_region(
        self, phone_storage: MockStorage[MockPhoneSubject]
    ) -> None:
        identifier = PhoneIdentifier(
            phone_storage, allowed_regions=frozenset({"US", "CA"})
        )
        result = await identifier.verify_identifier("+14155551234")
        assert result == "+14155551234"

    async def test_disallowed_region(
        self, phone_storage: MockStorage[MockPhoneSubject]
    ) -> None:
        identifier = PhoneIdentifier(
            phone_storage, allowed_regions=frozenset({"US", "CA"})
        )
        with pytest.raises(IdentifierVerificationError) as exc_info:
            await identifier.verify_identifier("+442079460958")
        assert "not allowed" in str(exc_info.value)
