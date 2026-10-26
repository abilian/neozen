"""Phone identifier implementation for NeoZen."""

from __future__ import annotations

import typing

import dishka

from neozen.core.identifiers.base import (
    IdentifierProtocol,
    IdentifierProvider,
    IdentifierVerificationError,
    InvalidIdentifierFormat,
)
from neozen.core.repository import RepositoryProtocol
from neozen.core.subject import Subject


class PhoneSubjectModel(Subject):
    """Subject model with phone field."""

    phone: str


class PhoneIdentifier[S: PhoneSubjectModel](IdentifierProtocol[S]):
    """Phone number-based identifier implementation.

    Phone numbers are:
    - Validated using the phonenumbers library
    - Stored in E.164 format (e.g., +14155551234)
    - Optionally restricted to specific regions
    """

    def __init__(
        self,
        phone_storage: RepositoryProtocol[S],
        default_region: str | None = None,
        allowed_regions: frozenset[str] | None = None,
    ) -> None:
        """Initialize the phone identifier.

        Args:
            phone_storage: Storage backend for phone-based subjects.
            default_region: Default region code for parsing (e.g., "US").
                If not set, numbers must include country code.
            allowed_regions: Set of allowed region codes. If not set, all regions
                are allowed.

        """
        self.phone_storage = phone_storage
        self.default_region = default_region
        self.allowed_regions = allowed_regions

    async def get_by_identifier(self, identifier: str) -> S:
        return await self.phone_storage.get_one_by(phone=identifier)

    async def parse_identifier(self, identifier: typing.Any) -> str:
        if not isinstance(identifier, str):
            msg = "Phone number must be a string."
            raise InvalidIdentifierFormat(msg)
        return identifier

    async def verify_identifier(self, identifier: str) -> str:
        # Lazy import: phonenumbers is an optional extra (`neozen[phone]`)
        import phonenumbers  # noqa: PLC0415

        try:
            parsed = phonenumbers.parse(identifier, self.default_region)
        except phonenumbers.NumberParseException as e:
            msg = f"Invalid phone number: {e}"
            raise IdentifierVerificationError(msg) from e

        # Validate the number
        if not phonenumbers.is_valid_number(parsed):
            msg = "The phone number is not valid for its region."
            raise IdentifierVerificationError(msg)

        # Check region restrictions if configured
        if self.allowed_regions is not None:
            region = phonenumbers.region_code_for_number(parsed)
            if region not in self.allowed_regions:
                msg = f"Phone numbers from region '{region}' are not allowed."
                raise IdentifierVerificationError(msg)

        # Return in E.164 format
        return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)


class PhoneIdentifierProvider(IdentifierProvider):
    """Dishka provider for phone identifiers."""

    def __init__(
        self,
        default_region: str | None = None,
        allowed_regions: frozenset[str] | None = None,
    ) -> None:
        super().__init__()
        self.default_region = default_region
        self.allowed_regions = allowed_regions

    @dishka.provide(scope=dishka.Scope.REQUEST)
    def identifier[M](
        self, phone_storage: RepositoryProtocol[M]
    ) -> IdentifierProtocol[M]:
        # Unbounded type variable: dishka checks bounds nominally, and storage
        # models usually match PhoneSubjectModel only by shape.
        storage: RepositoryProtocol[typing.Any] = phone_storage
        return PhoneIdentifier(
            storage,
            default_region=self.default_region,
            allowed_regions=self.allowed_regions,
        )


__all__ = [
    "PhoneIdentifier",
    "PhoneIdentifierProvider",
    "PhoneSubjectModel",
]
