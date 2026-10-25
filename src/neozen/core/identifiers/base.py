"""Base identifier protocol and provider for NeoZen."""

from __future__ import annotations

import typing

import dishka

from neozen.core.exceptions import NeoZenException


class IdentifierError(NeoZenException):
    """Base exception for identifier-related errors."""


class InvalidIdentifierFormat(IdentifierError):
    """Raised when identifier doesn't match expected type/structure."""

    def __init__(
        self, message: str = "The provided identifier format is invalid."
    ) -> None:
        super().__init__(message)


class IdentifierVerificationError(IdentifierError):
    """Raised when identifier fails business logic validation."""

    def __init__(self, message: str = "The identifier verification failed.") -> None:
        super().__init__(message)


class IdentifierProtocol[S](typing.Protocol):
    """Protocol for identifier providers."""

    async def get_by_identifier(self, identifier: typing.Any) -> S:
        """Retrieve a subject by their identifier."""
        ...

    async def parse_identifier(self, identifier: typing.Any) -> typing.Any:
        """Parse and normalize the identifier."""
        ...

    async def verify_identifier(self, identifier: typing.Any) -> typing.Any:
        """Verify that the identifier is valid."""
        ...


class IdentifierProvider(dishka.Provider):
    """Base class for identifier providers.

    Subclasses provide `IdentifierProtocol[M]` for any model `M`, so a
    container holds at most one of them.
    """


__all__ = [
    "IdentifierError",
    "IdentifierProtocol",
    "IdentifierProvider",
    "IdentifierVerificationError",
    "InvalidIdentifierFormat",
]
