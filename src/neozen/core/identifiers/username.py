"""Username identifier implementation for NeoZen."""

from __future__ import annotations

import re
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

# Default reserved usernames that cannot be registered
DEFAULT_RESERVED_USERNAMES = frozenset({
    "admin",
    "administrator",
    "api",
    "auth",
    "contact",
    "help",
    "info",
    "login",
    "logout",
    "neozen",
    "null",
    "oauth",
    "register",
    "root",
    "signup",
    "support",
    "system",
    "undefined",
    "user",
    "www",
})

# Username validation pattern: alphanumeric, underscore, hyphen
# Must start with alphanumeric, 3-32 characters
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{2,31}$")


class UsernameSubjectModel(Subject):
    """Subject model with username field."""

    username: str


class UsernameIdentifier[S: UsernameSubjectModel](IdentifierProtocol[S]):
    """Username-based identifier implementation.

    Usernames are:
    - 3-32 characters long
    - Alphanumeric with underscores and hyphens allowed
    - Must start with an alphanumeric character
    - Case-insensitive (stored and compared in lowercase)
    - Cannot be in the reserved username list
    """

    def __init__(
        self,
        username_storage: RepositoryProtocol[S],
        reserved_usernames: frozenset[str] | None = None,
    ) -> None:
        self.username_storage = username_storage
        self.reserved_usernames = reserved_usernames or DEFAULT_RESERVED_USERNAMES

    async def get_by_identifier(self, identifier: str) -> S:
        # Always search with lowercase
        return await self.username_storage.get_one_by(username=identifier.lower())

    async def parse_identifier(self, identifier: typing.Any) -> str:
        if not isinstance(identifier, str):
            msg = "Username must be a string."
            raise InvalidIdentifierFormat(msg)
        return identifier

    async def verify_identifier(self, identifier: str) -> str:
        # Check length first for better error messages
        if len(identifier) < 3:
            msg = "Username must be at least 3 characters long."
            raise IdentifierVerificationError(msg)
        if len(identifier) > 32:
            msg = "Username must be at most 32 characters long."
            raise IdentifierVerificationError(msg)

        # Check pattern
        if not USERNAME_PATTERN.match(identifier):
            msg = (
                "Username must start with a letter or number and contain only "
                "letters, numbers, underscores, and hyphens."
            )
            raise IdentifierVerificationError(msg)

        # Normalize to lowercase
        normalized = identifier.lower()

        # Check reserved usernames
        if normalized in self.reserved_usernames:
            msg = f"The username '{identifier}' is reserved and cannot be used."
            raise IdentifierVerificationError(msg)

        return normalized


class UsernameIdentifierProvider(IdentifierProvider):
    """Dishka provider for username identifiers."""

    def __init__(self, reserved_usernames: frozenset[str] | None = None) -> None:
        super().__init__()
        self.reserved_usernames = reserved_usernames

    @dishka.provide(scope=dishka.Scope.REQUEST)
    def identifier[M](
        self, username_storage: RepositoryProtocol[M]
    ) -> IdentifierProtocol[M]:
        # Unbounded type variable: dishka checks bounds nominally, and storage
        # models usually match UsernameSubjectModel only by shape.
        storage: RepositoryProtocol[typing.Any] = username_storage
        return UsernameIdentifier(storage, reserved_usernames=self.reserved_usernames)


__all__ = [
    "DEFAULT_RESERVED_USERNAMES",
    "USERNAME_PATTERN",
    "UsernameIdentifier",
    "UsernameIdentifierProvider",
    "UsernameSubjectModel",
]
