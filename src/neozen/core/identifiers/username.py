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
from neozen.core.storage import StorageProtocol
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
        username_storage: StorageProtocol[S],
        reserved_usernames: frozenset[str] | None = None,
    ) -> None:
        self.username_storage = username_storage
        self.reserved_usernames = reserved_usernames or DEFAULT_RESERVED_USERNAMES

    async def get_by_identifier(self, identifier: str) -> S:
        # Always search with lowercase
        return await self.username_storage.get_one_by(username=identifier.lower())

    async def parse_identifier(self, identifier: typing.Any) -> str:
        if not isinstance(identifier, str):
            raise InvalidIdentifierFormat("Username must be a string.")
        return identifier

    async def verify_identifier(self, identifier: str) -> str:
        # Check length first for better error messages
        if len(identifier) < 3:
            raise IdentifierVerificationError(
                "Username must be at least 3 characters long."
            )
        if len(identifier) > 32:
            raise IdentifierVerificationError(
                "Username must be at most 32 characters long."
            )

        # Check pattern
        if not USERNAME_PATTERN.match(identifier):
            raise IdentifierVerificationError(
                "Username must start with a letter or number and contain only "
                "letters, numbers, underscores, and hyphens."
            )

        # Normalize to lowercase
        normalized = identifier.lower()

        # Check reserved usernames
        if normalized in self.reserved_usernames:
            raise IdentifierVerificationError(
                f"The username '{identifier}' is reserved and cannot be used."
            )

        return normalized


class UsernameIdentifierProvider[S: UsernameSubjectModel](IdentifierProvider[S]):
    """Dishka provider for username identifiers."""

    def __init__(
        self, reserved_usernames: frozenset[str] | None = None
    ) -> None:
        super().__init__()
        self.reserved_usernames = reserved_usernames

    @dishka.provide(scope=dishka.Scope.REQUEST)
    def identifier[_S: UsernameSubjectModel](
        self, subject: type[_S], username_storage: StorageProtocol[_S]
    ) -> IdentifierProtocol[_S]:
        return UsernameIdentifier[_S](
            username_storage, reserved_usernames=self.reserved_usernames
        )


__all__ = [
    "DEFAULT_RESERVED_USERNAMES",
    "USERNAME_PATTERN",
    "UsernameIdentifier",
    "UsernameIdentifierProvider",
    "UsernameSubjectModel",
]
