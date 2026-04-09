"""Email identifier implementation for NeoZen."""

from __future__ import annotations

import typing

import dishka
import email_validator

from neozen.core.identifiers.base import (
    IdentifierProtocol,
    IdentifierProvider,
    IdentifierVerificationError,
    InvalidIdentifierFormat,
)
from neozen.core.repository import RepositoryProtocol
from neozen.core.subject import Subject


class EmailSubjectModel(Subject):
    """Subject model with email field."""

    email: str


class EmailIdentifier[S: EmailSubjectModel](IdentifierProtocol[S]):
    """Email-based identifier implementation."""

    def __init__(self, email_storage: RepositoryProtocol[S]) -> None:
        self.email_storage = email_storage

    async def get_by_identifier(self, identifier: str) -> S:
        return await self.email_storage.get_one_by(email=identifier)

    async def parse_identifier(self, identifier: typing.Any) -> str:
        if not isinstance(identifier, str):
            raise InvalidIdentifierFormat
        return identifier

    async def verify_identifier(self, identifier: str) -> str:
        try:
            validated_email = email_validator.validate_email(
                identifier, check_deliverability=False
            )
        except email_validator.EmailNotValidError as e:
            raise IdentifierVerificationError(str(e)) from e
        else:
            return validated_email.normalized


class EmailIdentifierProvider[S: EmailSubjectModel](IdentifierProvider[S]):
    """Dishka provider for email identifiers."""

    @dishka.provide(scope=dishka.Scope.REQUEST)
    def identifier[_S: EmailSubjectModel](
        self, subject: type[_S], email_storage: RepositoryProtocol[_S]
    ) -> IdentifierProtocol[_S]:
        return EmailIdentifier[_S](email_storage)


def create_email_identifier(
    email_storage: RepositoryProtocol[typing.Any],
) -> EmailIdentifier[typing.Any]:
    """Create an EmailIdentifier without generic type constraints.

    Use this when your User model structurally matches EmailSubjectModel
    (has email, id, is_active fields) but doesn't inherit from it.

    Example:
        identifier = create_email_identifier(my_user_repo_adapter)
    """
    return EmailIdentifier(email_storage)


__all__ = [
    "EmailIdentifier",
    "EmailIdentifierProvider",
    "EmailSubjectModel",
    "create_email_identifier",
]
