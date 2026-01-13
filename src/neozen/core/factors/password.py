"""Password authentication factor for NeoZen."""

from __future__ import annotations

import typing

from pydantic import BaseModel, ValidationError

from neozen.core.exceptions import InvalidRequestError, NeoZenException
from neozen.core.identifiers.base import IdentifierProtocol, InvalidIdentifierFormat
from neozen.core.repository import DoesNotExist, RepositoryProtocol
from neozen.core.subject import Subject


class PasswordFactorError(NeoZenException):
    """Base exception for password factor errors."""


class InvalidCredentialsError(PasswordFactorError):
    """Raised when the provided credentials are invalid."""

    def __init__(self) -> None:
        super().__init__("Invalid credentials provided.")


class PasswordHasherProtocol(typing.Protocol):
    """Protocol for password hashers."""

    def verify_and_update(
        self, password: str | bytes, hash: str | bytes
    ) -> tuple[bool, str | None]:
        """Verify a password and optionally return an updated hash."""
        ...  # pragma: no cover

    def hash(
        self,
        password: str | bytes,
        *,
        salt: bytes | None = None,
    ) -> str:
        """Hash a password."""
        ...  # pragma: no cover


class PasswordSubjectModel(Subject):
    """Subject model with hashed password field."""

    hashed_password: str | None


class PasswordAuthenticateRequest(BaseModel):
    """Request model for password authentication."""

    identifier: typing.Any
    password: str


class PasswordEnrollRequest(BaseModel):
    """Request model for password enrollment."""

    password: str


class PasswordFactor[S: PasswordSubjectModel]:
    """Password-based authentication factor.

    Supports:
    - Password verification with timing-safe error handling
    - Automatic password hash upgrades
    - Password enrollment for new users
    """

    def __init__(
        self,
        identifier: IdentifierProtocol[S],
        subject_storage: RepositoryProtocol[S],
        hasher: PasswordHasherProtocol,
    ) -> None:
        self.identifier = identifier
        self.subject_storage = subject_storage
        self.hasher = hasher

    async def authenticate(self, payload: dict[str, typing.Any]) -> S:
        """Authenticate a subject using their identifier and password.

        Args:
            payload: Dictionary containing 'identifier' and 'password' fields.

        Returns:
            The authenticated subject.

        Raises:
            InvalidRequestError: If the request payload is invalid.
            InvalidCredentialsError: If the credentials are invalid.

        """
        try:
            request = PasswordAuthenticateRequest.model_validate(payload)
        except ValidationError as e:
            raise InvalidRequestError.from_validation_error(e) from e

        try:
            identifier = await self.identifier.parse_identifier(request.identifier)
        except InvalidIdentifierFormat as e:
            raise InvalidRequestError([
                {
                    "type": "value_error",
                    "loc": ("identifier",),
                    "msg": e.message,
                    "input": request.identifier,
                }
            ]) from e

        try:
            subject = await self.identifier.get_by_identifier(identifier)
        except DoesNotExist:
            # Never returns - runs hasher to prevent timing attacks, then raises
            # Use 'from None' to avoid leaking whether user exists via exception chain
            raise self._raise_invalid_credentials_timing_safe(
                request.password
            ) from None

        hashed_password = subject.hashed_password
        if hashed_password is None:
            raise self._raise_invalid_credentials_timing_safe(request.password)

        # Verify the password
        is_valid, updated_hash = self.hasher.verify_and_update(
            request.password, hashed_password
        )

        if not is_valid:
            raise InvalidCredentialsError

        # Update the password hash if needed
        if updated_hash is not None:
            subject = await self.subject_storage.update_obj(
                subject, hashed_password=updated_hash
            )

        return subject

    async def enroll(self, subject: S, payload: dict[str, typing.Any]) -> S:
        """Enroll a password for a subject.

        Args:
            subject: The subject to enroll.
            payload: Dictionary containing 'password' field.

        Returns:
            The updated subject.

        Raises:
            InvalidRequestError: If the request payload is invalid.

        """
        try:
            request = PasswordEnrollRequest.model_validate(payload)
        except ValidationError as e:
            raise InvalidRequestError.from_validation_error(e) from e

        hashed_password = self.hasher.hash(request.password)

        subject = await self.subject_storage.update_obj(
            subject, hashed_password=hashed_password
        )

        return subject

    def _raise_invalid_credentials_timing_safe(self, password: str) -> typing.Never:
        """Raise InvalidCredentialsError while running the hasher to mitigate timing attacks.

        Inspired from Django: https://code.djangoproject.com/ticket/20760
        """
        self.hasher.hash(password)
        raise InvalidCredentialsError


__all__ = [
    "InvalidCredentialsError",
    "PasswordAuthenticateRequest",
    "PasswordEnrollRequest",
    "PasswordFactor",
    "PasswordFactorError",
    "PasswordHasherProtocol",
    "PasswordSubjectModel",
]
