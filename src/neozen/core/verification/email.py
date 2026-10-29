"""Email verification token and service for NeoZen."""

from __future__ import annotations

import typing
from datetime import UTC, datetime, timedelta

from neozen.core.crypto import generate_token_hash_pair, get_token_hash
from neozen.core.repository import DoesNotExist, RepositoryProtocol
from neozen.core.utils import ensure_utc


class EmailVerificationTokenModel(typing.Protocol):
    """Protocol for email verification token storage model."""

    token_hash: str
    email: str
    subject_id: str
    expires_at: datetime
    used_at: datetime | None
    created_at: datetime


class EmailVerificationError(Exception):
    """Base exception for email verification errors."""

    message: str

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class EmailVerificationTokenNotFoundError(EmailVerificationError):
    """Raised when verification token is not found."""

    def __init__(self) -> None:
        super().__init__("The verification token was not found or is invalid.")


class EmailVerificationTokenExpiredError(EmailVerificationError):
    """Raised when verification token has expired."""

    def __init__(self) -> None:
        super().__init__("The verification token has expired.")


class VerificationCooldownError(EmailVerificationError):
    """Raised when verification is requested too soon."""

    def __init__(self, seconds_remaining: int) -> None:
        self.seconds_remaining = seconds_remaining
        super().__init__(
            f"Please wait {seconds_remaining} seconds before requesting "
            "another verification email."
        )


class EmailVerificationService[T: EmailVerificationTokenModel]:
    """Service for managing email verification tokens.

    This service handles:
    - Creating verification tokens with secure hashing
    - Verifying tokens and marking them as used
    - Enforcing cooldown between resend requests
    - Automatic expiration of old tokens

    Token Format:
        Tokens are generated using the NeoZen crypto utilities with:
        - Prefix: nz_ev_ (email verification)
        - CRC32 checksum for quick validation
        - HMAC-SHA256 hash stored in database

    Example:
        service = EmailVerificationService(
            storage=token_storage,
            hash_key="your-secret-key",
        )

        # Create verification token
        token = await service.create_token(
            email="user@example.com",
            subject_id="user_123",
        )

        # Send token to user via email...

        # Verify token when user clicks link
        result = await service.verify_token(token)

    """

    def __init__(
        self,
        storage: RepositoryProtocol[T],
        hash_key: str,
        *,
        token_prefix: str = "nz_ev_",
        expiration_hours: int = 24,
        cooldown_seconds: int = 60,
    ) -> None:
        """Initialize the email verification service.

        Args:
            storage: Storage backend for verification tokens.
            hash_key: Secret key for HMAC hashing of tokens.
            token_prefix: Prefix for generated tokens (default: "nz_ev_").
            expiration_hours: Hours until token expires (default: 24).
            cooldown_seconds: Seconds between resend requests (default: 60).

        """
        self.storage = storage
        self.hash_key = hash_key
        self.token_prefix = token_prefix
        self.expiration_hours = expiration_hours
        self.cooldown_seconds = cooldown_seconds

    async def create_token(
        self,
        email: str,
        subject_id: str,
        *,
        skip_cooldown: bool = False,
    ) -> str:
        """Create a new email verification token.

        Args:
            email: The email address to verify.
            subject_id: The ID of the subject owning this email.
            skip_cooldown: If True, skip cooldown check (admin use).

        Returns:
            The plaintext token to send to the user.

        Raises:
            VerificationCooldownError: If cooldown hasn't elapsed.

        """
        now = datetime.now(UTC)

        # Check cooldown unless skipped
        if not skip_cooldown:
            await self._check_cooldown(email, now)

        # Generate token and hash
        token, token_hash = generate_token_hash_pair(
            self.hash_key, prefix=self.token_prefix
        )

        # Calculate expiration
        expires_at = now + timedelta(hours=self.expiration_hours)

        # Store token
        await self.storage.create(
            token_hash=token_hash,
            email=email,
            subject_id=subject_id,
            expires_at=expires_at,
            used_at=None,
            created_at=now,
        )

        return token

    async def verify_token(self, token: str) -> T:
        """Verify an email verification token.

        Args:
            token: The plaintext token from the user.

        Returns:
            The verification token record.

        Raises:
            EmailVerificationTokenNotFoundError: If token not found.
            EmailVerificationTokenExpiredError: If token has expired.

        """
        # Hash the token to look up in storage
        token_hash = get_token_hash(token, key=self.hash_key)

        try:
            verification = await self.storage.get_one_by(token_hash=token_hash)
        except DoesNotExist as e:
            raise EmailVerificationTokenNotFoundError from e

        # Check if already used
        if verification.used_at is not None:
            raise EmailVerificationTokenNotFoundError

        # Check expiration
        now = datetime.now(UTC)
        expires_at = ensure_utc(verification.expires_at)
        if expires_at < now:
            raise EmailVerificationTokenExpiredError

        # Mark as used
        await self.storage.update_obj(verification, used_at=now)

        return verification

    async def resend_verification(
        self,
        email: str,
        subject_id: str,
    ) -> str:
        """Request a new verification token (with cooldown check).

        This is a convenience method that wraps create_token with
        cooldown enforcement.

        Args:
            email: The email address to verify.
            subject_id: The ID of the subject owning this email.

        Returns:
            The new plaintext token.

        Raises:
            VerificationCooldownError: If cooldown hasn't elapsed.

        """
        return await self.create_token(email, subject_id)

    async def _check_cooldown(self, email: str, now: datetime) -> None:
        """Check if cooldown has elapsed for this email.

        Args:
            email: The email address to check.
            now: Current timestamp.

        Raises:
            VerificationCooldownError: If cooldown hasn't elapsed.

        """
        try:
            # Find most recent token for this email
            # Note: This is a simplified implementation. In production,
            # you might want a more efficient query method.
            recent = await self.storage.get_one_by(email=email)

            # Check cooldown
            cooldown_end = recent.created_at + timedelta(seconds=self.cooldown_seconds)
            if now < cooldown_end:
                remaining = int((cooldown_end - now).total_seconds())
                raise VerificationCooldownError(remaining)
        except DoesNotExist:
            # No previous token, cooldown doesn't apply
            pass

    async def invalidate_tokens_for_email(self, email: str) -> None:
        """Invalidate all pending tokens for an email address.

        This should be called after successful verification to prevent
        token reuse.

        Note: This is a simplified implementation. In production,
        you would want a bulk update method on the storage.

        Args:
            email: The email address whose tokens to invalidate.

        """
        now = datetime.now(UTC)
        try:
            while True:
                token = await self.storage.get_one_by(email=email, used_at=None)
                await self.storage.update_obj(token, used_at=now)
        except DoesNotExist:
            pass  # No more unused tokens


__all__ = [
    "EmailVerificationError",
    "EmailVerificationService",
    "EmailVerificationTokenExpiredError",
    "EmailVerificationTokenModel",
    "EmailVerificationTokenNotFoundError",
    "VerificationCooldownError",
]
