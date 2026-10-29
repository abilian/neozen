"""Password reset service for NeoZen.

Provides secure password reset functionality with token-based verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from neozen.core.crypto import generate_token_hash_pair, get_token_hash
from neozen.core.models import NeoZenModel
from neozen.core.utils import ensure_utc


@dataclass(frozen=True)
class PasswordResetConfig:
    """Configuration for password reset.

    Attributes:
        token_lifetime: How long reset tokens are valid.
        max_pending_requests: Maximum pending reset requests per subject.
        rate_limit_window: Time window for rate limiting requests.
        token_prefix: Prefix for generated tokens.
    """

    token_lifetime: timedelta = timedelta(hours=1)
    max_pending_requests: int = 3
    rate_limit_window: timedelta = timedelta(hours=24)
    token_prefix: str = "nz_pr_"


@dataclass(frozen=True)
class PasswordResetResult:
    """Result of password reset request or completion.

    Attributes:
        success: Whether the operation succeeded.
        message: User-facing message.
        token_sent: Whether an email was sent (only for request).
        error_code: Error code if failed.
    """

    success: bool
    message: str
    token_sent: bool = False
    error_code: str | None = None


class PasswordResetToken(NeoZenModel):
    """Base model for password reset tokens.

    Attributes:
        id: Unique identifier.
        subject_id: Subject requesting reset.
        token_hash: HMAC-SHA256 hash of the token.
        created_at: When the token was created.
        expires_at: When the token expires.
        used_at: When the token was used (None if unused).
        ip_address: IP address of the requester.
    """

    id: str
    subject_id: str
    token_hash: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None
    ip_address: str | None


class PasswordResetTokenRepository(Protocol):
    """Repository protocol for password reset tokens."""

    async def create(self, **kwargs: Any) -> PasswordResetToken:
        """Create a new reset token."""
        ...

    async def get_by_hash(self, token_hash: str) -> PasswordResetToken | None:
        """Get token by hash."""
        ...

    async def mark_used(self, token_id: str, used_at: datetime) -> None:
        """Mark token as used."""
        ...

    async def count_pending(
        self,
        subject_id: str,
        since: datetime,
    ) -> int:
        """Count pending (unused, unexpired) tokens for subject since time."""
        ...

    async def invalidate_all(self, subject_id: str) -> int:
        """Invalidate all pending tokens for subject."""
        ...


class SubjectLookup(Protocol):
    """Protocol for looking up subjects by email."""

    async def get_by_email(self, email: str) -> Any | None:
        """Get subject by email address."""
        ...


class PasswordChanger(Protocol):
    """Protocol for changing passwords."""

    async def change_password(
        self,
        subject_id: str,
        new_password: str,
    ) -> bool:
        """Change password for subject."""
        ...


class EmailSender(Protocol):
    """Protocol for sending password reset emails."""

    async def send_reset_email(
        self,
        email: str,
        token: str,
        expires_at: datetime,
    ) -> bool:
        """Send password reset email."""
        ...


class PasswordResetService:
    """Service for password reset flow.

    Handles:
    - Reset request with token generation
    - Token validation
    - Password reset completion
    - Rate limiting of requests

    Example:
        service = PasswordResetService(
            config=PasswordResetConfig(),
            token_repository=token_repo,
            subject_lookup=subject_service,
            password_changer=password_factor,
            token_hash_key="secret",
        )

        # Request reset (always returns success to prevent enumeration)
        result = await service.request_reset("user@example.com")

        # Validate token
        is_valid = await service.validate_token(token)

        # Reset password
        result = await service.reset_password(token, "new_password")
    """

    def __init__(
        self,
        config: PasswordResetConfig,
        token_repository: PasswordResetTokenRepository,
        subject_lookup: SubjectLookup,
        password_changer: PasswordChanger,
        token_hash_key: str,
        *,
        email_sender: EmailSender | None = None,
    ) -> None:
        """Initialize password reset service.

        Args:
            config: Reset configuration.
            token_repository: Repository for reset tokens.
            subject_lookup: Service to look up subjects by email.
            password_changer: Service to change passwords.
            token_hash_key: Key for hashing tokens.
            email_sender: Optional email sender for reset emails.
        """
        self.config = config
        self.token_repository = token_repository
        self.subject_lookup = subject_lookup
        self.password_changer = password_changer
        self.token_hash_key = token_hash_key
        self.email_sender = email_sender

    async def request_reset(
        self,
        email: str,
        *,
        ip_address: str | None = None,
    ) -> PasswordResetResult:
        """Request password reset.

        Always returns success to prevent email enumeration.
        Only sends email if account exists and rate limit not exceeded.

        Args:
            email: Email address for reset.
            ip_address: Client IP address.

        Returns:
            PasswordResetResult (always success for security).
        """
        # Always return success to prevent enumeration
        success_result = PasswordResetResult(
            success=True,
            message="If an account exists with this email, a reset link has been sent.",
            token_sent=True,
        )

        # Look up subject
        subject = await self.subject_lookup.get_by_email(email)
        if subject is None:
            return success_result

        subject_id = getattr(subject, "id", None)
        if subject_id is None:
            return success_result

        # Check rate limit
        now = datetime.now(UTC)
        since = now - self.config.rate_limit_window
        pending_count = await self.token_repository.count_pending(subject_id, since)

        if pending_count >= self.config.max_pending_requests:
            # Rate limited, but still return success for security
            return success_result

        # Generate token
        token, token_hash = generate_token_hash_pair(
            self.token_hash_key,
            prefix=self.config.token_prefix,
        )

        expires_at = now + self.config.token_lifetime

        # Create token record
        await self.token_repository.create(
            subject_id=subject_id,
            token_hash=token_hash,
            created_at=now,
            expires_at=expires_at,
            used_at=None,
            ip_address=ip_address,
        )

        # Send email if sender configured
        if self.email_sender:
            await self.email_sender.send_reset_email(email, token, expires_at)

        return success_result

    async def validate_token(self, token: str) -> bool:
        """Validate a reset token.

        Args:
            token: The reset token to validate.

        Returns:
            True if token is valid and unused.
        """
        token_hash = get_token_hash(token, self.token_hash_key)
        token_record = await self.token_repository.get_by_hash(token_hash)

        if token_record is None:
            return False

        # Check if already used
        if token_record.used_at is not None:
            return False

        # Check if expired
        now = datetime.now(UTC)
        return ensure_utc(token_record.expires_at) > now

    async def reset_password(
        self,
        token: str,
        new_password: str,
    ) -> PasswordResetResult:
        """Reset password using token.

        Args:
            token: The reset token.
            new_password: The new password.

        Returns:
            PasswordResetResult indicating success or failure.
        """
        token_hash = get_token_hash(token, self.token_hash_key)
        token_record = await self.token_repository.get_by_hash(token_hash)

        if token_record is None:
            return PasswordResetResult(
                success=False,
                message="Invalid or expired reset link.",
                error_code="invalid_token",
            )

        # Check if already used
        if token_record.used_at is not None:
            return PasswordResetResult(
                success=False,
                message="This reset link has already been used.",
                error_code="token_used",
            )

        # Check if expired
        now = datetime.now(UTC)
        if ensure_utc(token_record.expires_at) <= now:
            return PasswordResetResult(
                success=False,
                message="This reset link has expired.",
                error_code="token_expired",
            )

        # Change password
        changed = await self.password_changer.change_password(
            token_record.subject_id,
            new_password,
        )

        if not changed:
            return PasswordResetResult(
                success=False,
                message="Failed to change password.",
                error_code="change_failed",
            )

        # Mark token as used
        await self.token_repository.mark_used(token_record.id, now)

        # Invalidate all other pending tokens for this subject
        await self.token_repository.invalidate_all(token_record.subject_id)

        return PasswordResetResult(
            success=True,
            message="Your password has been reset successfully.",
        )

    async def get_token_subject_id(self, token: str) -> str | None:
        """Get the subject ID associated with a token.

        Useful for displaying user info on reset page.

        Args:
            token: The reset token.

        Returns:
            Subject ID if token is valid, None otherwise.
        """
        if not await self.validate_token(token):
            return None

        token_hash = get_token_hash(token, self.token_hash_key)
        token_record = await self.token_repository.get_by_hash(token_hash)

        return token_record.subject_id if token_record else None


__all__ = [
    "EmailSender",
    "PasswordChanger",
    "PasswordResetConfig",
    "PasswordResetResult",
    "PasswordResetService",
    "PasswordResetToken",
    "PasswordResetTokenRepository",
    "SubjectLookup",
]
