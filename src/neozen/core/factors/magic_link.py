"""Magic link authentication factor for NeoZen.

Provides passwordless authentication via email links.
Implements ChallengingFactorProtocol with a two-step flow:
1. begin_authentication: generate token, send magic link email
2. complete_authentication: verify token from the link URL
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from neozen.core.crypto import generate_token_hash_pair, get_token_hash
from neozen.core.email.base import EmailMessage, EmailSenderProtocol
from neozen.core.models import NeoZenModel
from neozen.core.utils import ensure_utc


@dataclass(frozen=True)
class MagicLinkConfig:
    """Configuration for magic link authentication.

    Attributes:
        token_lifetime: How long magic link tokens are valid.
        max_pending_per_subject: Maximum pending tokens per subject (rate limit).
        rate_limit_window: Time window for rate limiting.
        token_prefix: Prefix for generated tokens.
        link_base_url: Base URL for magic link (e.g. "https://app.example.com/magic-login").
    """

    token_lifetime: timedelta = timedelta(minutes=15)
    max_pending_per_subject: int = 3
    rate_limit_window: timedelta = timedelta(hours=1)
    token_prefix: str = "nz_ml_"
    link_base_url: str = ""


class MagicLinkToken(NeoZenModel):
    """Model for magic link tokens.

    Attributes:
        id: Unique identifier.
        subject_id: Subject this token is for.
        token_hash: HMAC-SHA256 hash of the token.
        email: Email address the link was sent to.
        created_at: When the token was created.
        expires_at: When the token expires.
        used_at: When the token was used (None if unused).
        ip_address: IP address of the requester.
    """

    id: str
    subject_id: str
    token_hash: str
    email: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None
    ip_address: str | None


class MagicLinkTokenRepository(Protocol):
    """Repository protocol for magic link tokens."""

    async def create(self, **kwargs: Any) -> MagicLinkToken:
        """Create a new magic link token."""
        ...

    async def get_by_hash(self, token_hash: str) -> MagicLinkToken | None:
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


class SubjectEmailLookup(Protocol):
    """Protocol for looking up subject email addresses."""

    async def get_email(self, subject_id: str) -> str | None:
        """Get email address for a subject."""
        ...

    async def subject_exists(self, subject_id: str) -> bool:
        """Check if subject exists."""
        ...


class MagicLinkFactor:
    """Authentication factor using email magic links.

    Implements the challenge-response pattern:
    - begin_authentication: generates a token, sends the magic link email
    - complete_authentication: verifies the token from the clicked link

    No explicit enrollment is needed -- any subject with a valid email
    can use magic links.

    Example:
        factor = MagicLinkFactor(
            config=MagicLinkConfig(
                link_base_url="https://app.example.com/magic-login",
            ),
            token_repository=token_repo,
            subject_email_lookup=email_lookup,
            email_sender=email_service,
            token_hash_key="secret",
        )

        # Request magic link (sends email)
        challenge = await factor.begin_authentication("user123")

        # User clicks link, verify the token
        valid = await factor.complete_authentication(
            "user123", response=token_from_url
        )
    """

    def __init__(
        self,
        config: MagicLinkConfig,
        token_repository: MagicLinkTokenRepository,
        subject_email_lookup: SubjectEmailLookup,
        email_sender: EmailSenderProtocol,
        token_hash_key: str,
    ) -> None:
        self.config = config
        self.token_repository = token_repository
        self.subject_email_lookup = subject_email_lookup
        self.email_sender = email_sender
        self.token_hash_key = token_hash_key

    @property
    def factor_id(self) -> str:
        return "magic_link"

    @property
    def display_name(self) -> str:
        return "Email Magic Link"

    @property
    def factor_type(self) -> str:
        return "possession"

    async def is_enrolled(self, subject_id: str) -> bool:
        """Magic link is available if the subject has an email."""
        email = await self.subject_email_lookup.get_email(subject_id)
        return email is not None

    async def supports_subject(self, subject_id: str) -> bool:
        """Any subject with an email can use magic links."""
        return await self.subject_email_lookup.subject_exists(subject_id)

    async def begin_authentication(
        self,
        subject_id: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate a magic link token and send it via email.

        Always returns a success-shaped response to prevent
        email/account enumeration.

        Args:
            subject_id: The subject requesting authentication.
            **kwargs: Optional 'ip_address' for audit.

        Returns:
            Challenge data with status and expiry info.
        """
        ip_address: str | None = kwargs.get("ip_address")

        # Look up email
        email = await self.subject_email_lookup.get_email(subject_id)
        if email is None:
            # Don't reveal that the subject doesn't exist
            return {
                "status": "sent",
                "message": "If the account exists, a magic link has been sent.",
            }

        # Check rate limit
        now = datetime.now(UTC)
        since = now - self.config.rate_limit_window
        pending_count = await self.token_repository.count_pending(subject_id, since)

        if pending_count >= self.config.max_pending_per_subject:
            return {
                "status": "sent",
                "message": "If the account exists, a magic link has been sent.",
                "rate_limited": True,
            }

        # Generate token
        token, token_hash = generate_token_hash_pair(
            self.token_hash_key,
            prefix=self.config.token_prefix,
        )

        expires_at = now + self.config.token_lifetime

        # Store token hash
        await self.token_repository.create(
            subject_id=subject_id,
            token_hash=token_hash,
            email=email,
            created_at=now,
            expires_at=expires_at,
            used_at=None,
            ip_address=ip_address,
        )

        # Build magic link URL
        magic_link_url = f"{self.config.link_base_url}?token={token}"

        # Send email
        message = EmailMessage(
            to=email,
            subject="Sign in to your account",
            body_text=(
                f"Click this link to sign in:\n\n{magic_link_url}\n\n"
                f"This link expires in {int(self.config.token_lifetime.total_seconds() // 60)} minutes.\n"
                "If you didn't request this, you can safely ignore this email."
            ),
            body_html=(
                f"<p>Click the link below to sign in:</p>"
                f'<p><a href="{magic_link_url}">Sign in</a></p>'
                f"<p>This link expires in {int(self.config.token_lifetime.total_seconds() // 60)} minutes.</p>"
                f"<p>If you didn't request this, you can safely ignore this email.</p>"
            ),
        )
        await self.email_sender.send(message)

        return {
            "status": "sent",
            "message": "If the account exists, a magic link has been sent.",
            "expires_at": expires_at.isoformat(),
        }

    async def complete_authentication(
        self,
        subject_id: str,
        response: Any = None,
        **kwargs: Any,
    ) -> bool:
        """Verify a magic link token.

        Checks: token matches hash, not expired, not already used,
        and belongs to the correct subject.
        Marks the token as used on success.

        Args:
            subject_id: The subject authenticating.
            response: The token string from the magic link URL.
            **kwargs: Optional 'token' as alternative to response.

        Returns:
            True if authentication succeeded.
        """
        token = response or kwargs.get("token")
        if not token or not isinstance(token, str):
            return False

        token_hash = get_token_hash(token, self.token_hash_key)
        token_record = await self.token_repository.get_by_hash(token_hash)

        if token_record is None:
            return False

        # Verify subject matches
        if token_record.subject_id != subject_id:
            return False

        # Check if already used
        if token_record.used_at is not None:
            return False

        # Check if expired
        now = datetime.now(UTC)
        if ensure_utc(token_record.expires_at) <= now:
            return False

        # Mark as used
        await self.token_repository.mark_used(token_record.id, now)

        # Invalidate all other pending tokens for this subject
        await self.token_repository.invalidate_all(subject_id)

        return True


__all__ = [
    "MagicLinkConfig",
    "MagicLinkFactor",
    "MagicLinkToken",
    "MagicLinkTokenRepository",
    "SubjectEmailLookup",
]
