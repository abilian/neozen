"""Email OTP authentication factor for NeoZen.

Sends a short numeric code to the user's email. The user enters it
to complete authentication. Implements `ChallengingFactorProtocol`:
1. begin_authentication: generate code, store hash, send email
2. complete_authentication: verify code

Use cases:
- 2FA for users without an authenticator app
- Step-up authentication for sensitive actions
- Email verification with one-time codes
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol

from neozen.core.crypto import get_token_hash
from neozen.core.email.templates import email_otp_email
from neozen.core.factors.magic_link import SubjectEmailLookup
from neozen.core.models import NeoZenModel

if TYPE_CHECKING:
    from neozen.core.email.base import EmailSenderProtocol


@dataclass(frozen=True)
class EmailOTPConfig:
    """Configuration for email OTP authentication.

    Attributes:
        code_length: Number of digits in the OTP code.
        code_lifetime: How long codes are valid.
        max_pending_per_subject: Rate limit on active codes.
        rate_limit_window: Time window for rate limiting.
        max_attempts: Max verification attempts before code is invalidated.
        app_name: Name shown in the email.
    """

    code_length: int = 6
    code_lifetime: timedelta = timedelta(minutes=10)
    max_pending_per_subject: int = 3
    rate_limit_window: timedelta = timedelta(hours=1)
    max_attempts: int = 5
    app_name: str = "NeoZen"


class EmailOTPCode(NeoZenModel):
    """Model for stored email OTP codes."""

    id: str
    subject_id: str
    code_hash: str
    email: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None
    attempts: int


class EmailOTPCodeRepository(Protocol):
    """Repository protocol for email OTP codes."""

    async def create(self, **kwargs: Any) -> EmailOTPCode: ...

    async def get_latest_pending(
        self, subject_id: str, now: datetime
    ) -> EmailOTPCode | None:
        """Get the most recent unused, unexpired code for a subject."""
        ...

    async def mark_used(self, code_id: str, used_at: datetime) -> None: ...

    async def increment_attempts(self, code_id: str) -> int: ...

    async def count_pending(self, subject_id: str, since: datetime) -> int: ...

    async def invalidate_all(self, subject_id: str) -> int: ...


def _generate_code(length: int) -> str:
    """Generate a numeric OTP code of the given length."""
    upper = 10**length
    return f"{secrets.randbelow(upper):0{length}d}"


class EmailOTPFactor:
    """Authentication factor using email-delivered OTP codes.

    Implements `ChallengingFactorProtocol`:
    - begin_authentication generates a code, stores its hash, sends an email
    - complete_authentication verifies the code

    Codes are short numeric strings (default 6 digits) and are rate
    limited per subject. Hashes (not plain codes) are stored.

    Example:
        factor = EmailOTPFactor(
            config=EmailOTPConfig(),
            code_repository=otp_repo,
            subject_email_lookup=email_lookup,
            email_sender=sender,
            code_hash_key="secret",
        )

        # Send code
        await factor.begin_authentication(user_id)

        # User enters code from email
        ok = await factor.complete_authentication(user_id, response="123456")
    """

    def __init__(
        self,
        config: EmailOTPConfig,
        code_repository: EmailOTPCodeRepository,
        subject_email_lookup: SubjectEmailLookup,
        email_sender: EmailSenderProtocol,
        code_hash_key: str,
    ) -> None:
        self.config = config
        self.code_repository = code_repository
        self.subject_email_lookup = subject_email_lookup
        self.email_sender = email_sender
        self.code_hash_key = code_hash_key

    @property
    def factor_id(self) -> str:
        return "email_otp"

    @property
    def display_name(self) -> str:
        return "Email OTP"

    @property
    def factor_type(self) -> str:
        return "possession"

    async def is_enrolled(self, subject_id: str) -> bool:
        """Email OTP works for any subject with an email."""
        email = await self.subject_email_lookup.get_email(subject_id)
        return email is not None

    async def supports_subject(self, subject_id: str) -> bool:
        return await self.subject_email_lookup.subject_exists(subject_id)

    async def begin_authentication(
        self,
        subject_id: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate an OTP code and send it via email.

        Always returns a success-shaped response to prevent enumeration.

        Args:
            subject_id: The subject requesting authentication.

        Returns:
            Challenge data with status, message, and expiry.
        """
        email = await self.subject_email_lookup.get_email(subject_id)
        if email is None:
            return {
                "status": "sent",
                "message": "If the account exists, a code has been sent.",
            }

        # Rate limit
        now = datetime.now(UTC)
        since = now - self.config.rate_limit_window
        pending = await self.code_repository.count_pending(subject_id, since)
        if pending >= self.config.max_pending_per_subject:
            return {
                "status": "sent",
                "message": "If the account exists, a code has been sent.",
                "rate_limited": True,
            }

        # Generate code
        code = _generate_code(self.config.code_length)
        code_hash = get_token_hash(code, key=self.code_hash_key)
        expires_at = now + self.config.code_lifetime

        await self.code_repository.create(
            subject_id=subject_id,
            code_hash=code_hash,
            email=email,
            created_at=now,
            expires_at=expires_at,
            used_at=None,
            attempts=0,
        )

        # Send email
        message = email_otp_email(
            to=email,
            code=code,
            lifetime_seconds=int(self.config.code_lifetime.total_seconds()),
            app_name=self.config.app_name,
        )
        await self.email_sender.send(message)

        return {
            "status": "sent",
            "message": "If the account exists, a code has been sent.",
            "expires_at": expires_at.isoformat(),
        }

    async def complete_authentication(
        self,
        subject_id: str,
        response: Any = None,
        **kwargs: Any,
    ) -> bool:
        """Verify a submitted OTP code.

        Args:
            subject_id: The subject authenticating.
            response: The OTP code as a string.

        Returns:
            True if the code is valid, False otherwise.
        """
        code = response or kwargs.get("code")
        if not code or not isinstance(code, str):
            return False

        now = datetime.now(UTC)
        record = await self.code_repository.get_latest_pending(subject_id, now)
        if record is None:
            return False

        # Track attempt
        attempts = await self.code_repository.increment_attempts(record.id)
        if attempts > self.config.max_attempts:
            # Too many attempts -- invalidate this code
            await self.code_repository.mark_used(record.id, now)
            return False

        # Constant-time comparison
        expected_hash = get_token_hash(code, key=self.code_hash_key)
        if not hmac.compare_digest(record.code_hash, expected_hash):
            return False

        # Mark used and invalidate any other pending codes for this subject
        await self.code_repository.mark_used(record.id, now)
        await self.code_repository.invalidate_all(subject_id)
        return True


__all__ = [
    "EmailOTPCode",
    "EmailOTPCodeRepository",
    "EmailOTPConfig",
    "EmailOTPFactor",
]
