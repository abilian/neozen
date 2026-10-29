"""Password policy validation for NeoZen.

This module provides password policy validation including:
- Complexity requirements (length, character types)
- Have I Been Pwned (HIBP) breach checking
- Password history to prevent reuse
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import typing
from dataclasses import dataclass, field
from datetime import UTC, datetime

from neozen.core.exceptions import NeoZenException
from neozen.core.factors.password import PasswordHasherProtocol
from neozen.core.utils import hex_id

_log = logging.getLogger(__name__)


class PasswordPolicyError(NeoZenException):
    """Base exception for password policy errors."""


class PasswordPolicyViolation(PasswordPolicyError):
    """Raised when a password violates the policy."""

    def __init__(self, violations: list[str]) -> None:
        self.violations = violations
        message = "; ".join(violations)
        super().__init__(message)


@dataclass(frozen=True)
class PasswordPolicy:
    """Configuration for password validation rules.

    Attributes:
        min_length: Minimum password length.
        max_length: Maximum password length.
        require_uppercase: Require at least one uppercase letter.
        require_lowercase: Require at least one lowercase letter.
        require_digit: Require at least one digit.
        require_special: Require at least one special character.
        special_characters: The set of allowed special characters.
        check_hibp: Check password against Have I Been Pwned API.
        password_history_count: Number of previous passwords to check.

    """

    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = False
    special_characters: str = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
    check_hibp: bool = False
    password_history_count: int = 0


class PasswordHistoryModel(typing.Protocol):
    """Protocol for password history records."""

    id: str
    subject_id: str
    hashed_password: str
    created_at: datetime


class PasswordHistoryRepositoryProtocol[Model: PasswordHistoryModel](typing.Protocol):
    """Protocol for password history storage."""

    async def get_many_by(
        self,
        *,
        offset: int = 0,
        limit: int | None = None,
        **filters: typing.Any,
    ) -> list[Model]: ...

    async def create(self, **data: typing.Any) -> Model: ...

    async def delete(self, obj: Model) -> None: ...


class HIBPCheckerProtocol(typing.Protocol):
    """Protocol for Have I Been Pwned checker."""

    async def is_compromised(self, password: str) -> bool:
        """Check if password appears in HIBP breach database."""
        ...


@dataclass
class DefaultHIBPChecker:
    """Default HIBP checker using k-Anonymity API.

    Uses the Pwned Passwords API with k-Anonymity to check if a password
    has been compromised without sending the full hash.

    ``http_client`` is an ``httpx.AsyncClient``. When the API can't be
    reached or answers with an error, the password is accepted and a
    warning is logged: an outage must not block every password change.
    """

    http_client: typing.Any = field(default=None)
    api_url: str = "https://api.pwnedpasswords.com/range/"

    async def is_compromised(self, password: str) -> bool:
        """Check if password appears in HIBP breach database.

        Uses k-Anonymity: sends only first 5 chars of SHA-1 hash.
        """
        if self.http_client is None:
            return False

        # SHA1 is required by HIBP API - not used for security
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        import httpx  # noqa: PLC0415  # ken: optional dependency

        try:
            response = await self.http_client.get(f"{self.api_url}{prefix}")
        except httpx.HTTPError as e:
            _log.warning("HIBP check skipped, API unreachable: %s", e)
            return False
        if response.status_code != 200:
            _log.warning("HIBP check skipped, API status %s", response.status_code)
            return False

        for line in response.text.splitlines():
            hash_suffix, _count = line.split(":")
            if hmac.compare_digest(hash_suffix, suffix):
                return True
        return False


class PasswordPolicyValidator[S]:
    """Validates passwords against configured policies.

    Supports:
    - Complexity requirements
    - HIBP breach checking
    - Password history to prevent reuse
    """

    def __init__(
        self,
        policy: PasswordPolicy,
        hasher: PasswordHasherProtocol | None = None,
        history_repository: PasswordHistoryRepositoryProtocol[typing.Any] | None = None,
        hibp_checker: HIBPCheckerProtocol | None = None,
        id_generator: typing.Callable[[], str] = hex_id,
    ) -> None:
        self.policy = policy
        self.hasher = hasher
        self.history_repository = history_repository
        self.hibp_checker = hibp_checker
        self._id_generator = id_generator

    def _validate_complexity(self, password: str) -> list[str]:
        """Validate password complexity requirements."""
        violations: list[str] = []

        if len(password) < self.policy.min_length:
            violations.append(
                f"Password must be at least {self.policy.min_length} characters"
            )

        if len(password) > self.policy.max_length:
            violations.append(
                f"Password must be at most {self.policy.max_length} characters"
            )

        if self.policy.require_uppercase and not any(c.isupper() for c in password):
            violations.append("Password must contain at least one uppercase letter")

        if self.policy.require_lowercase and not any(c.islower() for c in password):
            violations.append("Password must contain at least one lowercase letter")

        if self.policy.require_digit and not any(c.isdigit() for c in password):
            violations.append("Password must contain at least one digit")

        if self.policy.require_special and not any(
            c in self.policy.special_characters for c in password
        ):
            violations.append("Password must contain at least one special character")

        return violations

    async def _check_hibp(self, password: str) -> str | None:
        """Check password against HIBP database."""
        if not self.policy.check_hibp or not self.hibp_checker:
            return None
        if await self.hibp_checker.is_compromised(password):
            return "Password has been found in a data breach and cannot be used"
        return None

    async def _check_history(self, password: str, subject_id: str | None) -> str | None:
        """Check password against history."""
        if self.policy.password_history_count <= 0:
            return None
        if not subject_id or not self.history_repository or not self.hasher:
            return None

        history = await self.history_repository.get_many_by(
            subject_id=subject_id,
            limit=self.policy.password_history_count,
        )
        for record in history:
            is_match, _ = self.hasher.verify_and_update(
                password, record.hashed_password
            )
            if is_match:
                return f"Password was used recently (last {self.policy.password_history_count} passwords)"
        return None

    async def validate(
        self,
        password: str,
        subject_id: str | None = None,
    ) -> None:
        """Validate a password against the policy.

        Args:
            password: The password to validate.
            subject_id: Optional subject ID for history check.

        Raises:
            PasswordPolicyViolation: If password violates the policy.

        """
        violations = self._validate_complexity(password)

        hibp_violation = await self._check_hibp(password)
        if hibp_violation:
            violations.append(hibp_violation)

        history_violation = await self._check_history(password, subject_id)
        if history_violation:
            violations.append(history_violation)

        if violations:
            raise PasswordPolicyViolation(violations)

    async def record_password(
        self,
        subject_id: str,
        hashed_password: str,
    ) -> None:
        """Record a password in history for future reuse checking.

        Args:
            subject_id: The subject's ID.
            hashed_password: The hashed password to record.

        """
        if self.history_repository is None:
            return

        if self.policy.password_history_count <= 0:
            return

        # Create new history record
        await self.history_repository.create(
            id=self._id_generator(),
            subject_id=subject_id,
            hashed_password=hashed_password,
            created_at=datetime.now(UTC),
        )

        # Clean up old records beyond the history limit
        all_history = await self.history_repository.get_many_by(subject_id=subject_id)
        # Sort by created_at descending to keep newest
        sorted_history = sorted(all_history, key=lambda x: x.created_at, reverse=True)

        # Delete records beyond the limit
        for old_record in sorted_history[self.policy.password_history_count :]:
            await self.history_repository.delete(old_record)


__all__ = [
    "DefaultHIBPChecker",
    "HIBPCheckerProtocol",
    "PasswordHasherProtocol",
    "PasswordHistoryModel",
    "PasswordHistoryRepositoryProtocol",
    "PasswordPolicy",
    "PasswordPolicyError",
    "PasswordPolicyValidator",
    "PasswordPolicyViolation",
]
