"""Account lockout management for NeoZen.

Provides account lockout functionality after multiple failed login attempts.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from neozen.core.security.rate_limit_store import RateLimitEntry, RateLimitStore


@dataclass(frozen=True)
class LockoutConfig:
    """Configuration for account lockout.

    Attributes:
        max_failed_attempts: Maximum failed attempts before lockout.
        lockout_duration: Initial lockout duration.
        progressive: Whether to increase lockout duration progressively.
        max_lockout_duration: Maximum lockout duration (for progressive).
        progression_multiplier: Multiplier for progressive lockout.
    """

    max_failed_attempts: int = 5
    lockout_duration: timedelta = timedelta(minutes=30)
    progressive: bool = True
    max_lockout_duration: timedelta = timedelta(hours=24)
    progression_multiplier: float = 2.0


@dataclass
class LockoutStatus:
    """Account lockout status.

    Attributes:
        is_locked: Whether the account is currently locked.
        failed_attempts: Number of consecutive failed attempts.
        locked_until: When the lockout expires (if locked).
        remaining_lockout: Time remaining until unlock (if locked).
        lockout_count: Number of times the account has been locked.
    """

    is_locked: bool
    failed_attempts: int
    locked_until: datetime | None = None
    remaining_lockout: timedelta | None = None
    lockout_count: int = 0


class LockoutManager:
    """Manages account lockout state.

    Tracks failed login attempts per subject and locks accounts
    after too many failures. Supports progressive lockout where
    each subsequent lockout is longer.

    Example:
        config = LockoutConfig(max_failed_attempts=5)
        store = InMemoryRateLimitStore()
        manager = LockoutManager(config, store)

        # Check if account is locked
        status = await manager.is_locked("user123")
        if status.is_locked:
            raise AccountLocked(until=status.locked_until)

        # Record failed attempt
        status = await manager.record_failed_attempt("user123")
        if status.is_locked:
            # Account just got locked
            send_lockout_notification(user)

        # Record successful login
        await manager.record_success("user123")
    """

    def __init__(
        self,
        config: LockoutConfig,
        store: RateLimitStore,
    ) -> None:
        """Initialize lockout manager.

        Args:
            config: Lockout configuration.
            store: Storage backend for lockout data.
        """
        self.config = config
        self.store = store

    def _make_key(self, subject_id: str) -> str:
        """Create storage key for subject."""
        return f"lockout:{subject_id}"

    def _calculate_lockout_duration(self, lockout_count: int) -> timedelta:
        """Calculate lockout duration based on lockout count.

        For progressive lockout, each subsequent lockout is longer.
        """
        if not self.config.progressive or lockout_count <= 1:
            return self.config.lockout_duration

        # Progressive: multiply by progression_multiplier for each lockout
        multiplier = self.config.progression_multiplier ** (lockout_count - 1)
        duration = self.config.lockout_duration * multiplier

        # Cap at max duration
        if duration > self.config.max_lockout_duration:
            return self.config.max_lockout_duration

        return duration

    async def is_locked(self, subject_id: str) -> LockoutStatus:
        """Check if account is locked.

        Args:
            subject_id: Subject identifier.

        Returns:
            LockoutStatus with current state.
        """
        now = datetime.now(UTC)
        key = self._make_key(subject_id)
        entry = await self.store.get(key)

        if entry is None:
            return LockoutStatus(
                is_locked=False,
                failed_attempts=0,
            )

        # Check if locked
        if entry.locked_until and entry.locked_until > now:
            remaining = entry.locked_until - now
            return LockoutStatus(
                is_locked=True,
                failed_attempts=entry.attempts,
                locked_until=entry.locked_until,
                remaining_lockout=remaining,
            )

        # Lockout expired or not locked
        return LockoutStatus(
            is_locked=False,
            failed_attempts=entry.attempts,
        )

    async def record_failed_attempt(self, subject_id: str) -> LockoutStatus:
        """Record failed login attempt.

        Args:
            subject_id: Subject identifier.

        Returns:
            Updated lockout status.
        """
        now = datetime.now(UTC)
        key = self._make_key(subject_id)
        entry = await self.store.get(key)

        # Get current lockout count from existing entry
        lockout_count = 0
        if entry and entry.locked_until:
            # Previous lockout existed
            lockout_count = 1  # At least one previous lockout

        # Increment attempts
        entry = await self.store.increment(key)

        # Check if should lock
        if entry.attempts >= self.config.max_failed_attempts:
            lockout_count += 1
            duration = self._calculate_lockout_duration(lockout_count)
            locked_until = now + duration

            new_entry = RateLimitEntry(
                attempts=entry.attempts,
                first_attempt_at=entry.first_attempt_at,
                last_attempt_at=entry.last_attempt_at,
                locked_until=locked_until,
            )
            await self.store.set(key, new_entry, ttl=duration)

            return LockoutStatus(
                is_locked=True,
                failed_attempts=entry.attempts,
                locked_until=locked_until,
                remaining_lockout=duration,
                lockout_count=lockout_count,
            )

        return LockoutStatus(
            is_locked=False,
            failed_attempts=entry.attempts,
        )

    async def record_success(self, subject_id: str) -> None:
        """Record successful login (resets counter).

        Args:
            subject_id: Subject identifier.
        """
        key = self._make_key(subject_id)
        await self.store.delete(key)

    async def unlock(self, subject_id: str) -> None:
        """Manually unlock an account (admin action).

        Args:
            subject_id: Subject identifier.
        """
        key = self._make_key(subject_id)
        await self.store.delete(key)

    async def get_failed_attempts(self, subject_id: str) -> int:
        """Get the number of failed attempts for a subject.

        Args:
            subject_id: Subject identifier.

        Returns:
            Number of failed attempts.
        """
        key = self._make_key(subject_id)
        entry = await self.store.get(key)
        return entry.attempts if entry else 0


__all__ = [
    "LockoutConfig",
    "LockoutManager",
    "LockoutStatus",
]
