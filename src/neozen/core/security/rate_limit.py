"""Rate limiting for authentication endpoints.

Protects against brute force attacks by limiting authentication attempts.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from neozen.core.security.rate_limit_store import RateLimitEntry, RateLimitStore


@dataclass(frozen=True)
class RateLimitConfig:
    """Configuration for rate limiting.

    Attributes:
        max_attempts: Maximum attempts allowed within the window.
        window: Time window for counting attempts.
        lockout_duration: How long to lock after exceeding max_attempts.
        by_ip: Whether to rate limit by IP address.
        by_subject: Whether to rate limit by subject ID.
    """

    max_attempts: int = 5
    window: timedelta = timedelta(minutes=15)
    lockout_duration: timedelta = timedelta(minutes=30)
    by_ip: bool = True
    by_subject: bool = True


@dataclass(frozen=True)
class RateLimitResult:
    """Result of rate limit check.

    Attributes:
        allowed: Whether the request is allowed.
        remaining_attempts: Number of attempts remaining before lockout.
        reset_at: When the rate limit window resets.
        retry_after: How long to wait before retrying (if locked).
        current_attempts: Current number of attempts in the window.
    """

    allowed: bool
    remaining_attempts: int
    reset_at: datetime | None = None
    retry_after: timedelta | None = None
    current_attempts: int = 0


class RateLimiter:
    """Rate limiter for authentication attempts.

    Example:
        config = RateLimitConfig(max_attempts=5, window=timedelta(minutes=15))
        store = InMemoryRateLimitStore()
        limiter = RateLimiter(config, store)

        # Check if request is allowed
        result = await limiter.check("ip:192.168.1.1")
        if not result.allowed:
            raise RateLimitExceeded(retry_after=result.retry_after)

        # Record attempt outcome
        await limiter.record_attempt("ip:192.168.1.1", success=False)
    """

    def __init__(
        self,
        config: RateLimitConfig,
        store: RateLimitStore,
    ) -> None:
        """Initialize rate limiter.

        Args:
            config: Rate limit configuration.
            store: Storage backend for rate limit data.
        """
        self.config = config
        self.store = store

    def make_key(
        self,
        *,
        ip_address: str | None = None,
        subject_id: str | None = None,
        action: str = "login",
    ) -> str:
        """Create a rate limit key.

        Args:
            ip_address: Client IP address.
            subject_id: Subject identifier.
            action: Action being rate limited (e.g., "login", "reset").

        Returns:
            Rate limit key string.
        """
        parts = [action]
        if self.config.by_ip and ip_address:
            parts.append(f"ip:{ip_address}")
        if self.config.by_subject and subject_id:
            parts.append(f"sub:{subject_id}")
        return ":".join(parts)

    async def check(
        self,
        key: str,
        *,
        increment: bool = False,
    ) -> RateLimitResult:
        """Check if request is allowed.

        With ``increment``, the attempt is counted first and the decision
        made on the count the store returns, so concurrent requests can't
        all pass on the same stale count.

        Args:
            key: Rate limit key.
            increment: Whether to count this request as an attempt.

        Returns:
            RateLimitResult with allowed status and remaining attempts.
        """
        now = datetime.now(UTC)
        entry = await self.store.get(key)

        if entry is not None and entry.locked_until and entry.locked_until > now:
            return RateLimitResult(
                allowed=False,
                remaining_attempts=0,
                reset_at=entry.locked_until,
                retry_after=entry.locked_until - now,
                current_attempts=entry.attempts,
            )

        if entry is not None and self._window_expired(entry, now):
            await self.store.delete(key)
            entry = None

        if increment:
            entry = await self.store.increment(key)

        result = self._decide(entry, now, counted=increment)
        if not result.allowed:
            locked = replace(entry or RateLimitEntry(), locked_until=result.reset_at)
            await self.store.set(key, locked, ttl=self.config.lockout_duration)
        return result

    def _window_expired(self, entry: RateLimitEntry, now: datetime) -> bool:
        return (
            entry.first_attempt_at is not None
            and entry.first_attempt_at + self.config.window <= now
        )

    def _decide(
        self, entry: RateLimitEntry | None, now: datetime, *, counted: bool
    ) -> RateLimitResult:
        """Allow or deny on the attempt count alone.

        ``counted`` says whether ``entry`` already includes this request.
        """
        attempts = entry.attempts if entry else 0
        previous = attempts - 1 if counted else attempts
        if previous >= self.config.max_attempts:
            return RateLimitResult(
                allowed=False,
                remaining_attempts=0,
                reset_at=now + self.config.lockout_duration,
                retry_after=self.config.lockout_duration,
                current_attempts=attempts,
            )
        first = entry.first_attempt_at if entry else None
        return RateLimitResult(
            allowed=True,
            remaining_attempts=max(0, self.config.max_attempts - attempts),
            reset_at=(first or now) + self.config.window,
            current_attempts=attempts,
        )

    async def record_attempt(
        self,
        key: str,
        *,
        success: bool,
    ) -> RateLimitResult:
        """Record an authentication attempt.

        Successful attempts reset the counter.
        Failed attempts increment the counter.

        Args:
            key: Rate limit key.
            success: Whether the attempt was successful.

        Returns:
            Updated rate limit status.
        """
        if success:
            await self.store.delete(key)
            return RateLimitResult(
                allowed=True,
                remaining_attempts=self.config.max_attempts,
                current_attempts=0,
            )

        return await self.check(key, increment=True)

    async def reset(self, key: str) -> None:
        """Reset rate limit for a key.

        Args:
            key: Rate limit key to reset.
        """
        await self.store.delete(key)

    async def is_locked(self, key: str) -> bool:
        """Check if a key is currently locked.

        Args:
            key: Rate limit key.

        Returns:
            True if the key is locked.
        """
        result = await self.check(key)
        return not result.allowed


__all__ = [
    "RateLimitConfig",
    "RateLimitResult",
    "RateLimiter",
]
