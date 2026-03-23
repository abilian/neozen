"""Rate limit storage backends for NeoZen.

Provides storage abstraction for rate limiting data.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol


@dataclass
class RateLimitEntry:
    """Rate limit entry tracking attempts."""

    attempts: int = 0
    first_attempt_at: datetime | None = None
    last_attempt_at: datetime | None = None
    locked_until: datetime | None = None


class RateLimitStore(Protocol):
    """Storage interface for rate limiting."""

    async def get(self, key: str) -> RateLimitEntry | None:
        """Get rate limit entry for key."""
        ...

    async def set(
        self,
        key: str,
        entry: RateLimitEntry,
        ttl: timedelta | None = None,
    ) -> None:
        """Set rate limit entry with optional TTL."""
        ...

    async def increment(self, key: str) -> RateLimitEntry:
        """Increment attempt count and return updated entry."""
        ...

    async def delete(self, key: str) -> None:
        """Delete rate limit entry."""
        ...


class InMemoryRateLimitStore:
    """In-memory rate limit store.

    Suitable for single-instance deployments and testing.
    For multi-instance deployments, use Redis or database-backed store.
    """

    def __init__(self) -> None:
        self._entries: dict[str, RateLimitEntry] = {}
        self._expirations: dict[str, datetime] = {}

    async def get(self, key: str) -> RateLimitEntry | None:
        """Get rate limit entry for key."""
        self._cleanup_expired()
        return self._entries.get(key)

    async def set(
        self,
        key: str,
        entry: RateLimitEntry,
        ttl: timedelta | None = None,
    ) -> None:
        """Set rate limit entry with optional TTL."""
        self._entries[key] = entry
        if ttl:
            self._expirations[key] = datetime.now(UTC) + ttl
        elif key in self._expirations:
            del self._expirations[key]

    async def increment(self, key: str) -> RateLimitEntry:
        """Increment attempt count and return updated entry."""
        now = datetime.now(UTC)
        entry = self._entries.get(key)

        if entry is None:
            entry = RateLimitEntry(
                attempts=1,
                first_attempt_at=now,
                last_attempt_at=now,
            )
        else:
            entry = RateLimitEntry(
                attempts=entry.attempts + 1,
                first_attempt_at=entry.first_attempt_at or now,
                last_attempt_at=now,
                locked_until=entry.locked_until,
            )

        self._entries[key] = entry
        return entry

    async def delete(self, key: str) -> None:
        """Delete rate limit entry."""
        self._entries.pop(key, None)
        self._expirations.pop(key, None)

    def _cleanup_expired(self) -> None:
        """Remove expired entries."""
        now = datetime.now(UTC)
        expired_keys = [
            key for key, exp_time in self._expirations.items() if exp_time <= now
        ]
        for key in expired_keys:
            self._entries.pop(key, None)
            self._expirations.pop(key, None)


__all__ = [
    "InMemoryRateLimitStore",
    "RateLimitEntry",
    "RateLimitStore",
]
