"""Unit tests for rate limiting."""

from __future__ import annotations

from datetime import timedelta

import pytest

from neozen.core.security.rate_limit import (
    RateLimitConfig,
    RateLimiter,
)
from neozen.core.security.rate_limit_store import (
    InMemoryRateLimitStore,
    RateLimitEntry,
)


@pytest.fixture
def store() -> InMemoryRateLimitStore:
    """Create an in-memory rate limit store."""
    return InMemoryRateLimitStore()


@pytest.fixture
def config() -> RateLimitConfig:
    """Create rate limit config."""
    return RateLimitConfig(
        max_attempts=5,
        window=timedelta(minutes=15),
        lockout_duration=timedelta(minutes=30),
    )


@pytest.fixture
def limiter(config: RateLimitConfig, store: InMemoryRateLimitStore) -> RateLimiter:
    """Create rate limiter."""
    return RateLimiter(config, store)


class TestInMemoryRateLimitStore:
    """Tests for InMemoryRateLimitStore."""

    @pytest.mark.anyio
    async def test_get_nonexistent_key(self, store: InMemoryRateLimitStore) -> None:
        """Test getting a nonexistent key returns None."""
        result = await store.get("nonexistent")
        assert result is None

    @pytest.mark.anyio
    async def test_set_and_get(self, store: InMemoryRateLimitStore) -> None:
        """Test setting and getting an entry."""
        entry = RateLimitEntry(attempts=3)
        await store.set("key1", entry)

        result = await store.get("key1")
        assert result is not None
        assert result.attempts == 3

    @pytest.mark.anyio
    async def test_increment_new_key(self, store: InMemoryRateLimitStore) -> None:
        """Test incrementing a new key."""
        result = await store.increment("new_key")

        assert result.attempts == 1
        assert result.first_attempt_at is not None
        assert result.last_attempt_at is not None

    @pytest.mark.anyio
    async def test_increment_existing_key(self, store: InMemoryRateLimitStore) -> None:
        """Test incrementing an existing key."""
        await store.increment("key1")
        await store.increment("key1")
        result = await store.increment("key1")

        assert result.attempts == 3

    @pytest.mark.anyio
    async def test_delete(self, store: InMemoryRateLimitStore) -> None:
        """Test deleting an entry."""
        await store.increment("key1")
        await store.delete("key1")

        result = await store.get("key1")
        assert result is None

    @pytest.mark.anyio
    async def test_delete_nonexistent(self, store: InMemoryRateLimitStore) -> None:
        """Test deleting a nonexistent key doesn't raise."""
        await store.delete("nonexistent")  # Should not raise


class TestRateLimitConfig:
    """Tests for RateLimitConfig."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = RateLimitConfig()

        assert config.max_attempts == 5
        assert config.window == timedelta(minutes=15)
        assert config.lockout_duration == timedelta(minutes=30)
        assert config.by_ip is True
        assert config.by_subject is True

    def test_custom_values(self) -> None:
        """Test custom configuration values."""
        config = RateLimitConfig(
            max_attempts=10,
            window=timedelta(hours=1),
            lockout_duration=timedelta(hours=2),
            by_ip=False,
            by_subject=True,
        )

        assert config.max_attempts == 10
        assert config.window == timedelta(hours=1)
        assert config.lockout_duration == timedelta(hours=2)
        assert config.by_ip is False


class TestRateLimiter:
    """Tests for RateLimiter."""

    @pytest.mark.anyio
    async def test_make_key_ip_only(self, limiter: RateLimiter) -> None:
        """Test key generation with IP only."""
        key = limiter.make_key(ip_address="192.168.1.1")
        assert "ip:192.168.1.1" in key

    @pytest.mark.anyio
    async def test_make_key_subject_only(self, limiter: RateLimiter) -> None:
        """Test key generation with subject only."""
        key = limiter.make_key(subject_id="user123")
        assert "sub:user123" in key

    @pytest.mark.anyio
    async def test_make_key_both(self, limiter: RateLimiter) -> None:
        """Test key generation with both IP and subject."""
        key = limiter.make_key(ip_address="192.168.1.1", subject_id="user123")
        assert "ip:192.168.1.1" in key
        assert "sub:user123" in key

    @pytest.mark.anyio
    async def test_make_key_with_action(self, limiter: RateLimiter) -> None:
        """Test key generation with custom action."""
        key = limiter.make_key(ip_address="192.168.1.1", action="reset")
        assert key.startswith("reset:")

    @pytest.mark.anyio
    async def test_check_allowed_first_request(self, limiter: RateLimiter) -> None:
        """Test that first request is allowed."""
        result = await limiter.check("key1")

        assert result.allowed is True
        assert result.remaining_attempts == 5
        assert result.current_attempts == 0

    @pytest.mark.anyio
    async def test_check_with_increment(self, limiter: RateLimiter) -> None:
        """Test check with increment."""
        result = await limiter.check("key1", increment=True)

        assert result.allowed is True
        assert result.remaining_attempts == 4
        assert result.current_attempts == 1

    @pytest.mark.anyio
    async def test_check_multiple_attempts(self, limiter: RateLimiter) -> None:
        """Test multiple attempts."""
        for i in range(4):
            result = await limiter.check("key1", increment=True)
            assert result.allowed is True
            assert result.remaining_attempts == 5 - (i + 1)

    @pytest.mark.anyio
    async def test_check_max_attempts_exceeded(self, limiter: RateLimiter) -> None:
        """Test that exceeding max attempts causes lockout."""
        # Make max_attempts
        for _ in range(5):
            await limiter.check("key1", increment=True)

        # Next check should be locked
        result = await limiter.check("key1")

        assert result.allowed is False
        assert result.remaining_attempts == 0
        assert result.retry_after is not None

    @pytest.mark.anyio
    async def test_record_attempt_success(self, limiter: RateLimiter) -> None:
        """Test recording successful attempt resets counter."""
        # Make some failed attempts
        for _ in range(3):
            await limiter.record_attempt("key1", success=False)

        # Successful attempt
        result = await limiter.record_attempt("key1", success=True)

        assert result.allowed is True
        assert result.remaining_attempts == 5
        assert result.current_attempts == 0

    @pytest.mark.anyio
    async def test_record_attempt_failure(self, limiter: RateLimiter) -> None:
        """Test recording failed attempt increments counter."""
        result = await limiter.record_attempt("key1", success=False)

        assert result.allowed is True
        assert result.remaining_attempts == 4
        assert result.current_attempts == 1

    @pytest.mark.anyio
    async def test_reset(self, limiter: RateLimiter) -> None:
        """Test resetting rate limit."""
        # Make some attempts
        for _ in range(3):
            await limiter.check("key1", increment=True)

        # Reset
        await limiter.reset("key1")

        # Should be fresh
        result = await limiter.check("key1")
        assert result.remaining_attempts == 5
        assert result.current_attempts == 0

    @pytest.mark.anyio
    async def test_is_locked(self, limiter: RateLimiter) -> None:
        """Test is_locked helper."""
        assert await limiter.is_locked("key1") is False

        # Lock the key
        for _ in range(5):
            await limiter.check("key1", increment=True)

        # Trigger lockout check
        await limiter.check("key1")

        assert await limiter.is_locked("key1") is True

    @pytest.mark.anyio
    async def test_lockout_has_retry_after(self, limiter: RateLimiter) -> None:
        """Test that lockout result has retry_after."""
        # Lock the key
        for _ in range(5):
            await limiter.check("key1", increment=True)

        result = await limiter.check("key1")

        assert result.allowed is False
        assert result.retry_after is not None
        assert result.retry_after > timedelta(0)
        assert result.retry_after <= timedelta(minutes=30)
