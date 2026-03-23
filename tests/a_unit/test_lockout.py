"""Unit tests for account lockout."""

from __future__ import annotations

from datetime import timedelta

import pytest

from neozen.core.security.lockout import (
    LockoutConfig,
    LockoutManager,
)
from neozen.core.security.rate_limit_store import InMemoryRateLimitStore


@pytest.fixture
def store() -> InMemoryRateLimitStore:
    """Create an in-memory store."""
    return InMemoryRateLimitStore()


@pytest.fixture
def config() -> LockoutConfig:
    """Create lockout config."""
    return LockoutConfig(
        max_failed_attempts=5,
        lockout_duration=timedelta(minutes=30),
        progressive=True,
        max_lockout_duration=timedelta(hours=24),
        progression_multiplier=2.0,
    )


@pytest.fixture
def manager(config: LockoutConfig, store: InMemoryRateLimitStore) -> LockoutManager:
    """Create lockout manager."""
    return LockoutManager(config, store)


class TestLockoutConfig:
    """Tests for LockoutConfig."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = LockoutConfig()

        assert config.max_failed_attempts == 5
        assert config.lockout_duration == timedelta(minutes=30)
        assert config.progressive is True
        assert config.max_lockout_duration == timedelta(hours=24)
        assert config.progression_multiplier == pytest.approx(2.0)

    def test_custom_values(self) -> None:
        """Test custom configuration values."""
        config = LockoutConfig(
            max_failed_attempts=3,
            lockout_duration=timedelta(minutes=15),
            progressive=False,
        )

        assert config.max_failed_attempts == 3
        assert config.lockout_duration == timedelta(minutes=15)
        assert config.progressive is False


class TestLockoutManager:
    """Tests for LockoutManager."""

    @pytest.mark.anyio
    async def test_is_locked_new_user(self, manager: LockoutManager) -> None:
        """Test that new user is not locked."""
        status = await manager.is_locked("user123")

        assert status.is_locked is False
        assert status.failed_attempts == 0
        assert status.locked_until is None

    @pytest.mark.anyio
    async def test_record_failed_attempt(self, manager: LockoutManager) -> None:
        """Test recording failed attempt."""
        status = await manager.record_failed_attempt("user123")

        assert status.is_locked is False
        assert status.failed_attempts == 1

    @pytest.mark.anyio
    async def test_record_multiple_failed_attempts(
        self,
        manager: LockoutManager,
    ) -> None:
        """Test recording multiple failed attempts."""
        for i in range(4):
            status = await manager.record_failed_attempt("user123")
            assert status.is_locked is False
            assert status.failed_attempts == i + 1

    @pytest.mark.anyio
    async def test_lockout_after_max_attempts(self, manager: LockoutManager) -> None:
        """Test lockout after max failed attempts."""
        for _ in range(5):
            status = await manager.record_failed_attempt("user123")

        assert status.is_locked is True
        assert status.locked_until is not None
        assert status.remaining_lockout is not None

    @pytest.mark.anyio
    async def test_is_locked_after_lockout(self, manager: LockoutManager) -> None:
        """Test is_locked returns True after lockout."""
        for _ in range(5):
            await manager.record_failed_attempt("user123")

        status = await manager.is_locked("user123")

        assert status.is_locked is True
        assert status.remaining_lockout is not None
        assert status.remaining_lockout > timedelta(0)

    @pytest.mark.anyio
    async def test_record_success_resets(self, manager: LockoutManager) -> None:
        """Test successful login resets counter."""
        for _ in range(3):
            await manager.record_failed_attempt("user123")

        await manager.record_success("user123")

        status = await manager.is_locked("user123")
        assert status.is_locked is False
        assert status.failed_attempts == 0

    @pytest.mark.anyio
    async def test_unlock_clears_lockout(self, manager: LockoutManager) -> None:
        """Test manual unlock clears lockout."""
        for _ in range(5):
            await manager.record_failed_attempt("user123")

        # Verify locked
        status = await manager.is_locked("user123")
        assert status.is_locked is True

        # Unlock
        await manager.unlock("user123")

        # Verify unlocked
        status = await manager.is_locked("user123")
        assert status.is_locked is False

    @pytest.mark.anyio
    async def test_get_failed_attempts(self, manager: LockoutManager) -> None:
        """Test getting failed attempts count."""
        assert await manager.get_failed_attempts("user123") == 0

        await manager.record_failed_attempt("user123")
        await manager.record_failed_attempt("user123")

        assert await manager.get_failed_attempts("user123") == 2

    @pytest.mark.anyio
    async def test_progressive_lockout_duration(
        self,
        config: LockoutConfig,
        store: InMemoryRateLimitStore,
    ) -> None:
        """Test progressive lockout increases duration."""
        manager = LockoutManager(config, store)

        # Calculate expected duration
        duration = manager._calculate_lockout_duration(1)
        assert duration == config.lockout_duration

        duration = manager._calculate_lockout_duration(2)
        expected = config.lockout_duration * 2
        assert duration == expected

        duration = manager._calculate_lockout_duration(3)
        expected = config.lockout_duration * 4
        assert duration == expected

    @pytest.mark.anyio
    async def test_progressive_lockout_max_duration(
        self,
        store: InMemoryRateLimitStore,
    ) -> None:
        """Test progressive lockout caps at max duration."""
        config = LockoutConfig(
            lockout_duration=timedelta(hours=1),
            max_lockout_duration=timedelta(hours=2),
            progression_multiplier=10.0,
        )
        manager = LockoutManager(config, store)

        # Second lockout would be 10 hours, but capped at 2
        duration = manager._calculate_lockout_duration(2)
        assert duration == timedelta(hours=2)

    @pytest.mark.anyio
    async def test_non_progressive_lockout(
        self,
        store: InMemoryRateLimitStore,
    ) -> None:
        """Test non-progressive lockout uses constant duration."""
        config = LockoutConfig(
            lockout_duration=timedelta(minutes=30),
            progressive=False,
        )
        manager = LockoutManager(config, store)

        duration = manager._calculate_lockout_duration(1)
        assert duration == timedelta(minutes=30)

        duration = manager._calculate_lockout_duration(5)
        assert duration == timedelta(minutes=30)

    @pytest.mark.anyio
    async def test_different_users_independent(
        self,
        manager: LockoutManager,
    ) -> None:
        """Test different users have independent lockouts."""
        # Lock user1
        for _ in range(5):
            await manager.record_failed_attempt("user1")

        status1 = await manager.is_locked("user1")
        status2 = await manager.is_locked("user2")

        assert status1.is_locked is True
        assert status2.is_locked is False
