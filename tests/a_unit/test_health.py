"""Unit tests for health checks."""

from __future__ import annotations

import asyncio

import pytest

from neozen.monitoring.health import (
    CheckResult,
    HealthChecker,
    HealthStatus,
    create_ping_check,
)


@pytest.fixture
def checker() -> HealthChecker:
    """Create a health checker."""
    return HealthChecker(version="1.0.0")


class TestCheckResult:
    """Tests for CheckResult."""

    def test_healthy_check(self) -> None:
        """Test creating a healthy check result."""
        result = CheckResult(
            name="database",
            healthy=True,
            message="Connected",
        )

        assert result.name == "database"
        assert result.healthy is True
        assert result.message == "Connected"

    def test_unhealthy_check(self) -> None:
        """Test creating an unhealthy check result."""
        result = CheckResult(
            name="redis",
            healthy=False,
            message="Connection refused",
        )

        assert result.healthy is False

    def test_check_with_latency(self) -> None:
        """Test check result with latency."""
        result = CheckResult(
            name="api",
            healthy=True,
            latency_ms=42.5,
        )

        assert result.latency_ms == pytest.approx(42.5)

    def test_check_with_details(self) -> None:
        """Test check result with details."""
        result = CheckResult(
            name="database",
            healthy=True,
            details={"connections": 5, "max_connections": 100},
        )

        assert result.details["connections"] == 5


class TestHealthStatus:
    """Tests for HealthStatus."""

    def test_healthy_status(self) -> None:
        """Test creating healthy status."""
        from datetime import UTC, datetime

        status = HealthStatus(
            healthy=True,
            checks={},
            timestamp=datetime.now(UTC),
        )

        assert status.healthy is True

    def test_status_with_checks(self) -> None:
        """Test status with check results."""
        from datetime import UTC, datetime

        checks = {
            "db": CheckResult(name="db", healthy=True),
            "redis": CheckResult(name="redis", healthy=False),
        }

        status = HealthStatus(
            healthy=False,
            checks=checks,
            timestamp=datetime.now(UTC),
        )

        assert len(status.checks) == 2
        assert status.checks["db"].healthy is True
        assert status.checks["redis"].healthy is False

    def test_to_dict(self) -> None:
        """Test converting status to dict."""
        from datetime import UTC, datetime

        checks = {
            "db": CheckResult(name="db", healthy=True, message="OK"),
        }

        status = HealthStatus(
            healthy=True,
            checks=checks,
            timestamp=datetime.now(UTC),
            version="1.0.0",
        )

        result = status.to_dict()

        assert result["healthy"] is True
        assert result["version"] == "1.0.0"
        assert "timestamp" in result
        assert "checks" in result
        assert result["checks"]["db"]["healthy"] is True


class TestHealthChecker:
    """Tests for HealthChecker."""

    @pytest.mark.anyio
    async def test_register_check(self, checker: HealthChecker) -> None:
        """Test registering a check."""

        async def dummy_check() -> CheckResult:
            await asyncio.sleep(0)
            return CheckResult(name="dummy", healthy=True)

        checker.register("dummy", dummy_check)

        assert "dummy" in checker.registered_checks

    @pytest.mark.anyio
    async def test_unregister_check(self, checker: HealthChecker) -> None:
        """Test unregistering a check."""

        async def dummy_check() -> CheckResult:
            await asyncio.sleep(0)
            return CheckResult(name="dummy", healthy=True)

        checker.register("dummy", dummy_check)
        checker.unregister("dummy")

        assert "dummy" not in checker.registered_checks

    @pytest.mark.anyio
    async def test_check_single(self, checker: HealthChecker) -> None:
        """Test running a single check."""

        async def db_check() -> CheckResult:
            await asyncio.sleep(0)
            return CheckResult(name="db", healthy=True, message="Connected")

        checker.register("db", db_check)
        result = await checker.check("db")

        assert result.healthy is True
        assert result.message == "Connected"
        assert result.latency_ms is not None

    @pytest.mark.anyio
    async def test_check_nonexistent(self, checker: HealthChecker) -> None:
        """Test checking nonexistent check."""
        with pytest.raises(KeyError, match="not registered"):
            await checker.check("nonexistent")

    @pytest.mark.anyio
    async def test_check_exception_handling(self, checker: HealthChecker) -> None:
        """Test that exceptions in checks are handled."""

        async def failing_check() -> CheckResult:
            await asyncio.sleep(0)
            msg = "Connection failed"
            raise RuntimeError(msg)

        checker.register("failing", failing_check)
        result = await checker.check("failing")

        assert result.healthy is False
        assert "Connection failed" in str(result.message)

    @pytest.mark.anyio
    async def test_check_all_healthy(self, checker: HealthChecker) -> None:
        """Test check_all when all checks pass."""

        async def check1() -> CheckResult:
            await asyncio.sleep(0)
            return CheckResult(name="check1", healthy=True)

        async def check2() -> CheckResult:
            await asyncio.sleep(0)
            return CheckResult(name="check2", healthy=True)

        checker.register("check1", check1)
        checker.register("check2", check2)

        status = await checker.check_all()

        assert status.healthy is True
        assert len(status.checks) == 2

    @pytest.mark.anyio
    async def test_check_all_unhealthy(self, checker: HealthChecker) -> None:
        """Test check_all when a check fails."""

        async def healthy_check() -> CheckResult:
            await asyncio.sleep(0)
            return CheckResult(name="healthy", healthy=True)

        async def unhealthy_check() -> CheckResult:
            await asyncio.sleep(0)
            return CheckResult(name="unhealthy", healthy=False)

        checker.register("healthy", healthy_check)
        checker.register("unhealthy", unhealthy_check)

        status = await checker.check_all()

        assert status.healthy is False

    @pytest.mark.anyio
    async def test_check_all_empty(self, checker: HealthChecker) -> None:
        """Test check_all with no registered checks."""
        status = await checker.check_all()

        assert status.healthy is True
        assert len(status.checks) == 0

    @pytest.mark.anyio
    async def test_version_in_status(self, checker: HealthChecker) -> None:
        """Test version is included in status."""
        status = await checker.check_all()

        assert status.version == "1.0.0"

    @pytest.mark.anyio
    async def test_timestamp_in_status(self, checker: HealthChecker) -> None:
        """Test timestamp is included in status."""
        status = await checker.check_all()

        assert status.timestamp is not None

    @pytest.mark.anyio
    async def test_registered_checks_list(self, checker: HealthChecker) -> None:
        """Test getting list of registered checks."""

        async def check1() -> CheckResult:
            await asyncio.sleep(0)
            return CheckResult(name="check1", healthy=True)

        async def check2() -> CheckResult:
            await asyncio.sleep(0)
            return CheckResult(name="check2", healthy=True)

        checker.register("check1", check1)
        checker.register("check2", check2)

        checks = checker.registered_checks

        assert "check1" in checks
        assert "check2" in checks


class TestPingCheck:
    """Tests for ping check factory."""

    @pytest.mark.anyio
    async def test_create_ping_check(self) -> None:
        """Test creating a ping check."""
        check = create_ping_check()
        result = await check()

        assert result.healthy is True
        assert result.message == "pong"

    @pytest.mark.anyio
    async def test_create_ping_check_custom_name(self) -> None:
        """Test creating a ping check with custom name."""
        check = create_ping_check(name="liveness")
        result = await check()

        assert result.name == "liveness"

    @pytest.mark.anyio
    async def test_ping_check_in_checker(self) -> None:
        """Test using ping check in health checker."""
        checker = HealthChecker()
        checker.register("ping", create_ping_check())

        status = await checker.check_all()

        assert status.healthy is True
        assert "ping" in status.checks
