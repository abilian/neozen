"""Health check service for NeoZen.

Provides health check functionality for monitoring production deployments.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime


@dataclass(frozen=True)
class CheckResult:
    """Individual health check result.

    Attributes:
        name: Name of the check.
        healthy: Whether the check passed.
        message: Optional message with details.
        latency_ms: How long the check took in milliseconds.
        details: Additional check-specific details.
    """

    name: str
    healthy: bool
    message: str | None = None
    latency_ms: float | None = None
    details: dict[str, str | int | float | bool] = field(default_factory=dict)


@dataclass(frozen=True)
class HealthStatus:
    """Overall health status.

    Attributes:
        healthy: Whether all checks passed.
        checks: Individual check results.
        timestamp: When the health check was performed.
        version: Optional application version.
    """

    healthy: bool
    checks: dict[str, CheckResult]
    timestamp: datetime
    version: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for JSON serialization."""
        return {
            "healthy": self.healthy,
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "checks": {
                name: {
                    "healthy": check.healthy,
                    "message": check.message,
                    "latency_ms": check.latency_ms,
                    "details": check.details,
                }
                for name, check in self.checks.items()
            },
        }


# Type alias for health check functions
HealthCheckFn = Callable[[], Awaitable[CheckResult]]


class HealthChecker:
    """Health check service.

    Manages and executes health checks for various components.

    Example:
        checker = HealthChecker(version="1.0.0")

        # Register checks
        checker.register("database", database_check)
        checker.register("redis", redis_check)

        # Run all checks
        status = await checker.check_all()
        if not status.healthy:
            alert_ops_team()
    """

    def __init__(
        self,
        *,
        version: str | None = None,
    ) -> None:
        """Initialize health checker.

        Args:
            version: Optional application version to include in status.
        """
        self._checks: dict[str, HealthCheckFn] = {}
        self.version = version

    def register(
        self,
        name: str,
        check: HealthCheckFn,
    ) -> None:
        """Register a health check.

        Args:
            name: Name for the check.
            check: Async function that returns CheckResult.
        """
        self._checks[name] = check

    def unregister(self, name: str) -> None:
        """Unregister a health check.

        Args:
            name: Name of the check to remove.
        """
        self._checks.pop(name, None)

    async def check(self, name: str) -> CheckResult:
        """Run a single health check.

        Args:
            name: Name of the check to run.

        Returns:
            CheckResult from the check.

        Raises:
            KeyError: If check not registered.
        """
        if name not in self._checks:
            msg = f"Health check '{name}' not registered"
            raise KeyError(msg)

        check_fn = self._checks[name]
        start = time.perf_counter()

        # A check that raises reports an unhealthy dependency.
        try:
            result = await check_fn()
        except Exception as e:
            return CheckResult(
                name=name,
                healthy=False,
                message=f"Check failed with error: {e!s}",
                latency_ms=(time.perf_counter() - start) * 1000,
            )
        return replace(result, latency_ms=(time.perf_counter() - start) * 1000)

    async def check_all(self) -> HealthStatus:
        """Run all registered health checks.

        Returns:
            HealthStatus with all check results.
        """
        results: dict[str, CheckResult] = {}
        all_healthy = True

        for name in self._checks:
            result = await self.check(name)
            results[name] = result
            if not result.healthy:
                all_healthy = False

        return HealthStatus(
            healthy=all_healthy,
            checks=results,
            timestamp=datetime.now(UTC),
            version=self.version,
        )

    @property
    def registered_checks(self) -> list[str]:
        """Get list of registered check names."""
        return list(self._checks.keys())


# Built-in check factories


def create_database_check(
    session_factory: Callable[[], object],
) -> HealthCheckFn:
    """Create a database health check.

    Args:
        session_factory: SQLAlchemy session factory.

    Returns:
        Health check function.
    """

    async def check() -> CheckResult:
        try:
            session = session_factory()
            # Try to execute a simple query
            if hasattr(session, "execute"):
                await session.execute("SELECT 1")  # type: ignore[attr-defined]  # ty: ignore[call-non-callable]
            return CheckResult(
                name="database",
                healthy=True,
                message="Database connection successful",
            )
        except Exception as e:
            return CheckResult(
                name="database",
                healthy=False,
                message=f"Database connection failed: {e!s}",
            )

    return check


def create_ping_check(name: str = "ping") -> HealthCheckFn:
    """Create a simple ping check that always passes.

    Useful as a basic liveness probe.

    Args:
        name: Name for the check.

    Returns:
        Health check function.
    """

    async def check() -> CheckResult:
        # Explicit await to satisfy async requirement
        await asyncio.sleep(0)
        return CheckResult(
            name=name,
            healthy=True,
            message="pong",
        )

    return check


__all__ = [
    "CheckResult",
    "HealthCheckFn",
    "HealthChecker",
    "HealthStatus",
    "create_database_check",
    "create_ping_check",
]
