"""Rate limiting for NeoZen Litestar extension.

Provides rate limiting middleware and guards for protecting endpoints
against brute force attacks.
"""

from __future__ import annotations

import json
import typing

from litestar.connection import ASGIConnection
from litestar.enums import ScopeType
from litestar.handlers import BaseRouteHandler
from litestar.types import ASGIApp, Message, Receive, Scope, Send

from neozen.core.security import RateLimiter, RateLimitResult

if typing.TYPE_CHECKING:
    from collections.abc import Callable


def get_client_ip(scope: Scope) -> str:
    """Get client IP address from ASGI scope.

    Handles X-Forwarded-For header for reverse proxies.

    Args:
        scope: ASGI scope.

    Returns:
        Client IP address.
    """
    headers = dict(scope.get("headers", []))

    # Check X-Forwarded-For header (common in reverse proxy setups)
    forwarded_for = headers.get(b"x-forwarded-for")
    if forwarded_for:
        # Take the first IP (client IP) from the comma-separated list
        return forwarded_for.decode("utf-8").split(",")[0].strip()

    # Check X-Real-IP header (nginx)
    real_ip = headers.get(b"x-real-ip")
    if real_ip:
        return real_ip.decode("utf-8").strip()

    # Fall back to client host
    client = scope.get("client")
    if client:
        return client[0]

    return "unknown"


class RateLimitMiddleware:
    """Litestar middleware for rate limiting.

    Applies rate limiting to requests matching configured paths.

    Example:
        from litestar import Litestar
        from neozen.ext.litestar.rate_limit import RateLimitMiddleware

        app = Litestar(
            route_handlers=[...],
            middleware=[RateLimitMiddleware],
        )
        app.state.rate_limiter = limiter
    """

    def __init__(
        self,
        app: ASGIApp,
        limiter: RateLimiter | None = None,
        paths: list[str] | None = None,
        action: str = "request",
        exclude_paths: list[str] | None = None,
    ) -> None:
        """Initialize middleware.

        Args:
            app: ASGI application.
            limiter: RateLimiter instance. If None, looks in app.state.rate_limiter.
            paths: Paths to rate limit. If None, limits all paths (except excluded).
            action: Action name for rate limit key.
            exclude_paths: Paths to exclude from rate limiting.
        """
        self.app = app
        self._limiter = limiter
        self.paths = set(paths) if paths else None
        self.action = action
        self.exclude_paths = set(exclude_paths or [])

    def _get_limiter(self, scope: Scope) -> RateLimiter | None:
        """Get rate limiter from scope state or instance."""
        if self._limiter:
            return self._limiter

        state = scope.get("state", {})
        return state.get("rate_limiter")

    def _should_rate_limit(self, path: str) -> bool:
        """Check if path should be rate limited."""
        if path in self.exclude_paths:
            return False
        if self.paths is None:
            return True
        return path in self.paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process request with rate limiting."""
        if scope["type"] != ScopeType.HTTP:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Check if path should be rate limited
        if not self._should_rate_limit(path):
            await self.app(scope, receive, send)
            return

        # Get rate limiter
        limiter = self._get_limiter(scope)
        if not limiter:
            await self.app(scope, receive, send)
            return

        # Store config reference for type checker (limiter is guaranteed non-None here)
        config = limiter.config

        # Get client IP
        ip_address = get_client_ip(scope)

        # Get subject ID if available
        subject_id = None
        state = scope.get("state", {})
        session = state.get("neozen_session")
        if session:
            subject_id = getattr(session, "subject_id", None)

        # Create rate limit key
        key = limiter.make_key(
            ip_address=ip_address,
            subject_id=subject_id,
            action=self.action,
        )

        # Check rate limit
        result = await limiter.check(key, increment=True)

        # Store result in scope state
        if "state" not in scope:
            scope["state"] = {}
        scope["state"]["rate_limit_result"] = result

        if not result.allowed:
            retry_after = (
                int(result.retry_after.total_seconds()) if result.retry_after else 60
            )

            body = json.dumps({
                "error": "Too Many Requests",
                "message": "Rate limit exceeded. Please try again later.",
                "retry_after": retry_after,
            }).encode()
            headers: list[tuple[bytes, bytes]] = [
                (b"content-type", b"application/json"),
                (b"retry-after", str(retry_after).encode()),
                (b"x-ratelimit-limit", str(config.max_attempts).encode()),
                (b"x-ratelimit-remaining", b"0"),
            ]
            await send(
                typing.cast(
                    Message,
                    {
                        "type": "http.response.start",
                        "status": 429,
                        "headers": headers,
                    },
                )
            )
            await send(
                typing.cast(
                    Message,
                    {
                        "type": "http.response.body",
                        "body": body,
                    },
                )
            )
            return

        # Wrap send to add headers
        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend([
                    (
                        b"x-ratelimit-limit",
                        str(config.max_attempts).encode(),
                    ),
                    (
                        b"x-ratelimit-remaining",
                        str(result.remaining_attempts).encode(),
                    ),
                ])
                if result.reset_at:
                    headers.append((
                        b"x-ratelimit-reset",
                        str(int(result.reset_at.timestamp())).encode(),
                    ))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


class RateLimitGuard:
    """Litestar guard for rate limiting specific routes.

    Example:
        from litestar import get
        from neozen.ext.litestar.rate_limit import RateLimitGuard

        guard = RateLimitGuard(limiter, action="login")

        @get("/login", guards=[guard])
        async def login(request: Request) -> dict:
            ...
    """

    def __init__(
        self,
        limiter: RateLimiter,
        action: str = "request",
    ) -> None:
        """Initialize guard.

        Args:
            limiter: RateLimiter instance.
            action: Action name for rate limit key.
        """
        self.limiter = limiter
        self.action = action

    async def __call__(
        self,
        connection: ASGIConnection,
        _: BaseRouteHandler,
    ) -> None:
        """Check rate limit.

        Args:
            connection: ASGI connection.
            _: Route handler (unused).

        Raises:
            RateLimitExceededError: If rate limit exceeded.
        """
        ip_address = get_client_ip(connection.scope)

        subject_id = None
        if hasattr(connection, "state") and hasattr(connection.state, "neozen_session"):
            session = connection.state.neozen_session
            if session:
                subject_id = getattr(session, "subject_id", None)

        key = self.limiter.make_key(
            ip_address=ip_address,
            subject_id=subject_id,
            action=self.action,
        )

        result = await self.limiter.check(key, increment=True)

        # Store result in connection state
        connection.state.rate_limit_result = result

        if not result.allowed:
            from litestar.exceptions import HTTPException  # noqa: PLC0415

            retry_after = (
                int(result.retry_after.total_seconds()) if result.retry_after else 60
            )
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Please try again later.",
                headers={"Retry-After": str(retry_after)},
            )


def rate_limit_guard(
    limiter: RateLimiter,
    action: str = "request",
) -> Callable[
    [ASGIConnection, BaseRouteHandler],
    typing.Coroutine[typing.Any, typing.Any, None],
]:
    """Create a rate limit guard.

    Factory function for creating rate limit guards.

    Args:
        limiter: RateLimiter instance.
        action: Action name for rate limit key.

    Returns:
        Guard function.

    Example:
        from litestar import get
        from neozen.ext.litestar.rate_limit import rate_limit_guard

        @get("/login", guards=[rate_limit_guard(limiter, action="login")])
        async def login() -> dict:
            ...
    """
    guard = RateLimitGuard(limiter, action)
    return guard.__call__


def get_rate_limit_result(connection: ASGIConnection) -> RateLimitResult | None:
    """Get rate limit result from connection state.

    Args:
        connection: ASGI connection.

    Returns:
        RateLimitResult if available, None otherwise.
    """
    if hasattr(connection, "state") and hasattr(connection.state, "rate_limit_result"):
        return connection.state.rate_limit_result
    return None


__all__ = [
    "RateLimitGuard",
    "RateLimitMiddleware",
    "get_client_ip",
    "get_rate_limit_result",
    "rate_limit_guard",
]
