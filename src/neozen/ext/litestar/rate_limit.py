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
from neozen.web.rate_limit import (
    LIMIT_EXCEEDED,
    rate_limit_headers,
    too_many_requests,
)

if typing.TYPE_CHECKING:
    from collections.abc import Callable


def get_client_ip(scope: Scope) -> str:
    """Return the client IP address from an ASGI scope.

    Forwarded headers (``X-Forwarded-For``, ``X-Real-IP``) are ignored:
    any client can set them, which would let it pick a fresh address for
    each request and dodge rate limits and lockout. Behind a reverse proxy,
    let the server rewrite the peer address for trusted proxies only
    (uvicorn ``--proxy-headers --forwarded-allow-ips``, Werkzeug ``ProxyFix``).
    """
    client = scope.get("client")
    return client[0] if client else "unknown"


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
            body, limited_headers = too_many_requests(result, config.max_attempts)
            headers = [
                (b"content-type", b"application/json"),
                *_encode(limited_headers),
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
                        "body": json.dumps(body).encode(),
                    },
                )
            )
            return

        # Wrap send to add headers
        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = [
                    *message.get("headers", []),
                    *_encode(rate_limit_headers(result, config.max_attempts)),
                ]
            await send(message)

        await self.app(scope, receive, send_wrapper)


def _encode(headers: dict[str, str]) -> list[tuple[bytes, bytes]]:
    """ASGI header pairs."""
    return [(k.lower().encode(), v.encode()) for k, v in headers.items()]


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

            headers = too_many_requests(result, self.limiter.config.max_attempts)[1]
            raise HTTPException(status_code=429, detail=LIMIT_EXCEEDED, headers=headers)


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
