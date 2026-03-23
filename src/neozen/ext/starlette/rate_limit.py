"""Rate limiting for NeoZen Starlette extension.

Provides rate limiting middleware for protecting endpoints
against brute force attacks.
"""

from __future__ import annotations

import typing

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from neozen.core.security import RateLimiter

if typing.TYPE_CHECKING:
    from starlette.types import ASGIApp


def get_client_ip(request: Request) -> str:
    """Get client IP address from Starlette request.

    Handles X-Forwarded-For header for reverse proxies.

    Args:
        request: Starlette Request object.

    Returns:
        Client IP address.
    """
    # Check X-Forwarded-For header (common in reverse proxy setups)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take the first IP (client IP) from the comma-separated list
        return forwarded_for.split(",")[0].strip()

    # Check X-Real-IP header (nginx)
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    # Fall back to client host
    if request.client:
        return request.client.host

    return "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Starlette middleware for rate limiting.

    Applies rate limiting to requests matching configured paths.

    Example:
        from starlette.applications import Starlette
        from starlette.middleware import Middleware
        from neozen.ext.starlette.rate_limit import RateLimitMiddleware

        app = Starlette(
            middleware=[
                Middleware(
                    RateLimitMiddleware,
                    limiter=limiter,
                    paths=["/login", "/register"],
                ),
            ],
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        limiter: RateLimiter,
        paths: list[str] | None = None,
        action: str = "request",
        exclude_paths: list[str] | None = None,
    ) -> None:
        """Initialize middleware.

        Args:
            app: ASGI application.
            limiter: RateLimiter instance.
            paths: Paths to rate limit. If None, limits all paths (except excluded).
            action: Action name for rate limit key.
            exclude_paths: Paths to exclude from rate limiting.
        """
        super().__init__(app)
        self.limiter = limiter
        self.paths = set(paths) if paths else None
        self.action = action
        self.exclude_paths = set(exclude_paths or [])

    def _should_rate_limit(self, path: str) -> bool:
        """Check if path should be rate limited."""
        if path in self.exclude_paths:
            return False
        if self.paths is None:
            return True
        return path in self.paths

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Process request with rate limiting.

        Args:
            request: Incoming request.
            call_next: Next middleware/handler.

        Returns:
            Response.
        """
        # Check if path should be rate limited
        if not self._should_rate_limit(request.url.path):
            return await call_next(request)

        # Get client IP
        ip_address = get_client_ip(request)

        # Get subject ID if available
        subject_id = None
        if hasattr(request.state, "neozen_session") and request.state.neozen_session:
            subject_id = request.state.neozen_session.subject_id

        # Create rate limit key
        key = self.limiter.make_key(
            ip_address=ip_address,
            subject_id=subject_id,
            action=self.action,
        )

        # Check rate limit
        result = await self.limiter.check(key, increment=True)

        # Store result in request state
        request.state.rate_limit_result = result

        if not result.allowed:
            retry_after = (
                int(result.retry_after.total_seconds()) if result.retry_after else 60
            )
            return JSONResponse(
                {
                    "error": "Too Many Requests",
                    "message": "Rate limit exceeded. Please try again later.",
                    "retry_after": retry_after,
                },
                status_code=429,
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(self.limiter.config.max_attempts),
                    "X-RateLimit-Remaining": "0",
                },
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.limiter.config.max_attempts)
        response.headers["X-RateLimit-Remaining"] = str(result.remaining_attempts)
        if result.reset_at:
            response.headers["X-RateLimit-Reset"] = str(
                int(result.reset_at.timestamp())
            )

        return response


class LoginRateLimitMiddleware(BaseHTTPMiddleware):
    """Specialized middleware for rate limiting login attempts.

    Records successful/failed attempts and resets on success.

    Example:
        from starlette.middleware import Middleware
        from neozen.ext.starlette.rate_limit import LoginRateLimitMiddleware

        app = Starlette(
            middleware=[
                Middleware(
                    LoginRateLimitMiddleware,
                    limiter=limiter,
                    login_path="/login",
                ),
            ],
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        limiter: RateLimiter,
        login_path: str = "/login",
        action: str = "login",
    ) -> None:
        """Initialize middleware.

        Args:
            app: ASGI application.
            limiter: RateLimiter instance.
            login_path: Path to the login endpoint.
            action: Action name for rate limit key.
        """
        super().__init__(app)
        self.limiter = limiter
        self.login_path = login_path
        self.action = action

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Process login request with rate limiting.

        Args:
            request: Incoming request.
            call_next: Next middleware/handler.

        Returns:
            Response.
        """
        # Only rate limit POST to login path
        if request.url.path != self.login_path or request.method != "POST":
            return await call_next(request)

        # Get client IP
        ip_address = get_client_ip(request)

        # Create rate limit key
        key = self.limiter.make_key(
            ip_address=ip_address,
            action=self.action,
        )

        # Check rate limit (don't increment yet)
        result = await self.limiter.check(key)

        if not result.allowed:
            retry_after = (
                int(result.retry_after.total_seconds()) if result.retry_after else 60
            )
            return JSONResponse(
                {
                    "error": "Too Many Requests",
                    "message": "Too many login attempts. Please try again later.",
                    "retry_after": retry_after,
                },
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )

        # Store key in request state for later recording
        request.state.rate_limit_key = key

        # Process request
        response = await call_next(request)

        # Record attempt based on response status
        success = 200 <= response.status_code < 400
        await self.limiter.record_attempt(key, success=success)

        return response


__all__ = [
    "LoginRateLimitMiddleware",
    "RateLimitMiddleware",
    "get_client_ip",
]
