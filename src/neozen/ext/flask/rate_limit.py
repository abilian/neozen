"""Rate limiting for NeoZen Flask extension.

Provides rate limiting decorators and middleware for protecting endpoints
against brute force attacks.
"""

from __future__ import annotations

import typing
from functools import wraps

from flask import Response, g, jsonify, request

from neozen.core.security import RateLimiter, RateLimitResult

if typing.TYPE_CHECKING:
    from collections.abc import Callable

    F = typing.TypeVar("F", bound=Callable[..., typing.Any])


def get_client_ip() -> str:
    """Get client IP address from Flask request.

    Handles X-Forwarded-For header for reverse proxies.

    Returns:
        Client IP address.
    """
    # Check X-Forwarded-For header (common in reverse proxy setups)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP (client IP) from the comma-separated list
        return forwarded_for.split(",")[0].strip()

    # Check X-Real-IP header (nginx)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Fall back to remote_addr
    return request.remote_addr or "unknown"


def rate_limit(
    limiter: RateLimiter,
    *,
    action: str = "request",
    get_subject_id: Callable[[], str | None] | None = None,
    on_limited: Callable[[RateLimitResult], Response | None] | None = None,
) -> Callable[[F], F]:
    """Decorator to apply rate limiting to a Flask view.

    Args:
        limiter: The RateLimiter instance to use.
        action: Action name for the rate limit key (default: "request").
        get_subject_id: Optional callable to get subject ID for rate limiting.
        on_limited: Optional callback when rate limited. If None, returns 429.

    Returns:
        Decorator function.

    Example:
        limiter = RateLimiter(config, store)

        @app.route("/login", methods=["POST"])
        @rate_limit(limiter, action="login")
        def login():
            # Handle login...

        # With subject ID extraction
        @app.route("/api/action", methods=["POST"])
        @rate_limit(
            limiter,
            action="api",
            get_subject_id=lambda: current_user.id if current_user else None
        )
        def api_action():
            # Handle action...
    """

    def decorator(f: F) -> F:
        @wraps(f)
        def decorated_function(*args: typing.Any, **kwargs: typing.Any) -> Response:
            import asyncio  # noqa: PLC0415

            # Get client identifiers
            ip_address = get_client_ip()
            subject_id = get_subject_id() if get_subject_id else None

            # Create rate limit key
            key = limiter.make_key(
                ip_address=ip_address,
                subject_id=subject_id,
                action=action,
            )

            # Check rate limit (run async in sync context)
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            result = loop.run_until_complete(limiter.check(key, increment=True))

            # Store result in g for access in view
            g.rate_limit_result = result

            if not result.allowed:
                if on_limited:
                    custom_response = on_limited(result)
                    if custom_response:
                        return custom_response

                # Default 429 response
                retry_after = (
                    int(result.retry_after.total_seconds())
                    if result.retry_after
                    else 60
                )
                response = jsonify({
                    "error": "Too Many Requests",
                    "message": "Rate limit exceeded. Please try again later.",
                    "retry_after": retry_after,
                })
                response.status_code = 429
                response.headers["Retry-After"] = str(retry_after)
                return response

            # Add rate limit headers to response
            response = f(*args, **kwargs)

            # Ensure response is a Response object
            if not isinstance(response, Response):
                return response

            # Add rate limit headers
            response.headers["X-RateLimit-Limit"] = str(limiter.config.max_attempts)
            response.headers["X-RateLimit-Remaining"] = str(result.remaining_attempts)
            if result.reset_at:
                response.headers["X-RateLimit-Reset"] = str(
                    int(result.reset_at.timestamp())
                )

            return response

        return decorated_function  # type: ignore[return-value]

    return decorator


class FlaskRateLimitMiddleware:
    """Flask middleware for global rate limiting.

    Applies rate limiting to all requests matching configured paths.

    Example:
        from flask import Flask
        from neozen.ext.flask.rate_limit import FlaskRateLimitMiddleware

        app = Flask(__name__)
        middleware = FlaskRateLimitMiddleware(
            limiter=limiter,
            paths=["/login", "/register", "/forgot-password"],
        )
        middleware.init_app(app)
    """

    def __init__(
        self,
        limiter: RateLimiter,
        paths: list[str] | None = None,
        action: str = "request",
    ) -> None:
        """Initialize middleware.

        Args:
            limiter: RateLimiter instance.
            paths: Paths to rate limit. If None, limits all paths.
            action: Action name for rate limit key.
        """
        self.limiter = limiter
        self.paths = set(paths) if paths else None
        self.action = action
        self._app = None

    def init_app(self, app: typing.Any) -> None:
        """Initialize the middleware with a Flask app.

        Args:
            app: Flask application instance.
        """
        self._app = app
        app.before_request(self._check_rate_limit)
        app.after_request(self._add_headers)

    def _check_rate_limit(self) -> Response | None:
        """Check rate limit before request."""
        import asyncio  # noqa: PLC0415

        # Check if path should be rate limited
        if self.paths and request.path not in self.paths:
            return None

        ip_address = get_client_ip()
        key = self.limiter.make_key(
            ip_address=ip_address,
            action=self.action,
        )

        # Run async check
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(self.limiter.check(key, increment=True))

        g.rate_limit_result = result

        if not result.allowed:
            retry_after = (
                int(result.retry_after.total_seconds()) if result.retry_after else 60
            )
            response = jsonify({
                "error": "Too Many Requests",
                "message": "Rate limit exceeded. Please try again later.",
                "retry_after": retry_after,
            })
            response.status_code = 429
            response.headers["Retry-After"] = str(retry_after)
            return response

        return None

    def _add_headers(self, response: Response) -> Response:
        """Add rate limit headers to response."""
        result = getattr(g, "rate_limit_result", None)
        if result:
            response.headers["X-RateLimit-Limit"] = str(
                self.limiter.config.max_attempts
            )
            response.headers["X-RateLimit-Remaining"] = str(result.remaining_attempts)
            if result.reset_at:
                response.headers["X-RateLimit-Reset"] = str(
                    int(result.reset_at.timestamp())
                )
        return response


__all__ = [
    "FlaskRateLimitMiddleware",
    "get_client_ip",
    "rate_limit",
]
