"""Middleware for NeoZen Litestar extension."""

from __future__ import annotations

import typing

from litestar.types import ASGIApp, Receive, Scope, Send

if typing.TYPE_CHECKING:
    from .config import NeoZenConfig


class NeoZenMiddleware:
    """Middleware for NeoZen session validation.

    This middleware validates the session cookie on each request and
    stores the session and user information in connection state.

    State set on scope["state"]:
        - neozen_config: The NeoZenConfig instance
        - neozen_session: The validated session (or None)
        - neozen_user: The authenticated user (lazy loaded, or None)
        - neozen_user_loaded: Whether the user has been loaded
    """

    def __init__(self, app: ASGIApp, config: NeoZenConfig) -> None:
        """Initialize the middleware.

        Args:
            app: The ASGI application
            config: NeoZen configuration
        """
        self.app = app
        self.config = config

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process the request and validate session.

        Args:
            scope: ASGI scope
            receive: ASGI receive callable
            send: ASGI send callable
        """
        if scope["type"] != "http":  # type: ignore[comparison-overlap]
            await self.app(scope, receive, send)
            return

        # Initialize state
        if "state" not in scope:
            scope["state"] = {}

        scope["state"]["neozen_config"] = self.config
        scope["state"]["neozen_session"] = None
        scope["state"]["neozen_user"] = None
        scope["state"]["neozen_user_loaded"] = False

        # Skip authentication for excluded paths
        path = scope.get("path", "")
        if path in self.config.exclude_paths:
            await self.app(scope, receive, send)
            return

        # Get session token from cookie
        cookies = self._parse_cookies(scope)
        token = cookies.get(self.config.cookie_name)

        if token:
            # Validate session
            session = await self.config.get_session(token)
            if session:
                scope["state"]["neozen_session"] = session

        await self.app(scope, receive, send)

    def _parse_cookies(self, scope: Scope) -> dict[str, str]:
        """Parse cookies from request headers.

        Args:
            scope: ASGI scope

        Returns:
            Dictionary of cookie name to value
        """
        cookies: dict[str, str] = {}
        headers = scope.get("headers", [])

        for name, value in headers:
            if name == b"cookie":
                cookie_str = value.decode("utf-8", errors="ignore")
                for part in cookie_str.split(";"):
                    part = part.strip()
                    if "=" in part:
                        key, val = part.split("=", 1)
                        cookies[key.strip()] = val.strip()

        return cookies


__all__ = ["NeoZenMiddleware"]
