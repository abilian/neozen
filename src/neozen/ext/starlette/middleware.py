"""Middleware for NeoZen Starlette extension."""

from __future__ import annotations

import typing

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from .backend import NeoZenBackend

if typing.TYPE_CHECKING:
    from starlette.types import ASGIApp


class NeoZenMiddleware(BaseHTTPMiddleware):
    """Middleware for NeoZen session validation.

    This middleware validates the session cookie on each request and
    stores the session and user information in request.state.

    Attributes set on request.state:
        - neozen_backend: The NeoZenBackend instance
        - neozen_session: The validated session (or None)
        - neozen_user: The authenticated user (lazy loaded, or None)
        - neozen_user_loaded: Whether the user has been loaded

    Example:
        from starlette.applications import Starlette
        from starlette.middleware import Middleware

        backend = NeoZenBackend(
            session_service=session_service,
            subject_loader=load_subject,
        )

        app = Starlette(
            middleware=[
                Middleware(NeoZenMiddleware, backend=backend),
            ],
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        backend: NeoZenBackend,
        exclude_paths: list[str] | None = None,
    ) -> None:
        """Initialize the middleware.

        Args:
            app: The ASGI application
            backend: NeoZen backend for session/subject management
            exclude_paths: Paths to skip authentication (e.g., ["/health"])
        """
        super().__init__(app)
        self.backend = backend
        self.exclude_paths = set(exclude_paths or [])

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Process the request and validate session.

        Args:
            request: The incoming request
            call_next: The next middleware/route handler

        Returns:
            The response
        """
        # Initialize request state
        request.state.neozen_backend = self.backend
        request.state.neozen_session = None
        request.state.neozen_user = None
        request.state.neozen_user_loaded = False

        # Skip authentication for excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        # Get session token from cookie
        token = request.cookies.get(self.backend.cookie_name)

        if token:
            # Validate session
            session = await self.backend.get_session(token)
            if session:
                request.state.neozen_session = session

        return await call_next(request)


__all__ = ["NeoZenMiddleware"]
