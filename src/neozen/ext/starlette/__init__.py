"""NeoZen Starlette extension.

A Starlette extension for NeoZen authentication, providing middleware,
decorators, and helper functions for session-based authentication.

Example:
    from starlette.applications import Starlette
    from starlette.middleware import Middleware

    from neozen.ext.starlette import (
        NeoZenMiddleware,
        NeoZenBackend,
        login_required,
        get_current_user,
        login_user,
        logout_user,
    )

    # Create backend
    async def load_subject(subject_id: str) -> Subject | None:
        return await user_repo.get(subject_id)

    backend = NeoZenBackend(
        session_service=session_service,
        subject_loader=load_subject,
    )

    # Create app with middleware
    app = Starlette(
        middleware=[
            Middleware(NeoZenMiddleware, backend=backend),
        ],
        routes=[...],
    )

    # Protect routes
    @login_required
    async def dashboard(request: Request) -> Response:
        user = await get_current_user(request)
        return templates.TemplateResponse("dashboard.html", {"user": user})
"""

from __future__ import annotations

from .backend import NeoZenBackend, SubjectLoader
from .decorators import login_required, permissions_required, roles_required
from .helpers import (
    get_backend,
    get_current_user,
    is_authenticated,
    login_user,
    logout_user,
)
from .middleware import NeoZenMiddleware
from .oauth import create_oauth_routes

__all__ = [
    # Backend
    "NeoZenBackend",
    "SubjectLoader",
    # Middleware
    "NeoZenMiddleware",
    # Decorators
    "login_required",
    "permissions_required",
    "roles_required",
    # Helpers
    "get_backend",
    "get_current_user",
    "is_authenticated",
    "login_user",
    "logout_user",
    # OAuth
    "create_oauth_routes",
]
