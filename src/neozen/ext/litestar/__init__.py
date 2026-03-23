"""NeoZen Litestar extension.

A Litestar plugin for NeoZen authentication, providing middleware,
guards, and helper functions for session-based authentication.

Example:
    from litestar import Litestar, get, post, Request
    from litestar.response import Redirect

    from neozen.ext.litestar import (
        NeoZenPlugin,
        NeoZenConfig,
        login_required,
        get_current_user,
        login_user,
        logout_user,
    )

    # Create config
    async def load_subject(subject_id: str) -> Subject | None:
        return await user_repo.get(subject_id)

    config = NeoZenConfig(
        session_service=session_service,
        subject_loader=load_subject,
    )

    # Protect routes with guards
    @get("/dashboard", guards=[login_required()])
    async def dashboard(request: Request) -> Template:
        user = await get_current_user(request)
        return Template("dashboard.html", context={"user": user})

    # Create app with plugin
    app = Litestar(
        route_handlers=[dashboard],
        plugins=[NeoZenPlugin(config)],
    )
"""

from __future__ import annotations

from .config import NeoZenConfig, SameSitePolicy, SubjectLoader
from .guards import (
    AuthenticationRequiredError,
    LoginRequiredGuard,
    PermissionDeniedError,
    PermissionsRequiredGuard,
    RolesRequiredGuard,
    login_required,
    permissions_required,
    roles_required,
)
from .helpers import (
    get_config,
    get_current_user,
    is_authenticated,
    login_user,
    logout_user,
)
from .middleware import NeoZenMiddleware
from .oauth import create_oauth_router
from .plugin import NeoZenPlugin
from .rate_limit import (
    RateLimitGuard,
    RateLimitMiddleware as RateLimitMiddlewareLitestar,
    get_client_ip,
    get_rate_limit_result,
    rate_limit_guard,
)

__all__ = [
    # Config
    "NeoZenConfig",
    "SameSitePolicy",
    "SubjectLoader",
    # Plugin
    "NeoZenPlugin",
    # Middleware
    "NeoZenMiddleware",
    # Guards
    "AuthenticationRequiredError",
    "LoginRequiredGuard",
    "PermissionDeniedError",
    "PermissionsRequiredGuard",
    "RolesRequiredGuard",
    "login_required",
    "permissions_required",
    "roles_required",
    # Helpers
    "get_config",
    "get_current_user",
    "is_authenticated",
    "login_user",
    "logout_user",
    # OAuth
    "create_oauth_router",
    # Rate limiting
    "RateLimitGuard",
    "RateLimitMiddlewareLitestar",
    "get_client_ip",
    "get_rate_limit_result",
    "rate_limit_guard",
]
