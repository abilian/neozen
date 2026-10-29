"""Admin UI Litestar application.

Enterprise-grade admin console built with HTMX + Alpine.js + Tailwind CSS.
The routes live in `neozen.admin.routes`.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Any

from litestar import Litestar, Response
from litestar.config.csrf import CSRFConfig
from litestar.datastructures import State
from litestar.di import Provide
from litestar.exceptions import NotAuthorizedException
from litestar.middleware import DefineMiddleware
from litestar.stores.file import FileStore
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from neozen.admin.auth import (
    AdminAuthMiddleware,
    RotatingSessionConfig,
    redirect_to_login_handler,
)
from neozen.admin.config import AdminConfig
from neozen.admin.routes.audit import (
    audit_log_detail,
    audit_log_tail,
    list_audit_logs,
)
from neozen.admin.routes.auth import (
    login,
    login_page,
    logout,
)
from neozen.admin.routes.dashboard import (
    dashboard,
    dashboard_stats,
)
from neozen.admin.routes.groups import (
    add_group_member,
    add_group_role,
    create_group,
    create_group_form,
    delete_group,
    group_detail,
    list_groups,
    remove_group_member,
    remove_group_role,
)
from neozen.admin.routes.organizations import (
    create_organization,
    create_organization_form,
    delete_organization,
    list_organizations,
    organization_detail,
    update_organization,
)
from neozen.admin.routes.permissions import (
    access_analyzer,
    create_custom_role,
    permission_matrix,
    role_builder_form,
    toggle_permission,
)
from neozen.admin.routes.roles import (
    create_role,
    create_role_form,
    delete_role,
    list_roles,
    role_detail,
)
from neozen.admin.routes.security import (
    security_dashboard,
    security_policies,
    security_stats,
)
from neozen.admin.routes.sessions import (
    list_sessions,
    revoke_session,
)
from neozen.admin.routes.settings import (
    api_keys,
    branding,
    email_templates,
    identity_providers,
    oauth_clients,
    settings,
    social_providers,
    system_health,
    webhooks,
)
from neozen.admin.routes.users import (
    activate_user,
    add_user_role,
    create_user,
    create_user_form,
    deactivate_user,
    delete_user,
    end_impersonation,
    export_users,
    impersonate_user,
    import_users,
    import_users_form,
    list_subjects,
    list_users,
    remove_user_role,
    revoke_user_sessions,
    user_detail,
)
from neozen.admin.services import AdminService
from neozen.admin.web import get_admin_service, get_templates
from neozen.core.security import InMemoryRateLimitStore, RateLimitConfig, RateLimiter
from neozen.storage.sqlalchemy.schema import prepare_schema

# -----------------------------------------------------------------------------
# App Factory
# -----------------------------------------------------------------------------


# Every admin console route, shared with `neozen serve`.
ROUTE_HANDLERS: list[Any] = [
    # Authentication
    login_page,
    login,
    logout,
    # Dashboard
    dashboard,
    dashboard_stats,
    # Users
    list_users,
    create_user_form,
    create_user,
    import_users_form,
    import_users,
    export_users,
    user_detail,
    activate_user,
    deactivate_user,
    delete_user,
    revoke_user_sessions,
    add_user_role,
    remove_user_role,
    impersonate_user,
    end_impersonation,
    list_subjects,  # Legacy redirect
    # Roles
    list_roles,
    create_role_form,
    create_role,
    role_detail,
    delete_role,
    # Sessions
    list_sessions,
    revoke_session,
    # Groups
    list_groups,
    create_group_form,
    create_group,
    group_detail,
    add_group_member,
    remove_group_member,
    add_group_role,
    remove_group_role,
    delete_group,
    # Organizations
    list_organizations,
    create_organization_form,
    create_organization,
    organization_detail,
    update_organization,
    delete_organization,
    # Permissions & RBAC Visual Editor
    permission_matrix,
    toggle_permission,
    role_builder_form,
    create_custom_role,
    access_analyzer,
    # Audit
    list_audit_logs,
    audit_log_tail,
    audit_log_detail,
    # Security
    security_dashboard,
    security_stats,
    security_policies,
    # Settings
    settings,
    identity_providers,
    social_providers,
    api_keys,
    webhooks,
    oauth_clients,
    branding,
    email_templates,
    system_health,
]

# Authentication setup, shared with `neozen serve`. The session middleware
# must come before AUTH_MIDDLEWARE.
AUTH_MIDDLEWARE = DefineMiddleware(AdminAuthMiddleware)
EXCEPTION_HANDLERS: dict[Any, Any] = {NotAuthorizedException: redirect_to_login_handler}
# Handlers take `service: AdminService`, on a session opened per request.
DEPENDENCIES = {"service": Provide(get_admin_service)}

# The console must not be framed by another site (clickjacking).
SECURITY_HEADERS = {
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
}


def add_security_headers(response: Response) -> Response:
    """``after_request`` hook: set ``SECURITY_HEADERS`` on every response."""
    response.headers.update(SECURITY_HEADERS)
    return response


def csrf_config(config: AdminConfig) -> CSRFConfig:
    """CSRF protection for every admin form and HTMX request.

    Templates post the token back as ``_csrf_token``; HTMX sends it in the
    ``x-csrftoken`` header (set on ``<body>``).
    """
    return CSRFConfig(
        secret=config.secret_key,
        cookie_secure=config.cookie_secure,
        cookie_httponly=True,
        cookie_samesite="strict",
    )


def session_config(config: AdminConfig) -> RotatingSessionConfig:
    """Session settings for the admin console (login state and flash messages)."""
    return RotatingSessionConfig(
        key=config.cookie_name,
        max_age=86400,
        secure=config.cookie_secure,
    )


# Sign-in attempts per address and email before a pause (see LOGIN_LIMITS).
LOGIN_LIMITS = RateLimitConfig(
    max_attempts=5, window=timedelta(minutes=15), lockout_duration=timedelta(minutes=15)
)

type StartupHook = Callable[[async_sessionmaker[AsyncSession]], Awaitable[None]]


def create_admin_app(
    config: AdminConfig | None = None,
    *,
    extra_handlers: Sequence[Any] = (),
    on_ready: Sequence[StartupHook] = (),
) -> Litestar:
    """Create the admin Litestar application.

    Args:
        config: Admin configuration. If not provided, uses environment variables.
        extra_handlers: More routes, mounted beside the console's.
        on_ready: Run at startup, once the schema and built-in roles exist.

    Returns:
        Configured Litestar application
    """
    if config is None:
        config = AdminConfig(
            db_url=os.environ.get(
                "NEOZEN_DATABASE_URL", "sqlite+aiosqlite:///data/neozen.db"
            ),
            secret_key=os.environ.get(
                "NEOZEN_SECRET_KEY", "admin-secret-key-change-me"
            ),
        )

    engine = create_async_engine(config.db_url, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def on_startup() -> None:
        await prepare_schema(engine)
        async with session_factory() as session:
            await AdminService(session).ensure_builtin_roles()
            await session.commit()
        for hook in on_ready:
            await hook(session_factory)

    sessions = session_config(config)

    return Litestar(
        route_handlers=[*ROUTE_HANDLERS, *extra_handlers],
        middleware=[sessions.middleware, AUTH_MIDDLEWARE],
        exception_handlers=EXCEPTION_HANDLERS,
        dependencies=DEPENDENCIES,
        after_request=add_security_headers,
        csrf_config=csrf_config(config),
        on_startup=[on_startup],
        on_shutdown=[engine.dispose],
        stores={"sessions": FileStore(config.session_dir)}
        if config.session_dir
        else {},
        state=State({
            "config": config,
            "session_factory": session_factory,
            "templates": get_templates(config),
            # ponytail: per process; a shared store when running several workers
            "login_limiter": RateLimiter(LOGIN_LIMITS, InMemoryRateLimitStore()),
        }),
    )


__all__ = [
    "AUTH_MIDDLEWARE",
    "DEPENDENCIES",
    "EXCEPTION_HANDLERS",
    "ROUTE_HANDLERS",
    "SECURITY_HEADERS",
    "AdminConfig",
    "add_security_headers",
    "create_admin_app",
    "csrf_config",
    "session_config",
]
