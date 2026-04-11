"""Litestar application builder for `neozen serve`.

Builds a unified Litestar app that exposes:

- The admin console (all routes from `neozen.admin.app`)
- `/healthz` and `/readyz` health endpoints

Future composition (deferred to a follow-up): the OIDC provider
endpoints (`/.well-known/openid-configuration`, `/.well-known/jwks.json`,
`/oauth/*`, `/userinfo`) and the SCIM endpoints (`/scim/v2/*`) will mount
under the same Litestar instance once the framework adapter glue exists.

The serve app shares a single `async_sessionmaker` across all routes
via `app.state.session_factory`. The admin route handlers already
read from there, so they work unchanged when imported here.
"""

from __future__ import annotations

import sys
from typing import Any

from litestar import Litestar
from litestar.datastructures import State
from litestar.middleware.session.server_side import ServerSideSessionConfig
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from neozen.admin import app as admin_app_module
from neozen.admin.config import AdminConfig
from neozen.admin.services import AdminService
from neozen.serve.bootstrap import bootstrap_admin_if_needed, format_bootstrap_notice
from neozen.serve.config import ServeConfig
from neozen.serve.healthcheck import healthz, readyz
from neozen.storage.sqlalchemy.base import Base


# Route handlers exported by the admin app. We import them by reference
# rather than re-declaring so the serve app stays in lock-step with any
# new admin route added in the future. The list mirrors the one in
# `neozen.admin.app.create_admin_app`.
def _admin_route_handlers() -> list[Any]:
    m = admin_app_module
    return [
        # Authentication
        m.login_page,
        m.login,
        m.logout,
        # Dashboard
        m.dashboard,
        m.dashboard_stats,
        # Users
        m.list_users,
        m.create_user_form,
        m.create_user,
        m.import_users_form,
        m.import_users,
        m.export_users,
        m.user_detail,
        m.activate_user,
        m.deactivate_user,
        m.delete_user,
        m.revoke_user_sessions,
        m.add_user_role,
        m.remove_user_role,
        m.impersonate_user,
        m.end_impersonation,
        m.list_subjects,
        # Roles
        m.list_roles,
        m.create_role_form,
        m.create_role,
        m.role_detail,
        m.delete_role,
        # Sessions
        m.list_sessions,
        m.revoke_session,
        # Groups
        m.list_groups,
        m.create_group_form,
        m.create_group,
        m.group_detail,
        m.add_group_member,
        m.remove_group_member,
        m.add_group_role,
        m.remove_group_role,
        m.delete_group,
        # Organizations
        m.list_organizations,
        m.create_organization_form,
        m.create_organization,
        m.organization_detail,
        m.update_organization,
        m.delete_organization,
        # Permissions & RBAC Visual Editor
        m.permission_matrix,
        m.toggle_permission,
        m.role_builder_form,
        m.create_custom_role,
        m.access_analyzer,
        # Audit
        m.list_audit_logs,
        m.audit_log_tail,
        m.audit_log_detail,
        # Security
        m.security_dashboard,
        m.security_stats,
        m.security_policies,
        # Settings
        m.settings,
        m.identity_providers,
        m.social_providers,
        m.api_keys,
        m.webhooks,
        m.oauth_clients,
        m.branding,
        m.email_templates,
        m.system_health,
    ]


def build_serve_app(config: ServeConfig | None = None) -> Litestar:
    """Build the unified `neozen serve` Litestar application.

    Args:
        config: Runtime config. If None, loaded from the environment.

    Returns:
        A Litestar instance ready to be served by uvicorn (or any
        ASGI server).
    """
    if config is None:
        config = ServeConfig.from_env()

    # Surface validation warnings to stderr so operators see them
    # at startup without crashing the server.
    for warning in config.validate():
        print(f"[neozen serve] WARNING: {warning}", file=sys.stderr)

    engine = create_async_engine(config.db_url, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    # Reuse the admin templates environment unchanged.
    admin_config = AdminConfig(
        db_url=config.db_url,
        secret_key=config.secret_key,
    )
    templates = admin_app_module.get_templates(admin_config)

    async def on_startup() -> None:
        """Initialize schema, ensure built-in roles, optionally bootstrap."""
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with session_factory() as session:
            service = AdminService(session)
            await service.ensure_builtin_roles()
            await session.commit()

        if config.bootstrap_admin:
            result = await bootstrap_admin_if_needed(
                session_factory,
                admin_email=config.bootstrap_admin_email,
            )
            notice = format_bootstrap_notice(result)
            if notice:
                # Print directly to stdout so the marker is grep-able
                # in container logs.
                print(notice)

    session_config = ServerSideSessionConfig(
        key="neozen_admin_session",
        max_age=86400,
    )

    return Litestar(
        route_handlers=[
            *_admin_route_handlers(),
            healthz,
            readyz,
        ],
        middleware=[session_config.middleware],
        on_startup=[on_startup],
        state=State({
            "config": admin_config,
            "session_factory": session_factory,
            "templates": templates,
        }),
    )
