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

from litestar import Litestar
from litestar.datastructures import State
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from neozen.admin import app as admin_app_module
from neozen.admin.config import AdminConfig
from neozen.admin.services import AdminService
from neozen.serve.bootstrap import bootstrap_admin_if_needed, format_bootstrap_notice
from neozen.serve.config import ServeConfig
from neozen.serve.healthcheck import healthz, readyz
from neozen.storage.sqlalchemy.base import Base


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
        cookie_secure=config.cookie_secure,
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

    sessions = admin_app_module.session_config(admin_config)

    return Litestar(
        route_handlers=[
            *admin_app_module.ROUTE_HANDLERS,
            healthz,
            readyz,
        ],
        middleware=[sessions.middleware, admin_app_module.AUTH_MIDDLEWARE],
        exception_handlers=admin_app_module.EXCEPTION_HANDLERS,
        after_request=admin_app_module.add_security_headers,
        csrf_config=admin_app_module.csrf_config(admin_config),
        on_startup=[on_startup],
        state=State({
            "config": admin_config,
            "session_factory": session_factory,
            "templates": templates,
        }),
    )
