"""Litestar application builder for `neozen serve`.

Builds a unified Litestar app that exposes:

- The admin console (all routes from `neozen.admin.app`)
- `/healthz` and `/readyz` health endpoints

Future composition (deferred to a follow-up): the OIDC provider
endpoints (`/.well-known/openid-configuration`, `/.well-known/jwks.json`,
`/oauth/*`, `/userinfo`) and the SCIM endpoints (`/scim/v2/*`) will mount
under the same Litestar instance once the framework adapter glue exists.

It is the admin console's app (`create_admin_app`), with the health
routes added and the first-run admin bootstrap at startup.
"""

from __future__ import annotations

import logging
from pathlib import Path

from litestar import Litestar
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from neozen.admin.app import create_admin_app
from neozen.admin.config import AdminConfig
from neozen.serve.bootstrap import bootstrap_admin_if_needed, format_bootstrap_notice
from neozen.serve.config import ServeConfig
from neozen.serve.healthcheck import healthz, readyz

logger = logging.getLogger(__name__)


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

    # Operators see configuration problems at startup; they are not fatal.
    for warning in config.validate():
        logger.warning(warning)

    admin_config = AdminConfig(
        db_url=config.db_url,
        secret_key=config.secret_key,
        cookie_secure=config.cookie_secure,
        session_dir=Path(config.session_dir),
    )

    async def bootstrap(session_factory: async_sessionmaker[AsyncSession]) -> None:
        """Create the first admin, if asked to and there is none yet."""
        result = await bootstrap_admin_if_needed(
            session_factory, admin_email=config.bootstrap_admin_email
        )
        notice = format_bootstrap_notice(result)
        if notice:
            # Printed, not logged: operators grep container logs for it.
            print(notice)

    return create_admin_app(
        admin_config,
        extra_handlers=[healthz, readyz],
        on_ready=[bootstrap] if config.bootstrap_admin else [],
    )
