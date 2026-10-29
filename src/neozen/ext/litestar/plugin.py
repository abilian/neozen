"""Plugin for NeoZen Litestar extension."""

from __future__ import annotations

import typing
from functools import partial

from litestar import Request, Response
from litestar.config.app import AppConfig
from litestar.plugins import InitPluginProtocol
from litestar.response import Redirect

if typing.TYPE_CHECKING:
    from litestar.types import ExceptionHandler

from neozen.web.auth.responses import forbidden_body, unauthorized_body

from .config import NeoZenConfig
from .guards import AuthenticationRequiredError, PermissionDeniedError
from .middleware import NeoZenMiddleware


def redirect_to_login(
    _: Request, exc: AuthenticationRequiredError
) -> Response[dict[str, str]] | Redirect:
    """Send a guard's unauthenticated visitor to the login page.

    Guards with ``redirect=False`` (APIs) still get a 401.
    """
    if exc.redirect_to:
        return Redirect(path=exc.redirect_to)
    return Response(unauthorized_body(), status_code=401)


def permission_denied(
    _: Request, exc: PermissionDeniedError
) -> Response[dict[str, str]]:
    """A guard's 403, with the body every adapter sends."""
    return Response(forbidden_body(exc.detail), status_code=403)


class NeoZenPlugin(InitPluginProtocol):
    """Litestar plugin for NeoZen authentication.

    This plugin configures the NeoZen middleware and makes the config
    available throughout the application.

    Example:
        async def load_subject(subject_id: str) -> Subject | None:
            return await user_repo.get(subject_id)

        config = NeoZenConfig(
            session_service=session_service,
            subject_loader=load_subject,
        )

        app = Litestar(
            route_handlers=[...],
            plugins=[NeoZenPlugin(config)],
        )
    """

    __slots__ = ("config",)

    def __init__(self, config: NeoZenConfig) -> None:
        """Initialize plugin with configuration.

        Args:
            config: NeoZen configuration
        """
        self.config = config

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        """Configure application on initialization.

        This adds the NeoZen middleware to the application.

        Args:
            app_config: The application configuration

        Returns:
            Modified application configuration
        """
        # Create middleware factory that includes our config
        middleware_factory = partial(NeoZenMiddleware, config=self.config)

        app_config.middleware.insert(0, middleware_factory)

        # The app's own handler, if it has one, wins.
        # (Litestar types handlers as taking any Exception.)
        app_config.exception_handlers.setdefault(
            AuthenticationRequiredError,
            typing.cast("ExceptionHandler", redirect_to_login),
        )
        app_config.exception_handlers.setdefault(
            PermissionDeniedError, typing.cast("ExceptionHandler", permission_denied)
        )

        return app_config


__all__ = ["NeoZenPlugin"]
