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

from .config import NeoZenConfig
from .guards import AuthenticationRequiredError
from .middleware import NeoZenMiddleware


def redirect_to_login(
    _: Request, exc: AuthenticationRequiredError
) -> Response[dict[str, object]] | Redirect:
    """Send a guard's unauthenticated visitor to the login page.

    Guards with ``redirect=False`` (APIs) still get a 401.
    """
    if exc.redirect_to:
        return Redirect(path=exc.redirect_to)
    return Response({"status_code": 401, "detail": exc.detail}, status_code=401)


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

        # Add our middleware to the list
        if app_config.middleware is None:
            # pyrefly: ignore [bad-assignment]
            app_config.middleware = []

        app_config.middleware.insert(0, middleware_factory)

        # The app's own handler, if it has one, wins.
        # (Litestar types handlers as taking any Exception.)
        app_config.exception_handlers.setdefault(
            AuthenticationRequiredError,
            typing.cast("ExceptionHandler", redirect_to_login),
        )

        return app_config


__all__ = ["NeoZenPlugin"]
