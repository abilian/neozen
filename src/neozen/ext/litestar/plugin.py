"""Plugin for NeoZen Litestar extension."""

from __future__ import annotations

from functools import partial

from litestar.config.app import AppConfig
from litestar.plugins import InitPluginProtocol

from .config import NeoZenConfig
from .middleware import NeoZenMiddleware


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
            app_config.middleware = []  # type: ignore[assignment]

        app_config.middleware.insert(0, middleware_factory)

        return app_config


__all__ = ["NeoZenPlugin"]
