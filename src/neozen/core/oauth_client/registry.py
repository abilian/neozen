"""OAuth provider registry for managing OAuth providers."""

from __future__ import annotations

import logging
from typing import Any

from .models import OAuthProviderConfig
from .providers.base import OAuthProvider

logger = logging.getLogger(__name__)


class ProviderNotFoundError(Exception):
    """Raised when a requested provider is not found in the registry."""

    def __init__(self, provider_id: str) -> None:
        super().__init__(f"OAuth provider not found: {provider_id}")
        self.provider_id = provider_id


class ProviderAlreadyRegisteredError(Exception):
    """Raised when trying to register a provider that already exists."""

    def __init__(self, provider_id: str) -> None:
        super().__init__(f"OAuth provider already registered: {provider_id}")
        self.provider_id = provider_id


class OAuthProviderRegistry:
    """Registry for OAuth providers.

    The provider registry manages available OAuth providers for social login.

    Example:
        from neozen.core.oauth_client.providers.google import create_google_config
        from neozen.core.oauth_client.providers.github import create_github_config

        registry = OAuthProviderRegistry()

        # Register providers
        registry.register_config(create_google_config(
            client_id="...",
            client_secret="...",
        ))
        registry.register_config(create_github_config(
            client_id="...",
            client_secret="...",
        ))

        # List enabled providers
        providers = registry.list_enabled()

        # Get specific provider
        google = registry.get("google")
    """

    def __init__(self, http_client: Any = None) -> None:
        """Initialize the registry.

        Args:
            http_client: HTTP client for making OAuth requests.
                Should support async get/post methods (e.g., httpx.AsyncClient).
        """
        self._providers: dict[str, OAuthProvider] = {}
        self._configs: dict[str, OAuthProviderConfig] = {}
        self._enabled: set[str] = set()
        self._http_client = http_client

    def register(
        self,
        provider: OAuthProvider,
        *,
        enabled: bool = True,
        replace: bool = False,
    ) -> None:
        """Register an OAuth provider instance.

        Args:
            provider: The provider instance to register.
            enabled: Whether the provider is enabled.
            replace: If True, replace existing provider.

        Raises:
            ProviderAlreadyRegisteredError: If provider exists and replace=False.
        """
        provider_id = provider.config.provider_id

        if provider_id in self._providers and not replace:
            raise ProviderAlreadyRegisteredError(provider_id)

        self._providers[provider_id] = provider
        self._configs[provider_id] = provider.config

        if enabled:
            self._enabled.add(provider_id)
        else:
            self._enabled.discard(provider_id)

        logger.debug("Registered OAuth provider: %s", provider_id)

    def register_config(
        self,
        config: OAuthProviderConfig,
        *,
        provider_class: type[OAuthProvider] = OAuthProvider,
        enabled: bool = True,
        replace: bool = False,
    ) -> None:
        """Register a provider from its configuration.

        Args:
            config: The provider configuration.
            provider_class: The provider class to instantiate.
            enabled: Whether the provider is enabled.
            replace: If True, replace existing provider.

        Raises:
            ProviderAlreadyRegisteredError: If provider exists and replace=False.
        """
        provider = provider_class(config=config, http_client=self._http_client)
        self.register(provider, enabled=enabled, replace=replace)

    def unregister(self, provider_id: str) -> None:
        """Remove a provider from the registry.

        Args:
            provider_id: ID of the provider to remove.
        """
        if provider_id in self._providers:
            del self._providers[provider_id]
            del self._configs[provider_id]
            self._enabled.discard(provider_id)
            logger.debug("Unregistered OAuth provider: %s", provider_id)

    def get(self, provider_id: str) -> OAuthProvider:
        """Get a provider by ID.

        Args:
            provider_id: The provider ID to look up.

        Returns:
            The registered provider.

        Raises:
            ProviderNotFoundError: If provider is not registered.
        """
        if provider_id not in self._providers:
            raise ProviderNotFoundError(provider_id)
        return self._providers[provider_id]

    def get_or_none(self, provider_id: str) -> OAuthProvider | None:
        """Get a provider by ID, or None if not found.

        Args:
            provider_id: The provider ID to look up.

        Returns:
            The registered provider, or None.
        """
        return self._providers.get(provider_id)

    def get_config(self, provider_id: str) -> OAuthProviderConfig:
        """Get a provider's configuration.

        Args:
            provider_id: The provider ID to look up.

        Returns:
            The provider configuration.

        Raises:
            ProviderNotFoundError: If provider is not registered.
        """
        if provider_id not in self._configs:
            raise ProviderNotFoundError(provider_id)
        return self._configs[provider_id]

    def has(self, provider_id: str) -> bool:
        """Check if a provider is registered.

        Args:
            provider_id: The provider ID to check.

        Returns:
            True if the provider is registered.
        """
        return provider_id in self._providers

    def is_enabled(self, provider_id: str) -> bool:
        """Check if a provider is enabled.

        Args:
            provider_id: The provider ID to check.

        Returns:
            True if the provider is registered and enabled.
        """
        return provider_id in self._enabled

    def enable(self, provider_id: str) -> None:
        """Enable a registered provider.

        Args:
            provider_id: The provider ID to enable.

        Raises:
            ProviderNotFoundError: If provider is not registered.
        """
        if provider_id not in self._providers:
            raise ProviderNotFoundError(provider_id)
        self._enabled.add(provider_id)

    def disable(self, provider_id: str) -> None:
        """Disable a registered provider.

        Args:
            provider_id: The provider ID to disable.
        """
        self._enabled.discard(provider_id)

    def list_all(self) -> list[OAuthProvider]:
        """List all registered providers.

        Returns:
            List of all registered providers.
        """
        return list(self._providers.values())

    def list_enabled(self) -> list[OAuthProvider]:
        """List all enabled providers.

        Returns:
            List of enabled providers.
        """
        return [self._providers[pid] for pid in self._enabled if pid in self._providers]

    def list_enabled_ids(self) -> list[str]:
        """List IDs of enabled providers.

        Returns:
            List of enabled provider IDs.
        """
        return [pid for pid in self._enabled if pid in self._providers]

    def clear(self) -> None:
        """Remove all registered providers."""
        self._providers.clear()
        self._configs.clear()
        self._enabled.clear()

    def set_http_client(self, http_client: Any) -> None:
        """Set the HTTP client for all providers.

        Args:
            http_client: HTTP client for making OAuth requests.
        """
        self._http_client = http_client
        for provider in self._providers.values():
            provider.http_client = http_client

    @property
    def provider_count(self) -> int:
        """Number of registered providers."""
        return len(self._providers)

    @property
    def enabled_count(self) -> int:
        """Number of enabled providers."""
        return len(self._enabled)

    @property
    def provider_ids(self) -> list[str]:
        """List of registered provider IDs."""
        return list(self._providers.keys())

    def get_provider_info(self) -> list[dict[str, Any]]:
        """Get summary information about all providers.

        Returns:
            List of provider info dicts.
        """
        return [
            {
                "provider_id": config.provider_id,
                "display_name": config.display_name,
                "enabled": config.provider_id in self._enabled,
            }
            for config in self._configs.values()
        ]
