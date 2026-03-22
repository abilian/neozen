"""Unit tests for OAuth provider registry."""

from __future__ import annotations

import pytest

from neozen.core.oauth_client import (
    OAuthProviderConfig,
    OAuthProviderRegistry,
    ProviderAlreadyRegisteredError,
    ProviderNotFoundError,
)
from neozen.core.oauth_client.providers.base import OAuthProvider


class MockHttpClient:
    """Mock HTTP client for testing."""

    async def get(self, url: str, **kwargs):
        return {"status": 200}

    async def post(self, url: str, **kwargs):
        return {"status": 200}


def create_test_config(
    provider_id: str = "test",
    display_name: str = "Test Provider",
) -> OAuthProviderConfig:
    """Create a test OAuth provider config."""
    return OAuthProviderConfig(
        provider_id=provider_id,
        client_id="test_client_id",
        client_secret="test_client_secret",
        authorization_endpoint="https://example.com/oauth/authorize",
        token_endpoint="https://example.com/oauth/token",
        display_name=display_name,
        userinfo_endpoint="https://example.com/oauth/userinfo",
        scopes=["openid", "profile", "email"],
    )


def create_test_provider(
    provider_id: str = "test",
    display_name: str = "Test Provider",
    http_client=None,
) -> OAuthProvider:
    """Create a test OAuth provider."""
    config = create_test_config(provider_id, display_name)
    return OAuthProvider(config=config, http_client=http_client)


class TestOAuthProviderRegistry:
    """Tests for OAuthProviderRegistry."""

    def test_register_provider(self) -> None:
        registry = OAuthProviderRegistry()
        provider = create_test_provider("google")

        registry.register(provider)

        assert registry.has("google")
        assert registry.provider_count == 1

    def test_register_duplicate(self) -> None:
        registry = OAuthProviderRegistry()
        provider1 = create_test_provider("google")
        provider2 = create_test_provider("google")

        registry.register(provider1)

        with pytest.raises(ProviderAlreadyRegisteredError) as exc_info:
            registry.register(provider2)

        assert exc_info.value.provider_id == "google"

    def test_register_replace(self) -> None:
        registry = OAuthProviderRegistry()
        provider1 = create_test_provider("google", display_name="First")
        provider2 = create_test_provider("google", display_name="Second")

        registry.register(provider1)
        registry.register(provider2, replace=True)

        assert registry.get("google").config.display_name == "Second"

    def test_register_config(self) -> None:
        registry = OAuthProviderRegistry()
        config = create_test_config("github")

        registry.register_config(config)

        assert registry.has("github")
        assert registry.get("github").config.provider_id == "github"

    def test_register_disabled(self) -> None:
        registry = OAuthProviderRegistry()
        provider = create_test_provider("google")

        registry.register(provider, enabled=False)

        assert registry.has("google")
        assert not registry.is_enabled("google")
        assert registry.enabled_count == 0

    def test_unregister(self) -> None:
        registry = OAuthProviderRegistry()
        provider = create_test_provider("google")

        registry.register(provider)
        assert registry.has("google")

        registry.unregister("google")
        assert not registry.has("google")

    def test_unregister_nonexistent(self) -> None:
        registry = OAuthProviderRegistry()

        # Should not raise
        registry.unregister("nonexistent")

    def test_get(self) -> None:
        registry = OAuthProviderRegistry()
        provider = create_test_provider("google")

        registry.register(provider)

        result = registry.get("google")
        assert result is provider

    def test_get_not_found(self) -> None:
        registry = OAuthProviderRegistry()

        with pytest.raises(ProviderNotFoundError) as exc_info:
            registry.get("nonexistent")

        assert exc_info.value.provider_id == "nonexistent"

    def test_get_or_none(self) -> None:
        registry = OAuthProviderRegistry()
        provider = create_test_provider("google")

        assert registry.get_or_none("google") is None

        registry.register(provider)

        assert registry.get_or_none("google") is provider

    def test_get_config(self) -> None:
        registry = OAuthProviderRegistry()
        provider = create_test_provider("google")

        registry.register(provider)

        config = registry.get_config("google")
        assert config.provider_id == "google"

    def test_get_config_not_found(self) -> None:
        registry = OAuthProviderRegistry()

        with pytest.raises(ProviderNotFoundError):
            registry.get_config("nonexistent")

    def test_has(self) -> None:
        registry = OAuthProviderRegistry()
        provider = create_test_provider("google")

        assert registry.has("google") is False

        registry.register(provider)

        assert registry.has("google") is True

    def test_is_enabled(self) -> None:
        registry = OAuthProviderRegistry()
        provider = create_test_provider("google")

        registry.register(provider, enabled=True)

        assert registry.is_enabled("google") is True

    def test_is_enabled_disabled_provider(self) -> None:
        registry = OAuthProviderRegistry()
        provider = create_test_provider("google")

        registry.register(provider, enabled=False)

        assert registry.is_enabled("google") is False

    def test_is_enabled_nonexistent(self) -> None:
        registry = OAuthProviderRegistry()

        assert registry.is_enabled("nonexistent") is False

    def test_enable(self) -> None:
        registry = OAuthProviderRegistry()
        provider = create_test_provider("google")

        registry.register(provider, enabled=False)
        assert not registry.is_enabled("google")

        registry.enable("google")
        assert registry.is_enabled("google")

    def test_enable_not_found(self) -> None:
        registry = OAuthProviderRegistry()

        with pytest.raises(ProviderNotFoundError):
            registry.enable("nonexistent")

    def test_disable(self) -> None:
        registry = OAuthProviderRegistry()
        provider = create_test_provider("google")

        registry.register(provider, enabled=True)
        assert registry.is_enabled("google")

        registry.disable("google")
        assert not registry.is_enabled("google")

    def test_disable_nonexistent(self) -> None:
        registry = OAuthProviderRegistry()

        # Should not raise
        registry.disable("nonexistent")

    def test_list_all(self) -> None:
        registry = OAuthProviderRegistry()
        google = create_test_provider("google")
        github = create_test_provider("github")

        registry.register(google)
        registry.register(github)

        providers = registry.list_all()

        assert len(providers) == 2
        assert google in providers
        assert github in providers

    def test_list_enabled(self) -> None:
        registry = OAuthProviderRegistry()
        google = create_test_provider("google")
        github = create_test_provider("github")

        registry.register(google, enabled=True)
        registry.register(github, enabled=False)

        enabled = registry.list_enabled()

        assert len(enabled) == 1
        assert google in enabled
        assert github not in enabled

    def test_list_enabled_ids(self) -> None:
        registry = OAuthProviderRegistry()
        google = create_test_provider("google")
        github = create_test_provider("github")

        registry.register(google, enabled=True)
        registry.register(github, enabled=False)

        ids = registry.list_enabled_ids()

        assert ids == ["google"]

    def test_clear(self) -> None:
        registry = OAuthProviderRegistry()
        registry.register(create_test_provider("google"))
        registry.register(create_test_provider("github"))

        assert registry.provider_count == 2

        registry.clear()

        assert registry.provider_count == 0
        assert registry.enabled_count == 0

    def test_provider_ids(self) -> None:
        registry = OAuthProviderRegistry()
        registry.register(create_test_provider("google"))
        registry.register(create_test_provider("github"))

        ids = registry.provider_ids

        assert "google" in ids
        assert "github" in ids

    def test_provider_count(self) -> None:
        registry = OAuthProviderRegistry()

        assert registry.provider_count == 0

        registry.register(create_test_provider("google"))
        assert registry.provider_count == 1

        registry.register(create_test_provider("github"))
        assert registry.provider_count == 2

    def test_enabled_count(self) -> None:
        registry = OAuthProviderRegistry()

        assert registry.enabled_count == 0

        registry.register(create_test_provider("google"), enabled=True)
        assert registry.enabled_count == 1

        registry.register(create_test_provider("github"), enabled=False)
        assert registry.enabled_count == 1

    def test_get_provider_info(self) -> None:
        registry = OAuthProviderRegistry()
        registry.register(
            create_test_provider("google", display_name="Google"),
            enabled=True,
        )
        registry.register(
            create_test_provider("github", display_name="GitHub"),
            enabled=False,
        )

        info = registry.get_provider_info()

        assert len(info) == 2

        google_info = next(i for i in info if i["provider_id"] == "google")
        assert google_info["display_name"] == "Google"
        assert google_info["enabled"] is True

        github_info = next(i for i in info if i["provider_id"] == "github")
        assert github_info["display_name"] == "GitHub"
        assert github_info["enabled"] is False

    def test_set_http_client(self) -> None:
        registry = OAuthProviderRegistry()
        google = create_test_provider("google")
        github = create_test_provider("github")

        registry.register(google)
        registry.register(github)

        http_client = MockHttpClient()
        registry.set_http_client(http_client)

        assert google.http_client is http_client
        assert github.http_client is http_client

    def test_init_with_http_client(self) -> None:
        http_client = MockHttpClient()
        registry = OAuthProviderRegistry(http_client=http_client)

        config = create_test_config("google")
        registry.register_config(config)

        provider = registry.get("google")
        assert provider.http_client is http_client
