"""OAuth client module for social login support.

This module provides OAuth 2.0 client functionality for social login
with providers like Google and GitHub.
"""

from __future__ import annotations

from neozen.core.oauth_client.exceptions import (
    OAuthCallbackError,
    OAuthClientError,
    OAuthProviderNotFoundError,
    OAuthStateError,
    OAuthTokenError,
    OAuthUserInfoError,
    SocialAccountNotFoundError,
)
from neozen.core.oauth_client.models import (
    AuthorizationResult,
    CallbackResult,
    OAuthProviderConfig,
    OAuthStateModel,
    OAuthStateRepositoryProtocol,
    OAuthTokens,
    OAuthUserInfo,
    SocialAccountModel,
    SocialAccountRepositoryProtocol,
)
from neozen.core.oauth_client.providers import (
    GitHubProvider,
    GoogleProvider,
    OAuthProvider,
)
from neozen.core.oauth_client.providers.github import create_github_config
from neozen.core.oauth_client.providers.google import create_google_config
from neozen.core.oauth_client.registry import (
    OAuthProviderRegistry,
    ProviderAlreadyRegisteredError,
    ProviderNotFoundError,
)
from neozen.core.oauth_client.service import OAuthClientService

__all__ = [
    # Exceptions
    "OAuthCallbackError",
    "OAuthClientError",
    "OAuthProviderNotFoundError",
    "OAuthStateError",
    "OAuthTokenError",
    "OAuthUserInfoError",
    "ProviderAlreadyRegisteredError",
    "ProviderNotFoundError",
    "SocialAccountNotFoundError",
    # Models
    "AuthorizationResult",
    "CallbackResult",
    "OAuthProviderConfig",
    "OAuthStateModel",
    "OAuthStateRepositoryProtocol",
    "OAuthTokens",
    "OAuthUserInfo",
    "SocialAccountModel",
    "SocialAccountRepositoryProtocol",
    # Providers
    "GitHubProvider",
    "GoogleProvider",
    "OAuthProvider",
    "create_github_config",
    "create_google_config",
    # Registry
    "OAuthProviderRegistry",
    # Service
    "OAuthClientService",
]
