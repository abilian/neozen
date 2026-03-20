"""OAuth providers package."""

from __future__ import annotations

from neozen.core.oauth_client.providers.base import OAuthProvider
from neozen.core.oauth_client.providers.github import GitHubProvider
from neozen.core.oauth_client.providers.google import GoogleProvider

__all__ = [
    "GitHubProvider",
    "GoogleProvider",
    "OAuthProvider",
]
