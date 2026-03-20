"""Google OAuth provider."""

from __future__ import annotations

import typing
from dataclasses import dataclass

from neozen.core.oauth_client.models import OAuthProviderConfig, OAuthUserInfo
from neozen.core.oauth_client.providers.base import OAuthProvider


def create_google_config(
    client_id: str,
    client_secret: str,
    scopes: list[str] | None = None,
) -> OAuthProviderConfig:
    """Create a Google OAuth provider configuration.

    Args:
        client_id: Google OAuth client ID.
        client_secret: Google OAuth client secret.
        scopes: Optional list of scopes (defaults to openid, email, profile).

    Returns:
        The provider configuration.

    """
    if scopes is None:
        scopes = ["openid", "email", "profile"]

    return OAuthProviderConfig(
        provider_id="google",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint="https://oauth2.googleapis.com/token",
        userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
        scopes=scopes,
        use_pkce=True,
    )


@dataclass
class GoogleProvider(OAuthProvider):
    """Google OAuth provider.

    Supports OpenID Connect for authentication.
    """

    def _parse_user_info(self, data: dict[str, typing.Any]) -> OAuthUserInfo:
        """Parse Google user info response."""
        return OAuthUserInfo(
            provider_id="google",
            provider_user_id=data.get("sub", ""),
            email=data.get("email"),
            email_verified=data.get("email_verified", False),
            display_name=data.get("name"),
            avatar_url=data.get("picture"),
            raw_data=data,
        )


__all__ = ["GoogleProvider", "create_google_config"]
