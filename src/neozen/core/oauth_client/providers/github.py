"""GitHub OAuth provider."""

from __future__ import annotations

import typing
from dataclasses import dataclass

from neozen.core.oauth_client.exceptions import OAuthUserInfoError
from neozen.core.oauth_client.models import OAuthProviderConfig, OAuthUserInfo
from neozen.core.oauth_client.providers.base import OAuthProvider


def create_github_config(
    client_id: str,
    client_secret: str,
    scopes: list[str] | None = None,
) -> OAuthProviderConfig:
    """Create a GitHub OAuth provider configuration.

    Args:
        client_id: GitHub OAuth client ID.
        client_secret: GitHub OAuth client secret.
        scopes: Optional list of scopes (defaults to read:user, user:email).

    Returns:
        The provider configuration.

    """
    if scopes is None:
        scopes = ["read:user", "user:email"]

    return OAuthProviderConfig(
        provider_id="github",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://github.com/login/oauth/authorize",
        token_endpoint="https://github.com/login/oauth/access_token",
        userinfo_endpoint="https://api.github.com/user",
        scopes=scopes,
        use_pkce=False,  # GitHub doesn't support PKCE yet
    )


@dataclass
class GitHubProvider(OAuthProvider):
    """GitHub OAuth provider.

    Note: GitHub doesn't support PKCE and requires a separate call
    to get verified email addresses.
    """

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        """Fetch user information from GitHub.

        GitHub requires a separate API call to get email addresses.
        """
        user_data = await self._get_json(
            "https://api.github.com/user", access_token, self._GH_HEADERS
        )
        primary_email, email_verified = await self._fetch_primary_email(access_token)
        return OAuthUserInfo(
            provider_id="github",
            provider_user_id=str(user_data.get("id", "")),
            email=primary_email or user_data.get("email"),
            email_verified=email_verified,
            display_name=user_data.get("name") or user_data.get("login"),
            avatar_url=user_data.get("avatar_url"),
            raw_data=user_data,
        )

    _GH_HEADERS: typing.ClassVar[dict[str, str]] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    async def _fetch_primary_email(self, access_token: str) -> tuple[str | None, bool]:
        """The primary email and whether it is verified, or ``(None, False)``.

        The call fails when the token lacks the ``user:email`` scope: the
        caller then falls back to the profile's public email.
        """
        try:
            emails = await self._get_json(
                "https://api.github.com/user/emails", access_token, self._GH_HEADERS
            )
        except OAuthUserInfoError:
            return None, False
        for email_data in emails:
            if email_data.get("primary"):
                return email_data.get("email"), email_data.get("verified", False)
        return None, False

    def _parse_user_info(self, data: dict[str, typing.Any]) -> OAuthUserInfo:
        """Parse GitHub user info response."""
        return OAuthUserInfo(
            provider_id="github",
            provider_user_id=str(data.get("id", "")),
            email=data.get("email"),
            email_verified=False,  # GitHub doesn't include this in /user
            display_name=data.get("name") or data.get("login"),
            avatar_url=data.get("avatar_url"),
            raw_data=data,
        )


__all__ = ["GitHubProvider", "create_github_config"]
