"""Base OAuth provider class."""

from __future__ import annotations

import base64
import hashlib
import secrets
import typing
import urllib.parse
from dataclasses import dataclass, field

from neozen.core.oauth_client.exceptions import OAuthTokenError, OAuthUserInfoError
from neozen.core.oauth_client.models import (
    OAuthProviderConfig,
    OAuthTokens,
    OAuthUserInfo,
)


@dataclass
class OAuthProvider:
    """Base class for OAuth providers.

    Handles the core OAuth 2.0 flows with PKCE support.
    """

    config: OAuthProviderConfig
    http_client: typing.Any = field(default=None, repr=False)

    def generate_state(self) -> str:
        """Generate a cryptographically secure state parameter."""
        return secrets.token_urlsafe(32)

    def generate_code_verifier(self) -> str:
        """Generate a PKCE code verifier."""
        return secrets.token_urlsafe(64)

    def generate_code_challenge(self, code_verifier: str) -> str:
        """Generate a PKCE code challenge from a verifier."""
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        code_challenge: str | None = None,
    ) -> str:
        """Build the authorization URL.

        Args:
            redirect_uri: The redirect URI after authorization.
            state: The state parameter for CSRF protection.
            code_challenge: The PKCE code challenge (if using PKCE).

        Returns:
            The full authorization URL.

        """
        params: dict[str, str] = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
        }

        if self.config.scopes:
            params["scope"] = " ".join(self.config.scopes)

        if self.config.use_pkce and code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        query_string = urllib.parse.urlencode(params)
        return f"{self.config.authorization_endpoint}?{query_string}"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> OAuthTokens:
        """Exchange an authorization code for tokens.

        Args:
            code: The authorization code.
            redirect_uri: The redirect URI used in authorization.
            code_verifier: The PKCE code verifier (if using PKCE).

        Returns:
            The OAuth tokens.

        Raises:
            OAuthTokenError: If token exchange fails.

        """
        if self.http_client is None:
            msg = "HTTP client is required for token exchange"
            raise OAuthTokenError(msg)

        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }

        if self.config.use_pkce and code_verifier:
            data["code_verifier"] = code_verifier

        try:
            response = await self.http_client.post(
                self.config.token_endpoint,
                data=data,
                headers={"Accept": "application/json"},
            )

            if response.status_code != 200:
                msg = f"Token exchange failed: {response.status_code}"
                raise OAuthTokenError(msg)

            token_data = response.json()
            return OAuthTokens(
                access_token=token_data["access_token"],
                token_type=token_data.get("token_type", "Bearer"),
                refresh_token=token_data.get("refresh_token"),
                expires_in=token_data.get("expires_in"),
                scope=token_data.get("scope"),
                id_token=token_data.get("id_token"),
            )
        except OAuthTokenError:
            raise
        except Exception as e:
            msg = f"Token exchange failed: {e}"
            raise OAuthTokenError(msg) from e

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        """Fetch user information from the provider.

        Args:
            access_token: The OAuth access token.

        Returns:
            The user information.

        Raises:
            OAuthUserInfoError: If fetching user info fails.

        """
        if self.http_client is None:
            msg = "HTTP client is required for user info"
            raise OAuthUserInfoError(msg)

        if not self.config.userinfo_endpoint:
            msg = "User info endpoint not configured"
            raise OAuthUserInfoError(msg)

        try:
            response = await self.http_client.get(
                self.config.userinfo_endpoint,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )

            if response.status_code != 200:
                msg = f"User info request failed: {response.status_code}"
                raise OAuthUserInfoError(msg)

            data = response.json()
            return self._parse_user_info(data)
        except OAuthUserInfoError:
            raise
        except Exception as e:
            msg = f"User info request failed: {e}"
            raise OAuthUserInfoError(msg) from e

    def _parse_user_info(self, data: dict[str, typing.Any]) -> OAuthUserInfo:
        """Parse user info from the provider's response.

        Override this method in subclasses to handle provider-specific formats.

        Args:
            data: The raw response from the provider.

        Returns:
            Parsed user information.

        """
        return OAuthUserInfo(
            provider_id=self.config.provider_id,
            provider_user_id=str(data.get("sub") or data.get("id") or ""),
            email=data.get("email"),
            email_verified=data.get("email_verified", False),
            display_name=data.get("name"),
            avatar_url=data.get("picture"),
            raw_data=data,
        )


__all__ = ["OAuthProvider"]
