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


def _transport_errors() -> tuple[type[Exception], ...]:
    """What the HTTP client raises when the provider can't be reached."""
    import httpx  # noqa: PLC0415  # ken: optional dependency (oauth-client extra)

    return (httpx.HTTPError,)


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

    def _http(self) -> typing.Any:
        """The HTTP client (an ``httpx.AsyncClient``), set by the registry."""
        if self.http_client is None:
            msg = f"OAuth provider {self.config.provider_id!r} has no HTTP client"
            raise RuntimeError(msg)
        return self.http_client

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

        Raises:
            OAuthTokenError: If token exchange fails.
        """
        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        if self.config.use_pkce and code_verifier:
            data["code_verifier"] = code_verifier
        return await self._token_request(data, "Token exchange failed")

    async def refresh_access_token(self, refresh_token: str) -> OAuthTokens:
        """Refresh an access token using a refresh token.

        Args:
            refresh_token: The refresh token from the original grant.

        Returns:
            New OAuth tokens; the refresh token is kept unless rotated.

        Raises:
            OAuthTokenError: If the refresh fails.
        """
        data: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        return await self._token_request(
            data, "Token refresh failed", refresh_token=refresh_token
        )

    async def _token_request(
        self, data: dict[str, str], failure: str, *, refresh_token: str | None = None
    ) -> OAuthTokens:
        """POST to the token endpoint; ``refresh_token`` is the fallback."""
        try:
            response = await self._http().post(
                self.config.token_endpoint,
                data=data,
                headers={"Accept": "application/json"},
            )
        except _transport_errors() as e:
            msg = f"{failure}: {e}"
            raise OAuthTokenError(msg) from e
        if response.status_code != 200:
            msg = f"{failure}: {response.status_code}"
            raise OAuthTokenError(msg)
        try:
            token_data = response.json()
            return OAuthTokens(
                access_token=token_data["access_token"],
                token_type=token_data.get("token_type", "Bearer"),
                refresh_token=token_data.get("refresh_token", refresh_token),
                expires_in=token_data.get("expires_in"),
                scope=token_data.get("scope"),
                id_token=token_data.get("id_token"),
            )
        except (KeyError, ValueError) as e:  # missing field, not JSON
            msg = f"{failure}: bad response ({e})"
            raise OAuthTokenError(msg) from e

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        """Fetch user information from the provider.

        Raises:
            OAuthUserInfoError: If fetching user info fails.
        """
        if not self.config.userinfo_endpoint:
            msg = "User info endpoint not configured"
            raise OAuthUserInfoError(msg)
        data = await self._get_json(self.config.userinfo_endpoint, access_token)
        return self._parse_user_info(data)

    async def _get_json(
        self, url: str, access_token: str, headers: dict[str, str] | None = None
    ) -> typing.Any:
        """GET a provider API with the access token; OAuthUserInfoError if not 200."""
        try:
            response = await self._http().get(
                url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    **(headers or {}),
                },
            )
        except _transport_errors() as e:
            msg = f"User info request failed: {e}"
            raise OAuthUserInfoError(msg) from e
        if response.status_code != 200:
            msg = f"User info request failed: {response.status_code}"
            raise OAuthUserInfoError(msg)
        try:
            return response.json()
        except ValueError as e:
            msg = f"User info request failed: bad response ({e})"
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
