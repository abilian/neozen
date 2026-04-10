"""UserInfo endpoint (OIDC Core 1.0 Section 5.3).

Returns claims about the authenticated subject. Requires a valid
access token with the `openid` scope.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from neozen.core.oidc.claims import filter_claims_by_scopes

if TYPE_CHECKING:
    from neozen.core.oauth.models import (
        OAuthAccessTokenModel,
        OAuthClientModel,
        OAuthRefreshTokenModel,
    )
    from neozen.core.oauth.services import OAuthTokenService
    from neozen.core.oidc.claims import ClaimsProvider


class UserInfoError(Exception):
    """Raised when the UserInfo endpoint cannot serve a request.

    Attributes:
        status_code: HTTP status code (401 or 403).
        error: OAuth error code (`invalid_token`, `insufficient_scope`).
        description: Human-readable description.
    """

    def __init__(
        self,
        error: str,
        description: str,
        status_code: int,
    ) -> None:
        self.error = error
        self.description = description
        self.status_code = status_code
        super().__init__(description)

    def to_response(self) -> tuple[dict[str, Any], int, dict[str, str]]:
        """Build the response body, status code, and WWW-Authenticate header."""
        body = {"error": self.error, "error_description": self.description}
        header = {
            "WWW-Authenticate": (
                f'Bearer error="{self.error}", error_description="{self.description}"'
            )
        }
        return body, self.status_code, header


class UserInfoEndpoint:
    """HTTP adapter for the OIDC UserInfo endpoint.

    Validates the bearer access token, checks for `openid` scope,
    looks up the subject's claims, filters them by the token's scopes,
    and returns them as JSON.

    Example:
        endpoint = UserInfoEndpoint(
            token_service=token_service,
            claims_provider=claims_provider,
        )

        try:
            claims = await endpoint(authorization_header)
            # Return claims as 200 OK JSON
        except UserInfoError as e:
            body, status, headers = e.to_response()
            # Return error response
    """

    def __init__(
        self,
        token_service: OAuthTokenService[
            OAuthClientModel,
            Any,
            OAuthAccessTokenModel,
            OAuthRefreshTokenModel,
        ],
        claims_provider: ClaimsProvider,
    ) -> None:
        self.token_service = token_service
        self.claims_provider = claims_provider

    async def __call__(self, authorization: str | None) -> dict[str, Any]:
        """Process a UserInfo request.

        Args:
            authorization: The Authorization header value (e.g., "Bearer abc123").

        Returns:
            The user's claims as a dict, filtered by the token's scopes.

        Raises:
            UserInfoError: If the token is invalid, expired, or lacks
                the openid scope.
        """
        token = self._extract_bearer_token(authorization)

        # Validate the access token via introspection
        introspection = await self.token_service.introspect_access_token(token)
        if introspection is None or not introspection.get("active"):
            raise UserInfoError(
                error="invalid_token",
                description="Access token is invalid or expired.",
                status_code=401,
            )

        # Check that openid scope was granted
        raw_scope = introspection.get("scope")
        scope_str = str(raw_scope) if raw_scope else ""
        scopes: list[str] = list(scope_str.split())
        if "openid" not in scopes:
            raise UserInfoError(
                error="insufficient_scope",
                description="Access token does not have the openid scope.",
                status_code=403,
            )

        subject_id = introspection.get("sub")
        if not subject_id:
            raise UserInfoError(
                error="invalid_token",
                description="Access token is missing subject identifier.",
                status_code=401,
            )

        # Look up claims
        subject_claims = await self.claims_provider.get_claims(subject_id, scopes)
        if subject_claims is None:
            raise UserInfoError(
                error="invalid_token",
                description="Subject not found.",
                status_code=401,
            )

        # Convert and filter by scopes
        all_claims = subject_claims.to_dict()
        return filter_claims_by_scopes(all_claims, scopes)

    def _extract_bearer_token(self, authorization: str | None) -> str:
        """Extract the bearer token from the Authorization header."""
        if not authorization:
            raise UserInfoError(
                error="invalid_token",
                description="Missing Authorization header.",
                status_code=401,
            )

        parts = authorization.split(maxsplit=1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise UserInfoError(
                error="invalid_token",
                description="Authorization header must use Bearer scheme.",
                status_code=401,
            )

        return parts[1]


__all__ = [
    "UserInfoEndpoint",
    "UserInfoError",
]
