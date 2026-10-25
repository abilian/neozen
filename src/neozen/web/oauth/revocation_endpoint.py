"""OAuth 2.1 token revocation endpoint (RFC 7009) for NeoZen.

This module provides the HTTP adapter for the OAuth token revocation endpoint.
"""

from __future__ import annotations

import typing

from pydantic import BaseModel, ValidationError

from neozen.core.oauth.client_service import OAuthClientService
from neozen.core.oauth.exceptions import (
    TokenInvalidRequestError,
)
from neozen.core.oauth.models import (
    OAuthAccessTokenModel,
    OAuthClientModel,
    OAuthRefreshTokenModel,
)
from neozen.core.oauth.services import OAuthTokenService
from neozen.web.oauth.utils import authenticate_client


class RevocationRequest(BaseModel):
    """Request model for token revocation."""

    token: str
    token_type_hint: str | None = None


class RevocationEndpoint[
    OC: OAuthClientModel,
    OAT: OAuthAccessTokenModel,
    ORT: OAuthRefreshTokenModel,
]:
    """OAuth 2.1 token revocation endpoint (RFC 7009).

    Allows clients to revoke access or refresh tokens that
    are no longer needed.

    Per RFC 7009, the endpoint always returns 200 OK, even if
    the token was already revoked or doesn't exist.

    Example:
        client_service = OAuthClientService(...)
        token_service = OAuthTokenService(...)
        endpoint = RevocationEndpoint(
            client_service=client_service,
            token_service=token_service,
        )

        # Handle POST request
        await endpoint(
            payload=form_data,
            client_id=client_id,
            client_secret=client_secret,
        )
    """

    def __init__(
        self,
        client_service: OAuthClientService[OC],
        token_service: OAuthTokenService[OC, typing.Any, OAT, ORT],
    ) -> None:
        """Initialize the revocation endpoint.

        Args:
            client_service: Service for client authentication.
            token_service: Service for token operations.
        """
        self.client_service = client_service
        self.token_service = token_service

    async def __call__(
        self,
        payload: dict[str, typing.Any],
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> None:
        """Process a revocation request.

        Args:
            payload: The request payload (form data).
            client_id: Client ID from Basic auth.
            client_secret: Client secret from Basic auth.

        Returns:
            None. Per RFC 7009, always returns 200 OK.

        Raises:
            TokenInvalidClientError: Client authentication failed.
            TokenInvalidRequestError: Invalid request parameters.
        """
        client = await authenticate_client(
            self.client_service, client_id, client_secret
        )

        # Parse request
        try:
            request = RevocationRequest.model_validate(payload)
        except ValidationError as e:
            errors = e.errors()
            if errors:
                msg = f"Invalid parameter: {errors[0]['loc'][0]}"
            else:
                msg = "Invalid request"
            raise TokenInvalidRequestError(msg) from e

        # Revoke based on type hint. Only the caller's own tokens are revoked
        # (RFC 7009 §2.1); anyone else's are treated as unknown.
        owner = client.client_id
        if request.token_type_hint == "access_token":
            await self.token_service.revoke_access_token(request.token, owner)
        elif request.token_type_hint == "refresh_token":
            await self.token_service.revoke_refresh_token(request.token, owner)
        else:
            # Try both - access token first, then refresh token
            revoked = await self.token_service.revoke_access_token(request.token, owner)
            if not revoked:
                await self.token_service.revoke_refresh_token(request.token, owner)

        # Per RFC 7009, always return success (200 OK with empty body)
        # The caller handles the HTTP response


__all__ = [
    "RevocationEndpoint",
    "RevocationRequest",
]
