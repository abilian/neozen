"""OAuth 2.1 token introspection endpoint (RFC 7662) for NeoZen.

This module provides the HTTP adapter for the OAuth token introspection endpoint.
"""

from __future__ import annotations

import typing
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError

from neozen.core.oauth.client_service import OAuthClientService
from neozen.core.oauth.exceptions import (
    TokenInvalidClientError,
    TokenInvalidRequestError,
)
from neozen.core.oauth.models import (
    OAuthAccessTokenModel,
    OAuthClientModel,
    OAuthRefreshTokenModel,
)
from neozen.core.oauth.services import OAuthTokenService
from neozen.web.oauth.utils import authenticate_client


class IntrospectionRequest(BaseModel):
    """Request model for token introspection."""

    token: str
    token_type_hint: str | None = None


@dataclass(frozen=True)
class IntrospectionResponse:
    """Response from introspection endpoint."""

    active: bool
    scope: str | None = None
    client_id: str | None = None
    sub: str | None = None
    exp: int | None = None
    iat: int | None = None
    token_type: str | None = None

    def to_dict(self) -> dict[str, typing.Any]:
        """Convert to dictionary for JSON response."""
        if not self.active:
            return {"active": False}

        result: dict[str, typing.Any] = {"active": True}
        if self.scope:
            result["scope"] = self.scope
        if self.client_id:
            result["client_id"] = self.client_id
        if self.sub:
            result["sub"] = self.sub
        if self.exp:
            result["exp"] = self.exp
        if self.iat:
            result["iat"] = self.iat
        if self.token_type:
            result["token_type"] = self.token_type
        return result


class IntrospectionEndpoint[
    OC: OAuthClientModel,
    OAT: OAuthAccessTokenModel,
    ORT: OAuthRefreshTokenModel,
]:
    """OAuth 2.1 token introspection endpoint (RFC 7662).

    Allows resource servers to query the authorization server
    to determine the active state of a token and its metadata.

    Example:
        client_service = OAuthClientService(...)
        token_service = OAuthTokenService(...)
        endpoint = IntrospectionEndpoint(
            client_service=client_service,
            token_service=token_service,
        )

        # Handle POST request
        response = await endpoint(
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
        """Initialize the introspection endpoint.

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
    ) -> IntrospectionResponse:
        """Process an introspection request.

        Args:
            payload: The request payload (form data).
            client_id: Client ID from Basic auth.
            client_secret: Client secret from Basic auth.

        Returns:
            Introspection response.

        Raises:
            TokenInvalidClientError: Client authentication failed.
            TokenInvalidRequestError: Invalid request parameters.
        """
        # RFC 7662 §2.1: the caller must be authorized. Public clients hold
        # no secret, so they could probe any token.
        client = await authenticate_client(
            self.client_service, client_id, client_secret
        )
        if client.is_public_client():
            msg = "Client authentication failed."
            raise TokenInvalidClientError(msg)

        # Parse request
        request = self._parse_request(payload)

        # Introspect token
        result = await self._introspect_token(request)

        # Token not found - return inactive
        if result is None:
            return IntrospectionResponse(active=False)

        return IntrospectionResponse(
            active=result.get("active", False),
            scope=result.get("scope"),
            client_id=result.get("client_id"),
            sub=result.get("sub"),
            exp=result.get("exp"),
            iat=result.get("iat"),
            token_type=result.get("token_type"),
        )

    def _parse_request(self, payload: dict[str, typing.Any]) -> IntrospectionRequest:
        """Parse and validate the request payload."""
        try:
            return IntrospectionRequest.model_validate(payload)
        except ValidationError as e:
            errors = e.errors()
            if errors:
                msg = f"Invalid parameter: {errors[0]['loc'][0]}"
            else:
                msg = "Invalid request"
            raise TokenInvalidRequestError(msg) from e

    async def _introspect_token(
        self, request: IntrospectionRequest
    ) -> dict[str, typing.Any] | None:
        """Introspect the token based on type hint."""
        if request.token_type_hint == "access_token":
            return await self.token_service.introspect_access_token(request.token)
        if request.token_type_hint == "refresh_token":
            return await self.token_service.introspect_refresh_token(request.token)

        # Try access token first, then refresh token
        result = await self.token_service.introspect_access_token(request.token)
        if result is None:
            result = await self.token_service.introspect_refresh_token(request.token)
        return result


__all__ = [
    "IntrospectionEndpoint",
    "IntrospectionRequest",
    "IntrospectionResponse",
]
