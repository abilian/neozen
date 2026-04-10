"""OAuth 2.1 token endpoint HTTP adapter for NeoZen.

This module provides the HTTP adapter for the OAuth token endpoint.
It handles request parsing, response formatting, and delegates to
the core OAuthTokenService for business logic.
"""

from __future__ import annotations

import typing
from dataclasses import dataclass

from pydantic import BaseModel, Field, ValidationError

from neozen.core.oauth.exceptions import (
    AuthorizationCodeExpiredError,
    AuthorizationCodeNotFoundError,
    ClientMismatchError,
    InvalidClientError,
    PKCEVerificationFailedError,
    RedirectUriMismatchError,
    RefreshTokenExpiredError,
    RefreshTokenNotFoundError,
    RefreshTokenRevokedError,
    ScopeExceedsGrantError,
    TokenInvalidClientError,
    TokenInvalidGrantError,
    TokenInvalidRequestError,
    TokenInvalidScopeError,
    TokenUnsupportedGrantTypeError,
)
from neozen.core.oauth.models import (
    OAuthAccessTokenModel,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthRefreshTokenModel,
)
from neozen.core.oauth.services import OAuthTokenService

# =============================================================================
# Request Models (HTTP layer)
# =============================================================================


class AuthorizationCodeTokenRequest(BaseModel):
    """Request for authorization code token exchange."""

    grant_type: typing.Literal["authorization_code"]
    code: str
    redirect_uri: str | None = None
    client_id: str
    code_verifier: str = Field(min_length=43, max_length=128)


class RefreshTokenRequest(BaseModel):
    """Request for refresh token exchange."""

    grant_type: typing.Literal["refresh_token"]
    refresh_token: str
    scope: str | None = None
    client_id: str | None = None


class ClientCredentialsTokenRequest(BaseModel):
    """Request for client_credentials grant.

    Per RFC 6749 Section 4.4, the client authenticates via the
    token endpoint (Basic auth or POST body) and receives an
    access token directly.
    """

    grant_type: typing.Literal["client_credentials"]
    scope: str | None = None
    client_id: str | None = None


# =============================================================================
# Response Models (HTTP layer)
# =============================================================================


@dataclass
class TokenResponse:
    """Response from token endpoint."""

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str | None = None
    scope: str | None = None

    def to_dict(self) -> dict[str, typing.Any]:
        """Convert to dictionary for JSON response."""
        result: dict[str, typing.Any] = {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
        }
        if self.refresh_token:
            result["refresh_token"] = self.refresh_token
        if self.scope:
            result["scope"] = self.scope
        return result


# =============================================================================
# Token Endpoint (HTTP Adapter)
# =============================================================================


class TokenEndpoint[
    OC: OAuthClientModel,
    OAC: OAuthAuthorizationCodeModel,
    OAT: OAuthAccessTokenModel,
    ORT: OAuthRefreshTokenModel,
]:
    """OAuth 2.1 token endpoint HTTP adapter.

    This class handles HTTP concerns:
    - Request parsing and validation
    - Response formatting
    - Error mapping to OAuth error responses

    Business logic is delegated to OAuthTokenService.

    Example:
        service = OAuthTokenService(...)
        endpoint = TokenEndpoint(service)

        # Handle HTTP request
        response = await endpoint(request_payload)
    """

    def __init__(self, service: OAuthTokenService[OC, OAC, OAT, ORT]) -> None:
        """Initialize the token endpoint.

        Args:
            service: The OAuth token service for business logic.
        """
        self.service = service

    async def __call__(
        self,
        payload: dict[str, typing.Any],
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> TokenResponse:
        """Process a token request.

        Args:
            payload: The request payload (form data).
            client_id: Client ID from Basic auth (optional).
            client_secret: Client secret from Basic auth (optional).

        Returns:
            Token response with access token and optionally refresh token.

        Raises:
            TokenInvalidRequestError: Invalid request parameters.
            TokenInvalidClientError: Client authentication failed.
            TokenInvalidGrantError: Invalid authorization code or refresh token.
            TokenUnsupportedGrantTypeError: Unsupported grant type.
            TokenInvalidScopeError: Invalid scope request.
        """
        match payload.get("grant_type"):
            case "authorization_code":
                return await self._handle_authorization_code(
                    payload, client_id, client_secret
                )
            case "refresh_token":
                return await self._handle_refresh_token(
                    payload, client_id, client_secret
                )
            case "client_credentials":
                return await self._handle_client_credentials(
                    payload, client_id, client_secret
                )
            case None:
                msg = "Missing required parameter: grant_type"
                raise TokenInvalidRequestError(msg)
            case grant_type:
                raise TokenUnsupportedGrantTypeError(str(grant_type))

    async def _handle_authorization_code(
        self,
        payload: dict[str, typing.Any],
        auth_client_id: str | None,
        auth_client_secret: str | None,
    ) -> TokenResponse:
        """Handle authorization code grant."""
        # Parse request
        request = self._parse_authorization_code_request(payload)

        # Verify client_id consistency
        client_id = self._resolve_client_id(request.client_id, auth_client_id)

        # Get client
        client = await self._get_client(client_id)

        # Validate authorization code (delegates to service)
        try:
            auth_code = await self.service.validate_authorization_code(
                code=request.code,
                client_id=client_id,
                redirect_uri=request.redirect_uri,
                code_verifier=request.code_verifier,
            )
        except AuthorizationCodeNotFoundError as e:
            msg = "Authorization code not found."
            raise TokenInvalidGrantError(msg) from e
        except AuthorizationCodeExpiredError as e:
            msg = "Authorization code has expired."
            raise TokenInvalidGrantError(msg) from e
        except ClientMismatchError as e:
            msg = "Authorization code was not issued to this client."
            raise TokenInvalidGrantError(msg) from e
        except RedirectUriMismatchError as e:
            msg = "redirect_uri does not match."
            raise TokenInvalidGrantError(msg) from e
        except PKCEVerificationFailedError as e:
            msg = "PKCE verification failed."
            raise TokenInvalidGrantError(msg) from e

        # Exchange for tokens
        token_pair = await self.service.exchange_authorization_code(auth_code, client)

        return TokenResponse(
            access_token=token_pair.access_token,
            token_type="Bearer",
            expires_in=int(self.service.access_token_lifetime.total_seconds()),
            refresh_token=token_pair.refresh_token,
            scope=token_pair.scope,
        )

    async def _handle_refresh_token(
        self,
        payload: dict[str, typing.Any],
        auth_client_id: str | None,
        auth_client_secret: str | None,
    ) -> TokenResponse:
        """Handle refresh token grant."""
        # Parse request
        request = self._parse_refresh_token_request(payload)

        # Resolve client_id (from request, auth header, or will get from token)
        client_id = request.client_id or auth_client_id

        # Validate refresh token first to get client_id if not provided
        try:
            # We need client_id - if not provided, we'll validate after getting token
            if not client_id:
                # This is a simplified flow - in production you'd want to
                # get the client_id from the token first
                msg = "client_id is required"
                raise TokenInvalidRequestError(msg)

            stored_refresh = await self.service.validate_refresh_token(
                refresh_token=request.refresh_token,
                client_id=client_id,
            )
        except RefreshTokenNotFoundError as e:
            msg = "Refresh token not found."
            raise TokenInvalidGrantError(msg) from e
        except RefreshTokenRevokedError as e:
            msg = "Refresh token has been revoked."
            raise TokenInvalidGrantError(msg) from e
        except RefreshTokenExpiredError as e:
            msg = "Refresh token has expired."
            raise TokenInvalidGrantError(msg) from e
        except ClientMismatchError as e:
            msg = "Refresh token was not issued to this client."
            raise TokenInvalidGrantError(msg) from e

        # Get client
        client = await self._get_client(client_id)

        # Validate scope
        try:
            scope = self.service.validate_scope_downgrade(
                request.scope, stored_refresh.scope
            )
        except ScopeExceedsGrantError as e:
            msg = "Requested scope exceeds original grant scope."
            raise TokenInvalidScopeError(msg) from e

        # Generate new access token
        result = await self.service.refresh_access_token(stored_refresh, client, scope)

        return TokenResponse(
            access_token=result.access_token,
            token_type="Bearer",
            expires_in=int(self.service.access_token_lifetime.total_seconds()),
            refresh_token=result.new_refresh_token,
            scope=scope if scope != stored_refresh.scope else None,
        )

    async def _handle_client_credentials(
        self,
        payload: dict[str, typing.Any],
        auth_client_id: str | None,
        auth_client_secret: str | None,
    ) -> TokenResponse:
        """Handle client_credentials grant.

        Per RFC 6749 Section 4.4, the client authenticates and
        receives an access token (no refresh token).
        """
        # Parse request
        request = self._parse_client_credentials_request(payload)

        # Resolve client_id from request body or auth header
        client_id = request.client_id or auth_client_id
        if not client_id:
            msg = "client_id is required"
            raise TokenInvalidRequestError(msg)

        if request.client_id and auth_client_id and request.client_id != auth_client_id:
            msg = "Client ID mismatch."
            raise TokenInvalidClientError(msg)

        # Get client
        client = await self._get_client(client_id)

        # Verify client is allowed to use this grant type
        if not client.is_grant_type_allowed("client_credentials"):
            msg = "Client is not allowed to use client_credentials grant."
            raise TokenInvalidGrantError(msg)

        # Validate scope
        scope = request.scope
        if scope and not client.is_scope_allowed(scope):
            msg = "One or more requested scopes are not allowed for this client."
            raise TokenInvalidScopeError(msg)

        # Issue access token
        result = await self.service.issue_client_credentials_token(client, scope)

        return TokenResponse(
            access_token=result.access_token,
            token_type="Bearer",
            expires_in=int(self.service.access_token_lifetime.total_seconds()),
            refresh_token=None,  # No refresh token for client_credentials
            scope=scope,
        )

    def _parse_client_credentials_request(
        self, payload: dict[str, typing.Any]
    ) -> ClientCredentialsTokenRequest:
        """Parse and validate client_credentials request."""
        try:
            return ClientCredentialsTokenRequest.model_validate(payload)
        except ValidationError as e:
            errors = e.errors()
            if errors:
                msg = f"Invalid parameter: {errors[0]['loc'][0]}"
                raise TokenInvalidRequestError(msg) from e
            msg = "Invalid request"
            raise TokenInvalidRequestError(msg) from e

    def _parse_authorization_code_request(
        self, payload: dict[str, typing.Any]
    ) -> AuthorizationCodeTokenRequest:
        """Parse and validate authorization code request."""
        try:
            return AuthorizationCodeTokenRequest.model_validate(payload)
        except ValidationError as e:
            errors = e.errors()
            if errors:
                msg = f"Invalid parameter: {errors[0]['loc'][0]}"
                raise TokenInvalidRequestError(msg) from e
            msg = "Invalid request"
            raise TokenInvalidRequestError(msg) from e

    def _parse_refresh_token_request(
        self, payload: dict[str, typing.Any]
    ) -> RefreshTokenRequest:
        """Parse and validate refresh token request."""
        try:
            return RefreshTokenRequest.model_validate(payload)
        except ValidationError as e:
            errors = e.errors()
            if errors:
                msg = f"Invalid parameter: {errors[0]['loc'][0]}"
                raise TokenInvalidRequestError(msg) from e
            msg = "Invalid request"
            raise TokenInvalidRequestError(msg) from e

    def _resolve_client_id(
        self, request_client_id: str, auth_client_id: str | None
    ) -> str:
        """Resolve client_id from request and auth header."""
        if auth_client_id and auth_client_id != request_client_id:
            msg = "Client ID mismatch."
            raise TokenInvalidClientError(msg)
        return request_client_id

    async def _get_client(self, client_id: str) -> OC:
        """Get OAuth client."""
        try:
            return await self.service.get_client(client_id)
        except InvalidClientError as e:
            msg = "Unknown client."
            raise TokenInvalidClientError(msg) from e


__all__ = [
    "AuthorizationCodeTokenRequest",
    "ClientCredentialsTokenRequest",
    "RefreshTokenRequest",
    "TokenEndpoint",
    "TokenResponse",
]
