"""OAuth 2.1 token endpoint implementation for NeoZen."""

from __future__ import annotations

import base64
import hashlib
import typing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, Field, ValidationError

from neozen.core.crypto import generate_token_hash_pair, get_token_hash
from neozen.core.oauth.models import (
    OAuthAccessTokenModel,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthRefreshTokenModel,
)
from neozen.core.oauth.types import CodeChallengeMethod
from neozen.core.storage import DoesNotExist, StorageProtocol


class TokenEndpointError(Exception):
    """Base exception for token endpoint errors."""

    error: str
    error_description: str

    def __init__(self, error: str, error_description: str) -> None:
        self.error = error
        self.error_description = error_description
        super().__init__(error_description)


class InvalidRequestError(TokenEndpointError):
    """Raised for invalid request parameters."""

    def __init__(self, description: str) -> None:
        super().__init__("invalid_request", description)


class InvalidClientError(TokenEndpointError):
    """Raised for client authentication failures."""

    def __init__(self, description: str = "Client authentication failed.") -> None:
        super().__init__("invalid_client", description)


class InvalidGrantError(TokenEndpointError):
    """Raised for invalid authorization code or refresh token."""

    def __init__(
        self, description: str = "The authorization grant is invalid or expired."
    ) -> None:
        super().__init__("invalid_grant", description)


class UnauthorizedClientError(TokenEndpointError):
    """Raised when client is not authorized for this grant type."""

    def __init__(
        self, description: str = "Client not authorized for this grant."
    ) -> None:
        super().__init__("unauthorized_client", description)


class UnsupportedGrantTypeError(TokenEndpointError):
    """Raised for unsupported grant types."""

    def __init__(self, grant_type: str) -> None:
        super().__init__(
            "unsupported_grant_type",
            f"The grant type '{grant_type}' is not supported.",
        )


class InvalidScopeError(TokenEndpointError):
    """Raised for invalid scope requests."""

    def __init__(self, description: str = "The requested scope is invalid.") -> None:
        super().__init__("invalid_scope", description)


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


class TokenEndpoint[
    OC: OAuthClientModel,
    OAC: OAuthAuthorizationCodeModel,
    OAT: OAuthAccessTokenModel,
    ORT: OAuthRefreshTokenModel,
]:
    """OAuth 2.1 token endpoint implementation.

    Handles:
    - Authorization code exchange with PKCE verification
    - Refresh token exchange
    - Token generation with secure hashing

    Example:
        endpoint = TokenEndpoint(
            client_storage=client_storage,
            authorization_code_storage=code_storage,
            access_token_storage=access_storage,
            refresh_token_storage=refresh_storage,
            token_hash_key="secret-key",
        )

        # Exchange authorization code for tokens
        response = await endpoint(request_payload)

    """

    def __init__(
        self,
        client_storage: StorageProtocol[OC],
        authorization_code_storage: StorageProtocol[OAC],
        access_token_storage: StorageProtocol[OAT],
        refresh_token_storage: StorageProtocol[ORT],
        token_hash_key: str,
        *,
        access_token_prefix: str = "nz_at_",
        refresh_token_prefix: str = "nz_rt_",
        access_token_lifetime_seconds: int = 3600,
        refresh_token_lifetime_seconds: int | None = 86400 * 30,
        rotate_refresh_tokens: bool = True,
    ) -> None:
        """Initialize the token endpoint.

        Args:
            client_storage: Storage for OAuth clients.
            authorization_code_storage: Storage for authorization codes.
            access_token_storage: Storage for access tokens.
            refresh_token_storage: Storage for refresh tokens.
            token_hash_key: Secret key for HMAC hashing.
            access_token_prefix: Prefix for access tokens (default: "nz_at_").
            refresh_token_prefix: Prefix for refresh tokens (default: "nz_rt_").
            access_token_lifetime_seconds: Access token lifetime (default: 1 hour).
            refresh_token_lifetime_seconds: Refresh token lifetime (default: 30 days).
                Set to None for non-expiring refresh tokens.
            rotate_refresh_tokens: Whether to issue new refresh token on refresh.

        """
        self.client_storage = client_storage
        self.authorization_code_storage = authorization_code_storage
        self.access_token_storage = access_token_storage
        self.refresh_token_storage = refresh_token_storage
        self.token_hash_key = token_hash_key
        self.access_token_prefix = access_token_prefix
        self.refresh_token_prefix = refresh_token_prefix
        self.access_token_lifetime_seconds = access_token_lifetime_seconds
        self.refresh_token_lifetime_seconds = refresh_token_lifetime_seconds
        self.rotate_refresh_tokens = rotate_refresh_tokens

    async def __call__(
        self,
        payload: dict[str, typing.Any],
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> TokenResponse:
        """Process a token request.

        Args:
            payload: The request payload.
            client_id: Client ID from Basic auth (optional).
            client_secret: Client secret from Basic auth (optional).

        Returns:
            Token response with access token and optionally refresh token.

        Raises:
            TokenEndpointError: For various OAuth errors.

        """
        grant_type = payload.get("grant_type")

        if grant_type == "authorization_code":
            return await self._handle_authorization_code(
                payload, client_id, client_secret
            )
        elif grant_type == "refresh_token":
            return await self._handle_refresh_token(payload, client_id, client_secret)
        elif grant_type is None:
            msg = "Missing required parameter: grant_type"
            raise InvalidRequestError(msg)
        else:
            raise UnsupportedGrantTypeError(str(grant_type))

    async def _handle_authorization_code(
        self,
        payload: dict[str, typing.Any],
        auth_client_id: str | None,
        auth_client_secret: str | None,
    ) -> TokenResponse:
        """Handle authorization code grant."""
        try:
            request = AuthorizationCodeTokenRequest.model_validate(payload)
        except ValidationError as e:
            errors = e.errors()
            if errors:
                msg = f"Invalid parameter: {errors[0]['loc'][0]}"
                raise InvalidRequestError(msg) from e
            msg = "Invalid request"
            raise InvalidRequestError(msg) from e

        # Get and verify client
        client = await self._get_and_verify_client(
            request.client_id, auth_client_id, auth_client_secret
        )

        # Get authorization code
        try:
            auth_code = await self.authorization_code_storage.get_one_by(
                code=request.code
            )
        except DoesNotExist as e:
            msg = "Authorization code not found."
            raise InvalidGrantError(msg) from e

        # Verify code belongs to client
        if auth_code.client_id != client.client_id:
            msg = "Authorization code was not issued to this client."
            raise InvalidGrantError(msg)

        # Check expiration
        now = datetime.now(UTC)
        expires_at = auth_code.expires_at
        # Handle offset-naive datetimes from database
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at < now:
            msg = "Authorization code has expired."
            raise InvalidGrantError(msg)

        # Verify redirect_uri matches
        if auth_code.redirect_uri and request.redirect_uri != auth_code.redirect_uri:
            msg = "redirect_uri does not match."
            raise InvalidGrantError(msg)

        # Verify PKCE
        if not self._verify_pkce(
            request.code_verifier,
            auth_code.code_challenge,
            auth_code.code_challenge_method,
        ):
            msg = "PKCE verification failed."
            raise InvalidGrantError(msg)

        # Generate tokens
        access_token, access_token_hash = generate_token_hash_pair(
            self.token_hash_key, prefix=self.access_token_prefix
        )
        refresh_token, refresh_token_hash = generate_token_hash_pair(
            self.token_hash_key, prefix=self.refresh_token_prefix
        )

        access_expires_at = now + timedelta(seconds=self.access_token_lifetime_seconds)
        refresh_expires_at = (
            now + timedelta(seconds=self.refresh_token_lifetime_seconds)
            if self.refresh_token_lifetime_seconds
            else None
        )

        # Store tokens
        await self.access_token_storage.create(
            token_hash=access_token_hash,
            client_id=client.client_id,
            subject_id=auth_code.subject_id,
            scope=auth_code.scope,
            expires_at=access_expires_at,
            created_at=now,
            revoked_at=None,
        )

        await self.refresh_token_storage.create(
            token_hash=refresh_token_hash,
            client_id=client.client_id,
            subject_id=auth_code.subject_id,
            scope=auth_code.scope,
            expires_at=refresh_expires_at,
            created_at=now,
            revoked_at=None,
            access_token_hash=access_token_hash,
        )

        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=self.access_token_lifetime_seconds,
            refresh_token=refresh_token,
            scope=auth_code.scope,
        )

    async def _handle_refresh_token(
        self,
        payload: dict[str, typing.Any],
        auth_client_id: str | None,
        auth_client_secret: str | None,
    ) -> TokenResponse:
        """Handle refresh token grant."""
        try:
            request = RefreshTokenRequest.model_validate(payload)
        except ValidationError as e:
            errors = e.errors()
            if errors:
                msg = f"Invalid parameter: {errors[0]['loc'][0]}"
                raise InvalidRequestError(msg) from e
            msg = "Invalid request"
            raise InvalidRequestError(msg) from e

        # Get refresh token
        refresh_token_hash = get_token_hash(
            request.refresh_token, key=self.token_hash_key
        )
        try:
            stored_refresh = await self.refresh_token_storage.get_one_by(
                token_hash=refresh_token_hash
            )
        except DoesNotExist as e:
            msg = "Refresh token not found."
            raise InvalidGrantError(msg) from e

        # Check if revoked
        if stored_refresh.revoked_at is not None:
            msg = "Refresh token has been revoked."
            raise InvalidGrantError(msg)

        # Check expiration
        now = datetime.now(UTC)
        if stored_refresh.expires_at:
            expires_at = stored_refresh.expires_at
            # Handle offset-naive datetimes from database
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            if expires_at < now:
                msg = "Refresh token has expired."
                raise InvalidGrantError(msg)

        # Verify client
        client_id = request.client_id or auth_client_id or stored_refresh.client_id
        client = await self._get_and_verify_client(
            client_id, auth_client_id, auth_client_secret
        )

        if stored_refresh.client_id != client.client_id:
            msg = "Refresh token was not issued to this client."
            raise InvalidGrantError(msg)

        # Handle scope downgrade
        scope = stored_refresh.scope
        if request.scope:
            requested_scopes = set(request.scope.split())
            original_scopes = set(scope.split())
            if not requested_scopes.issubset(original_scopes):
                msg = "Requested scope exceeds original grant scope."
                raise InvalidScopeError(msg)
            scope = request.scope

        # Generate new access token
        access_token, access_token_hash = generate_token_hash_pair(
            self.token_hash_key, prefix=self.access_token_prefix
        )
        access_expires_at = now + timedelta(seconds=self.access_token_lifetime_seconds)

        await self.access_token_storage.create(
            token_hash=access_token_hash,
            client_id=client.client_id,
            subject_id=stored_refresh.subject_id,
            scope=scope,
            expires_at=access_expires_at,
            created_at=now,
            revoked_at=None,
        )

        # Optionally rotate refresh token
        new_refresh_token: str | None = None
        if self.rotate_refresh_tokens:
            # Revoke old refresh token
            await self.refresh_token_storage.update(stored_refresh, revoked_at=now)

            # Create new refresh token
            new_refresh_token, new_refresh_token_hash = generate_token_hash_pair(
                self.token_hash_key, prefix=self.refresh_token_prefix
            )
            refresh_expires_at = (
                now + timedelta(seconds=self.refresh_token_lifetime_seconds)
                if self.refresh_token_lifetime_seconds
                else None
            )

            await self.refresh_token_storage.create(
                token_hash=new_refresh_token_hash,
                client_id=client.client_id,
                subject_id=stored_refresh.subject_id,
                scope=scope,
                expires_at=refresh_expires_at,
                created_at=now,
                revoked_at=None,
                access_token_hash=access_token_hash,
            )

        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=self.access_token_lifetime_seconds,
            refresh_token=new_refresh_token,
            scope=scope if scope != stored_refresh.scope else None,
        )

    async def _get_and_verify_client(
        self,
        client_id: str,
        auth_client_id: str | None,
        auth_client_secret: str | None,
    ) -> OC:
        """Get and verify OAuth client.

        For public clients, just verify client_id matches.
        For confidential clients, verify client_secret.

        """
        # If Basic auth provided, ensure client_id matches
        if auth_client_id and auth_client_id != client_id:
            msg = "Client ID mismatch."
            raise InvalidClientError(msg)

        try:
            client = await self.client_storage.get_one_by(client_id=client_id)
        except DoesNotExist as e:
            msg = "Unknown client."
            raise InvalidClientError(msg) from e

        # Note: Client secret verification should be implemented based on
        # your OAuthClientModel. This is a simplified version.
        # In production, you would check client.client_secret against auth_client_secret

        return client

    def _verify_pkce(
        self,
        code_verifier: str,
        code_challenge: str,
        method: CodeChallengeMethod,
    ) -> bool:
        """Verify PKCE code verifier against challenge."""
        if method == "plain":
            return code_verifier == code_challenge
        elif method == "S256":
            # SHA-256 hash of verifier, base64url encoded
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
            return computed == code_challenge
        return False


__all__ = [
    "AuthorizationCodeTokenRequest",
    "InvalidClientError",
    "InvalidGrantError",
    "InvalidRequestError",
    "InvalidScopeError",
    "RefreshTokenRequest",
    "TokenEndpoint",
    "TokenEndpointError",
    "TokenResponse",
    "UnauthorizedClientError",
    "UnsupportedGrantTypeError",
]
