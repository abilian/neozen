"""OAuth 2.1 business logic services for NeoZen.

This module contains pure business logic for OAuth operations,
without HTTP/web concerns. These services are used by web adapters.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from neozen.core.crypto import generate_token_hash_pair, get_token_hash
from neozen.core.oauth.exceptions import (
    AuthorizationCodeExpiredError,
    AuthorizationCodeNotFoundError,
    ClientMismatchError,
    InvalidClientError,
    RedirectUriMismatchError,
    RefreshTokenExpiredError,
    RefreshTokenNotFoundError,
    RefreshTokenRevokedError,
    ScopeExceedsGrantError,
)
from neozen.core.oauth.models import (
    OAuthAccessTokenModel,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthRefreshTokenModel,
)
from neozen.core.oauth.pkce import verify_pkce
from neozen.core.repository import DoesNotExist, RepositoryProtocol
from neozen.core.utils import ensure_utc


@dataclass
class TokenPair:
    """Generated token pair."""

    access_token: str
    access_token_hash: str
    refresh_token: str
    refresh_token_hash: str
    access_expires_at: datetime
    refresh_expires_at: datetime | None
    scope: str | None


@dataclass
class AccessTokenResult:
    """Result of access token generation (for refresh)."""

    access_token: str
    access_token_hash: str
    expires_at: datetime
    scope: str | None
    new_refresh_token: str | None = None
    new_refresh_token_hash: str | None = None
    new_refresh_expires_at: datetime | None = None


class OAuthTokenService[
    OC: OAuthClientModel,
    OAC: OAuthAuthorizationCodeModel,
    OAT: OAuthAccessTokenModel,
    ORT: OAuthRefreshTokenModel,
]:
    """Service for OAuth token operations.

    Handles:
    - Authorization code validation and exchange
    - Refresh token validation and exchange
    - Token generation

    This is pure business logic - no HTTP concerns.
    """

    def __init__(
        self,
        client_repository: RepositoryProtocol[OC],
        authorization_code_repository: RepositoryProtocol[OAC],
        access_token_repository: RepositoryProtocol[OAT],
        refresh_token_repository: RepositoryProtocol[ORT],
        token_hash_key: str,
        *,
        access_token_prefix: str = "nz_at_",
        refresh_token_prefix: str = "nz_rt_",
        access_token_lifetime: timedelta = timedelta(hours=1),
        refresh_token_lifetime: timedelta | None = timedelta(days=30),
        rotate_refresh_tokens: bool = True,
    ) -> None:
        self.client_repository = client_repository
        self.authorization_code_repository = authorization_code_repository
        self.access_token_repository = access_token_repository
        self.refresh_token_repository = refresh_token_repository
        self.token_hash_key = token_hash_key
        self.access_token_prefix = access_token_prefix
        self.refresh_token_prefix = refresh_token_prefix
        self.access_token_lifetime = access_token_lifetime
        self.refresh_token_lifetime = refresh_token_lifetime
        self.rotate_refresh_tokens = rotate_refresh_tokens

    async def get_client(self, client_id: str) -> OC:
        """Get OAuth client by ID.

        Raises:
            InvalidClientError: If client not found.
        """
        try:
            return await self.client_repository.get_one_by(client_id=client_id)
        except DoesNotExist as e:
            raise InvalidClientError("Unknown client.") from e

    async def validate_authorization_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str | None,
        code_verifier: str,
    ) -> OAC:
        """Validate an authorization code for token exchange.

        Args:
            code: The authorization code.
            client_id: The client ID making the request.
            redirect_uri: The redirect URI (must match original if provided).
            code_verifier: The PKCE code verifier.

        Returns:
            The validated authorization code model.

        Raises:
            AuthorizationCodeNotFoundError: Code not found.
            AuthorizationCodeExpiredError: Code has expired.
            ClientMismatchError: Code was issued to different client.
            RedirectUriMismatchError: Redirect URI doesn't match.
            PKCEVerificationFailedError: PKCE verification failed.
        """
        try:
            auth_code = await self.authorization_code_repository.get_one_by(code=code)
        except DoesNotExist as e:
            raise AuthorizationCodeNotFoundError from e

        # Verify client
        if auth_code.client_id != client_id:
            raise ClientMismatchError

        # Check expiration
        if ensure_utc(auth_code.expires_at) < datetime.now(UTC):
            raise AuthorizationCodeExpiredError

        # Verify redirect_uri
        if auth_code.redirect_uri and redirect_uri != auth_code.redirect_uri:
            raise RedirectUriMismatchError

        # Verify PKCE
        verify_pkce(
            code_verifier,
            auth_code.code_challenge,
            auth_code.code_challenge_method,
        )

        return auth_code

    async def validate_refresh_token(
        self,
        refresh_token: str,
        client_id: str,
    ) -> ORT:
        """Validate a refresh token.

        Args:
            refresh_token: The refresh token.
            client_id: The client ID making the request.

        Returns:
            The validated refresh token model.

        Raises:
            RefreshTokenNotFoundError: Token not found.
            RefreshTokenRevokedError: Token has been revoked.
            RefreshTokenExpiredError: Token has expired.
            ClientMismatchError: Token was issued to different client.
        """
        token_hash = get_token_hash(refresh_token, key=self.token_hash_key)

        try:
            stored = await self.refresh_token_repository.get_one_by(
                token_hash=token_hash
            )
        except DoesNotExist as e:
            raise RefreshTokenNotFoundError from e

        if stored.revoked_at is not None:
            raise RefreshTokenRevokedError

        if stored.expires_at and ensure_utc(stored.expires_at) < datetime.now(UTC):
            raise RefreshTokenExpiredError

        if stored.client_id != client_id:
            raise ClientMismatchError

        return stored

    def validate_scope_downgrade(
        self,
        requested_scope: str | None,
        original_scope: str | None,
    ) -> str | None:
        """Validate that requested scope is subset of original.

        Args:
            requested_scope: The requested scope (space-separated).
            original_scope: The original granted scope.

        Returns:
            The validated scope to use.

        Raises:
            ScopeExceedsGrantError: If requested scope exceeds original.
        """
        if not requested_scope:
            return original_scope

        if not original_scope:
            raise ScopeExceedsGrantError

        requested = set(requested_scope.split())
        original = set(original_scope.split())

        if not requested.issubset(original):
            raise ScopeExceedsGrantError

        return requested_scope

    async def exchange_authorization_code(
        self,
        auth_code: OAC,
        client: OC,
    ) -> TokenPair:
        """Exchange a validated authorization code for tokens.

        Args:
            auth_code: The validated authorization code.
            client: The OAuth client.

        Returns:
            Generated token pair.
        """
        now = datetime.now(UTC)

        # Generate tokens
        access_token, access_token_hash = generate_token_hash_pair(
            self.token_hash_key, prefix=self.access_token_prefix
        )
        refresh_token, refresh_token_hash = generate_token_hash_pair(
            self.token_hash_key, prefix=self.refresh_token_prefix
        )

        access_expires_at = now + self.access_token_lifetime
        refresh_expires_at = (
            now + self.refresh_token_lifetime if self.refresh_token_lifetime else None
        )

        # Store access token
        await self.access_token_repository.create(
            token_hash=access_token_hash,
            client_id=client.client_id,
            subject_id=auth_code.subject_id,
            scope=auth_code.scope,
            expires_at=access_expires_at,
            created_at=now,
            revoked_at=None,
        )

        # Store refresh token
        await self.refresh_token_repository.create(
            token_hash=refresh_token_hash,
            client_id=client.client_id,
            subject_id=auth_code.subject_id,
            scope=auth_code.scope,
            expires_at=refresh_expires_at,
            created_at=now,
            revoked_at=None,
            access_token_hash=access_token_hash,
        )

        return TokenPair(
            access_token=access_token,
            access_token_hash=access_token_hash,
            refresh_token=refresh_token,
            refresh_token_hash=refresh_token_hash,
            access_expires_at=access_expires_at,
            refresh_expires_at=refresh_expires_at,
            scope=auth_code.scope,
        )

    async def refresh_access_token(
        self,
        stored_refresh: ORT,
        client: OC,
        scope: str | None,
    ) -> AccessTokenResult:
        """Generate new access token from refresh token.

        Args:
            stored_refresh: The validated refresh token.
            client: The OAuth client.
            scope: The scope to use (already validated).

        Returns:
            Access token result with optional new refresh token.
        """
        now = datetime.now(UTC)

        # Generate new access token
        access_token, access_token_hash = generate_token_hash_pair(
            self.token_hash_key, prefix=self.access_token_prefix
        )
        access_expires_at = now + self.access_token_lifetime

        await self.access_token_repository.create(
            token_hash=access_token_hash,
            client_id=client.client_id,
            subject_id=stored_refresh.subject_id,
            scope=scope,
            expires_at=access_expires_at,
            created_at=now,
            revoked_at=None,
        )

        result = AccessTokenResult(
            access_token=access_token,
            access_token_hash=access_token_hash,
            expires_at=access_expires_at,
            scope=scope,
        )

        # Optionally rotate refresh token
        if self.rotate_refresh_tokens:
            await self.refresh_token_repository.update_obj(
                stored_refresh, revoked_at=now
            )

            new_refresh, new_refresh_hash = generate_token_hash_pair(
                self.token_hash_key, prefix=self.refresh_token_prefix
            )
            new_refresh_expires_at = (
                now + self.refresh_token_lifetime
                if self.refresh_token_lifetime
                else None
            )

            await self.refresh_token_repository.create(
                token_hash=new_refresh_hash,
                client_id=client.client_id,
                subject_id=stored_refresh.subject_id,
                scope=scope,
                expires_at=new_refresh_expires_at,
                created_at=now,
                revoked_at=None,
                access_token_hash=access_token_hash,
            )

            result.new_refresh_token = new_refresh
            result.new_refresh_token_hash = new_refresh_hash
            result.new_refresh_expires_at = new_refresh_expires_at

        return result


__all__ = [
    "AccessTokenResult",
    "OAuthTokenService",
    "TokenPair",
]
