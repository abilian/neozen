"""OAuth 2.1 business logic services for NeoZen.

This module contains pure business logic for OAuth operations,
without HTTP/web concerns. These services are used by web adapters.
"""

from __future__ import annotations

import typing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from neozen.core.crypto import generate_token_hash_pair, get_token_hash
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

if typing.TYPE_CHECKING:
    from neozen.core.oauth.jwt_access_token import JWTAccessTokenSigner


async def _revoke_matching[T](
    repository: RepositoryProtocol[T], now: datetime, **filters: typing.Any
) -> None:
    for token in await repository.get_many_by(**filters):
        await repository.update_obj(token, revoked_at=now)


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
        access_token_signer: JWTAccessTokenSigner | None = None,
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
        self.access_token_signer = access_token_signer

    async def _issue_access_token(
        self,
        subject_id: typing.Any,
        client_id: str,
        scope: str | None,
        issued_at: datetime,
    ) -> AccessTokenResult:
        """Generate an access token (opaque, or a JWT with a signer) and store its hash."""
        expires_at = issued_at + self.access_token_lifetime
        if self.access_token_signer is None:
            token, token_hash = generate_token_hash_pair(
                self.token_hash_key, prefix=self.access_token_prefix
            )
        else:
            token = await self.access_token_signer.sign(
                subject_id=subject_id,
                client_id=client_id,
                scope=scope,
                issued_at=issued_at,
                expires_at=expires_at,
            )
            token_hash = get_token_hash(token, key=self.token_hash_key)
        await self.access_token_repository.create(
            token_hash=token_hash,
            client_id=client_id,
            subject_id=subject_id,
            scope=scope,
            expires_at=expires_at,
            created_at=issued_at,
            revoked_at=None,
        )
        return AccessTokenResult(
            access_token=token,
            access_token_hash=token_hash,
            expires_at=expires_at,
            scope=scope,
        )

    async def get_client(self, client_id: str) -> OC:
        """Get OAuth client by ID.

        Raises:
            InvalidClientError: If client not found.
        """
        try:
            return await self.client_repository.get_one_by(client_id=client_id)
        except DoesNotExist as e:
            msg = "Unknown client."
            raise InvalidClientError(msg) from e

    async def validate_authorization_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str | None,
        code_verifier: str | None,
    ) -> OAC:
        """Validate an authorization code for token exchange.

        Args:
            code: The authorization code.
            client_id: The client ID making the request.
            redirect_uri: The redirect URI (must match original if provided).
            code_verifier: The PKCE code verifier, or None when the code was
                issued without a challenge.

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

        # Verify PKCE. A verifier for a code issued without a challenge is
        # rejected too (RFC 9700 §4.8.2, PKCE downgrade).
        if auth_code.code_challenge is None:
            if code_verifier is not None:
                raise PKCEVerificationFailedError
        elif code_verifier is None:
            raise PKCEVerificationFailedError
        else:
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
            # RFC 9700 §4.14.2: a revoked refresh token coming back has
            # leaked. Tokens don't record their rotation chain, so revoke
            # everything this client holds for the subject.
            await self._revoke_all(stored.client_id, stored.subject_id)
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

        Raises:
            AuthorizationCodeNotFoundError: The code was already used, e.g.
                by a concurrent request.
        """
        # OAuth 2.1 §4.1.2: codes are single-use. Consume the code before
        # issuing anything: of two concurrent exchanges, only one deletes it.
        try:
            await self.authorization_code_repository.delete(auth_code)
        except DoesNotExist as e:
            raise AuthorizationCodeNotFoundError from e

        now = datetime.now(UTC)
        access = await self._issue_access_token(
            auth_code.subject_id, client.client_id, auth_code.scope, now
        )
        refresh_token, refresh_token_hash = generate_token_hash_pair(
            self.token_hash_key, prefix=self.refresh_token_prefix
        )
        refresh_expires_at = (
            now + self.refresh_token_lifetime if self.refresh_token_lifetime else None
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
            access_token_hash=access.access_token_hash,
        )

        return TokenPair(
            access_token=access.access_token,
            access_token_hash=access.access_token_hash,
            refresh_token=refresh_token,
            refresh_token_hash=refresh_token_hash,
            access_expires_at=access.expires_at,
            refresh_expires_at=refresh_expires_at,
            scope=auth_code.scope,
        )

    async def issue_client_credentials_token(
        self,
        client: OC,
        scope: str | None,
    ) -> AccessTokenResult:
        """Issue an access token via the client_credentials grant.

        Per RFC 6749 Section 4.4, refresh tokens are NOT issued for
        the client_credentials grant -- the client can simply request
        a new token if needed.

        Args:
            client: The authenticated OAuth client.
            scope: The scope (already validated against client's allowed scopes).

        Returns:
            Access token result (no refresh token).
        """
        # The "subject" for client_credentials is the client itself
        return await self._issue_access_token(
            client.client_id, client.client_id, scope, datetime.now(UTC)
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

        result = await self._issue_access_token(
            stored_refresh.subject_id, client.client_id, scope, now
        )

        # Optionally rotate refresh token
        # OAuth 2.1 §4.3.1: public clients' refresh tokens always rotate.
        if self.rotate_refresh_tokens or client.is_public_client():
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
                access_token_hash=result.access_token_hash,
            )

            result.new_refresh_token = new_refresh
            result.new_refresh_token_hash = new_refresh_hash
            result.new_refresh_expires_at = new_refresh_expires_at

        return result

    async def _revoke_all(self, client_id: str, subject_id: typing.Any) -> None:
        """Revoke every live access and refresh token of `client_id` for `subject_id`."""
        now = datetime.now(UTC)
        live = {"client_id": client_id, "subject_id": subject_id, "revoked_at": None}
        await _revoke_matching(self.access_token_repository, now, **live)
        await _revoke_matching(self.refresh_token_repository, now, **live)

    async def revoke_access_token(self, token: str, client_id: str) -> bool:
        """Revoke an access token issued to `client_id`.

        Args:
            token: The access token to revoke.
            client_id: The client the token must belong to; tokens issued
                to other clients are treated as not found.

        Returns:
            True if token was found and revoked, False if not found.
        """
        token_hash = get_token_hash(token, key=self.token_hash_key)

        try:
            stored = await self.access_token_repository.get_one_by(
                token_hash=token_hash, client_id=client_id
            )
        except DoesNotExist:
            return False

        if stored.revoked_at is None:
            await self.access_token_repository.update_obj(
                stored, revoked_at=datetime.now(UTC)
            )
        return True

    async def revoke_refresh_token(self, token: str, client_id: str) -> bool:
        """Revoke a refresh token issued to `client_id`.

        Args:
            token: The refresh token to revoke.
            client_id: The client the token must belong to; tokens issued
                to other clients are treated as not found.

        Returns:
            True if token was found and revoked, False if not found.
        """
        token_hash = get_token_hash(token, key=self.token_hash_key)

        try:
            stored = await self.refresh_token_repository.get_one_by(
                token_hash=token_hash, client_id=client_id
            )
        except DoesNotExist:
            return False

        if stored.revoked_at is None:
            await self.refresh_token_repository.update_obj(
                stored, revoked_at=datetime.now(UTC)
            )
        return True

    async def introspect_access_token(self, token: str) -> dict[str, typing.Any] | None:
        """Introspect an access token.

        Args:
            token: The access token to introspect.

        Returns:
            Introspection response dict, or None if token not found.
        """
        token_hash = get_token_hash(token, key=self.token_hash_key)

        try:
            stored = await self.access_token_repository.get_one_by(
                token_hash=token_hash
            )
        except DoesNotExist:
            return None

        # Check if active
        now = datetime.now(UTC)
        is_active = stored.revoked_at is None and ensure_utc(stored.expires_at) > now

        if not is_active:
            return {"active": False}

        return {
            "active": True,
            "scope": stored.scope,
            "client_id": stored.client_id,
            "sub": stored.subject_id,
            "exp": int(ensure_utc(stored.expires_at).timestamp()),
            "iat": int(ensure_utc(stored.created_at).timestamp()),
            "token_type": "Bearer",  # RFC 7662 §2.2: the RFC 6749 §7.1 type
        }

    async def introspect_refresh_token(
        self, token: str
    ) -> dict[str, typing.Any] | None:
        """Introspect a refresh token.

        Args:
            token: The refresh token to introspect.

        Returns:
            Introspection response dict, or None if token not found.
        """
        token_hash = get_token_hash(token, key=self.token_hash_key)

        try:
            stored = await self.refresh_token_repository.get_one_by(
                token_hash=token_hash
            )
        except DoesNotExist:
            return None

        # Check if active
        now = datetime.now(UTC)
        is_active = stored.revoked_at is None
        if stored.expires_at:
            is_active = is_active and ensure_utc(stored.expires_at) > now

        if not is_active:
            return {"active": False}

        result: dict[str, typing.Any] = {
            "active": True,
            "scope": stored.scope,
            "client_id": stored.client_id,
            "sub": stored.subject_id,
            "iat": int(ensure_utc(stored.created_at).timestamp()),
        }
        if stored.expires_at:
            result["exp"] = int(ensure_utc(stored.expires_at).timestamp())

        return result


__all__ = [
    "AccessTokenResult",
    "OAuthTokenService",
    "TokenPair",
]
