"""Base OAuth models for NeoZen."""

from __future__ import annotations

import json
import typing
from datetime import datetime

from neozen.core.models import NeoZenModel
from neozen.core.oauth.types import CodeChallengeMethod


class OAuthClientModel(NeoZenModel):
    """Base model for OAuth client implementations.

    Attributes:
        client_id: Unique identifier for the client.
        client_name: Human-readable name for the client.
        client_secret_hash: Hashed client secret (None for public clients).
        client_type: "public" or "confidential".
        redirect_uris: JSON array of allowed redirect URIs.
        allowed_scopes: Space-separated list of allowed scopes.
        allowed_grant_types: Space-separated list of allowed grant types.
        token_endpoint_auth_method: Authentication method for token endpoint.
        is_active: Whether the client is active.
        created_at: When the client was created.
        updated_at: When the client was last updated.
    """

    client_id: str
    client_name: str
    client_secret_hash: str | None
    client_type: str  # "public" | "confidential"
    redirect_uris: str  # JSON array
    allowed_scopes: str  # Space-separated
    allowed_grant_types: str  # Space-separated
    token_endpoint_auth_method: str
    is_active: bool
    created_at: datetime
    updated_at: datetime | None

    def get_redirect_uris(self) -> list[str]:
        """Parse and return the list of allowed redirect URIs."""
        if not self.redirect_uris:
            return []
        try:
            return json.loads(self.redirect_uris)
        except json.JSONDecodeError:
            return []

    def is_redirect_uri_allowed(self, uri: str) -> bool:
        """Check if a redirect URI is allowed for this client."""
        return uri in self.get_redirect_uris()

    def is_scope_allowed(self, scope: str) -> bool:
        """Check if a scope is allowed for this client."""
        if not self.allowed_scopes:
            return True  # No restrictions
        allowed = set(self.allowed_scopes.split())
        requested = set(scope.split())
        return requested <= allowed

    def is_grant_type_allowed(self, grant_type: str) -> bool:
        """Check if a grant type is allowed for this client."""
        if not self.allowed_grant_types:
            return True  # No restrictions
        return grant_type in self.allowed_grant_types.split()

    def is_public_client(self) -> bool:
        """Check if this is a public client (no secret)."""
        return self.client_type == "public"

    def is_confidential_client(self) -> bool:
        """Check if this is a confidential client (has secret)."""
        return self.client_type == "confidential"


class OAuthGrantModel(NeoZenModel):
    """Base model for OAuth grant implementations."""

    client_id: str
    subject_id: typing.Any
    granted_at: datetime
    scope: str


class OAuthAuthorizationCodeModel(NeoZenModel):
    """Base model for OAuth authorization code implementations."""

    code: str
    client_id: str
    subject_id: typing.Any
    expires_at: datetime
    response_type: str
    redirect_uri: str | None
    scope: str
    code_challenge: str
    code_challenge_method: CodeChallengeMethod


class OAuthAccessTokenModel(NeoZenModel):
    """Base model for OAuth access token implementations.

    Access tokens are short-lived tokens used to access protected resources.
    They should be stored with their hash, not the plaintext token.

    Attributes:
        token_hash: HMAC-SHA256 hash of the token (for lookup).
        client_id: The OAuth client that requested the token.
        subject_id: The subject (user) who authorized the token.
        scope: Space-separated list of granted scopes.
        expires_at: When the token expires.
        created_at: When the token was created.
        revoked_at: When the token was revoked (None if active).

    """

    token_hash: str
    client_id: str
    subject_id: typing.Any
    scope: str
    expires_at: datetime
    created_at: datetime
    revoked_at: datetime | None


class OAuthRefreshTokenModel(NeoZenModel):
    """Base model for OAuth refresh token implementations.

    Refresh tokens are long-lived tokens used to obtain new access tokens.
    They should be stored with their hash, not the plaintext token.

    Attributes:
        token_hash: HMAC-SHA256 hash of the token (for lookup).
        client_id: The OAuth client that requested the token.
        subject_id: The subject (user) who authorized the token.
        scope: Space-separated list of granted scopes.
        expires_at: When the token expires (None for non-expiring).
        created_at: When the token was created.
        revoked_at: When the token was revoked (None if active).
        access_token_hash: Hash of the associated access token (optional).

    """

    token_hash: str
    client_id: str
    subject_id: typing.Any
    scope: str
    expires_at: datetime | None
    created_at: datetime
    revoked_at: datetime | None
    access_token_hash: str | None


__all__ = [
    "OAuthAccessTokenModel",
    "OAuthAuthorizationCodeModel",
    "OAuthClientModel",
    "OAuthGrantModel",
    "OAuthRefreshTokenModel",
]
