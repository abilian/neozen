"""Base OAuth models for NeoZen."""

from __future__ import annotations

import typing
from datetime import datetime

from neozen.core.models import NeoZenModel
from neozen.core.oauth.types import CodeChallengeMethod


class OAuthClientModel(NeoZenModel):
    """Base model for OAuth client implementations."""

    client_id: str


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
