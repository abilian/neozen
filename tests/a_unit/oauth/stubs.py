"""Stub OAuth models shared by the OAuth unit tests."""

from __future__ import annotations

import dataclasses
from datetime import datetime

from neozen.core.oauth import (
    CodeChallengeMethod,
    OAuthAccessTokenModel,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthRefreshTokenModel,
)


@dataclasses.dataclass
class MockOAuthClient(OAuthClientModel):
    client_id: str
    allowed_grant_types: str = ""
    allowed_scopes: str = ""
    client_type: str = "public"
    client_secret_hash: str | None = None
    is_active: bool = True


@dataclasses.dataclass
class MockOAuthAuthorizationCode(OAuthAuthorizationCodeModel):
    code: str
    client_id: str
    subject_id: str
    expires_at: datetime
    response_type: str
    redirect_uri: str | None
    scope: str
    code_challenge: str | None
    code_challenge_method: CodeChallengeMethod | None
    nonce: str | None = None


@dataclasses.dataclass
class MockOAuthAccessToken(OAuthAccessTokenModel):
    token_hash: str
    client_id: str
    subject_id: str
    scope: str
    expires_at: datetime
    created_at: datetime
    revoked_at: datetime | None


@dataclasses.dataclass
class MockOAuthRefreshToken(OAuthRefreshTokenModel):
    token_hash: str
    client_id: str
    subject_id: str
    scope: str
    expires_at: datetime | None
    created_at: datetime
    revoked_at: datetime | None
    access_token_hash: str | None
