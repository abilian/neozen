"""Tests for OIDC HTTP endpoints (Discovery, JWKS, UserInfo)."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from neozen.core.crypto import get_token_hash
from neozen.core.oauth.models import (
    OAuthAccessTokenModel,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthRefreshTokenModel,
)
from neozen.core.oauth.services import OAuthTokenService
from neozen.core.oidc.claims import DefaultClaimsProvider
from neozen.core.oidc.discovery import build_metadata_from_base_url
from neozen.core.oidc.keys import InMemoryKeyManager
from neozen.web.oidc import (
    DiscoveryEndpoint,
    JWKSEndpoint,
    UserInfoEndpoint,
    UserInfoError,
)
from tests.conftest import MockStorage

# =============================================================================
# JWKS Endpoint
# =============================================================================


class TestJWKSEndpoint:
    @pytest.mark.anyio
    async def test_returns_jwks_dict(self) -> None:
        manager = InMemoryKeyManager()
        endpoint = JWKSEndpoint(manager)

        result = await endpoint()

        assert "keys" in result
        assert len(result["keys"]) == 1
        assert result["keys"][0]["kty"] == "RSA"
        assert result["keys"][0]["use"] == "sig"


# =============================================================================
# Discovery Endpoint
# =============================================================================


class TestDiscoveryEndpoint:
    @pytest.mark.anyio
    async def test_returns_metadata(self) -> None:
        metadata = build_metadata_from_base_url(
            issuer="https://auth.example.com",
            base_url="https://auth.example.com",
        )
        endpoint = DiscoveryEndpoint(metadata)

        result = await endpoint()

        assert result["issuer"] == "https://auth.example.com"
        assert "authorization_endpoint" in result
        assert "token_endpoint" in result
        assert "userinfo_endpoint" in result
        assert "jwks_uri" in result


# =============================================================================
# UserInfo Endpoint
# =============================================================================


@dataclasses.dataclass
class MockOAuthClient(OAuthClientModel):
    client_id: str


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


@dataclasses.dataclass
class MockSubject:
    id: str
    email: str | None = None
    is_verified: bool = False
    name: str | None = None
    username: str | None = None


class MockSubjectLookup:
    def __init__(self, subjects: dict[str, MockSubject] | None = None) -> None:
        self._subjects = subjects or {}

    async def get_subject(self, subject_id: str) -> Any | None:
        return self._subjects.get(subject_id)


TOKEN_HASH_KEY = "test-secret"


@pytest.fixture
def access_token_storage() -> MockStorage[MockOAuthAccessToken]:
    return MockStorage(MockOAuthAccessToken, [])


@pytest.fixture
def token_service(
    access_token_storage: MockStorage[MockOAuthAccessToken],
) -> OAuthTokenService[
    MockOAuthClient,
    OAuthAuthorizationCodeModel,
    MockOAuthAccessToken,
    MockOAuthRefreshToken,
]:
    return OAuthTokenService(
        client_repository=MockStorage(MockOAuthClient, []),
        authorization_code_repository=MockStorage(OAuthAuthorizationCodeModel, []),
        access_token_repository=access_token_storage,
        refresh_token_repository=MockStorage(MockOAuthRefreshToken, []),
        token_hash_key=TOKEN_HASH_KEY,
    )


@pytest.fixture
def claims_provider() -> DefaultClaimsProvider:
    return DefaultClaimsProvider(
        MockSubjectLookup({
            "user_1": MockSubject(
                id="user_1",
                email="alice@example.com",
                is_verified=True,
                name="Alice",
                username="alice",
            ),
        })
    )


@pytest.fixture
def userinfo_endpoint(
    token_service: OAuthTokenService,
    claims_provider: DefaultClaimsProvider,
) -> UserInfoEndpoint:
    return UserInfoEndpoint(
        token_service=token_service,
        claims_provider=claims_provider,
    )


async def _seed_token(
    storage: MockStorage[MockOAuthAccessToken],
    *,
    token: str,
    subject_id: str = "user_1",
    client_id: str = "client_1",
    scope: str = "openid email",
    expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
) -> None:
    """Helper to insert an access token into mock storage."""
    if expires_at is None:
        expires_at = datetime.now(UTC) + timedelta(hours=1)
    await storage.create(
        token_hash=get_token_hash(token, key=TOKEN_HASH_KEY),
        client_id=client_id,
        subject_id=subject_id,
        scope=scope,
        expires_at=expires_at,
        created_at=datetime.now(UTC),
        revoked_at=revoked_at,
    )


@pytest.mark.anyio
class TestUserInfoEndpoint:
    async def test_valid_token(
        self,
        userinfo_endpoint: UserInfoEndpoint,
        access_token_storage: MockStorage[MockOAuthAccessToken],
    ) -> None:
        await _seed_token(access_token_storage, token="valid_token_123")

        claims = await userinfo_endpoint("Bearer valid_token_123")

        assert claims["sub"] == "user_1"
        assert claims["email"] == "alice@example.com"
        assert claims["email_verified"] is True

    async def test_filters_by_scope(
        self,
        userinfo_endpoint: UserInfoEndpoint,
        access_token_storage: MockStorage[MockOAuthAccessToken],
    ) -> None:
        # Token has only openid scope -- email should be filtered out
        await _seed_token(
            access_token_storage,
            token="openid_only",
            scope="openid",
        )

        claims = await userinfo_endpoint("Bearer openid_only")

        assert "sub" in claims
        assert "email" not in claims
        assert "name" not in claims

    async def test_includes_profile_claims(
        self,
        userinfo_endpoint: UserInfoEndpoint,
        access_token_storage: MockStorage[MockOAuthAccessToken],
    ) -> None:
        await _seed_token(
            access_token_storage,
            token="profile_token",
            scope="openid profile",
        )

        claims = await userinfo_endpoint("Bearer profile_token")

        assert claims["name"] == "Alice"
        assert claims["preferred_username"] == "alice"

    async def test_missing_authorization_header(
        self,
        userinfo_endpoint: UserInfoEndpoint,
    ) -> None:
        with pytest.raises(UserInfoError) as exc_info:
            await userinfo_endpoint(None)

        assert exc_info.value.status_code == 401
        assert exc_info.value.error == "invalid_token"

    async def test_wrong_auth_scheme(
        self,
        userinfo_endpoint: UserInfoEndpoint,
    ) -> None:
        with pytest.raises(UserInfoError) as exc_info:
            await userinfo_endpoint("Basic abc123")

        assert exc_info.value.status_code == 401

    async def test_unknown_token(
        self,
        userinfo_endpoint: UserInfoEndpoint,
    ) -> None:
        with pytest.raises(UserInfoError) as exc_info:
            await userinfo_endpoint("Bearer nonexistent")

        assert exc_info.value.status_code == 401
        assert exc_info.value.error == "invalid_token"

    async def test_expired_token(
        self,
        userinfo_endpoint: UserInfoEndpoint,
        access_token_storage: MockStorage[MockOAuthAccessToken],
    ) -> None:
        await _seed_token(
            access_token_storage,
            token="expired",
            expires_at=datetime.now(UTC) - timedelta(seconds=10),
        )

        with pytest.raises(UserInfoError) as exc_info:
            await userinfo_endpoint("Bearer expired")

        assert exc_info.value.status_code == 401

    async def test_revoked_token(
        self,
        userinfo_endpoint: UserInfoEndpoint,
        access_token_storage: MockStorage[MockOAuthAccessToken],
    ) -> None:
        await _seed_token(
            access_token_storage,
            token="revoked",
            revoked_at=datetime.now(UTC),
        )

        with pytest.raises(UserInfoError) as exc_info:
            await userinfo_endpoint("Bearer revoked")

        assert exc_info.value.status_code == 401

    async def test_token_without_openid_scope(
        self,
        userinfo_endpoint: UserInfoEndpoint,
        access_token_storage: MockStorage[MockOAuthAccessToken],
    ) -> None:
        await _seed_token(
            access_token_storage,
            token="no_openid",
            scope="api:read",
        )

        with pytest.raises(UserInfoError) as exc_info:
            await userinfo_endpoint("Bearer no_openid")

        assert exc_info.value.status_code == 403
        assert exc_info.value.error == "insufficient_scope"

    async def test_unknown_subject(
        self,
        userinfo_endpoint: UserInfoEndpoint,
        access_token_storage: MockStorage[MockOAuthAccessToken],
    ) -> None:
        await _seed_token(
            access_token_storage,
            token="ghost",
            subject_id="ghost_user",
        )

        with pytest.raises(UserInfoError) as exc_info:
            await userinfo_endpoint("Bearer ghost")

        assert exc_info.value.status_code == 401

    async def test_error_response_format(self) -> None:
        err = UserInfoError(
            error="invalid_token",
            description="Token is bad",
            status_code=401,
        )
        body, status, headers = err.to_response()

        assert body == {
            "error": "invalid_token",
            "error_description": "Token is bad",
        }
        assert status == 401
        assert "WWW-Authenticate" in headers
        assert "Bearer" in headers["WWW-Authenticate"]
