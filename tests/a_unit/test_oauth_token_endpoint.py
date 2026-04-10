"""Tests for OAuth Token Endpoint HTTP adapter."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from neozen.core.crypto import get_token_hash
from neozen.core.oauth import (
    CodeChallengeMethod,
    OAuthAccessTokenModel,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthRefreshTokenModel,
    TokenInvalidClientError,
    TokenInvalidGrantError,
    TokenInvalidRequestError,
    TokenInvalidScopeError,
    TokenUnsupportedGrantTypeError,
)
from neozen.core.oauth.services import OAuthTokenService
from neozen.web.oauth import TokenEndpoint, TokenResponse
from tests.conftest import MockStorage

# =============================================================================
# Mock Models
# =============================================================================


@dataclasses.dataclass
class MockOAuthClient(OAuthClientModel):
    client_id: str
    allowed_grant_types: str = ""
    allowed_scopes: str = ""


@dataclasses.dataclass
class MockOAuthAuthorizationCode(OAuthAuthorizationCodeModel):
    code: str
    client_id: str
    subject_id: str
    expires_at: datetime
    response_type: str
    redirect_uri: str | None
    scope: str
    code_challenge: str
    code_challenge_method: CodeChallengeMethod


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


# =============================================================================
# Fixtures
# =============================================================================


TOKEN_HASH_KEY = "test_secret_key"


@pytest.fixture
def client_storage() -> MockStorage[MockOAuthClient]:
    return MockStorage(MockOAuthClient, [])


@pytest.fixture
def auth_code_storage() -> MockStorage[MockOAuthAuthorizationCode]:
    return MockStorage(MockOAuthAuthorizationCode, [])


@pytest.fixture
def access_token_storage() -> MockStorage[MockOAuthAccessToken]:
    return MockStorage(MockOAuthAccessToken, [])


@pytest.fixture
def refresh_token_storage() -> MockStorage[MockOAuthRefreshToken]:
    return MockStorage(MockOAuthRefreshToken, [])


@pytest.fixture
def token_service(
    client_storage: MockStorage[MockOAuthClient],
    auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
    access_token_storage: MockStorage[MockOAuthAccessToken],
    refresh_token_storage: MockStorage[MockOAuthRefreshToken],
) -> OAuthTokenService[
    MockOAuthClient,
    MockOAuthAuthorizationCode,
    MockOAuthAccessToken,
    MockOAuthRefreshToken,
]:
    return OAuthTokenService(
        client_repository=client_storage,
        authorization_code_repository=auth_code_storage,
        access_token_repository=access_token_storage,
        refresh_token_repository=refresh_token_storage,
        token_hash_key=TOKEN_HASH_KEY,
    )


@pytest.fixture
def token_endpoint(
    token_service: OAuthTokenService,
) -> TokenEndpoint:
    return TokenEndpoint(token_service)


# =============================================================================
# Tests: Grant Type Handling
# =============================================================================


@pytest.mark.anyio
class TestGrantTypeHandling:
    async def test_missing_grant_type(self, token_endpoint: TokenEndpoint) -> None:
        with pytest.raises(TokenInvalidRequestError) as exc_info:
            await token_endpoint({})

        assert "grant_type" in exc_info.value.error_description

    async def test_unsupported_grant_type(self, token_endpoint: TokenEndpoint) -> None:
        with pytest.raises(TokenUnsupportedGrantTypeError) as exc_info:
            await token_endpoint({"grant_type": "password"})

        assert exc_info.value.error == "unsupported_grant_type"


# =============================================================================
# Tests: Authorization Code Grant
# =============================================================================


@pytest.mark.anyio
class TestAuthorizationCodeGrant:
    async def test_success(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")
        verifier = "a" * 43
        await auth_code_storage.create(
            code="test_code",
            client_id="client_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            response_type="code",
            redirect_uri="https://example.com/callback",
            scope="read write",
            code_challenge=verifier,
            code_challenge_method="plain",
        )

        response = await token_endpoint({
            "grant_type": "authorization_code",
            "code": "test_code",
            "redirect_uri": "https://example.com/callback",
            "client_id": "client_1",
            "code_verifier": verifier,
        })

        assert isinstance(response, TokenResponse)
        assert response.access_token.startswith("nz_at_")
        assert response.refresh_token.startswith("nz_rt_")
        assert response.token_type == "Bearer"
        assert response.expires_in == 3600
        assert response.scope == "read write"

    async def test_missing_code_verifier(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")

        with pytest.raises(TokenInvalidRequestError):
            await token_endpoint({
                "grant_type": "authorization_code",
                "code": "test_code",
                "client_id": "client_1",
            })

    async def test_unknown_client(
        self,
        token_endpoint: TokenEndpoint,
    ) -> None:
        with pytest.raises(TokenInvalidClientError):
            await token_endpoint({
                "grant_type": "authorization_code",
                "code": "test_code",
                "client_id": "nonexistent",
                "code_verifier": "a" * 43,
            })

    async def test_code_not_found(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")

        with pytest.raises(TokenInvalidGrantError) as exc_info:
            await token_endpoint({
                "grant_type": "authorization_code",
                "code": "nonexistent_code",
                "client_id": "client_1",
                "code_verifier": "a" * 43,
            })

        assert "not found" in exc_info.value.error_description

    async def test_expired_code(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")
        verifier = "a" * 43
        await auth_code_storage.create(
            code="expired_code",
            client_id="client_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),  # expired
            response_type="code",
            redirect_uri=None,
            scope="read",
            code_challenge=verifier,
            code_challenge_method="plain",
        )

        with pytest.raises(TokenInvalidGrantError) as exc_info:
            await token_endpoint({
                "grant_type": "authorization_code",
                "code": "expired_code",
                "client_id": "client_1",
                "code_verifier": verifier,
            })

        assert "expired" in exc_info.value.error_description

    async def test_pkce_failure(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")
        # Both strings must be at least 43 chars for valid PKCE
        correct_challenge = "correct_challenge_43_chars_xxxxxxxxxxxxxxxxxx"
        wrong_verifier = "wrong_verifier_43_chars_xxxxxxxxxxxxxxxxxxxxxx"
        await auth_code_storage.create(
            code="test_code",
            client_id="client_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            response_type="code",
            redirect_uri=None,
            scope="read",
            code_challenge=correct_challenge,
            code_challenge_method="plain",
        )

        with pytest.raises(TokenInvalidGrantError) as exc_info:
            await token_endpoint({
                "grant_type": "authorization_code",
                "code": "test_code",
                "client_id": "client_1",
                "code_verifier": wrong_verifier,
            })

        assert "PKCE" in exc_info.value.error_description

    async def test_client_id_mismatch_in_auth_header(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")

        with pytest.raises(TokenInvalidClientError) as exc_info:
            await token_endpoint(
                {
                    "grant_type": "authorization_code",
                    "code": "test_code",
                    "client_id": "client_1",
                    "code_verifier": "a" * 43,
                },
                client_id="different_client",  # Basic auth client_id
            )

        assert "mismatch" in exc_info.value.error_description.lower()


# =============================================================================
# Tests: Refresh Token Grant
# =============================================================================


@pytest.mark.anyio
class TestRefreshTokenGrant:
    async def test_success(
        self,
        client_storage: MockStorage[MockOAuthClient],
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")

        # Create refresh token with known value
        raw_token = "nz_rt_test_refresh_token"
        token_hash = get_token_hash(raw_token, key=TOKEN_HASH_KEY)
        await refresh_token_storage.create(
            token_hash=token_hash,
            client_id="client_1",
            subject_id="user_1",
            scope="read write",
            expires_at=datetime.now(UTC) + timedelta(days=30),
            created_at=datetime.now(UTC),
            revoked_at=None,
            access_token_hash=None,
        )

        response = await token_endpoint({
            "grant_type": "refresh_token",
            "refresh_token": raw_token,
            "client_id": "client_1",
        })

        assert isinstance(response, TokenResponse)
        assert response.access_token.startswith("nz_at_")
        assert response.token_type == "Bearer"
        # New refresh token due to rotation
        assert response.refresh_token.startswith("nz_rt_")

    async def test_missing_client_id(
        self,
        token_endpoint: TokenEndpoint,
    ) -> None:
        with pytest.raises(TokenInvalidRequestError) as exc_info:
            await token_endpoint({
                "grant_type": "refresh_token",
                "refresh_token": "some_token",
            })

        assert "client_id" in exc_info.value.error_description

    async def test_token_not_found(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")

        with pytest.raises(TokenInvalidGrantError) as exc_info:
            await token_endpoint({
                "grant_type": "refresh_token",
                "refresh_token": "nonexistent_token",
                "client_id": "client_1",
            })

        assert "not found" in exc_info.value.error_description

    async def test_token_revoked(
        self,
        client_storage: MockStorage[MockOAuthClient],
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")

        raw_token = "nz_rt_revoked_token"
        token_hash = get_token_hash(raw_token, key=TOKEN_HASH_KEY)
        await refresh_token_storage.create(
            token_hash=token_hash,
            client_id="client_1",
            subject_id="user_1",
            scope="read",
            expires_at=datetime.now(UTC) + timedelta(days=30),
            created_at=datetime.now(UTC),
            revoked_at=datetime.now(UTC),  # revoked
            access_token_hash=None,
        )

        with pytest.raises(TokenInvalidGrantError) as exc_info:
            await token_endpoint({
                "grant_type": "refresh_token",
                "refresh_token": raw_token,
                "client_id": "client_1",
            })

        assert "revoked" in exc_info.value.error_description

    async def test_scope_downgrade(
        self,
        client_storage: MockStorage[MockOAuthClient],
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")

        raw_token = "nz_rt_scope_test"
        token_hash = get_token_hash(raw_token, key=TOKEN_HASH_KEY)
        await refresh_token_storage.create(
            token_hash=token_hash,
            client_id="client_1",
            subject_id="user_1",
            scope="read write",
            expires_at=datetime.now(UTC) + timedelta(days=30),
            created_at=datetime.now(UTC),
            revoked_at=None,
            access_token_hash=None,
        )

        response = await token_endpoint({
            "grant_type": "refresh_token",
            "refresh_token": raw_token,
            "client_id": "client_1",
            "scope": "read",  # downgraded scope
        })

        assert response.scope == "read"

    async def test_scope_exceeds_grant(
        self,
        client_storage: MockStorage[MockOAuthClient],
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")

        raw_token = "nz_rt_scope_exceed"
        token_hash = get_token_hash(raw_token, key=TOKEN_HASH_KEY)
        await refresh_token_storage.create(
            token_hash=token_hash,
            client_id="client_1",
            subject_id="user_1",
            scope="read",
            expires_at=datetime.now(UTC) + timedelta(days=30),
            created_at=datetime.now(UTC),
            revoked_at=None,
            access_token_hash=None,
        )

        with pytest.raises(TokenInvalidScopeError):
            await token_endpoint({
                "grant_type": "refresh_token",
                "refresh_token": raw_token,
                "client_id": "client_1",
                "scope": "read write delete",  # exceeds original
            })


# =============================================================================
# Tests: Client Credentials Grant
# =============================================================================


@pytest.mark.anyio
class TestClientCredentialsGrant:
    async def test_success(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(
            client_id="svc_1",
            allowed_grant_types="client_credentials",
            allowed_scopes="api:read api:write",
        )

        response = await token_endpoint({
            "grant_type": "client_credentials",
            "client_id": "svc_1",
            "scope": "api:read",
        })

        assert isinstance(response, TokenResponse)
        assert response.access_token.startswith("nz_at_")
        assert response.token_type == "Bearer"
        assert response.expires_in == 3600
        assert response.scope == "api:read"
        # No refresh token for client_credentials per RFC 6749 Section 4.4
        assert response.refresh_token is None

    async def test_no_scope(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        """Scope is optional for client_credentials."""
        await client_storage.create(
            client_id="svc_1",
            allowed_grant_types="client_credentials",
        )

        response = await token_endpoint({
            "grant_type": "client_credentials",
            "client_id": "svc_1",
        })

        assert isinstance(response, TokenResponse)
        assert response.scope is None

    async def test_client_id_from_basic_auth(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        """client_id can come from Basic auth header instead of body."""
        await client_storage.create(
            client_id="svc_1",
            allowed_grant_types="client_credentials",
        )

        response = await token_endpoint(
            {"grant_type": "client_credentials"},
            client_id="svc_1",
            client_secret="secret",
        )

        assert isinstance(response, TokenResponse)
        assert response.access_token.startswith("nz_at_")

    async def test_client_id_mismatch(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        """If client_id is in both body and auth header, they must match."""
        await client_storage.create(
            client_id="svc_1",
            allowed_grant_types="client_credentials",
        )

        with pytest.raises(TokenInvalidClientError):
            await token_endpoint(
                {
                    "grant_type": "client_credentials",
                    "client_id": "svc_1",
                },
                client_id="svc_2",
            )

    async def test_missing_client_id(
        self,
        token_endpoint: TokenEndpoint,
    ) -> None:
        with pytest.raises(TokenInvalidRequestError):
            await token_endpoint({"grant_type": "client_credentials"})

    async def test_unknown_client(
        self,
        token_endpoint: TokenEndpoint,
    ) -> None:
        with pytest.raises(TokenInvalidClientError):
            await token_endpoint({
                "grant_type": "client_credentials",
                "client_id": "nonexistent",
            })

    async def test_grant_type_not_allowed(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        """Client must have client_credentials in allowed_grant_types."""
        await client_storage.create(
            client_id="svc_1",
            allowed_grant_types="authorization_code",  # No client_credentials
        )

        with pytest.raises(TokenInvalidGrantError):
            await token_endpoint({
                "grant_type": "client_credentials",
                "client_id": "svc_1",
            })

    async def test_scope_not_allowed(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(
            client_id="svc_1",
            allowed_grant_types="client_credentials",
            allowed_scopes="api:read",
        )

        with pytest.raises(TokenInvalidScopeError):
            await token_endpoint({
                "grant_type": "client_credentials",
                "client_id": "svc_1",
                "scope": "api:write admin:all",
            })

    async def test_token_subject_is_client(
        self,
        client_storage: MockStorage[MockOAuthClient],
        access_token_storage: MockStorage[MockOAuthAccessToken],
        token_endpoint: TokenEndpoint,
    ) -> None:
        """The token's subject_id should be the client_id itself."""
        await client_storage.create(
            client_id="svc_1",
            allowed_grant_types="client_credentials",
        )

        response = await token_endpoint({
            "grant_type": "client_credentials",
            "client_id": "svc_1",
        })

        token_hash = get_token_hash(response.access_token, TOKEN_HASH_KEY)
        stored = await access_token_storage.get_one_by(token_hash=token_hash)
        assert stored.subject_id == "svc_1"
        assert stored.client_id == "svc_1"


# =============================================================================
# Tests: TokenResponse
# =============================================================================


class TestTokenResponse:
    def test_to_dict_minimal(self) -> None:
        response = TokenResponse(
            access_token="at_123",
            token_type="Bearer",
            expires_in=3600,
        )

        result = response.to_dict()

        assert result == {
            "access_token": "at_123",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

    def test_to_dict_full(self) -> None:
        response = TokenResponse(
            access_token="at_123",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="rt_456",
            scope="read write",
        )

        result = response.to_dict()

        assert result == {
            "access_token": "at_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rt_456",
            "scope": "read write",
        }
