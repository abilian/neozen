"""Tests for OAuth Token Endpoint HTTP adapter."""

from __future__ import annotations

import typing
from datetime import UTC, datetime, timedelta

import pytest
from pwdlib import PasswordHash

from neozen.core.crypto import get_token_hash
from neozen.core.oauth import (
    AuthorizationCodeNotFoundError,
    TokenInvalidClientError,
    TokenInvalidGrantError,
    TokenInvalidRequestError,
    TokenInvalidScopeError,
    TokenUnauthorizedClientError,
    TokenUnsupportedGrantTypeError,
)
from neozen.core.oauth.client_service import OAuthClientService
from neozen.core.oauth.services import OAuthTokenService
from neozen.web.oauth import TokenEndpoint, TokenResponse
from tests.conftest import MockStorage

from .stubs import (
    MockOAuthAccessToken,
    MockOAuthAuthorizationCode,
    MockOAuthClient,
    MockOAuthRefreshToken,
)

# =============================================================================
# Mock Models
# =============================================================================


# =============================================================================
# Fixtures
# =============================================================================


TOKEN_HASH_KEY = "test_secret_key"
SERVICE_SECRET = "service-secret"
HASHER = PasswordHash.recommended()


async def _create_service_client(
    storage: MockStorage[MockOAuthClient], **fields: typing.Any
) -> MockOAuthClient:
    """A confidential client authenticating with SERVICE_SECRET."""
    return await storage.create(
        client_id="svc_1",
        client_type="confidential",
        client_secret_hash=HASHER.hash(SERVICE_SECRET),
        **fields,
    )


async def _store_code(
    storage: MockStorage[MockOAuthAuthorizationCode], challenge: str | None
) -> None:
    await storage.create(
        code="test_code",
        client_id="client_1",
        subject_id="user_1",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        response_type="code",
        redirect_uri=None,
        scope="read",
        code_challenge=challenge,
        code_challenge_method="plain" if challenge else None,
    )


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
def client_service(
    client_storage: MockStorage[MockOAuthClient],
) -> OAuthClientService[MockOAuthClient]:
    return OAuthClientService(client_storage, HASHER)


@pytest.fixture
def token_endpoint(
    token_service: OAuthTokenService,
    client_service: OAuthClientService[MockOAuthClient],
) -> TokenEndpoint:
    return TokenEndpoint(token_service, client_service)


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
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")
        await _store_code(auth_code_storage, challenge="a" * 43)

        with pytest.raises(TokenInvalidGrantError):
            await token_endpoint({
                "grant_type": "authorization_code",
                "code": "test_code",
                "client_id": "client_1",
            })

    async def test_code_without_challenge_needs_no_verifier(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")
        await _store_code(auth_code_storage, challenge=None)

        response = await token_endpoint({
            "grant_type": "authorization_code",
            "code": "test_code",
            "client_id": "client_1",
        })

        assert response.access_token

    async def test_verifier_for_code_without_challenge_is_rejected(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_endpoint: TokenEndpoint,
    ) -> None:
        """RFC 9700 §4.8.2: PKCE downgrade attack."""
        await client_storage.create(client_id="client_1")
        await _store_code(auth_code_storage, challenge=None)

        with pytest.raises(TokenInvalidGrantError):
            await token_endpoint({
                "grant_type": "authorization_code",
                "code": "test_code",
                "client_id": "client_1",
                "code_verifier": "a" * 43,
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
# Tests: ID Token Integration (OIDC)
# =============================================================================


@pytest.mark.anyio
class TestIDTokenIntegration:
    async def _build_endpoint_with_oidc(
        self,
        token_service: OAuthTokenService,
    ) -> TokenEndpoint:
        from neozen.core.oidc.claims import DefaultClaimsProvider
        from neozen.core.oidc.id_token import IDTokenGenerator
        from neozen.core.oidc.keys import InMemoryKeyManager

        class _StubLookup:
            async def get_subject(self, subject_id: str) -> dict | None:
                if subject_id == "user_1":
                    return {
                        "id": "user_1",
                        "email": "alice@example.com",
                        "is_verified": True,
                        "name": "Alice",
                    }
                return None

        # Wrap dict access via getattr-friendly object
        class _Wrap:
            def __init__(self, data: dict) -> None:
                for k, v in data.items():
                    setattr(self, k, v)

        class _Lookup:
            async def get_subject(self, subject_id: str) -> object | None:
                stub = _StubLookup()
                data = await stub.get_subject(subject_id)
                if data is None:
                    return None
                return _Wrap(data)

        return TokenEndpoint(
            token_service,
            OAuthClientService(token_service.client_repository, HASHER),
            id_token_generator=IDTokenGenerator(
                key_manager=InMemoryKeyManager(),
                issuer="https://auth.test",
            ),
            claims_provider=DefaultClaimsProvider(_Lookup()),
        )

    async def test_authorization_code_returns_id_token_with_openid_scope(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_service: OAuthTokenService,
    ) -> None:
        endpoint = await self._build_endpoint_with_oidc(token_service)

        await client_storage.create(client_id="client_1")
        verifier = "a" * 43
        await auth_code_storage.create(
            code="oidc_code",
            client_id="client_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            response_type="code",
            redirect_uri="https://example.com/callback",
            scope="openid email",
            code_challenge=verifier,
            code_challenge_method="plain",
        )

        response = await endpoint({
            "grant_type": "authorization_code",
            "code": "oidc_code",
            "redirect_uri": "https://example.com/callback",
            "client_id": "client_1",
            "code_verifier": verifier,
        })

        assert response.id_token is not None
        # JWT structure
        assert response.id_token.count(".") == 2

    async def test_no_id_token_without_openid_scope(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_service: OAuthTokenService,
    ) -> None:
        endpoint = await self._build_endpoint_with_oidc(token_service)

        await client_storage.create(client_id="client_1")
        verifier = "a" * 43
        await auth_code_storage.create(
            code="non_oidc_code",
            client_id="client_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            response_type="code",
            redirect_uri="https://example.com/callback",
            scope="api:read",
            code_challenge=verifier,
            code_challenge_method="plain",
        )

        response = await endpoint({
            "grant_type": "authorization_code",
            "code": "non_oidc_code",
            "redirect_uri": "https://example.com/callback",
            "client_id": "client_1",
            "code_verifier": verifier,
        })

        assert response.id_token is None

    async def test_no_id_token_when_oidc_not_configured(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_endpoint: TokenEndpoint,  # uses the standard fixture without OIDC
    ) -> None:
        await client_storage.create(client_id="client_1")
        verifier = "a" * 43
        await auth_code_storage.create(
            code="code_without_oidc",
            client_id="client_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            response_type="code",
            redirect_uri="https://example.com/callback",
            scope="openid email",
            code_challenge=verifier,
            code_challenge_method="plain",
        )

        response = await token_endpoint({
            "grant_type": "authorization_code",
            "code": "code_without_oidc",
            "redirect_uri": "https://example.com/callback",
            "client_id": "client_1",
            "code_verifier": verifier,
        })

        # No ID token because endpoint has no id_token_generator
        assert response.id_token is None

    async def test_id_token_response_serialization(self) -> None:
        response = TokenResponse(
            access_token="at_123",
            token_type="Bearer",
            expires_in=3600,
            id_token="eyJhbG.payload.sig",
        )
        d = response.to_dict()
        assert d["id_token"] == "eyJhbG.payload.sig"


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
        await _create_service_client(
            client_storage,
            allowed_grant_types="client_credentials",
            allowed_scopes="api:read api:write",
        )

        response = await token_endpoint(
            {
                "grant_type": "client_credentials",
                "client_id": "svc_1",
                "scope": "api:read",
            },
            client_secret=SERVICE_SECRET,
        )

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
        await _create_service_client(
            client_storage,
            allowed_grant_types="client_credentials",
        )

        response = await token_endpoint(
            {
                "grant_type": "client_credentials",
                "client_id": "svc_1",
            },
            client_secret=SERVICE_SECRET,
        )

        assert isinstance(response, TokenResponse)
        assert response.scope is None

    async def test_client_id_from_basic_auth(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        """client_id can come from Basic auth header instead of body."""
        await _create_service_client(
            client_storage,
            allowed_grant_types="client_credentials",
        )

        response = await token_endpoint(
            {"grant_type": "client_credentials"},
            client_id="svc_1",
            client_secret=SERVICE_SECRET,
        )

        assert isinstance(response, TokenResponse)
        assert response.access_token.startswith("nz_at_")

    async def test_client_id_mismatch(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        """If client_id is in both body and auth header, they must match."""
        await _create_service_client(
            client_storage,
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
        await _create_service_client(
            client_storage,
            allowed_grant_types="authorization_code",  # No client_credentials
        )

        with pytest.raises(TokenInvalidGrantError):
            await token_endpoint(
                {
                    "grant_type": "client_credentials",
                    "client_id": "svc_1",
                },
                client_secret=SERVICE_SECRET,
            )

    async def test_scope_not_allowed(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await _create_service_client(
            client_storage,
            allowed_grant_types="client_credentials",
            allowed_scopes="api:read",
        )

        with pytest.raises(TokenInvalidScopeError):
            await token_endpoint(
                {
                    "grant_type": "client_credentials",
                    "client_id": "svc_1",
                    "scope": "api:write admin:all",
                },
                client_secret=SERVICE_SECRET,
            )

    async def test_token_subject_is_client(
        self,
        client_storage: MockStorage[MockOAuthClient],
        access_token_storage: MockStorage[MockOAuthAccessToken],
        token_endpoint: TokenEndpoint,
    ) -> None:
        """The token's subject_id should be the client_id itself."""
        await _create_service_client(
            client_storage,
            allowed_grant_types="client_credentials",
        )

        response = await token_endpoint(
            {
                "grant_type": "client_credentials",
                "client_id": "svc_1",
            },
            client_secret=SERVICE_SECRET,
        )

        token_hash = get_token_hash(response.access_token, TOKEN_HASH_KEY)
        stored = await access_token_storage.get_one_by(token_hash=token_hash)
        assert stored.subject_id == "svc_1"
        assert stored.client_id == "svc_1"

    async def test_wrong_secret_is_rejected(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await _create_service_client(
            client_storage, allowed_grant_types="client_credentials"
        )

        with pytest.raises(TokenInvalidClientError):
            await token_endpoint(
                {"grant_type": "client_credentials"},
                client_id="svc_1",
                client_secret="not-the-secret",
            )

    async def test_missing_secret_is_rejected(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await _create_service_client(
            client_storage, allowed_grant_types="client_credentials"
        )

        with pytest.raises(TokenInvalidClientError):
            await token_endpoint({
                "grant_type": "client_credentials",
                "client_id": "svc_1",
            })

    async def test_inactive_client_is_rejected(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await _create_service_client(
            client_storage, allowed_grant_types="client_credentials", is_active=False
        )

        with pytest.raises(TokenInvalidClientError):
            await token_endpoint(
                {"grant_type": "client_credentials"},
                client_id="svc_1",
                client_secret=SERVICE_SECRET,
            )

    async def test_public_client_cannot_use_grant(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(
            client_id="app", allowed_grant_types="client_credentials"
        )

        with pytest.raises(TokenUnauthorizedClientError):
            await token_endpoint({
                "grant_type": "client_credentials",
                "client_id": "app",
            })


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


@pytest.mark.anyio
class TestConfidentialCodeExchange:
    async def _seed(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
    ) -> None:
        await _create_service_client(client_storage)
        await auth_code_storage.create(
            code="test_code",
            client_id="svc_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            response_type="code",
            redirect_uri=None,
            scope="read",
            code_challenge="a" * 43,
            code_challenge_method="plain",
        )

    async def test_stolen_code_needs_the_client_secret(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await self._seed(client_storage, auth_code_storage)

        with pytest.raises(TokenInvalidClientError):
            await token_endpoint({
                "grant_type": "authorization_code",
                "code": "test_code",
                "client_id": "svc_1",
                "code_verifier": "a" * 43,
            })
        assert await auth_code_storage.count() == 1

    async def test_client_id_from_basic_auth_only(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await self._seed(client_storage, auth_code_storage)

        response = await token_endpoint(
            {
                "grant_type": "authorization_code",
                "code": "test_code",
                "code_verifier": "a" * 43,
            },
            client_id="svc_1",
            client_secret=SERVICE_SECRET,
        )

        assert response.access_token


@pytest.mark.anyio
async def test_challenge_without_method_fails_verification(
    client_storage: MockStorage[MockOAuthClient],
    auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
    token_endpoint: TokenEndpoint,
) -> None:
    """A half-filled PKCE row must not be treated as "no PKCE"."""
    await client_storage.create(client_id="client_1")
    verifier = "a" * 43
    await auth_code_storage.create(
        code="test_code",
        client_id="client_1",
        subject_id="user_1",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        response_type="code",
        redirect_uri=None,
        scope="read",
        code_challenge=verifier,
        code_challenge_method=None,
    )

    with pytest.raises(TokenInvalidGrantError):
        await token_endpoint({
            "grant_type": "authorization_code",
            "code": "test_code",
            "client_id": "client_1",
        })


@pytest.mark.anyio
async def test_code_cannot_be_exchanged_twice(
    client_storage: MockStorage[MockOAuthClient],
    auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
    token_endpoint: TokenEndpoint,
) -> None:
    """Even when both requests got past validation (a race)."""
    client = await client_storage.create(client_id="client_1")
    await _store_code(auth_code_storage, challenge=None)
    [code] = await auth_code_storage.get_many_by()
    service = token_endpoint.service

    await service.exchange_authorization_code(code, client)
    with pytest.raises(AuthorizationCodeNotFoundError):
        await service.exchange_authorization_code(code, client)


@pytest.mark.anyio
class TestRefreshTokenReuse:
    async def _refresh(self, endpoint: TokenEndpoint, token: str) -> TokenResponse:
        return await endpoint({
            "grant_type": "refresh_token",
            "refresh_token": token,
            "client_id": "client_1",
        })

    async def test_replayed_token_revokes_the_clients_tokens(
        self,
        client_storage: MockStorage[MockOAuthClient],
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        access_token_storage: MockStorage[MockOAuthAccessToken],
        token_endpoint: TokenEndpoint,
    ) -> None:
        await client_storage.create(client_id="client_1")
        old = "nz_rt_first"
        await refresh_token_storage.create(
            token_hash=get_token_hash(old, key=TOKEN_HASH_KEY),
            client_id="client_1",
            subject_id="user_1",
            scope="read",
            expires_at=datetime.now(UTC) + timedelta(days=30),
            created_at=datetime.now(UTC),
            revoked_at=None,
            access_token_hash=None,
        )
        rotated = await self._refresh(token_endpoint, old)  # rotates `old` out

        with pytest.raises(TokenInvalidGrantError):
            await self._refresh(token_endpoint, old)  # the leaked copy

        tokens = [
            *await refresh_token_storage.get_many_by(),
            *await access_token_storage.get_many_by(),
        ]
        assert all(token.revoked_at is not None for token in tokens)
        assert rotated.refresh_token
        with pytest.raises(TokenInvalidGrantError):
            await self._refresh(token_endpoint, rotated.refresh_token)

    async def test_public_client_tokens_rotate_even_if_disabled(
        self,
        client_storage: MockStorage[MockOAuthClient],
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        token_endpoint: TokenEndpoint,
    ) -> None:
        token_endpoint.service.rotate_refresh_tokens = False
        await client_storage.create(client_id="client_1")  # public
        await refresh_token_storage.create(
            token_hash=get_token_hash("nz_rt_x", key=TOKEN_HASH_KEY),
            client_id="client_1",
            subject_id="user_1",
            scope="read",
            expires_at=datetime.now(UTC) + timedelta(days=30),
            created_at=datetime.now(UTC),
            revoked_at=None,
            access_token_hash=None,
        )

        response = await self._refresh(token_endpoint, "nz_rt_x")

        assert response.refresh_token
