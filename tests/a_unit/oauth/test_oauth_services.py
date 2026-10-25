"""Tests for OAuth Token Service."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from neozen.core.crypto import get_token_hash
from neozen.core.oauth import (
    AuthorizationCodeExpiredError,
    AuthorizationCodeNotFoundError,
    ClientMismatchError,
    CodeChallengeMethod,
    InvalidClientError,
    OAuthAccessTokenModel,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthRefreshTokenModel,
    PKCEVerificationFailedError,
    RedirectUriMismatchError,
    RefreshTokenExpiredError,
    RefreshTokenNotFoundError,
    RefreshTokenRevokedError,
    ScopeExceedsGrantError,
)
from neozen.core.oauth.services import OAuthTokenService
from tests.conftest import MockStorage

# =============================================================================
# Mock Models
# =============================================================================


@dataclasses.dataclass
class MockOAuthClient(OAuthClientModel):
    client_id: str
    client_type: str = "confidential"


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


# =============================================================================
# Tests: get_client
# =============================================================================


@pytest.mark.anyio
class TestGetClient:
    async def test_returns_client(
        self,
        client_storage: MockStorage[MockOAuthClient],
        token_service: OAuthTokenService,
    ) -> None:
        await client_storage.create(client_id="test_client")

        client = await token_service.get_client("test_client")

        assert client.client_id == "test_client"

    async def test_raises_invalid_client_error_when_not_found(
        self,
        token_service: OAuthTokenService,
    ) -> None:
        with pytest.raises(InvalidClientError):
            await token_service.get_client("nonexistent")


# =============================================================================
# Tests: validate_authorization_code
# =============================================================================


@pytest.mark.anyio
class TestValidateAuthorizationCode:
    async def test_returns_valid_code(
        self,
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_service: OAuthTokenService,
    ) -> None:
        verifier = "a" * 43
        await auth_code_storage.create(
            code="test_code",
            client_id="client_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            response_type="code",
            redirect_uri="https://example.com/callback",
            scope="read write",
            code_challenge=verifier,  # plain method
            code_challenge_method="plain",
        )

        auth_code = await token_service.validate_authorization_code(
            code="test_code",
            client_id="client_1",
            redirect_uri="https://example.com/callback",
            code_verifier=verifier,
        )

        assert auth_code.code == "test_code"
        assert auth_code.client_id == "client_1"

    async def test_raises_not_found_error(
        self,
        token_service: OAuthTokenService,
    ) -> None:
        with pytest.raises(AuthorizationCodeNotFoundError):
            await token_service.validate_authorization_code(
                code="nonexistent",
                client_id="client_1",
                redirect_uri=None,
                code_verifier="a" * 43,
            )

    async def test_raises_client_mismatch_error(
        self,
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_service: OAuthTokenService,
    ) -> None:
        await auth_code_storage.create(
            code="test_code",
            client_id="client_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            response_type="code",
            redirect_uri=None,
            scope="read",
            code_challenge="a" * 43,
            code_challenge_method="plain",
        )

        with pytest.raises(ClientMismatchError):
            await token_service.validate_authorization_code(
                code="test_code",
                client_id="different_client",
                redirect_uri=None,
                code_verifier="a" * 43,
            )

    async def test_raises_expired_error(
        self,
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_service: OAuthTokenService,
    ) -> None:
        await auth_code_storage.create(
            code="test_code",
            client_id="client_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),  # expired
            response_type="code",
            redirect_uri=None,
            scope="read",
            code_challenge="a" * 43,
            code_challenge_method="plain",
        )

        with pytest.raises(AuthorizationCodeExpiredError):
            await token_service.validate_authorization_code(
                code="test_code",
                client_id="client_1",
                redirect_uri=None,
                code_verifier="a" * 43,
            )

    async def test_raises_redirect_uri_mismatch_error(
        self,
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_service: OAuthTokenService,
    ) -> None:
        await auth_code_storage.create(
            code="test_code",
            client_id="client_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            response_type="code",
            redirect_uri="https://example.com/callback",
            scope="read",
            code_challenge="a" * 43,
            code_challenge_method="plain",
        )

        with pytest.raises(RedirectUriMismatchError):
            await token_service.validate_authorization_code(
                code="test_code",
                client_id="client_1",
                redirect_uri="https://different.com/callback",
                code_verifier="a" * 43,
            )

    async def test_raises_pkce_verification_failed(
        self,
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_service: OAuthTokenService,
    ) -> None:
        await auth_code_storage.create(
            code="test_code",
            client_id="client_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            response_type="code",
            redirect_uri=None,
            scope="read",
            code_challenge="correct_challenge_43_chars_xxxxxxxxxxxxxxx",
            code_challenge_method="plain",
        )

        with pytest.raises(PKCEVerificationFailedError):
            await token_service.validate_authorization_code(
                code="test_code",
                client_id="client_1",
                redirect_uri=None,
                code_verifier="wrong_verifier_43_chars_xxxxxxxxxxxxxxxxx",
            )


# =============================================================================
# Tests: validate_refresh_token
# =============================================================================


@pytest.mark.anyio
class TestValidateRefreshToken:
    async def test_returns_valid_token(
        self,
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        token_service: OAuthTokenService,
    ) -> None:
        # Create a token with known hash
        raw_token = "nz_rt_test_token_value"
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

        stored = await token_service.validate_refresh_token(
            refresh_token=raw_token,
            client_id="client_1",
        )

        assert stored.client_id == "client_1"

    async def test_raises_not_found_error(
        self,
        token_service: OAuthTokenService,
    ) -> None:
        with pytest.raises(RefreshTokenNotFoundError):
            await token_service.validate_refresh_token(
                refresh_token="nonexistent_token",
                client_id="client_1",
            )

    async def test_raises_revoked_error(
        self,
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        token_service: OAuthTokenService,
    ) -> None:
        raw_token = "nz_rt_test_token_revoked"
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

        with pytest.raises(RefreshTokenRevokedError):
            await token_service.validate_refresh_token(
                refresh_token=raw_token,
                client_id="client_1",
            )

    async def test_raises_expired_error(
        self,
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        token_service: OAuthTokenService,
    ) -> None:
        raw_token = "nz_rt_test_token_expired"
        token_hash = get_token_hash(raw_token, key=TOKEN_HASH_KEY)

        await refresh_token_storage.create(
            token_hash=token_hash,
            client_id="client_1",
            subject_id="user_1",
            scope="read",
            expires_at=datetime.now(UTC) - timedelta(days=1),  # expired
            created_at=datetime.now(UTC) - timedelta(days=31),
            revoked_at=None,
            access_token_hash=None,
        )

        with pytest.raises(RefreshTokenExpiredError):
            await token_service.validate_refresh_token(
                refresh_token=raw_token,
                client_id="client_1",
            )

    async def test_raises_client_mismatch_error(
        self,
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        token_service: OAuthTokenService,
    ) -> None:
        raw_token = "nz_rt_test_token_mismatch"
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

        with pytest.raises(ClientMismatchError):
            await token_service.validate_refresh_token(
                refresh_token=raw_token,
                client_id="different_client",
            )


# =============================================================================
# Tests: validate_scope_downgrade
# =============================================================================


class TestValidateScopeDowngrade:
    def test_returns_original_when_no_request(
        self, token_service: OAuthTokenService
    ) -> None:
        result = token_service.validate_scope_downgrade(None, "read write")
        assert result == "read write"

    def test_returns_requested_when_valid_subset(
        self, token_service: OAuthTokenService
    ) -> None:
        result = token_service.validate_scope_downgrade("read", "read write")
        assert result == "read"

    def test_returns_same_scope(self, token_service: OAuthTokenService) -> None:
        result = token_service.validate_scope_downgrade("read write", "read write")
        assert result == "read write"

    def test_raises_error_when_exceeds_original(
        self, token_service: OAuthTokenService
    ) -> None:
        with pytest.raises(ScopeExceedsGrantError):
            token_service.validate_scope_downgrade("read write delete", "read write")

    def test_raises_error_when_original_is_none(
        self, token_service: OAuthTokenService
    ) -> None:
        with pytest.raises(ScopeExceedsGrantError):
            token_service.validate_scope_downgrade("read", None)


# =============================================================================
# Tests: exchange_authorization_code
# =============================================================================


@pytest.mark.anyio
class TestExchangeAuthorizationCode:
    async def test_creates_tokens(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        access_token_storage: MockStorage[MockOAuthAccessToken],
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        token_service: OAuthTokenService,
    ) -> None:
        client = await client_storage.create(client_id="client_1")
        auth_code = await auth_code_storage.create(
            code="test_code",
            client_id="client_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            response_type="code",
            redirect_uri=None,
            scope="read write",
            code_challenge="a" * 43,
            code_challenge_method="plain",
        )

        token_pair = await token_service.exchange_authorization_code(auth_code, client)

        assert token_pair.access_token.startswith("nz_at_")
        assert token_pair.refresh_token.startswith("nz_rt_")
        assert token_pair.scope == "read write"
        assert len(access_token_storage._data) == 1
        assert len(refresh_token_storage._data) == 1

    async def test_deletes_authorization_code_after_exchange(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        token_service: OAuthTokenService,
    ) -> None:
        """OAuth 2.1 §4.1.2: authorization codes MUST be single-use.

        After a successful exchange, the code row must be gone so that a
        second exchange attempt raises AuthorizationCodeNotFoundError.
        """
        client = await client_storage.create(client_id="client_1")
        auth_code = await auth_code_storage.create(
            code="test_code_single_use",
            client_id="client_1",
            subject_id="user_1",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            response_type="code",
            redirect_uri=None,
            scope="read",
            code_challenge="a" * 43,
            code_challenge_method="plain",
        )

        assert len(auth_code_storage._data) == 1
        await token_service.exchange_authorization_code(auth_code, client)
        assert len(auth_code_storage._data) == 0


# =============================================================================
# Tests: refresh_access_token
# =============================================================================


@pytest.mark.anyio
class TestRefreshAccessToken:
    async def test_creates_new_access_token(
        self,
        client_storage: MockStorage[MockOAuthClient],
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        access_token_storage: MockStorage[MockOAuthAccessToken],
        token_service: OAuthTokenService,
    ) -> None:
        client = await client_storage.create(client_id="client_1")
        stored_refresh = await refresh_token_storage.create(
            token_hash="old_hash",
            client_id="client_1",
            subject_id="user_1",
            scope="read write",
            expires_at=datetime.now(UTC) + timedelta(days=30),
            created_at=datetime.now(UTC),
            revoked_at=None,
            access_token_hash=None,
        )

        result = await token_service.refresh_access_token(
            stored_refresh, client, "read write"
        )

        assert result.access_token.startswith("nz_at_")
        assert result.scope == "read write"
        assert len(access_token_storage._data) == 1

    async def test_rotates_refresh_token_by_default(
        self,
        client_storage: MockStorage[MockOAuthClient],
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        access_token_storage: MockStorage[MockOAuthAccessToken],
        token_service: OAuthTokenService,
    ) -> None:
        client = await client_storage.create(client_id="client_1")
        stored_refresh = await refresh_token_storage.create(
            token_hash="old_hash",
            client_id="client_1",
            subject_id="user_1",
            scope="read write",
            expires_at=datetime.now(UTC) + timedelta(days=30),
            created_at=datetime.now(UTC),
            revoked_at=None,
            access_token_hash=None,
        )

        result = await token_service.refresh_access_token(
            stored_refresh, client, "read write"
        )

        # Old token should be revoked
        assert stored_refresh.revoked_at is not None
        # New refresh token should be created
        assert result.new_refresh_token is not None
        assert result.new_refresh_token.startswith("nz_rt_")
        # Should have 2 refresh tokens now (old revoked + new)
        assert len(refresh_token_storage._data) == 2

    async def test_no_rotation_when_disabled(
        self,
        client_storage: MockStorage[MockOAuthClient],
        auth_code_storage: MockStorage[MockOAuthAuthorizationCode],
        refresh_token_storage: MockStorage[MockOAuthRefreshToken],
        access_token_storage: MockStorage[MockOAuthAccessToken],
    ) -> None:
        service = OAuthTokenService(
            client_repository=client_storage,
            authorization_code_repository=auth_code_storage,
            access_token_repository=access_token_storage,
            refresh_token_repository=refresh_token_storage,
            token_hash_key=TOKEN_HASH_KEY,
            rotate_refresh_tokens=False,
        )

        client = await client_storage.create(client_id="client_1")
        stored_refresh = await refresh_token_storage.create(
            token_hash="old_hash",
            client_id="client_1",
            subject_id="user_1",
            scope="read write",
            expires_at=datetime.now(UTC) + timedelta(days=30),
            created_at=datetime.now(UTC),
            revoked_at=None,
            access_token_hash=None,
        )

        result = await service.refresh_access_token(stored_refresh, client, "read")

        # Old token should NOT be revoked
        assert stored_refresh.revoked_at is None
        # No new refresh token
        assert result.new_refresh_token is None
        # Only 1 refresh token
        assert len(refresh_token_storage._data) == 1
