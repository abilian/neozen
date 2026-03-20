"""Tests for OAuth client module."""

from __future__ import annotations

import dataclasses
import typing
from datetime import UTC, datetime, timedelta

import pytest

from neozen.core.oauth_client import (
    AuthorizationResult,
    CallbackResult,
    OAuthClientService,
    OAuthProviderConfig,
    OAuthProviderNotFoundError,
    OAuthStateError,
    OAuthTokens,
    OAuthUserInfo,
)
from neozen.core.oauth_client.providers.base import OAuthProvider
from tests.conftest import MockStorage


@dataclasses.dataclass
class MockOAuthState:
    state: str
    code_verifier: str
    redirect_uri: str
    provider_id: str
    existing_subject_id: str | None
    expires_at: datetime


@dataclasses.dataclass
class MockSocialAccount:
    id: str
    subject_id: str
    provider_id: str
    provider_user_id: str
    email: str | None
    display_name: str | None
    access_token: str | None
    refresh_token: str | None
    token_expires_at: datetime | None


class MockHttpResponse:
    """Mock HTTP response for testing."""

    def __init__(
        self, status_code: int, data: dict[str, typing.Any] | None = None
    ) -> None:
        self.status_code = status_code
        self._data = data or {}

    def json(self) -> dict[str, typing.Any]:
        return self._data

    @property
    def text(self) -> str:
        import json

        return json.dumps(self._data)


class MockHttpClient:
    """Mock HTTP client for testing."""

    def __init__(self) -> None:
        self.responses: dict[str, MockHttpResponse] = {}

    def set_response(self, url: str, response: MockHttpResponse) -> None:
        self.responses[url] = response

    async def get(
        self, url: str, headers: dict[str, str] | None = None
    ) -> MockHttpResponse:
        return self.responses.get(url, MockHttpResponse(404))

    async def post(
        self,
        url: str,
        data: dict[str, typing.Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> MockHttpResponse:
        return self.responses.get(url, MockHttpResponse(404))


@pytest.fixture
def state_storage() -> MockStorage[MockOAuthState]:
    return MockStorage(MockOAuthState, [])


@pytest.fixture
def social_account_storage() -> MockStorage[MockSocialAccount]:
    return MockStorage(MockSocialAccount, [])


@pytest.fixture
def http_client() -> MockHttpClient:
    return MockHttpClient()


@pytest.fixture
def test_config() -> OAuthProviderConfig:
    return OAuthProviderConfig(
        provider_id="test",
        client_id="test-client-id",
        client_secret="test-client-secret",
        authorization_endpoint="https://auth.test.com/authorize",
        token_endpoint="https://auth.test.com/token",
        userinfo_endpoint="https://api.test.com/userinfo",
        scopes=["openid", "email", "profile"],
        use_pkce=True,
    )


@pytest.fixture
def oauth_service(
    state_storage: MockStorage[MockOAuthState],
    social_account_storage: MockStorage[MockSocialAccount],
    http_client: MockHttpClient,
) -> OAuthClientService:
    return OAuthClientService(
        state_repository=state_storage,
        social_account_repository=social_account_storage,
        http_client=http_client,
    )


@pytest.mark.anyio
class TestOAuthProvider:
    """Tests for OAuth provider functionality."""

    def test_generate_state(self, test_config: OAuthProviderConfig) -> None:
        provider = OAuthProvider(config=test_config)
        state1 = provider.generate_state()
        state2 = provider.generate_state()

        assert len(state1) > 20
        assert state1 != state2

    def test_generate_code_verifier(self, test_config: OAuthProviderConfig) -> None:
        provider = OAuthProvider(config=test_config)
        verifier = provider.generate_code_verifier()

        assert len(verifier) > 40

    def test_generate_code_challenge(self, test_config: OAuthProviderConfig) -> None:
        provider = OAuthProvider(config=test_config)
        verifier = provider.generate_code_verifier()
        challenge = provider.generate_code_challenge(verifier)

        assert len(challenge) > 20
        assert challenge != verifier

    def test_get_authorization_url(self, test_config: OAuthProviderConfig) -> None:
        provider = OAuthProvider(config=test_config)
        url = provider.get_authorization_url(
            redirect_uri="https://app.test.com/callback",
            state="test-state",
            code_challenge="test-challenge",
        )

        assert url.startswith("https://auth.test.com/authorize?")
        assert "client_id=test-client-id" in url
        assert "redirect_uri=https%3A%2F%2Fapp.test.com%2Fcallback" in url
        assert "state=test-state" in url
        assert "code_challenge=test-challenge" in url
        assert "response_type=code" in url


@pytest.mark.anyio
class TestOAuthClientService:
    """Tests for OAuth client service."""

    async def test_register_provider(
        self,
        oauth_service: OAuthClientService,
        test_config: OAuthProviderConfig,
    ) -> None:
        provider = oauth_service.register_provider(test_config)

        assert provider.config.provider_id == "test"
        assert oauth_service.get_provider("test") is provider

    async def test_get_provider_not_found(
        self,
        oauth_service: OAuthClientService,
    ) -> None:
        with pytest.raises(OAuthProviderNotFoundError):
            oauth_service.get_provider("unknown")

    async def test_begin_authorization(
        self,
        oauth_service: OAuthClientService,
        test_config: OAuthProviderConfig,
        state_storage: MockStorage[MockOAuthState],
    ) -> None:
        oauth_service.register_provider(test_config)

        result = await oauth_service.begin_authorization(
            provider_id="test",
            redirect_uri="https://app.test.com/callback",
        )

        assert isinstance(result, AuthorizationResult)
        assert result.authorization_url.startswith("https://auth.test.com/authorize?")
        assert len(result.state) > 20

        # Check state was stored
        states = await state_storage.get_many_by()
        assert len(states) == 1
        assert states[0].state == result.state
        assert states[0].provider_id == "test"

    async def test_begin_authorization_for_linking(
        self,
        oauth_service: OAuthClientService,
        test_config: OAuthProviderConfig,
        state_storage: MockStorage[MockOAuthState],
    ) -> None:
        oauth_service.register_provider(test_config)

        await oauth_service.begin_authorization(
            provider_id="test",
            redirect_uri="https://app.test.com/callback",
            existing_subject_id="user123",
        )

        states = await state_storage.get_many_by()
        assert states[0].existing_subject_id == "user123"

    async def test_handle_callback_invalid_state(
        self,
        oauth_service: OAuthClientService,
        test_config: OAuthProviderConfig,
    ) -> None:
        oauth_service.register_provider(test_config)

        with pytest.raises(OAuthStateError):
            await oauth_service.handle_callback(
                provider_id="test",
                code="auth-code",
                state="invalid-state",
            )

    async def test_handle_callback_expired_state(
        self,
        oauth_service: OAuthClientService,
        test_config: OAuthProviderConfig,
        state_storage: MockStorage[MockOAuthState],
    ) -> None:
        oauth_service.register_provider(test_config)

        # Create expired state
        await state_storage.create(
            state="expired-state",
            code_verifier="verifier",
            redirect_uri="https://app.test.com/callback",
            provider_id="test",
            existing_subject_id=None,
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )

        with pytest.raises(OAuthStateError) as exc_info:
            await oauth_service.handle_callback(
                provider_id="test",
                code="auth-code",
                state="expired-state",
            )

        assert "expired" in str(exc_info.value.message)

    async def test_handle_callback_provider_mismatch(
        self,
        oauth_service: OAuthClientService,
        test_config: OAuthProviderConfig,
        state_storage: MockStorage[MockOAuthState],
    ) -> None:
        oauth_service.register_provider(test_config)

        # Create state for different provider
        await state_storage.create(
            state="test-state",
            code_verifier="verifier",
            redirect_uri="https://app.test.com/callback",
            provider_id="other-provider",
            existing_subject_id=None,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        with pytest.raises(OAuthStateError):
            await oauth_service.handle_callback(
                provider_id="test",
                code="auth-code",
                state="test-state",
            )

    async def test_link_account(
        self,
        oauth_service: OAuthClientService,
        social_account_storage: MockStorage[MockSocialAccount],
    ) -> None:
        callback_result = CallbackResult(
            tokens=OAuthTokens(
                access_token="access-token",
                refresh_token="refresh-token",
                expires_in=3600,
            ),
            user_info=OAuthUserInfo(
                provider_id="google",
                provider_user_id="12345",
                email="user@example.com",
                display_name="Test User",
            ),
        )

        account = await oauth_service.link_account("user123", callback_result)

        assert account.subject_id == "user123"
        assert account.provider_id == "google"
        assert account.provider_user_id == "12345"
        assert account.email == "user@example.com"

    async def test_get_or_create_subject_id_existing(
        self,
        oauth_service: OAuthClientService,
        social_account_storage: MockStorage[MockSocialAccount],
    ) -> None:
        # Create existing social account
        await social_account_storage.create(
            id="acc1",
            subject_id="user123",
            provider_id="google",
            provider_user_id="12345",
            email="user@example.com",
            display_name="Test User",
            access_token=None,
            refresh_token=None,
            token_expires_at=None,
        )

        callback_result = CallbackResult(
            tokens=OAuthTokens(access_token="token"),
            user_info=OAuthUserInfo(
                provider_id="google",
                provider_user_id="12345",
            ),
        )

        subject_id, is_new = await oauth_service.get_or_create_subject_id(
            callback_result
        )

        assert subject_id == "user123"
        assert is_new is False

    async def test_get_or_create_subject_id_new(
        self,
        oauth_service: OAuthClientService,
    ) -> None:
        callback_result = CallbackResult(
            tokens=OAuthTokens(access_token="token"),
            user_info=OAuthUserInfo(
                provider_id="google",
                provider_user_id="99999",
            ),
        )

        subject_id, is_new = await oauth_service.get_or_create_subject_id(
            callback_result
        )

        assert subject_id is None
        assert is_new is True

    async def test_unlink_account(
        self,
        oauth_service: OAuthClientService,
        social_account_storage: MockStorage[MockSocialAccount],
    ) -> None:
        # Create social account
        await social_account_storage.create(
            id="acc1",
            subject_id="user123",
            provider_id="google",
            provider_user_id="12345",
            email="user@example.com",
            display_name="Test User",
            access_token=None,
            refresh_token=None,
            token_expires_at=None,
        )

        await oauth_service.unlink_account("user123", "google")

        accounts = await social_account_storage.get_many_by(subject_id="user123")
        assert len(accounts) == 0

    async def test_get_linked_accounts(
        self,
        oauth_service: OAuthClientService,
        social_account_storage: MockStorage[MockSocialAccount],
    ) -> None:
        # Create multiple social accounts
        await social_account_storage.create(
            id="acc1",
            subject_id="user123",
            provider_id="google",
            provider_user_id="12345",
            email="user@gmail.com",
            display_name=None,
            access_token=None,
            refresh_token=None,
            token_expires_at=None,
        )
        await social_account_storage.create(
            id="acc2",
            subject_id="user123",
            provider_id="github",
            provider_user_id="67890",
            email="user@github.com",
            display_name=None,
            access_token=None,
            refresh_token=None,
            token_expires_at=None,
        )

        accounts = await oauth_service.get_linked_accounts("user123")

        assert len(accounts) == 2
        providers = {a.provider_id for a in accounts}
        assert providers == {"google", "github"}


@pytest.mark.anyio
class TestProviderConfigs:
    """Tests for provider configuration helpers."""

    def test_google_config(self) -> None:
        from neozen.core.oauth_client import create_google_config

        config = create_google_config(
            client_id="google-client-id",
            client_secret="google-client-secret",
        )

        assert config.provider_id == "google"
        assert config.client_id == "google-client-id"
        assert "openid" in config.scopes
        assert config.use_pkce is True
        assert "accounts.google.com" in config.authorization_endpoint

    def test_github_config(self) -> None:
        from neozen.core.oauth_client import create_github_config

        config = create_github_config(
            client_id="github-client-id",
            client_secret="github-client-secret",
        )

        assert config.provider_id == "github"
        assert config.client_id == "github-client-id"
        assert "read:user" in config.scopes
        assert config.use_pkce is False  # GitHub doesn't support PKCE
        assert "github.com" in config.authorization_endpoint
