"""Tests for OAuth authorization code grant."""

from __future__ import annotations

import dataclasses
from datetime import datetime

import pytest

from neozen.core.oauth import (
    AuthorizationCodeGrant,
    AuthorizationCodeGrantConsentResponse,
    AuthorizationCodeGrantGrantedResponse,
    AuthorizationCodeGrantRedirectionError,
    CodeChallengeMethod,
    MissingOrInvalidClientIDError,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthGrantModel,
    UnauthenticatedSubjectError,
)
from neozen.core.subject import Subject
from tests.conftest import MockStorage


@dataclasses.dataclass
class MockSubject(Subject):
    id: str


@dataclasses.dataclass
class MockOAuthClient(OAuthClientModel):
    client_id: str


@dataclasses.dataclass
class MockOAuthGrant(OAuthGrantModel):
    client_id: str
    subject_id: str
    granted_at: datetime
    scope: str


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


@pytest.fixture
def client_storage() -> MockStorage[MockOAuthClient]:
    return MockStorage(MockOAuthClient, [])


@pytest.fixture
def grant_storage() -> MockStorage[MockOAuthGrant]:
    return MockStorage(MockOAuthGrant, [])


@pytest.fixture
def authorization_code_storage() -> MockStorage[MockOAuthAuthorizationCode]:
    return MockStorage(MockOAuthAuthorizationCode, [])


@pytest.fixture
def authorization_code_grant(
    client_storage: MockStorage[MockOAuthClient],
    grant_storage: MockStorage[MockOAuthGrant],
    authorization_code_storage: MockStorage[MockOAuthAuthorizationCode],
) -> AuthorizationCodeGrant[
    MockOAuthClient, MockOAuthGrant, MockOAuthAuthorizationCode
]:
    return AuthorizationCodeGrant(
        oauth_client_storage=client_storage,
        oauth_grant_storage=grant_storage,
        oauth_authorization_code_storage=authorization_code_storage,
        code_hash_key="test_secret_key",
        code_prefix="nz_test_",
    )


def _valid_payload(client_id: str = "test_client") -> dict:
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "read write",
        "state": "random_state",
        "code_challenge": "a" * 43,
        "code_challenge_method": "plain",
    }


@pytest.mark.anyio
class TestAuthorizationCodeGrant:
    async def test_unauthenticated_subject(
        self,
        authorization_code_grant: AuthorizationCodeGrant[
            MockOAuthClient, MockOAuthGrant, MockOAuthAuthorizationCode
        ],
    ) -> None:
        with pytest.raises(UnauthenticatedSubjectError):
            await authorization_code_grant(None, _valid_payload())

    async def test_invalid_request(
        self,
        client_storage: MockStorage[MockOAuthClient],
        authorization_code_grant: AuthorizationCodeGrant[
            MockOAuthClient, MockOAuthGrant, MockOAuthAuthorizationCode
        ],
    ) -> None:
        # Client must exist for redirect errors to occur
        await client_storage.create(client_id="test_client")
        subject = MockSubject(id="user_1")

        # Missing code_challenge should cause an invalid_request error
        payload = _valid_payload()
        del payload["code_challenge"]

        with pytest.raises(AuthorizationCodeGrantRedirectionError) as exc_info:
            await authorization_code_grant(subject, payload)

        assert exc_info.value.error == "invalid_request"

    async def test_missing_client_id(
        self,
        authorization_code_grant: AuthorizationCodeGrant[
            MockOAuthClient, MockOAuthGrant, MockOAuthAuthorizationCode
        ],
    ) -> None:
        subject = MockSubject(id="user_1")
        payload = _valid_payload()
        del payload["client_id"]

        with pytest.raises(MissingOrInvalidClientIDError):
            await authorization_code_grant(subject, payload)

    async def test_invalid_client_id(
        self,
        authorization_code_grant: AuthorizationCodeGrant[
            MockOAuthClient, MockOAuthGrant, MockOAuthAuthorizationCode
        ],
    ) -> None:
        subject = MockSubject(id="user_1")

        with pytest.raises(MissingOrInvalidClientIDError):
            await authorization_code_grant(subject, _valid_payload("nonexistent"))

    async def test_consent_required(
        self,
        client_storage: MockStorage[MockOAuthClient],
        authorization_code_grant: AuthorizationCodeGrant[
            MockOAuthClient, MockOAuthGrant, MockOAuthAuthorizationCode
        ],
    ) -> None:
        await client_storage.create(client_id="test_client")
        subject = MockSubject(id="user_1")

        result = await authorization_code_grant(subject, _valid_payload())

        assert isinstance(result, AuthorizationCodeGrantConsentResponse)
        assert result.client.client_id == "test_client"
        assert result.scope == "read write"
        assert result.state == "random_state"

    async def test_authorization_granted(
        self,
        client_storage: MockStorage[MockOAuthClient],
        grant_storage: MockStorage[MockOAuthGrant],
        authorization_code_grant: AuthorizationCodeGrant[
            MockOAuthClient, MockOAuthGrant, MockOAuthAuthorizationCode
        ],
    ) -> None:
        await client_storage.create(client_id="test_client")
        await grant_storage.create(
            client_id="test_client",
            subject_id="user_1",
            granted_at=datetime.now(),
            scope="read write",
        )
        subject = MockSubject(id="user_1")

        result = await authorization_code_grant(subject, _valid_payload())

        assert isinstance(result, AuthorizationCodeGrantGrantedResponse)
        assert result.subject.id == "user_1"
        assert result.client.client_id == "test_client"
        assert result.code.startswith("nz_test_")
        assert len(result.code) == len("nz_test_") + 43

    async def test_authorization_code_stored(
        self,
        client_storage: MockStorage[MockOAuthClient],
        grant_storage: MockStorage[MockOAuthGrant],
        authorization_code_storage: MockStorage[MockOAuthAuthorizationCode],
        authorization_code_grant: AuthorizationCodeGrant[
            MockOAuthClient, MockOAuthGrant, MockOAuthAuthorizationCode
        ],
    ) -> None:
        await client_storage.create(client_id="test_client")
        await grant_storage.create(
            client_id="test_client",
            subject_id="user_1",
            granted_at=datetime.now(),
            scope="read write",
        )
        subject = MockSubject(id="user_1")

        result = await authorization_code_grant(subject, _valid_payload())

        assert isinstance(result, AuthorizationCodeGrantGrantedResponse)
        assert result.authorization_code.client_id == "test_client"
        assert result.authorization_code.subject_id == "user_1"
        assert result.authorization_code.scope == "read write"
        assert result.authorization_code.code_challenge == "a" * 43
        assert result.authorization_code.code_challenge_method == "plain"
