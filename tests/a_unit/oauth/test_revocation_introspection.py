"""Revocation (RFC 7009) and introspection (RFC 7662) are scoped to the caller."""

from __future__ import annotations

import typing
from datetime import UTC, datetime, timedelta

import pytest
from pwdlib import PasswordHash

from neozen.core.crypto import get_token_hash
from neozen.core.oauth import OAuthClientService, OAuthTokenService
from neozen.core.oauth.exceptions import TokenInvalidClientError
from neozen.web.oauth import IntrospectionEndpoint, RevocationEndpoint
from tests.conftest import MockStorage

from .stubs import (
    MockOAuthAccessToken,
    MockOAuthAuthorizationCode,
    MockOAuthClient,
    MockOAuthRefreshToken,
)

pytestmark = pytest.mark.anyio

HASH_KEY = "hash-key"
SECRET = "rs-secret"
HASHER = PasswordHash.recommended()
TOKEN = "nz_at_alice"


@pytest.fixture
async def clients() -> MockStorage[MockOAuthClient]:
    storage = MockStorage(MockOAuthClient)
    await storage.create(client_id="app")  # public
    await storage.create(client_id="other")  # public
    await storage.create(
        client_id="rs",
        client_type="confidential",
        client_secret_hash=HASHER.hash(SECRET),
    )
    return storage


@pytest.fixture
async def access_tokens() -> MockStorage[MockOAuthAccessToken]:
    storage = MockStorage(MockOAuthAccessToken)
    now = datetime.now(UTC)
    await storage.create(
        token_hash=get_token_hash(TOKEN, key=HASH_KEY),
        client_id="app",
        subject_id="alice",
        scope="read",
        expires_at=now + timedelta(hours=1),
        created_at=now,
        revoked_at=None,
    )
    return storage


@pytest.fixture
def services(
    clients: MockStorage[MockOAuthClient],
    access_tokens: MockStorage[MockOAuthAccessToken],
) -> dict[str, typing.Any]:
    return {
        "client_service": OAuthClientService(clients, HASHER),
        "token_service": OAuthTokenService(
            clients,
            MockStorage(MockOAuthAuthorizationCode),
            access_tokens,
            MockStorage(MockOAuthRefreshToken),
            HASH_KEY,
        ),
    }


async def _revoked_at(storage: MockStorage[MockOAuthAccessToken]) -> datetime | None:
    [token] = await storage.get_many_by()
    return token.revoked_at


class TestRevocation:
    async def test_owner_revokes_its_token(
        self,
        services: dict[str, typing.Any],
        access_tokens: MockStorage[MockOAuthAccessToken],
    ) -> None:
        await RevocationEndpoint(**services)({"token": TOKEN}, client_id="app")
        assert await _revoked_at(access_tokens) is not None

    async def test_other_client_cannot_revoke(
        self,
        services: dict[str, typing.Any],
        access_tokens: MockStorage[MockOAuthAccessToken],
    ) -> None:
        # Still a success response (RFC 7009 §2.2), but nothing changes.
        await RevocationEndpoint(**services)({"token": TOKEN}, client_id="other")
        assert await _revoked_at(access_tokens) is None


class TestIntrospection:
    async def test_confidential_client_introspects(
        self, services: dict[str, typing.Any]
    ) -> None:
        response = await IntrospectionEndpoint(**services)(
            {"token": TOKEN}, client_id="rs", client_secret=SECRET
        )
        assert response.active
        assert response.sub == "alice"

    async def test_public_client_is_refused(
        self, services: dict[str, typing.Any]
    ) -> None:
        with pytest.raises(TokenInvalidClientError):
            await IntrospectionEndpoint(**services)({"token": TOKEN}, client_id="app")

    async def test_wrong_secret_is_refused(
        self, services: dict[str, typing.Any]
    ) -> None:
        with pytest.raises(TokenInvalidClientError):
            await IntrospectionEndpoint(**services)(
                {"token": TOKEN}, client_id="rs", client_secret="wrong"
            )
