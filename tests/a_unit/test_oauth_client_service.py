"""Unit tests for OAuth client service."""

from __future__ import annotations

import json

import pytest

from neozen.core.oauth.client_service import OAuthClientService
from neozen.core.oauth.exceptions import (
    ClientAuthenticationError,
    ClientInactiveError,
    ClientNotFoundError,
    InvalidGrantTypeError,
    InvalidRedirectUriError,
    InvalidScopeError,
)
from tests.conftest import MockStorage


class MockOAuthClient:
    """Mock OAuth client for testing."""

    def __init__(
        self,
        client_id: str,
        client_name: str,
        client_secret_hash: str | None = None,
        client_type: str = "confidential",
        redirect_uris: str = "[]",
        allowed_scopes: str = "",
        allowed_grant_types: str = "authorization_code refresh_token",
        is_active: bool = True,
        **kwargs,
    ) -> None:
        self.client_id = client_id
        self.client_name = client_name
        self.client_secret_hash = client_secret_hash
        self.client_type = client_type
        self.redirect_uris = redirect_uris
        self.allowed_scopes = allowed_scopes
        self.allowed_grant_types = allowed_grant_types
        self.is_active = is_active
        self.created_at = kwargs.get("created_at")
        self.updated_at = kwargs.get("updated_at")

    def get_redirect_uris(self) -> list[str]:
        return json.loads(self.redirect_uris)

    def get_allowed_scopes(self) -> set[str]:
        if not self.allowed_scopes:
            return set()
        return set(self.allowed_scopes.split())

    def get_allowed_grant_types(self) -> set[str]:
        if not self.allowed_grant_types:
            return set()
        return set(self.allowed_grant_types.split())

    def is_redirect_uri_allowed(self, uri: str) -> bool:
        return uri in self.get_redirect_uris()

    def is_scope_allowed(self, scope: str) -> bool:
        allowed = self.get_allowed_scopes()
        if not allowed:
            return True
        return scope in allowed

    def is_grant_type_allowed(self, grant_type: str) -> bool:
        return grant_type in self.get_allowed_grant_types()

    def is_public_client(self) -> bool:
        return self.client_type == "public"

    def is_confidential_client(self) -> bool:
        return self.client_type == "confidential"


class MockHasher:
    """Mock password hasher for testing."""

    def hash(self, password: str) -> str:
        return f"hashed:{password}"

    def verify_and_update(
        self, password: str, hash_val: str
    ) -> tuple[bool, str | None]:
        expected = f"hashed:{password}"
        return (hash_val == expected, None)


@pytest.fixture
def client_storage() -> MockStorage[MockOAuthClient]:
    return MockStorage(MockOAuthClient, [])


@pytest.fixture
def hasher() -> MockHasher:
    return MockHasher()


@pytest.fixture
def client_service(
    client_storage: MockStorage[MockOAuthClient], hasher: MockHasher
) -> OAuthClientService[MockOAuthClient]:
    return OAuthClientService(
        client_repository=client_storage,
        hasher=hasher,
        client_id_length=16,
        client_secret_length=24,
    )


@pytest.mark.anyio
class TestClientCreation:
    """Tests for client creation."""

    async def test_create_confidential_client(
        self, client_service: OAuthClientService[MockOAuthClient]
    ) -> None:
        client, credentials = await client_service.create_client(
            client_name="Test App",
            redirect_uris=["https://app.com/callback"],
            client_type="confidential",
        )

        assert client.client_name == "Test App"
        assert client.client_type == "confidential"
        assert client.client_secret_hash is not None
        assert credentials.client_secret is not None
        assert credentials.client_id == client.client_id

    async def test_create_public_client(
        self, client_service: OAuthClientService[MockOAuthClient]
    ) -> None:
        client, credentials = await client_service.create_client(
            client_name="Mobile App",
            redirect_uris=["myapp://callback"],
            client_type="public",
        )

        assert client.client_name == "Mobile App"
        assert client.client_type == "public"
        assert client.client_secret_hash is None
        assert credentials.client_secret is None

    async def test_create_with_scopes(
        self, client_service: OAuthClientService[MockOAuthClient]
    ) -> None:
        client, _ = await client_service.create_client(
            client_name="Scoped App",
            redirect_uris=["https://app.com/callback"],
            allowed_scopes=["read", "write"],
        )

        assert client.allowed_scopes == "read write"

    async def test_create_with_grant_types(
        self, client_service: OAuthClientService[MockOAuthClient]
    ) -> None:
        client, _ = await client_service.create_client(
            client_name="Custom Grants",
            redirect_uris=["https://app.com/callback"],
            allowed_grant_types=["authorization_code"],
        )

        assert client.allowed_grant_types == "authorization_code"


@pytest.mark.anyio
class TestClientAuthentication:
    """Tests for client authentication."""

    async def test_authenticate_confidential_client(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        # Create client
        await client_storage.create(
            client_id="test123",
            client_name="Test",
            client_secret_hash="hashed:secret123",
            client_type="confidential",
        )

        client = await client_service.authenticate_client("test123", "secret123")
        assert client.client_id == "test123"

    async def test_authenticate_public_client_no_secret(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        await client_storage.create(
            client_id="public123",
            client_name="Public App",
            client_type="public",
        )

        client = await client_service.authenticate_client("public123", None)
        assert client.client_id == "public123"

    async def test_authenticate_wrong_secret(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        await client_storage.create(
            client_id="test123",
            client_name="Test",
            client_secret_hash="hashed:correct_secret",
            client_type="confidential",
        )

        with pytest.raises(ClientAuthenticationError):
            await client_service.authenticate_client("test123", "wrong_secret")

    async def test_authenticate_missing_secret(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        await client_storage.create(
            client_id="test123",
            client_name="Test",
            client_secret_hash="hashed:secret",
            client_type="confidential",
        )

        with pytest.raises(ClientAuthenticationError):
            await client_service.authenticate_client("test123", None)

    async def test_authenticate_unknown_client(
        self, client_service: OAuthClientService[MockOAuthClient]
    ) -> None:
        with pytest.raises(ClientNotFoundError):
            await client_service.authenticate_client("unknown", "secret")

    async def test_authenticate_inactive_client(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        await client_storage.create(
            client_id="inactive123",
            client_name="Inactive",
            client_type="public",
            is_active=False,
        )

        with pytest.raises(ClientInactiveError):
            await client_service.authenticate_client("inactive123", None)


@pytest.mark.anyio
class TestClientValidation:
    """Tests for client validation methods."""

    async def test_validate_redirect_uri_allowed(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        client = await client_storage.create(
            client_id="test",
            client_name="Test",
            redirect_uris='["https://app.com/callback"]',
        )

        # Should not raise
        client_service.validate_redirect_uri(client, "https://app.com/callback")

    async def test_validate_redirect_uri_not_allowed(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        client = await client_storage.create(
            client_id="test",
            client_name="Test",
            redirect_uris='["https://app.com/callback"]',
        )

        with pytest.raises(InvalidRedirectUriError):
            client_service.validate_redirect_uri(client, "https://evil.com/callback")

    async def test_validate_scope_allowed(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        client = await client_storage.create(
            client_id="test",
            client_name="Test",
            allowed_scopes="read write",
        )

        # Should not raise
        client_service.validate_scope(client, "read")
        client_service.validate_scope(client, "read write")

    async def test_validate_scope_not_allowed(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        client = await client_storage.create(
            client_id="test",
            client_name="Test",
            allowed_scopes="read",
        )

        with pytest.raises(InvalidScopeError):
            client_service.validate_scope(client, "write")

    async def test_validate_grant_type_allowed(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        client = await client_storage.create(
            client_id="test",
            client_name="Test",
            allowed_grant_types="authorization_code refresh_token",
        )

        # Should not raise
        client_service.validate_grant_type(client, "authorization_code")

    async def test_validate_grant_type_not_allowed(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        client = await client_storage.create(
            client_id="test",
            client_name="Test",
            allowed_grant_types="authorization_code",
        )

        with pytest.raises(InvalidGrantTypeError):
            client_service.validate_grant_type(client, "client_credentials")


@pytest.mark.anyio
class TestClientManagement:
    """Tests for client management operations."""

    async def test_deactivate_client(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        await client_storage.create(
            client_id="test",
            client_name="Test",
            is_active=True,
        )

        client = await client_service.deactivate_client("test")
        assert client.is_active is False

    async def test_activate_client(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        await client_storage.create(
            client_id="test",
            client_name="Test",
            is_active=False,
        )

        client = await client_service.activate_client("test")
        assert client.is_active is True

    async def test_rotate_secret(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        await client_storage.create(
            client_id="test",
            client_name="Test",
            client_type="confidential",
            client_secret_hash="hashed:old_secret",
        )

        new_secret = await client_service.rotate_secret("test")
        assert new_secret is not None
        assert len(new_secret) > 0

    async def test_rotate_secret_public_client_fails(
        self,
        client_service: OAuthClientService[MockOAuthClient],
        client_storage: MockStorage[MockOAuthClient],
    ) -> None:
        await client_storage.create(
            client_id="test",
            client_name="Test",
            client_type="public",
        )

        with pytest.raises(ClientAuthenticationError):
            await client_service.rotate_secret("test")
