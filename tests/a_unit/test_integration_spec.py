"""Tests for features from the LiteSaaS integration spec.

Covers:
- Split RepositoryProtocol (ReadableRepositoryProtocol, WritableRepositoryProtocol)
- SessionService.list_sessions()
- OAuth token refresh
- Type-safe factory functions (create_email_identifier, create_password_factor)
"""

from __future__ import annotations

import typing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from neozen.core.repository import (
    DoesNotExist,
    ReadableRepositoryProtocol,
    RepositoryProtocol,
    WritableRepositoryProtocol,
)

# =============================================================================
# Repository Protocol Split Tests
# =============================================================================


@dataclass
class MockModel:
    id: str
    name: str


class ReadOnlyRepo:
    """Implements only ReadableRepositoryProtocol."""

    def __init__(self, items: list[MockModel] | None = None) -> None:
        self._items = items or []

    async def get_one_by(self, **filters: typing.Any) -> MockModel:
        for item in self._items:
            if all(getattr(item, k) == v for k, v in filters.items()):
                return item
        raise DoesNotExist

    async def get_many_by(
        self, *, offset: int = 0, limit: int | None = None, **filters: typing.Any
    ) -> list[MockModel]:
        results = [
            item
            for item in self._items
            if all(getattr(item, k, None) == v for k, v in filters.items())
        ]
        return results[offset : offset + limit if limit else len(results)]

    async def count(self, **filters: typing.Any) -> int:
        return len([
            item
            for item in self._items
            if all(getattr(item, k, None) == v for k, v in filters.items())
        ])

    async def exists(self, **filters: typing.Any) -> bool:
        return await self.count(**filters) > 0


class WriteOnlyRepo:
    """Implements only WritableRepositoryProtocol."""

    def __init__(self) -> None:
        self._items: list[MockModel] = []

    async def create(self, **data: typing.Any) -> MockModel:
        item = MockModel(**data)
        self._items.append(item)
        return item

    async def update_obj(self, obj: MockModel, **data: typing.Any) -> MockModel:
        for k, v in data.items():
            setattr(obj, k, v)
        return obj

    async def delete(self, obj: MockModel) -> None:
        self._items.remove(obj)


class TestRepositoryProtocolSplit:
    """Tests for ReadableRepositoryProtocol and WritableRepositoryProtocol."""

    def test_readable_protocol_is_runtime_checkable(self) -> None:
        repo = ReadOnlyRepo([MockModel(id="1", name="test")])
        assert isinstance(repo, ReadableRepositoryProtocol)

    def test_writable_protocol_is_runtime_checkable(self) -> None:
        repo = WriteOnlyRepo()
        assert isinstance(repo, WritableRepositoryProtocol)

    def test_readable_is_not_writable(self) -> None:
        repo = ReadOnlyRepo()
        assert not isinstance(repo, WritableRepositoryProtocol)

    def test_writable_is_not_readable(self) -> None:
        repo = WriteOnlyRepo()
        assert not isinstance(repo, ReadableRepositoryProtocol)

    @pytest.mark.anyio
    async def test_read_only_repo_get_one_by(self) -> None:
        repo = ReadOnlyRepo([MockModel(id="1", name="alice")])
        result = await repo.get_one_by(id="1")
        assert result.name == "alice"

    @pytest.mark.anyio
    async def test_read_only_repo_not_found(self) -> None:
        repo = ReadOnlyRepo([])
        with pytest.raises(DoesNotExist):
            await repo.get_one_by(id="missing")

    @pytest.mark.anyio
    async def test_write_only_repo_create(self) -> None:
        repo = WriteOnlyRepo()
        item = await repo.create(id="1", name="bob")
        assert item.id == "1"
        assert len(repo._items) == 1

    @pytest.mark.anyio
    async def test_full_protocol_is_both(self) -> None:
        """RepositoryProtocol should satisfy both Read and Write."""
        assert issubclass(RepositoryProtocol, ReadableRepositoryProtocol)
        assert issubclass(RepositoryProtocol, WritableRepositoryProtocol)


# =============================================================================
# SessionService.list_sessions() Tests
# =============================================================================


@dataclass
class MockSession:
    token_hash: str
    subject_id: str
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(UTC) + timedelta(days=7)
    )
    last_activity_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    revoked_at: datetime | None = None


class MockSessionStorage:
    """Mock storage for session tests."""

    model_type = MockSession

    def __init__(self) -> None:
        self._sessions: list[MockSession] = []

    async def get_one_by(self, **filters: typing.Any) -> MockSession:
        for s in self._sessions:
            if all(getattr(s, k) == v for k, v in filters.items()):
                return s
        raise DoesNotExist

    async def get_many_by(
        self, *, offset: int = 0, limit: int | None = None, **filters: typing.Any
    ) -> list[MockSession]:
        results = [
            s
            for s in self._sessions
            if all(getattr(s, k, None) == v for k, v in filters.items())
        ]
        return results[offset : offset + limit if limit else len(results)]

    async def count(self, **filters: typing.Any) -> int:
        return len(await self.get_many_by(**filters))

    async def exists(self, **filters: typing.Any) -> bool:
        return await self.count(**filters) > 0

    async def create(self, **data: typing.Any) -> MockSession:
        s = MockSession(**data)
        self._sessions.append(s)
        return s

    async def update_obj(self, obj: MockSession, **data: typing.Any) -> MockSession:
        for k, v in data.items():
            setattr(obj, k, v)
        return obj

    async def delete(self, obj: MockSession) -> None:
        self._sessions.remove(obj)


class TestListSessions:
    """Tests for SessionService.list_sessions()."""

    @pytest.mark.anyio
    async def test_list_sessions_returns_active(self) -> None:
        from neozen.core.session.service import SessionService

        storage = MockSessionStorage()
        service = SessionService(storage=storage, hash_key="test")

        # Create a session via the service
        token = await service.create_session("user1", ip_address="1.2.3.4")
        assert token is not None

        sessions = await service.list_sessions("user1")
        assert len(sessions) == 1
        assert sessions[0].subject_id == "user1"

    @pytest.mark.anyio
    async def test_list_sessions_excludes_revoked(self) -> None:
        from neozen.core.session.service import SessionService

        storage = MockSessionStorage()
        service = SessionService(storage=storage, hash_key="test")

        await service.create_session("user1")
        token2 = await service.create_session("user1")

        # Revoke second session
        await service.revoke_session_by_token(token2)

        sessions = await service.list_sessions("user1")
        assert len(sessions) == 1

    @pytest.mark.anyio
    async def test_list_sessions_includes_revoked_when_requested(self) -> None:
        from neozen.core.session.service import SessionService

        storage = MockSessionStorage()
        service = SessionService(storage=storage, hash_key="test")

        await service.create_session("user1")
        token2 = await service.create_session("user1")
        await service.revoke_session_by_token(token2)

        sessions = await service.list_sessions("user1", include_revoked=True)
        assert len(sessions) == 2

    @pytest.mark.anyio
    async def test_list_sessions_excludes_expired(self) -> None:
        from neozen.core.session.service import SessionService

        storage = MockSessionStorage()
        # Very short session lifetime
        service = SessionService(
            storage=storage, hash_key="test", session_lifetime_seconds=0
        )

        await service.create_session("user1")

        sessions = await service.list_sessions("user1")
        assert len(sessions) == 0

    @pytest.mark.anyio
    async def test_list_sessions_includes_expired_when_requested(self) -> None:
        from neozen.core.session.service import SessionService

        storage = MockSessionStorage()
        service = SessionService(
            storage=storage, hash_key="test", session_lifetime_seconds=0
        )

        await service.create_session("user1")

        sessions = await service.list_sessions("user1", include_expired=True)
        assert len(sessions) == 1

    @pytest.mark.anyio
    async def test_list_sessions_filters_by_subject(self) -> None:
        from neozen.core.session.service import SessionService

        storage = MockSessionStorage()
        service = SessionService(storage=storage, hash_key="test")

        await service.create_session("user1")
        await service.create_session("user2")

        sessions = await service.list_sessions("user1")
        assert len(sessions) == 1
        assert sessions[0].subject_id == "user1"


# =============================================================================
# OAuth Token Refresh Tests
# =============================================================================


class MockHTTPResponse:
    def __init__(self, status_code: int, json_data: dict) -> None:
        self.status_code = status_code
        self._json = json_data

    def json(self) -> dict:
        return self._json


class MockHTTPClient:
    """Mock HTTP client for OAuth tests."""

    def __init__(self, responses: list[MockHTTPResponse] | None = None) -> None:
        self._responses = responses or []
        self._call_index = 0
        self.requests: list[dict] = []

    async def post(self, url: str, **kwargs: typing.Any) -> MockHTTPResponse:
        self.requests.append({"method": "POST", "url": url, **kwargs})
        if self._call_index < len(self._responses):
            resp = self._responses[self._call_index]
            self._call_index += 1
            return resp
        return MockHTTPResponse(500, {"error": "no mock response"})


class TestOAuthTokenRefresh:
    """Tests for OAuthProvider.refresh_access_token()."""

    @pytest.mark.anyio
    async def test_refresh_access_token(self) -> None:
        from neozen.core.oauth_client.models import OAuthProviderConfig
        from neozen.core.oauth_client.providers.base import OAuthProvider

        http_client = MockHTTPClient([
            MockHTTPResponse(
                200,
                {
                    "access_token": "new_access_token",
                    "token_type": "Bearer",
                    "refresh_token": "new_refresh_token",
                    "expires_in": 3600,
                },
            )
        ])

        provider = OAuthProvider(
            config=OAuthProviderConfig(
                provider_id="test",
                display_name="Test",
                authorization_endpoint="https://example.com/auth",
                token_endpoint="https://example.com/token",
                client_id="client_id",
                client_secret="client_secret",
            ),
            http_client=http_client,
        )

        tokens = await provider.refresh_access_token("old_refresh_token")

        assert tokens.access_token == "new_access_token"
        assert tokens.refresh_token == "new_refresh_token"
        assert tokens.expires_in == 3600

        # Verify the request
        req = http_client.requests[0]
        assert req["url"] == "https://example.com/token"
        assert req["data"]["grant_type"] == "refresh_token"
        assert req["data"]["refresh_token"] == "old_refresh_token"

    @pytest.mark.anyio
    async def test_refresh_preserves_old_refresh_token(self) -> None:
        """If provider doesn't return new refresh token, keep the old one."""
        from neozen.core.oauth_client.models import OAuthProviderConfig
        from neozen.core.oauth_client.providers.base import OAuthProvider

        http_client = MockHTTPClient([
            MockHTTPResponse(
                200,
                {
                    "access_token": "new_access",
                    "token_type": "Bearer",
                    # No refresh_token in response
                },
            )
        ])

        provider = OAuthProvider(
            config=OAuthProviderConfig(
                provider_id="test",
                display_name="Test",
                authorization_endpoint="https://example.com/auth",
                token_endpoint="https://example.com/token",
                client_id="cid",
                client_secret="csecret",
            ),
            http_client=http_client,
        )

        tokens = await provider.refresh_access_token("keep_this_token")
        assert tokens.refresh_token == "keep_this_token"

    @pytest.mark.anyio
    async def test_refresh_fails_on_error(self) -> None:
        from neozen.core.oauth_client.exceptions import OAuthTokenError
        from neozen.core.oauth_client.models import OAuthProviderConfig
        from neozen.core.oauth_client.providers.base import OAuthProvider

        http_client = MockHTTPClient([
            MockHTTPResponse(401, {"error": "invalid_grant"})
        ])

        provider = OAuthProvider(
            config=OAuthProviderConfig(
                provider_id="test",
                display_name="Test",
                authorization_endpoint="https://example.com/auth",
                token_endpoint="https://example.com/token",
                client_id="cid",
                client_secret="csecret",
            ),
            http_client=http_client,
        )

        with pytest.raises(OAuthTokenError, match="Token refresh failed"):
            await provider.refresh_access_token("bad_token")

    @pytest.mark.anyio
    async def test_refresh_fails_without_http_client(self) -> None:
        from neozen.core.oauth_client.exceptions import OAuthTokenError
        from neozen.core.oauth_client.models import OAuthProviderConfig
        from neozen.core.oauth_client.providers.base import OAuthProvider

        provider = OAuthProvider(
            config=OAuthProviderConfig(
                provider_id="test",
                display_name="Test",
                authorization_endpoint="https://example.com/auth",
                token_endpoint="https://example.com/token",
                client_id="cid",
                client_secret="csecret",
            ),
        )

        with pytest.raises(OAuthTokenError, match="HTTP client is required"):
            await provider.refresh_access_token("token")


# =============================================================================
# Factory Function Tests
# =============================================================================


@dataclass
class CustomUser:
    """User model that does NOT inherit from EmailSubjectModel."""

    id: str
    email: str
    hashed_password: str | None
    is_active: bool = True


class CustomUserRepo:
    """Repository that works with CustomUser."""

    def __init__(self, users: list[CustomUser] | None = None) -> None:
        self._users = users or []

    async def get_one_by(self, **filters: typing.Any) -> CustomUser:
        for u in self._users:
            if all(getattr(u, k) == v for k, v in filters.items()):
                return u
        raise DoesNotExist

    async def get_many_by(
        self, *, offset: int = 0, limit: int | None = None, **filters: typing.Any
    ) -> list[CustomUser]:
        return [
            u
            for u in self._users
            if all(getattr(u, k, None) == v for k, v in filters.items())
        ]

    async def count(self, **filters: typing.Any) -> int:
        return len(await self.get_many_by(**filters))

    async def exists(self, **filters: typing.Any) -> bool:
        return await self.count(**filters) > 0

    async def create(self, **data: typing.Any) -> CustomUser:
        u = CustomUser(**data)
        self._users.append(u)
        return u

    async def update_obj(self, obj: CustomUser, **data: typing.Any) -> CustomUser:
        for k, v in data.items():
            setattr(obj, k, v)
        return obj

    async def delete(self, obj: CustomUser) -> None:
        self._users.remove(obj)


class TestFactoryFunctions:
    """Tests for create_email_identifier and create_password_factor."""

    def test_create_email_identifier(self) -> None:
        from neozen.core.identifiers.email import create_email_identifier

        repo = CustomUserRepo([
            CustomUser(id="1", email="a@b.com", hashed_password=None)
        ])
        identifier = create_email_identifier(repo)
        assert identifier is not None

    @pytest.mark.anyio
    async def test_create_email_identifier_lookup(self) -> None:
        from neozen.core.identifiers.email import create_email_identifier

        repo = CustomUserRepo([
            CustomUser(id="1", email="a@b.com", hashed_password=None)
        ])
        identifier = create_email_identifier(repo)
        user = await identifier.get_by_identifier("a@b.com")
        assert user.id == "1"

    def test_create_password_factor(self) -> None:
        from neozen.core.factors.password import create_password_factor
        from neozen.core.identifiers.email import create_email_identifier

        repo = CustomUserRepo()
        identifier = create_email_identifier(repo)

        class SimpleHasher:
            def verify_and_update(
                self, password: str | bytes, hash: str | bytes
            ) -> tuple[bool, str | None]:
                return str(password) == str(hash), None

            def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
                return str(password)

        factor = create_password_factor(identifier, repo, SimpleHasher())
        assert factor is not None

    @pytest.mark.anyio
    async def test_password_factor_with_custom_model(self) -> None:
        from neozen.core.factors.password import (
            InvalidCredentialsError,
            create_password_factor,
        )
        from neozen.core.identifiers.email import create_email_identifier

        class SimpleHasher:
            def verify_and_update(
                self, password: str | bytes, hash: str | bytes
            ) -> tuple[bool, str | None]:
                return str(password) == str(hash), None

            def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
                return str(password)

        user = CustomUser(id="u1", email="test@example.com", hashed_password="secret")
        repo = CustomUserRepo([user])
        identifier = create_email_identifier(repo)
        factor = create_password_factor(identifier, repo, SimpleHasher())

        # Should authenticate successfully
        result = await factor.authenticate({
            "identifier": "test@example.com",
            "password": "secret",
        })
        assert result.id == "u1"

        # Should fail with wrong password
        with pytest.raises(InvalidCredentialsError):
            await factor.authenticate({
                "identifier": "test@example.com",
                "password": "wrong",
            })
