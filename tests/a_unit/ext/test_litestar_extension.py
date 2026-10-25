"""Unit tests for NeoZen Litestar extension."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

import pytest
from litestar import Litestar, Request, Response, get
from litestar.response import Redirect
from litestar.testing import TestClient

from neozen.ext.litestar import (
    AuthenticationRequiredError,
    NeoZenConfig,
    NeoZenPlugin,
    get_current_user,
    is_authenticated,
    login_required,
    permissions_required,
    roles_required,
)

# =============================================================================
# Test Fixtures
# =============================================================================


@dataclass
class DemoUser:
    """Simple demo user."""

    id: str
    email: str
    roles: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()


@dataclass
class InMemorySession:
    """Simple session object."""

    token: str
    subject_id: str


@dataclass
class InMemorySessionService:
    """Simple in-memory session service for testing."""

    sessions: dict[str, dict] = field(default_factory=dict)

    async def create_session(
        self,
        subject_id: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> str:
        token = secrets.token_urlsafe(32)
        self.sessions[token] = {"subject_id": subject_id}
        return token

    async def validate_session(self, token: str) -> InMemorySession | None:
        data = self.sessions.get(token)
        if data:
            return InMemorySession(token, data["subject_id"])
        return None

    async def revoke_session_by_token(self, token: str) -> None:
        self.sessions.pop(token, None)


@pytest.fixture
def session_service():
    return InMemorySessionService()


@pytest.fixture
def users_db():
    return {
        "user_1": DemoUser("user_1", "test@example.com"),
        "admin_1": DemoUser(
            "admin_1",
            "admin@example.com",
            roles=("admin",),
            permissions=("user:delete",),
        ),
    }


@pytest.fixture
def config(session_service, users_db):
    async def load_subject(subject_id: str) -> DemoUser | None:  # noqa: RUF029
        return users_db.get(subject_id)

    return NeoZenConfig(
        session_service=session_service,
        subject_loader=load_subject,
        cookie_secure=False,
    )


@pytest.fixture
def app(config):
    @get("/")
    async def index(request: Request) -> Response:
        user = await get_current_user(request)
        return Response(
            content={
                "authenticated": is_authenticated(request),
                "user_id": user.id if user else None,
            },
            media_type="application/json",
        )

    @get("/protected", guards=[login_required(redirect=False)])
    async def protected(request: Request) -> Response:
        user = await get_current_user(request)
        return Response(
            content={"user_id": user.id},
            media_type="application/json",
        )

    @get("/protected-redirect", guards=[login_required()], sync_to_thread=False)
    def protected_redirect(request: Request) -> Response:
        return Response(content={"status": "ok"}, media_type="application/json")

    @get("/admin-only", guards=[roles_required("admin")], sync_to_thread=False)
    def admin_only(request: Request) -> Response:
        return Response(content={"status": "ok"}, media_type="application/json")

    @get(
        "/can-delete",
        guards=[permissions_required("user:delete")],
        sync_to_thread=False,
    )
    def can_delete(request: Request) -> Response:
        return Response(content={"status": "ok"}, media_type="application/json")

    @get("/login", sync_to_thread=False)
    def login_route(request: Request) -> Response:
        return Response(content={"page": "login"}, media_type="application/json")

    # Exception handler for authentication redirects
    def handle_auth_error(
        request: Request, exc: AuthenticationRequiredError
    ) -> Response:
        if exc.redirect_to:
            return Redirect(path=exc.redirect_to)
        return Response(
            content={"error": exc.detail},
            status_code=401,
            media_type="application/json",
        )

    return Litestar(
        route_handlers=[
            index,
            protected,
            protected_redirect,
            admin_only,
            can_delete,
            login_route,
        ],
        plugins=[NeoZenPlugin(config)],
        exception_handlers={AuthenticationRequiredError: handle_auth_error},
    )


@pytest.fixture
def client(app):
    return TestClient(app)


# =============================================================================
# Tests
# =============================================================================


class TestNeoZenConfig:
    """Tests for NeoZenConfig."""

    @pytest.mark.anyio
    async def test_create_session(self, config, users_db):
        user = users_db["user_1"]
        token = await config.create_session(user.id)
        assert token is not None
        assert len(token) > 0

    @pytest.mark.anyio
    async def test_get_session(self, config, users_db):
        user = users_db["user_1"]
        token = await config.create_session(user.id)
        session = await config.get_session(token)
        assert session is not None
        assert session.subject_id == user.id

    @pytest.mark.anyio
    async def test_get_session_invalid(self, config):
        session = await config.get_session("invalid_token")
        assert session is None

    @pytest.mark.anyio
    async def test_get_subject(self, config):
        subject = await config.get_subject("user_1")
        assert subject is not None
        assert subject.email == "test@example.com"

    @pytest.mark.anyio
    async def test_get_subject_not_found(self, config):
        subject = await config.get_subject("nonexistent")
        assert subject is None

    @pytest.mark.anyio
    async def test_revoke_session(self, config, users_db):
        user = users_db["user_1"]
        token = await config.create_session(user.id)
        await config.revoke_session(token)
        session = await config.get_session(token)
        assert session is None


class TestNeoZenMiddleware:
    """Tests for NeoZenMiddleware."""

    def test_unauthenticated_request(self, client):
        response = client.get("/")
        data = response.json()
        assert data["authenticated"] is False
        assert data["user_id"] is None

    def test_authenticated_request(self, client, session_service, users_db):
        # Create a session directly in the service dict
        user = users_db["user_1"]
        token = secrets.token_urlsafe(32)
        session_service.sessions[token] = {"subject_id": user.id}

        # Set cookie on client and make request
        client.cookies.set("neozen_session", token)
        response = client.get("/")
        data = response.json()
        assert data["authenticated"] is True
        assert data["user_id"] == "user_1"


class TestLoginRequired:
    """Tests for login_required guard."""

    def test_unauthenticated_returns_401(self, client):
        response = client.get("/protected")
        assert response.status_code == 401

    def test_unauthenticated_redirects(self, client):
        response = client.get("/protected-redirect", follow_redirects=False)
        assert response.status_code in (302, 303, 307)
        assert "/login" in response.headers.get("location", "")

    def test_authenticated_access(self, client, session_service, users_db):
        user = users_db["user_1"]
        # Create session directly
        token = secrets.token_urlsafe(32)
        session_service.sessions[token] = {"subject_id": user.id}

        # Set cookie on client and make request
        client.cookies.set("neozen_session", token)
        response = client.get("/protected")
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "user_1"


class TestRoleAndPermissionGuards:
    """The guards must load the user themselves, before the handler runs."""

    def _login(self, client, session_service, subject_id: str) -> None:
        token = secrets.token_urlsafe(32)
        session_service.sessions[token] = {"subject_id": subject_id}
        client.cookies.set("neozen_session", token)

    @pytest.mark.parametrize("path", ["/admin-only", "/can-delete"])
    def test_unauthenticated_returns_401(self, client, path):
        assert client.get(path).status_code == 401

    @pytest.mark.parametrize("path", ["/admin-only", "/can-delete"])
    def test_authorized_user_passes(self, client, session_service, path):
        self._login(client, session_service, "admin_1")
        assert client.get(path).status_code == 200

    @pytest.mark.parametrize("path", ["/admin-only", "/can-delete"])
    def test_unauthorized_user_gets_403(self, client, session_service, path):
        self._login(client, session_service, "user_1")
        assert client.get(path).status_code == 403


class TestHelpers:
    """Tests for helper functions."""

    def test_is_authenticated_false(self, client):
        response = client.get("/")
        data = response.json()
        assert data["authenticated"] is False

    def test_is_authenticated_true(self, client, session_service, users_db):
        user = users_db["user_1"]
        # Create session directly
        token = secrets.token_urlsafe(32)
        session_service.sessions[token] = {"subject_id": user.id}

        # Set cookie on client and make request
        client.cookies.set("neozen_session", token)
        response = client.get("/")
        data = response.json()
        assert data["authenticated"] is True
