"""Unit tests for NeoZen Starlette extension."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

from neozen.ext.starlette import (
    NeoZenBackend,
    NeoZenMiddleware,
    get_current_user,
    is_authenticated,
    login_required,
)

# =============================================================================
# Test Fixtures
# =============================================================================


@dataclass
class DemoUser:
    """Simple demo user."""

    id: str
    email: str


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
    }


@pytest.fixture
def backend(session_service, users_db):
    async def load_subject(subject_id: str) -> DemoUser | None:
        return users_db.get(subject_id)

    return NeoZenBackend(
        session_service=session_service,
        subject_loader=load_subject,
        cookie_secure=False,
    )


@pytest.fixture
def app(backend):
    async def index(request: Request) -> Response:
        user = await get_current_user(request)
        return JSONResponse({
            "authenticated": is_authenticated(request),
            "user_id": user.id if user else None,
        })

    @login_required
    async def protected(request: Request) -> Response:
        user = await get_current_user(request)
        return JSONResponse({"user_id": user.id})

    @login_required(redirect_url="/login")
    async def protected_redirect(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def login_route(request: Request) -> Response:
        return JSONResponse({"page": "login"})

    routes = [
        Route("/", index),
        Route("/protected", protected),
        Route("/protected-redirect", protected_redirect),
        Route("/login", login_route),
    ]

    middleware = [
        Middleware(NeoZenMiddleware, backend=backend),
    ]

    return Starlette(routes=routes, middleware=middleware)


@pytest.fixture
def client(app):
    return TestClient(app)


# =============================================================================
# Tests
# =============================================================================


class TestNeoZenBackend:
    """Tests for NeoZenBackend."""

    @pytest.mark.anyio
    async def test_create_session(self, backend, users_db):
        user = users_db["user_1"]
        token = await backend.create_session(user.id)
        assert token is not None
        assert len(token) > 0

    @pytest.mark.anyio
    async def test_get_session(self, backend, users_db):
        user = users_db["user_1"]
        token = await backend.create_session(user.id)
        session = await backend.get_session(token)
        assert session is not None
        assert session.subject_id == user.id

    @pytest.mark.anyio
    async def test_get_session_invalid(self, backend):
        session = await backend.get_session("invalid_token")
        assert session is None

    @pytest.mark.anyio
    async def test_get_subject(self, backend):
        subject = await backend.get_subject("user_1")
        assert subject is not None
        assert subject.email == "test@example.com"

    @pytest.mark.anyio
    async def test_get_subject_not_found(self, backend):
        subject = await backend.get_subject("nonexistent")
        assert subject is None

    @pytest.mark.anyio
    async def test_revoke_session(self, backend, users_db):
        user = users_db["user_1"]
        token = await backend.create_session(user.id)
        await backend.revoke_session(token)
        session = await backend.get_session(token)
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
    """Tests for login_required decorator."""

    def test_unauthenticated_returns_401(self, client):
        response = client.get("/protected")
        assert response.status_code == 401
        data = response.json()
        assert "error" in data

    def test_unauthenticated_redirects(self, client):
        response = client.get("/protected-redirect", follow_redirects=False)
        assert response.status_code == 303
        assert "/login" in response.headers["location"]

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
