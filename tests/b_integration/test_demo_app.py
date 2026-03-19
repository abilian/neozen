"""Integration tests for the NeoZen demo application.

Tests both the web UI endpoints and JSON API endpoints.
Uses the simplified Starlette demo with SQLAlchemy storage.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

# Add project root to path for demos package
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


@pytest.fixture
async def app():
    """Create a fresh demo app for each test with cleared database."""
    # Import here to avoid import-time execution issues
    from demos.shared.database import create_database, init_database
    from neozen.admin.services import AdminService

    # Use a test-specific database path
    test_db_path = Path(__file__).parent / "test_demo.db"
    if test_db_path.exists():
        os.remove(test_db_path)

    # Create database
    engine, session_factory = create_database(str(test_db_path))

    # Initialize database
    await init_database(engine)

    # Ensure built-in roles exist
    async with session_factory() as db_session:
        service = AdminService(db_session)
        await service.ensure_builtin_roles()
        await db_session.commit()

    # Create app with patched database path
    import demos.starlette.app as starlette_app

    # Store original values
    orig_engine = starlette_app.engine
    orig_session_factory = starlette_app.session_factory
    orig_session_service = starlette_app.session_service
    orig_role_service = starlette_app.role_service
    orig_backend = starlette_app.backend

    # Patch module globals
    starlette_app.engine = engine
    starlette_app.session_factory = session_factory

    from demos.shared.auth import (
        RoleServiceFactory,
        SessionServiceFactory,
        create_subject_loader,
    )
    from neozen.ext.starlette import NeoZenBackend

    starlette_app.session_service = SessionServiceFactory(
        session_factory, starlette_app.SECRET_KEY
    )
    starlette_app.role_service = RoleServiceFactory(session_factory)
    starlette_app.backend = NeoZenBackend(
        session_service=starlette_app.session_service,
        subject_loader=create_subject_loader(session_factory),
        cookie_secure=False,
    )

    # Create app
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.middleware.sessions import SessionMiddleware
    from starlette.routing import Route

    from neozen.ext.starlette import NeoZenMiddleware

    routes = [
        Route("/", starlette_app.index, methods=["GET"]),
        Route("/login", starlette_app.login_page, methods=["GET"]),
        Route("/login", starlette_app.login_submit, methods=["POST"]),
        Route("/register", starlette_app.register_page, methods=["GET"]),
        Route("/register", starlette_app.register_submit, methods=["POST"]),
        Route("/dashboard", starlette_app.dashboard, methods=["GET"]),
        Route("/logout", starlette_app.logout_submit, methods=["POST"]),
        Route("/api/register", starlette_app.api_register, methods=["POST"]),
        Route("/api/login", starlette_app.api_login, methods=["POST"]),
        Route("/api/logout", starlette_app.api_logout, methods=["POST"]),
        Route("/api/me", starlette_app.api_me, methods=["GET"]),
    ]

    middleware = [
        Middleware(SessionMiddleware, secret_key=starlette_app.SECRET_KEY),
        Middleware(NeoZenMiddleware, backend=starlette_app.backend),
    ]

    app = Starlette(routes=routes, middleware=middleware)
    yield app

    # Restore original values
    starlette_app.engine = orig_engine
    starlette_app.session_factory = orig_session_factory
    starlette_app.session_service = orig_session_service
    starlette_app.role_service = orig_role_service
    starlette_app.backend = orig_backend

    # Cleanup
    await engine.dispose()
    if test_db_path.exists():
        os.remove(test_db_path)


@pytest.fixture
async def client(app):
    """Create an async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.mark.anyio
class TestIndex:
    """Tests for the index (home page) endpoint."""

    async def test_index_returns_html(self, client: AsyncClient) -> None:
        response = await client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "NeoZen" in response.text


@pytest.mark.anyio
class TestRegistrationAPI:
    """Tests for the registration JSON API endpoint."""

    async def test_register_success(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        assert response.status_code == 201
        data = response.json()
        assert "user_id" in data
        assert "Registered" in data["message"]

    async def test_register_invalid_email(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/register",
            json={"email": "invalid-email", "password": "securepassword123"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "error" in data

    async def test_register_missing_fields(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/register", json={"email": "test@example.com"}
        )
        assert response.status_code == 400
        data = response.json()
        assert "required" in data["error"]

    async def test_register_duplicate_email(self, client: AsyncClient) -> None:
        # First registration
        await client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Second registration with same email
        response = await client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "differentpassword"},
        )
        assert response.status_code == 409
        data = response.json()
        assert "already registered" in data["error"]


@pytest.mark.anyio
class TestLoginAPI:
    """Tests for the login JSON API endpoint."""

    async def test_login_success(self, client: AsyncClient) -> None:
        # Register first
        await client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Login
        response = await client.post(
            "/api/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "Logged in" in data["message"]
        assert "neozen_session" in response.cookies

    async def test_login_invalid_password(self, client: AsyncClient) -> None:
        # Register first
        await client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Login with wrong password
        response = await client.post(
            "/api/login",
            json={"email": "test@example.com", "password": "wrongpassword"},
        )
        assert response.status_code == 401
        data = response.json()
        assert "Invalid credentials" in data["error"]

    async def test_login_nonexistent_user(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/login",
            json={"email": "nonexistent@example.com", "password": "password"},
        )
        assert response.status_code == 401


@pytest.mark.anyio
class TestProtectedAPI:
    """Tests for protected JSON API routes."""

    async def test_me_without_auth(self, client: AsyncClient) -> None:
        response = await client.get("/api/me")
        assert response.status_code == 401
        data = response.json()
        assert "error" in data

    async def test_me_with_auth(self, client: AsyncClient) -> None:
        # Register and login
        await client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        login_response = await client.post(
            "/api/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Set the session cookie on client
        client.cookies.set("neozen_session", login_response.cookies["neozen_session"])
        response = await client.get("/api/me")
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"


@pytest.mark.anyio
class TestLogoutAPI:
    """Tests for the logout JSON API endpoint."""

    async def test_logout_success(self, client: AsyncClient) -> None:
        # Register and login
        await client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        login_response = await client.post(
            "/api/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        client.cookies.set("neozen_session", login_response.cookies["neozen_session"])

        # Logout
        response = await client.post("/api/logout")
        assert response.status_code == 200
        data = response.json()
        assert "Logged out" in data["message"]

    async def test_logout_invalidates_session(self, client: AsyncClient) -> None:
        # Register and login
        await client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        login_response = await client.post(
            "/api/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        session_token = login_response.cookies["neozen_session"]
        client.cookies.set("neozen_session", session_token)

        # Logout
        await client.post("/api/logout")

        # Try to access protected route with old session (re-set the cookie since logout clears it)
        client.cookies.set("neozen_session", session_token)
        response = await client.get("/api/me")
        assert response.status_code == 401


@pytest.mark.anyio
class TestWebUI:
    """Tests for web UI endpoints."""

    async def test_login_page_returns_html(self, client: AsyncClient) -> None:
        response = await client.get("/login")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Login" in response.text

    async def test_register_page_returns_html(self, client: AsyncClient) -> None:
        response = await client.get("/register")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Register" in response.text

    async def test_dashboard_redirects_when_not_logged_in(
        self, client: AsyncClient
    ) -> None:
        response = await client.get("/dashboard", follow_redirects=False)
        assert response.status_code == 303
        assert "/login" in response.headers["location"]


@pytest.mark.anyio
class TestFullFlowAPI:
    """End-to-end flow tests using JSON API."""

    async def test_full_auth_flow(self, client: AsyncClient) -> None:
        # 1. Register
        reg_response = await client.post(
            "/api/register",
            json={"email": "flow@example.com", "password": "testpassword123"},
        )
        assert reg_response.status_code == 201
        user_id = reg_response.json()["user_id"]

        # 2. Login
        login_response = await client.post(
            "/api/login",
            json={"email": "flow@example.com", "password": "testpassword123"},
        )
        assert login_response.status_code == 200
        session_token = login_response.cookies["neozen_session"]
        client.cookies.set("neozen_session", session_token)

        # 3. Access protected resource
        me_response = await client.get("/api/me")
        assert me_response.status_code == 200
        assert me_response.json()["id"] == user_id

        # 4. Logout
        logout_response = await client.post("/api/logout")
        assert logout_response.status_code == 200

        # 5. Verify session is invalidated (re-set cookie since logout clears it)
        client.cookies.set("neozen_session", session_token)
        me_response = await client.get("/api/me")
        assert me_response.status_code == 401
