"""Integration tests for the NeoZen demo application."""

from __future__ import annotations

import os
import tempfile

import pytest
from httpx import ASGITransport, AsyncClient

from neozen.demo.app import AppState, create_app
from neozen.cli.database import init_database


@pytest.fixture
async def app(tmp_path):
    """Create a fresh demo app for each test with temporary database."""
    # Use a temporary database for each test
    db_path = tmp_path / "test.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"

    # Set environment variable so the app uses our test database
    old_env = os.environ.get("NEOZEN_DATABASE_URL")
    os.environ["NEOZEN_DATABASE_URL"] = db_url

    try:
        app = create_app()
        # Manually initialize the app state (simulating lifespan startup)
        engine = await init_database(db_url)
        app.state.neozen = AppState(engine)
        yield app
        # Cleanup
        await engine.dispose()
    finally:
        if old_env is not None:
            os.environ["NEOZEN_DATABASE_URL"] = old_env
        else:
            os.environ.pop("NEOZEN_DATABASE_URL", None)


@pytest.fixture
async def client(app):
    """Create an async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.mark.anyio
class TestIndex:
    """Tests for the index endpoint."""

    async def test_index_returns_api_info(self, client: AsyncClient) -> None:
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "NeoZen Demo API"
        assert "endpoints" in data


@pytest.mark.anyio
class TestRegistration:
    """Tests for the registration endpoint."""

    async def test_register_success(self, client: AsyncClient) -> None:
        response = await client.post(
            "/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "test@example.com"
        assert "user_id" in data
        assert "Registration successful" in data["message"]

    async def test_register_invalid_email(self, client: AsyncClient) -> None:
        response = await client.post(
            "/register",
            json={"email": "invalid-email", "password": "securepassword123"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "error" in data

    async def test_register_missing_fields(self, client: AsyncClient) -> None:
        response = await client.post("/register", json={"email": "test@example.com"})
        assert response.status_code == 400
        data = response.json()
        assert "required" in data["error"]

    async def test_register_duplicate_email(self, client: AsyncClient) -> None:
        # First registration
        await client.post(
            "/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Second registration with same email
        response = await client.post(
            "/register",
            json={"email": "test@example.com", "password": "differentpassword"},
        )
        assert response.status_code == 409
        data = response.json()
        assert "already registered" in data["error"]


@pytest.mark.anyio
class TestLogin:
    """Tests for the login endpoint."""

    async def test_login_success(self, client: AsyncClient) -> None:
        # Register first
        await client.post(
            "/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Login
        response = await client.post(
            "/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "Login successful" in data["message"]
        assert "neozen_session" in response.cookies

    async def test_login_invalid_password(self, client: AsyncClient) -> None:
        # Register first
        await client.post(
            "/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Login with wrong password
        response = await client.post(
            "/login",
            json={"email": "test@example.com", "password": "wrongpassword"},
        )
        assert response.status_code == 401
        data = response.json()
        assert "Invalid email or password" in data["error"]

    async def test_login_nonexistent_user(self, client: AsyncClient) -> None:
        response = await client.post(
            "/login",
            json={"email": "nonexistent@example.com", "password": "password"},
        )
        assert response.status_code == 401


@pytest.mark.anyio
class TestProtectedRoutes:
    """Tests for protected routes."""

    async def test_me_without_auth(self, client: AsyncClient) -> None:
        response = await client.get("/me")
        assert response.status_code == 401
        data = response.json()
        assert "Not authenticated" in data["error"]

    async def test_me_with_auth(self, client: AsyncClient) -> None:
        # Register and login
        await client.post(
            "/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        login_response = await client.post(
            "/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Use the session cookie
        cookies = {"neozen_session": login_response.cookies["neozen_session"]}
        response = await client.get("/me", cookies=cookies)
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"

    async def test_protected_without_auth(self, client: AsyncClient) -> None:
        response = await client.get("/protected")
        assert response.status_code == 401

    async def test_protected_with_auth(self, client: AsyncClient) -> None:
        # Register and login
        await client.post(
            "/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        login_response = await client.post(
            "/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Use the session cookie
        cookies = {"neozen_session": login_response.cookies["neozen_session"]}
        response = await client.get("/protected", cookies=cookies)
        assert response.status_code == 200
        data = response.json()
        assert "access" in data["message"]


@pytest.mark.anyio
class TestLogout:
    """Tests for the logout endpoint."""

    async def test_logout_success(self, client: AsyncClient) -> None:
        # Register and login
        await client.post(
            "/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        login_response = await client.post(
            "/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        cookies = {"neozen_session": login_response.cookies["neozen_session"]}

        # Logout
        response = await client.post("/logout", cookies=cookies)
        assert response.status_code == 200
        data = response.json()
        assert "Logged out" in data["message"]

    async def test_logout_invalidates_session(self, client: AsyncClient) -> None:
        # Register and login
        await client.post(
            "/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        login_response = await client.post(
            "/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        cookies = {"neozen_session": login_response.cookies["neozen_session"]}

        # Logout
        await client.post("/logout", cookies=cookies)

        # Try to access protected route with old session
        response = await client.get("/me", cookies=cookies)
        assert response.status_code == 401


@pytest.mark.anyio
class TestFullFlow:
    """End-to-end flow tests."""

    async def test_full_auth_flow(self, client: AsyncClient) -> None:
        # 1. Register
        reg_response = await client.post(
            "/register",
            json={"email": "flow@example.com", "password": "testpassword123"},
        )
        assert reg_response.status_code == 201
        user_id = reg_response.json()["user_id"]

        # 2. Login
        login_response = await client.post(
            "/login",
            json={"email": "flow@example.com", "password": "testpassword123"},
        )
        assert login_response.status_code == 200
        cookies = {"neozen_session": login_response.cookies["neozen_session"]}

        # 3. Access protected resource
        me_response = await client.get("/me", cookies=cookies)
        assert me_response.status_code == 200
        assert me_response.json()["id"] == user_id

        # 4. Access another protected resource
        protected_response = await client.get("/protected", cookies=cookies)
        assert protected_response.status_code == 200

        # 5. Logout
        logout_response = await client.post("/logout", cookies=cookies)
        assert logout_response.status_code == 200

        # 6. Verify session is invalidated
        me_response = await client.get("/me", cookies=cookies)
        assert me_response.status_code == 401
