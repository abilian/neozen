"""End-to-end tests for the Flask demo application.

Tests the full authentication flow including registration, login, logout,
and protected routes.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

# Add project root to path for demos package
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

if TYPE_CHECKING:
    from flask.testing import FlaskClient


def run_async(coro):
    """Run async coroutine in sync context."""
    return asyncio.run(coro)


@pytest.fixture
def flask_app(tmp_path: Path):
    """Create a fresh Flask demo app for each test."""
    from demos.shared.auth import RoleServiceFactory
    from neozen.admin.services import AdminService

    from .conftest import create_test_database, init_test_database

    # Use a test-specific database path
    test_db_path = tmp_path / "flask_test.db"

    # Create database with NullPool to avoid thread cleanup issues
    engine, session_factory = create_test_database(str(test_db_path))

    # Initialize database
    run_async(init_test_database(engine))

    # Ensure built-in roles exist
    async def setup_roles():
        async with session_factory() as db_session:
            service = AdminService(db_session)
            await service.ensure_builtin_roles()
            await db_session.commit()

    run_async(setup_roles())

    # Import and patch Flask app
    import demos.flask.app as flask_module

    # Store original values
    orig_engine = flask_module.engine
    orig_session_factory = flask_module.session_factory
    orig_role_service = flask_module.role_service

    # Patch module globals
    flask_module.engine = engine
    flask_module.session_factory = session_factory
    flask_module.role_service = RoleServiceFactory(session_factory)

    # Get the app
    app = flask_module.app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    yield app

    # Restore original values
    flask_module.engine = orig_engine
    flask_module.session_factory = orig_session_factory
    flask_module.role_service = orig_role_service

    # Cleanup - dispose engine and close all connections
    async def cleanup():
        await engine.dispose()

    run_async(cleanup())


@pytest.fixture
def client(flask_app) -> FlaskClient:
    """Create Flask test client."""
    return flask_app.test_client()


class TestFlaskIndex:
    """Tests for the index page."""

    def test_index_returns_html(self, client: FlaskClient) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert b"NeoZen" in response.data

    def test_index_shows_login_link(self, client: FlaskClient) -> None:
        response = client.get("/")
        assert b"Login" in response.data or b"login" in response.data


class TestFlaskRegistration:
    """Tests for user registration."""

    def test_register_page_loads(self, client: FlaskClient) -> None:
        response = client.get("/register")
        assert response.status_code == 200
        assert b"Register" in response.data

    def test_register_api_success(self, client: FlaskClient) -> None:
        response = client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        assert response.status_code == 201
        data = response.get_json()
        assert "user_id" in data
        assert "Registered" in data["message"]

    def test_register_api_invalid_email(self, client: FlaskClient) -> None:
        response = client.post(
            "/api/register",
            json={"email": "not-an-email", "password": "securepassword123"},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_register_api_missing_password(self, client: FlaskClient) -> None:
        response = client.post(
            "/api/register",
            json={"email": "test@example.com"},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "required" in data["error"]

    def test_register_api_duplicate_email(self, client: FlaskClient) -> None:
        # First registration
        client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "password123"},
        )
        # Second registration with same email
        response = client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "different123"},
        )
        assert response.status_code == 409
        data = response.get_json()
        assert "already registered" in data["error"]


class TestFlaskLogin:
    """Tests for user login."""

    def test_login_page_loads(self, client: FlaskClient) -> None:
        response = client.get("/login")
        assert response.status_code == 200
        assert b"Login" in response.data

    def test_login_api_success(self, client: FlaskClient) -> None:
        # Register first
        client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Login
        response = client.post(
            "/api/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "Logged in" in data["message"]

    def test_login_api_invalid_password(self, client: FlaskClient) -> None:
        # Register first
        client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Login with wrong password
        response = client.post(
            "/api/login",
            json={"email": "test@example.com", "password": "wrongpassword"},
        )
        assert response.status_code == 401
        data = response.get_json()
        assert "Invalid" in data["error"]

    def test_login_api_nonexistent_user(self, client: FlaskClient) -> None:
        response = client.post(
            "/api/login",
            json={"email": "nobody@example.com", "password": "password"},
        )
        assert response.status_code == 401


class TestFlaskProtectedRoutes:
    """Tests for protected routes."""

    def test_dashboard_redirects_when_not_logged_in(self, client: FlaskClient) -> None:
        response = client.get("/dashboard")
        assert response.status_code == 302
        assert "/login" in response.location

    def test_dashboard_accessible_when_logged_in(self, client: FlaskClient) -> None:
        # Register and login
        client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        client.post(
            "/api/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Access dashboard
        response = client.get("/dashboard")
        assert response.status_code == 200
        assert b"Dashboard" in response.data

    def test_api_me_without_auth(self, client: FlaskClient) -> None:
        response = client.get("/api/me")
        assert response.status_code == 401

    def test_api_me_with_auth(self, client: FlaskClient) -> None:
        # Register and login
        client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        client.post(
            "/api/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Access /api/me
        response = client.get("/api/me")
        assert response.status_code == 200
        data = response.get_json()
        assert data["email"] == "test@example.com"


class TestFlaskLogout:
    """Tests for logout functionality."""

    def test_logout_success(self, client: FlaskClient) -> None:
        # Register and login
        client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        client.post(
            "/api/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Logout
        response = client.post("/api/logout")
        assert response.status_code == 200
        data = response.get_json()
        assert "Logged out" in data["message"]

    def test_logout_invalidates_session(self, client: FlaskClient) -> None:
        # Register and login
        client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        client.post(
            "/api/login",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        # Verify logged in
        response = client.get("/api/me")
        assert response.status_code == 200

        # Logout
        client.post("/api/logout")

        # Verify no longer logged in
        response = client.get("/api/me")
        assert response.status_code == 401


class TestFlaskAdmin:
    """Tests for admin functionality."""

    def test_admin_requires_login(self, client: FlaskClient) -> None:
        response = client.get("/admin")
        assert response.status_code == 302
        assert "/login" in response.location

    def test_first_user_gets_admin_role(self, client: FlaskClient) -> None:
        # First user should get admin role
        client.post(
            "/api/register",
            json={"email": "admin@example.com", "password": "securepassword123"},
        )
        client.post(
            "/api/login",
            json={"email": "admin@example.com", "password": "securepassword123"},
        )
        # Should be able to access admin
        response = client.get("/admin")
        assert response.status_code == 200

    def test_second_user_does_not_get_admin_role(self, client: FlaskClient) -> None:
        # First user (admin)
        client.post(
            "/api/register",
            json={"email": "admin@example.com", "password": "securepassword123"},
        )
        client.post("/api/logout")

        # Second user (not admin)
        client.post(
            "/api/register",
            json={"email": "user@example.com", "password": "securepassword123"},
        )
        client.post(
            "/api/login",
            json={"email": "user@example.com", "password": "securepassword123"},
        )
        # Should NOT be able to access admin
        response = client.get("/admin")
        assert response.status_code == 302  # Redirected away


class TestFlaskFullFlow:
    """End-to-end flow tests."""

    def test_complete_auth_flow(self, client: FlaskClient) -> None:
        # 1. Visit home page
        response = client.get("/")
        assert response.status_code == 200

        # 2. Register
        response = client.post(
            "/api/register",
            json={"email": "flow@example.com", "password": "testpassword123"},
        )
        assert response.status_code == 201
        user_id = response.get_json()["user_id"]

        # 3. Login
        response = client.post(
            "/api/login",
            json={"email": "flow@example.com", "password": "testpassword123"},
        )
        assert response.status_code == 200

        # 4. Access dashboard
        response = client.get("/dashboard")
        assert response.status_code == 200
        assert b"flow@example.com" in response.data

        # 5. Access /api/me
        response = client.get("/api/me")
        assert response.status_code == 200
        assert response.get_json()["id"] == user_id

        # 6. Logout
        response = client.post("/api/logout")
        assert response.status_code == 200

        # 7. Verify logged out
        response = client.get("/dashboard")
        assert response.status_code == 302
