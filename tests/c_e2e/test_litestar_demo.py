"""End-to-end tests for the Litestar demo application.

Tests the full authentication flow including registration, login, logout,
and protected routes.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

# Add project root to path for demos package
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


@pytest.fixture
async def litestar_app(tmp_path: Path):
    """Create a fresh Litestar demo app for each test."""
    from neozen.admin.services import AdminService

    from .conftest import create_test_database, init_test_database

    # Use a test-specific database path
    test_db_path = tmp_path / "litestar_test.db"

    # Create database with NullPool to avoid thread cleanup issues
    engine, session_factory = create_test_database(str(test_db_path))

    # Initialize database
    await init_test_database(engine)

    # Ensure built-in roles exist
    async with session_factory() as db_session:
        service = AdminService(db_session)
        await service.ensure_builtin_roles()
        await db_session.commit()

    # Import and patch Litestar module
    import demos.litestar.app as litestar_module

    # Store original values
    orig_engine = litestar_module.engine
    orig_session_factory = litestar_module.session_factory
    orig_session_service = litestar_module.session_service
    orig_role_service = litestar_module.role_service
    orig_neozen_config = litestar_module.neozen_config

    # Patch module globals
    litestar_module.engine = engine
    litestar_module.session_factory = session_factory

    from demos.shared.auth import (
        RoleServiceFactory,
        SessionServiceFactory,
        create_subject_loader,
    )
    from neozen.ext.litestar import NeoZenConfig

    litestar_module.session_service = SessionServiceFactory(
        session_factory, litestar_module.SECRET_KEY
    )
    litestar_module.role_service = RoleServiceFactory(session_factory)
    litestar_module.neozen_config = NeoZenConfig(
        session_service=litestar_module.session_service,
        subject_loader=create_subject_loader(session_factory),
        cookie_secure=False,
        login_path="/login",
    )

    # Create app using the module's factory
    from litestar import Litestar
    from litestar.datastructures import State
    from litestar.middleware.session.server_side import ServerSideSessionConfig
    from litestar.stores.memory import MemoryStore

    from neozen.ext.litestar import NeoZenPlugin

    session_config = ServerSideSessionConfig(
        key="neozen_flash_session",
        max_age=86400 * 7,
    )

    app = Litestar(
        route_handlers=[
            litestar_module.index,
            litestar_module.login_page,
            litestar_module.login_submit,
            litestar_module.register_page,
            litestar_module.register_submit,
            litestar_module.dashboard,
            litestar_module.logout_submit,
            litestar_module.api_register,
            litestar_module.api_login,
            litestar_module.api_logout,
            litestar_module.api_me,
        ],
        plugins=[NeoZenPlugin(litestar_module.neozen_config)],
        middleware=[session_config.middleware],
        stores={"sessions": MemoryStore()},
        state=State({"session_factory": session_factory}),
    )

    yield app

    # Restore original values
    litestar_module.engine = orig_engine
    litestar_module.session_factory = orig_session_factory
    litestar_module.session_service = orig_session_service
    litestar_module.role_service = orig_role_service
    litestar_module.neozen_config = orig_neozen_config

    # Cleanup
    await engine.dispose()


@pytest.fixture
async def client(litestar_app) -> AsyncClient:
    """Create async HTTP client for testing."""
    transport = ASGITransport(app=litestar_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.mark.anyio
class TestLitestarIndex:
    """Tests for the index page."""

    async def test_index_returns_html(self, client: AsyncClient) -> None:
        response = await client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "NeoZen" in response.text

    async def test_index_shows_login_link(self, client: AsyncClient) -> None:
        response = await client.get("/")
        assert "Login" in response.text or "login" in response.text


@pytest.mark.anyio
class TestLitestarRegistration:
    """Tests for user registration."""

    async def test_register_page_loads(self, client: AsyncClient) -> None:
        response = await client.get("/register")
        assert response.status_code == 200
        assert "Register" in response.text

    async def test_register_api_success(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "securepassword123"},
        )
        assert response.status_code == 201
        data = response.json()
        assert "user_id" in data
        assert "Registered" in data["message"]

    async def test_register_api_invalid_email(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/register",
            json={"email": "not-an-email", "password": "securepassword123"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "error" in data

    async def test_register_api_missing_password(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/register",
            json={"email": "test@example.com"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "required" in data["error"]

    async def test_register_api_duplicate_email(self, client: AsyncClient) -> None:
        # First registration
        await client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "password123"},
        )
        # Second registration with same email
        response = await client.post(
            "/api/register",
            json={"email": "test@example.com", "password": "different123"},
        )
        assert response.status_code == 409
        data = response.json()
        assert "already registered" in data["error"]


@pytest.mark.anyio
class TestLitestarLogin:
    """Tests for user login."""

    async def test_login_page_loads(self, client: AsyncClient) -> None:
        response = await client.get("/login")
        assert response.status_code == 200
        assert "Login" in response.text

    async def test_login_api_success(self, client: AsyncClient) -> None:
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

    async def test_login_api_invalid_password(self, client: AsyncClient) -> None:
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
        assert "Invalid" in data["error"]

    async def test_login_api_nonexistent_user(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/login",
            json={"email": "nobody@example.com", "password": "password"},
        )
        assert response.status_code == 401


@pytest.mark.anyio
class TestLitestarProtectedRoutes:
    """Tests for protected routes."""

    async def test_dashboard_unauthorized_when_not_logged_in(
        self, client: AsyncClient
    ) -> None:
        # Litestar returns 401 Unauthorized instead of redirecting
        response = await client.get("/dashboard", follow_redirects=False)
        assert response.status_code == 401

    async def test_dashboard_accessible_when_logged_in(
        self, client: AsyncClient
    ) -> None:
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
        # Access dashboard
        response = await client.get("/dashboard")
        assert response.status_code == 200
        assert "Dashboard" in response.text

    async def test_api_me_without_auth(self, client: AsyncClient) -> None:
        response = await client.get("/api/me")
        assert response.status_code == 401

    async def test_api_me_with_auth(self, client: AsyncClient) -> None:
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
        # Access /api/me
        response = await client.get("/api/me")
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"


@pytest.mark.anyio
class TestLitestarLogout:
    """Tests for logout functionality."""

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

        # Verify logged in
        response = await client.get("/api/me")
        assert response.status_code == 200

        # Logout
        await client.post("/api/logout")

        # Re-set cookie and verify no longer valid
        client.cookies.set("neozen_session", session_token)
        response = await client.get("/api/me")
        assert response.status_code == 401


@pytest.mark.anyio
class TestLitestarFullFlow:
    """End-to-end flow tests."""

    async def test_complete_auth_flow(self, client: AsyncClient) -> None:
        # 1. Visit home page
        response = await client.get("/")
        assert response.status_code == 200

        # 2. Register
        response = await client.post(
            "/api/register",
            json={"email": "flow@example.com", "password": "testpassword123"},
        )
        assert response.status_code == 201
        user_id = response.json()["user_id"]

        # 3. Login
        response = await client.post(
            "/api/login",
            json={"email": "flow@example.com", "password": "testpassword123"},
        )
        assert response.status_code == 200
        client.cookies.set("neozen_session", response.cookies["neozen_session"])

        # 4. Access dashboard
        response = await client.get("/dashboard")
        assert response.status_code == 200
        assert "flow@example.com" in response.text

        # 5. Access /api/me
        response = await client.get("/api/me")
        assert response.status_code == 200
        assert response.json()["id"] == user_id

        # 6. Logout
        response = await client.post("/api/logout")
        assert response.status_code == 200

        # 7. Verify logged out (dashboard returns 401)
        response = await client.get("/dashboard", follow_redirects=False)
        assert response.status_code == 401
