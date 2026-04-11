"""End-to-end tests for the Starlette demo's TOTP enrollment + login flow.

Mirrors `test_litestar_totp.py` for the Starlette demo. Builds the
Starlette app explicitly so it can rebind the demo module's
`totp_factor` to the test database.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pyotp
import pytest
from httpx import ASGITransport, AsyncClient

# Add project root to path for the demos package
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


@pytest.fixture
async def starlette_totp_app(tmp_path: Path):
    """Build the Starlette demo app wired to a fresh test DB."""
    from neozen.admin.services import AdminService
    from neozen.core.factors.totp import TOTPConfig, TOTPFactor

    from .conftest import create_test_database, init_test_database

    test_db_path = tmp_path / "starlette_totp_test.db"
    engine, session_factory = create_test_database(str(test_db_path))
    await init_test_database(engine)

    async with session_factory() as db_session:
        service = AdminService(db_session)
        await service.ensure_builtin_roles()
        await db_session.commit()

    import demos.starlette.app as starlette_module

    orig_engine = starlette_module.engine
    orig_session_factory = starlette_module.session_factory
    orig_session_service = starlette_module.session_service
    orig_role_service = starlette_module.role_service
    orig_backend = starlette_module.backend
    orig_totp_factor = starlette_module.totp_factor

    starlette_module.engine = engine
    starlette_module.session_factory = session_factory

    from demos.shared.auth import (
        RoleServiceFactory,
        SessionServiceFactory,
        create_subject_loader,
    )
    from neozen.ext.starlette import NeoZenBackend, NeoZenMiddleware

    starlette_module.session_service = SessionServiceFactory(
        session_factory, starlette_module.SECRET_KEY
    )
    starlette_module.role_service = RoleServiceFactory(session_factory)
    starlette_module.backend = NeoZenBackend(
        session_service=starlette_module.session_service,
        subject_loader=create_subject_loader(session_factory),
        cookie_secure=False,
    )
    starlette_module.totp_factor = TOTPFactor(
        config=TOTPConfig(issuer="NeoZen Demo (Starlette) — Test"),
        subject_repository=starlette_module.TOTPSubjectRepoAdapter(session_factory),
        backup_code_repository=None,
    )

    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.middleware.sessions import SessionMiddleware
    from starlette.routing import Route

    routes = [
        Route("/", starlette_module.index, methods=["GET"]),
        Route("/login", starlette_module.login_page, methods=["GET"]),
        Route("/login", starlette_module.login_submit, methods=["POST"]),
        Route("/register", starlette_module.register_page, methods=["GET"]),
        Route("/register", starlette_module.register_submit, methods=["POST"]),
        Route("/dashboard", starlette_module.dashboard, methods=["GET"]),
        Route("/logout", starlette_module.logout_submit, methods=["POST"]),
        Route("/totp/enroll", starlette_module.totp_enroll_page, methods=["GET"]),
        Route("/totp/enroll", starlette_module.totp_enroll_confirm, methods=["POST"]),
        Route("/totp/verify", starlette_module.totp_verify_page, methods=["GET"]),
        Route("/totp/verify", starlette_module.totp_verify_submit, methods=["POST"]),
        Route("/totp/disable", starlette_module.totp_disable, methods=["POST"]),
        Route("/api/register", starlette_module.api_register, methods=["POST"]),
        Route("/api/login", starlette_module.api_login, methods=["POST"]),
        Route("/api/logout", starlette_module.api_logout, methods=["POST"]),
        Route("/api/me", starlette_module.api_me, methods=["GET"]),
    ]

    middleware = [
        Middleware(SessionMiddleware, secret_key=starlette_module.SECRET_KEY),
        Middleware(NeoZenMiddleware, backend=starlette_module.backend),
    ]

    yield Starlette(routes=routes, middleware=middleware)

    starlette_module.engine = orig_engine
    starlette_module.session_factory = orig_session_factory
    starlette_module.session_service = orig_session_service
    starlette_module.role_service = orig_role_service
    starlette_module.backend = orig_backend
    starlette_module.totp_factor = orig_totp_factor

    await engine.dispose()


@pytest.fixture
async def client(starlette_totp_app) -> AsyncClient:
    transport = ASGITransport(app=starlette_totp_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        follow_redirects=False,
    ) as client:
        yield client


async def _register_and_login(client: AsyncClient, email: str, password: str) -> None:
    r = await client.post("/api/register", json={"email": email, "password": password})
    assert r.status_code == 201, r.text
    r = await client.post("/api/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text


def _extract_secret(html: str) -> str:
    """Pull the base32 TOTP secret out of the enrollment page."""
    import re

    match = re.search(r"<code>([A-Z2-7]{16,})</code>", html)
    assert match, "Could not find TOTP secret in enrollment page"
    return match.group(1)


# =============================================================================
# Enrollment
# =============================================================================


@pytest.mark.anyio
class TestStarletteTOTPEnrollment:
    async def test_enroll_page_requires_login(self, client: AsyncClient) -> None:
        response = await client.get("/totp/enroll")
        # login_required redirects unauthenticated users in this configuration
        assert response.status_code in (302, 303, 307, 401)

    async def test_full_enrollment_then_dashboard_shows_enabled(
        self, client: AsyncClient
    ) -> None:
        await _register_and_login(client, "alice@example.com", "password123")

        get_response = await client.get("/totp/enroll")
        assert get_response.status_code == 200
        secret = _extract_secret(get_response.text)

        code = pyotp.TOTP(secret).now()
        post_response = await client.post("/totp/enroll", data={"code": code})
        assert post_response.status_code in (302, 303, 307)
        assert post_response.headers["location"] == "/dashboard"

        dashboard = await client.get("/dashboard")
        assert dashboard.status_code == 200
        assert "Enabled" in dashboard.text

    async def test_enrollment_with_wrong_code_fails(self, client: AsyncClient) -> None:
        await _register_and_login(client, "bob@example.com", "password123")
        await client.get("/totp/enroll")

        post_response = await client.post("/totp/enroll", data={"code": "000000"})
        assert post_response.status_code in (302, 303, 307)
        assert post_response.headers["location"] == "/totp/enroll"


# =============================================================================
# Login flow with TOTP
# =============================================================================


@pytest.mark.anyio
class TestStarletteTOTPLoginFlow:
    async def _enroll_user(self, client: AsyncClient, email: str, password: str) -> str:
        await _register_and_login(client, email, password)
        get_response = await client.get("/totp/enroll")
        secret = _extract_secret(get_response.text)
        code = pyotp.TOTP(secret).now()
        await client.post("/totp/enroll", data={"code": code})
        await client.post("/api/logout")
        return secret

    async def test_password_login_redirects_to_totp_when_enabled(
        self, client: AsyncClient
    ) -> None:
        await self._enroll_user(client, "carol@example.com", "password123")
        response = await client.post(
            "/login",
            data={"email": "carol@example.com", "password": "password123"},
        )
        assert response.status_code in (302, 303, 307)
        assert response.headers["location"] == "/totp/verify"

    async def test_totp_verify_with_valid_code_completes_login(
        self, client: AsyncClient
    ) -> None:
        secret = await self._enroll_user(client, "dave@example.com", "password123")
        await client.post(
            "/login",
            data={"email": "dave@example.com", "password": "password123"},
        )
        code = pyotp.TOTP(secret).now()
        verify_response = await client.post("/totp/verify", data={"code": code})
        assert verify_response.status_code in (302, 303, 307)
        assert verify_response.headers["location"] == "/dashboard"

        dashboard = await client.get("/dashboard")
        assert dashboard.status_code == 200

    async def test_totp_verify_with_wrong_code_fails(self, client: AsyncClient) -> None:
        await self._enroll_user(client, "erin@example.com", "password123")
        await client.post(
            "/login",
            data={"email": "erin@example.com", "password": "password123"},
        )
        verify_response = await client.post("/totp/verify", data={"code": "000000"})
        assert verify_response.status_code in (302, 303, 307)
        assert verify_response.headers["location"] == "/totp/verify"

    async def test_totp_verify_without_pending_login_redirects_to_login(
        self, client: AsyncClient
    ) -> None:
        response = await client.get("/totp/verify")
        assert response.status_code in (302, 303, 307)
        assert response.headers["location"] == "/login"


# =============================================================================
# Disable
# =============================================================================


@pytest.mark.anyio
class TestStarletteTOTPDisable:
    async def test_disable_clears_totp_state(self, client: AsyncClient) -> None:
        await _register_and_login(client, "frank@example.com", "password123")

        get_response = await client.get("/totp/enroll")
        secret = _extract_secret(get_response.text)
        code = pyotp.TOTP(secret).now()
        await client.post("/totp/enroll", data={"code": code})

        disable_response = await client.post("/totp/disable")
        assert disable_response.status_code in (302, 303, 307)
        assert disable_response.headers["location"] == "/dashboard"

        dashboard = await client.get("/dashboard")
        assert dashboard.status_code == 200
        assert "Not enabled" in dashboard.text
