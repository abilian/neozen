"""End-to-end tests for the Litestar demo's TOTP enrollment + login flow.

Covers the two-step password+TOTP flow added for the 1.0 demo showcase:
- Enrollment: dashboard → enroll → confirm → enabled
- Login: password → TOTP step → dashboard
- Disable

Builds the Litestar app explicitly so it can rebind the demo module's
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
async def litestar_totp_app(tmp_path: Path):
    """Build the Litestar demo app wired to a fresh test DB and totp_factor."""
    from neozen.admin.services import AdminService
    from neozen.core.factors.totp import TOTPConfig, TOTPFactor

    from .conftest import create_test_database, init_test_database

    test_db_path = tmp_path / "litestar_totp_test.db"
    engine, session_factory = create_test_database(str(test_db_path))
    await init_test_database(engine)

    async with session_factory() as db_session:
        service = AdminService(db_session)
        await service.ensure_builtin_roles()
        await db_session.commit()

    import demos.litestar.app as litestar_module

    # Save originals
    orig_engine = litestar_module.engine
    orig_session_factory = litestar_module.session_factory
    orig_session_service = litestar_module.session_service
    orig_role_service = litestar_module.role_service
    orig_neozen_config = litestar_module.neozen_config
    orig_totp_factor = litestar_module.totp_factor

    # Patch module globals
    litestar_module.engine = engine
    litestar_module.session_factory = session_factory

    from demos.shared.auth import (
        RoleServiceFactory,
        SessionServiceFactory,
        create_subject_loader,
    )
    from neozen.ext.litestar import NeoZenConfig, NeoZenPlugin

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

    # Rebind the TOTP factor against the test session_factory.
    litestar_module.totp_factor = TOTPFactor(
        config=TOTPConfig(issuer="NeoZen Demo (Litestar) — Test"),
        subject_repository=litestar_module.TOTPSubjectRepoAdapter(session_factory),
        backup_code_repository=None,
    )

    from litestar import Litestar
    from litestar.datastructures import State
    from litestar.middleware.session.server_side import ServerSideSessionConfig
    from litestar.stores.memory import MemoryStore

    session_config = ServerSideSessionConfig(
        key="neozen_flash_session",
        max_age=86400 * 7,
    )

    yield Litestar(
        route_handlers=[
            litestar_module.index,
            litestar_module.login_page,
            litestar_module.login_submit,
            litestar_module.register_page,
            litestar_module.register_submit,
            litestar_module.dashboard,
            litestar_module.logout_submit,
            litestar_module.totp_enroll_page,
            litestar_module.totp_enroll_confirm,
            litestar_module.totp_verify_page,
            litestar_module.totp_verify_submit,
            litestar_module.totp_disable,
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

    # Restore
    litestar_module.engine = orig_engine
    litestar_module.session_factory = orig_session_factory
    litestar_module.session_service = orig_session_service
    litestar_module.role_service = orig_role_service
    litestar_module.neozen_config = orig_neozen_config
    litestar_module.totp_factor = orig_totp_factor

    await engine.dispose()


@pytest.fixture
async def client(litestar_totp_app) -> AsyncClient:
    transport = ASGITransport(app=litestar_totp_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        follow_redirects=False,
    ) as client:
        yield client


async def _register_and_login(client: AsyncClient, email: str, password: str) -> None:
    """Helper: register a user and log in via the API."""
    r = await client.post("/api/register", json={"email": email, "password": password})
    assert r.status_code == 201, r.text
    r = await client.post("/api/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text


# =============================================================================
# Enrollment
# =============================================================================


@pytest.mark.anyio
class TestTOTPEnrollment:
    async def test_enroll_page_requires_login(self, client: AsyncClient) -> None:
        response = await client.get("/totp/enroll")
        # Unauthenticated users are blocked by the login_required guard.
        # Litestar's guard returns 401 for direct GETs in this configuration.
        assert response.status_code in (302, 303, 307, 401)

    async def test_enroll_page_loads_when_authenticated(
        self, client: AsyncClient
    ) -> None:
        await _register_and_login(client, "alice@example.com", "password123")

        response = await client.get("/totp/enroll")
        assert response.status_code == 200
        # Page should mention the enrollment instructions
        assert "Two-Factor" in response.text
        assert "secret" in response.text.lower() or "Secret" in response.text

    async def test_full_enrollment_then_dashboard_shows_enabled(
        self, client: AsyncClient
    ) -> None:
        await _register_and_login(client, "bob@example.com", "password123")

        # Step 1: GET enroll → captures the secret from the page (or DB)
        get_response = await client.get("/totp/enroll")
        assert get_response.status_code == 200

        # Pull the secret out of the page (it's rendered for manual entry)
        # The base32 secret is rendered inside <code>{{ secret }}</code>
        import re

        match = re.search(r"<code>([A-Z2-7]{16,})</code>", get_response.text)
        assert match, "Could not find TOTP secret in enrollment page"
        secret = match.group(1)

        # Step 2: Generate a valid code with the captured secret and POST
        code = pyotp.TOTP(secret).now()
        post_response = await client.post(
            "/totp/enroll",
            data={"code": code},
        )
        assert post_response.status_code in (302, 303, 307)
        assert post_response.headers["location"] == "/dashboard"

        # Dashboard should now show "Enabled"
        dashboard_response = await client.get("/dashboard")
        assert dashboard_response.status_code == 200
        assert "Enabled" in dashboard_response.text

    async def test_enrollment_with_wrong_code_fails(self, client: AsyncClient) -> None:
        await _register_and_login(client, "carol@example.com", "password123")

        # Trigger enrollment to generate a secret
        await client.get("/totp/enroll")

        # POST with a deliberately wrong code
        post_response = await client.post(
            "/totp/enroll",
            data={"code": "000000"},
        )
        # Redirect back to enrollment page on failure
        assert post_response.status_code in (302, 303, 307)
        assert post_response.headers["location"] == "/totp/enroll"


# =============================================================================
# Login flow with TOTP
# =============================================================================


@pytest.mark.anyio
class TestTOTPLoginFlow:
    async def _enroll_user(self, client: AsyncClient, email: str, password: str) -> str:
        """Register, enroll TOTP, return the TOTP secret."""
        await _register_and_login(client, email, password)

        get_response = await client.get("/totp/enroll")
        import re

        match = re.search(r"<code>([A-Z2-7]{16,})</code>", get_response.text)
        assert match
        secret = match.group(1)
        code = pyotp.TOTP(secret).now()
        await client.post("/totp/enroll", data={"code": code})

        # Log out to test the full login flow next
        await client.post("/api/logout")
        return secret

    async def test_password_login_redirects_to_totp_when_enabled(
        self, client: AsyncClient
    ) -> None:
        await self._enroll_user(client, "dave@example.com", "password123")

        # Now hit the form-based password login
        response = await client.post(
            "/login",
            data={"email": "dave@example.com", "password": "password123"},
        )
        # Should redirect to TOTP verify, NOT dashboard
        assert response.status_code in (302, 303, 307)
        assert response.headers["location"] == "/totp/verify"

    async def test_totp_verify_with_valid_code_completes_login(
        self, client: AsyncClient
    ) -> None:
        secret = await self._enroll_user(client, "erin@example.com", "password123")

        # Step 1: password
        await client.post(
            "/login",
            data={"email": "erin@example.com", "password": "password123"},
        )

        # Step 2: TOTP verify
        code = pyotp.TOTP(secret).now()
        verify_response = await client.post(
            "/totp/verify",
            data={"code": code},
        )
        assert verify_response.status_code in (302, 303, 307)
        assert verify_response.headers["location"] == "/dashboard"

        # Dashboard should now be reachable
        dashboard = await client.get("/dashboard")
        assert dashboard.status_code == 200

    async def test_totp_verify_with_wrong_code_fails(self, client: AsyncClient) -> None:
        await self._enroll_user(client, "frank@example.com", "password123")

        await client.post(
            "/login",
            data={"email": "frank@example.com", "password": "password123"},
        )
        verify_response = await client.post(
            "/totp/verify",
            data={"code": "000000"},
        )
        assert verify_response.status_code in (302, 303, 307)
        assert verify_response.headers["location"] == "/totp/verify"

    async def test_totp_verify_without_pending_login_redirects_to_login(
        self, client: AsyncClient
    ) -> None:
        # Hit /totp/verify directly with no prior password step
        response = await client.get("/totp/verify")
        assert response.status_code in (302, 303, 307)
        assert response.headers["location"] == "/login"


# =============================================================================
# Disable
# =============================================================================


@pytest.mark.anyio
class TestTOTPDisable:
    async def test_disable_clears_totp_state(self, client: AsyncClient) -> None:
        await _register_and_login(client, "grace@example.com", "password123")

        # Enroll
        get_response = await client.get("/totp/enroll")
        import re

        match = re.search(r"<code>([A-Z2-7]{16,})</code>", get_response.text)
        assert match
        secret = match.group(1)
        code = pyotp.TOTP(secret).now()
        await client.post("/totp/enroll", data={"code": code})

        # Disable
        disable_response = await client.post("/totp/disable")
        assert disable_response.status_code in (302, 303, 307)
        assert disable_response.headers["location"] == "/dashboard"

        # Dashboard should now show "Not enabled"
        dashboard = await client.get("/dashboard")
        assert dashboard.status_code == 200
        assert "Not enabled" in dashboard.text
