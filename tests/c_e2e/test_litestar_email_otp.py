"""End-to-end tests for the Litestar demo's Email OTP login flow.

Covers the request → code → verify → dashboard flow added for the
1.0 demo showcase. Builds the Litestar app explicitly so it can
rebind the demo module's email_otp_factor and ConsoleEmailSender
to test-isolated instances.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

# Add project root to path for the demos package
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


@pytest.fixture
async def litestar_otp_app(tmp_path: Path):
    """Build the Litestar demo app wired to a fresh test DB."""
    from neozen.admin.services import AdminService
    from neozen.core.email.console import ConsoleEmailSender
    from neozen.core.factors.email_otp import EmailOTPConfig, EmailOTPFactor

    from .conftest import create_test_database, init_test_database

    test_db_path = tmp_path / "litestar_otp_test.db"
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
    orig_email_sender = litestar_module.email_sender
    orig_email_otp_factor = litestar_module.email_otp_factor

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

    # Fresh email sender + factor wired to the test DB
    test_email_sender = ConsoleEmailSender()
    litestar_module.email_sender = test_email_sender
    litestar_module.email_otp_factor = EmailOTPFactor(
        config=EmailOTPConfig(app_name="NeoZen Demo (Litestar) — Test"),
        code_repository=litestar_module.InMemoryEmailOTPCodeRepository(),
        subject_email_lookup=litestar_module.SubjectEmailLookupAdapter(session_factory),
        email_sender=test_email_sender,
        code_hash_key=litestar_module.SECRET_KEY,
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
            litestar_module.email_otp_request_page,
            litestar_module.email_otp_request_submit,
            litestar_module.email_otp_verify_page,
            litestar_module.email_otp_verify_submit,
            litestar_module.api_last_email_otp,
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
    litestar_module.email_sender = orig_email_sender
    litestar_module.email_otp_factor = orig_email_otp_factor

    await engine.dispose()


@pytest.fixture
async def client(litestar_otp_app) -> AsyncClient:
    transport = ASGITransport(app=litestar_otp_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        follow_redirects=False,
    ) as client:
        yield client


async def _register_user(client: AsyncClient, email: str, password: str) -> None:
    r = await client.post("/api/register", json={"email": email, "password": password})
    assert r.status_code == 201, r.text


# =============================================================================
# Request page
# =============================================================================


@pytest.mark.anyio
class TestEmailOTPRequest:
    async def test_request_page_loads(self, client: AsyncClient) -> None:
        response = await client.get("/email-otp")
        assert response.status_code == 200
        assert "Sign in with Email OTP" in response.text
        assert "Send code" in response.text

    async def test_request_with_existing_email_sends_code(
        self, client: AsyncClient
    ) -> None:
        await _register_user(client, "alice@example.com", "password123")

        response = await client.post("/email-otp", data={"email": "alice@example.com"})
        # Redirect to verify page
        assert response.status_code in (302, 303, 307)
        assert response.headers["location"] == "/email-otp/verify"

        # The test API endpoint should return the code that was just sent
        last = await client.get("/api/test/last-email-otp")
        assert last.status_code == 200
        data = last.json()
        assert data["code"] is not None
        assert len(data["code"]) == 6
        assert data["to"] == "alice@example.com"

    async def test_request_with_unknown_email_does_not_reveal(
        self, client: AsyncClient
    ) -> None:
        """Anti-enumeration: same redirect for unknown emails."""
        response = await client.post("/email-otp", data={"email": "nobody@example.com"})
        assert response.status_code in (302, 303, 307)
        assert response.headers["location"] == "/email-otp/verify"

    async def test_request_with_blank_email_returns_to_form(
        self, client: AsyncClient
    ) -> None:
        response = await client.post("/email-otp", data={"email": ""})
        assert response.status_code in (302, 303, 307)
        assert response.headers["location"] == "/email-otp"


# =============================================================================
# Verify page
# =============================================================================


@pytest.mark.anyio
class TestEmailOTPVerify:
    async def test_verify_page_requires_pending_request(
        self, client: AsyncClient
    ) -> None:
        # Hit verify without first requesting a code
        response = await client.get("/email-otp/verify")
        assert response.status_code in (302, 303, 307)
        assert response.headers["location"] == "/email-otp"

    async def test_verify_page_shows_email_after_request(
        self, client: AsyncClient
    ) -> None:
        await _register_user(client, "bob@example.com", "password123")
        await client.post("/email-otp", data={"email": "bob@example.com"})

        response = await client.get("/email-otp/verify")
        assert response.status_code == 200
        assert "bob@example.com" in response.text
        assert "Verify and sign in" in response.text

    async def test_full_flow_logs_in(self, client: AsyncClient) -> None:
        await _register_user(client, "carol@example.com", "password123")
        await client.post("/email-otp", data={"email": "carol@example.com"})

        # Capture the code via the test API endpoint
        last = await client.get("/api/test/last-email-otp")
        code = last.json()["code"]
        assert code is not None

        verify = await client.post("/email-otp/verify", data={"code": code})
        assert verify.status_code in (302, 303, 307)
        assert verify.headers["location"] == "/dashboard"

        # Dashboard should now be reachable
        dashboard = await client.get("/dashboard")
        assert dashboard.status_code == 200

    async def test_wrong_code_fails(self, client: AsyncClient) -> None:
        await _register_user(client, "dave@example.com", "password123")
        await client.post("/email-otp", data={"email": "dave@example.com"})

        verify = await client.post("/email-otp/verify", data={"code": "000000"})
        assert verify.status_code in (302, 303, 307)
        assert verify.headers["location"] == "/email-otp/verify"

    async def test_blank_code_returns_to_form(self, client: AsyncClient) -> None:
        await _register_user(client, "erin@example.com", "password123")
        await client.post("/email-otp", data={"email": "erin@example.com"})

        verify = await client.post("/email-otp/verify", data={"code": ""})
        assert verify.status_code in (302, 303, 307)
        assert verify.headers["location"] == "/email-otp/verify"

    async def test_unknown_email_in_session_redirects(
        self, client: AsyncClient
    ) -> None:
        """If an email gets stashed but no subject exists, fail closed."""
        # Trigger the anti-enum path with an unknown email — this stashes
        # the email in the session even though no subject exists
        await client.post("/email-otp", data={"email": "ghost@example.com"})

        verify = await client.post("/email-otp/verify", data={"code": "123456"})
        assert verify.status_code in (302, 303, 307)
        # Either back to /email-otp (clears state) or /email-otp/verify
        assert verify.headers["location"] in {"/email-otp", "/email-otp/verify"}
