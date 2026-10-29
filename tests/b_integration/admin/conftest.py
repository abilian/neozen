"""Shared helpers for admin console tests."""

from __future__ import annotations

from litestar import Litestar
from litestar.testing import TestClient

from neozen.admin.app import session_config
from neozen.admin.auth import ADMIN_SESSION_KEY, SUPERUSER_ROLE
from neozen.admin.services import AdminService

# HTTPS, so Secure session cookies (the `neozen serve` default) come back.
BASE_URL = "https://testserver.local"


def send_csrf_token(client: TestClient) -> None:
    """Get a CSRF cookie and send it back on every request, as the pages do."""
    client.get("/login")
    client.headers["x-csrftoken"] = client.cookies["csrftoken"]


class SuperadminClient:
    """A test client logged in as a subject created at app startup.

    The subject has the ``superuser`` role, or ``role`` when given.

    Use it as a context manager, like `TestClient`. Credential checks are
    covered separately by the login tests; this keeps route tests focused
    on the route.
    """

    def __init__(self, app: Litestar, role: str = SUPERUSER_ROLE) -> None:
        self.role = role
        self.subject_id = ""
        app.on_startup.append(self._create_superadmin)
        self.client = TestClient(
            app=app,
            raise_server_exceptions=True,
            session_config=session_config(app.state.config),
            base_url=BASE_URL,
        )

    async def _create_superadmin(self, app: Litestar) -> None:
        async with app.state.session_factory() as session:
            service = AdminService(session)
            if self.subject_id:  # entered again: the subject already exists
                return
            await service.ensure_builtin_roles()
            subject = await service.create_subject(email="admin@example.com")
            await service.assign_role_to_subject(subject.id, self.role)
            await session.commit()
        self.subject_id = subject.id

    def __enter__(self) -> TestClient:
        self.client.__enter__()
        self.client.set_session_data({ADMIN_SESSION_KEY: {"id": self.subject_id}})
        send_csrf_token(self.client)
        return self.client

    def __exit__(self, *exc_info: object) -> None:
        self.client.__exit__(*exc_info)


def superadmin_client(app: Litestar) -> SuperadminClient:
    """Return a client logged in as a superadmin (see `SuperadminClient`)."""
    return SuperadminClient(app)


def admin_client(app: Litestar) -> SuperadminClient:
    """Return a client logged in as a plain admin (the ``admin`` role)."""
    return SuperadminClient(app, role="admin")
