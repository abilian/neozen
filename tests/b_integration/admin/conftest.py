"""Shared helpers for admin console tests."""

from __future__ import annotations

from litestar import Litestar
from litestar.testing import TestClient

from neozen.admin.app import session_config
from neozen.admin.auth import ADMIN_SESSION_KEY, AdminRole

SUPERADMIN_SESSION = {
    ADMIN_SESSION_KEY: {
        "id": "test-admin",
        "email": "admin@example.com",
        "name": "Test Admin",
        "role": AdminRole.SUPERADMIN.value,
        "organization_id": None,
    }
}


def superadmin_client(app: Litestar) -> TestClient:
    """Return a test client whose session is logged in as a superadmin.

    Credential checks are covered separately by the login tests; this
    keeps route tests focused on the route.
    """
    client = TestClient(
        app=app,
        raise_server_exceptions=True,
        session_config=session_config(app.state.config),
    )
    client.set_session_data(SUPERADMIN_SESSION)
    return client
