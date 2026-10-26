"""Admin console authentication: every route needs a real admin login."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest
from litestar import Litestar
from litestar.testing import TestClient
from pwdlib import PasswordHash
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from neozen.admin.app import ROUTE_HANDLERS, create_admin_app
from neozen.admin.auth import AdminRole, admin_role_for
from neozen.admin.config import AdminConfig
from neozen.admin.services import AdminService
from neozen.serve import ServeConfig, build_serve_app

from .conftest import BASE_URL, send_csrf_token, superadmin_client


def _db_url(tmp_path: Path) -> str:
    return f"sqlite+aiosqlite:///{tmp_path / 'admin.db'}"


def _create_subject(db_url: str, email: str, password: str, role: str) -> None:
    """Create a subject with a password and one role, outside the app."""

    async def run() -> None:
        engine = create_async_engine(db_url)
        async with async_sessionmaker(engine)() as session:
            service = AdminService(session)
            subject = await service.create_subject(
                email=email, password=PasswordHash.recommended().hash(password)
            )
            await service.assign_role_to_subject(subject.id, role)
            await session.commit()
        await engine.dispose()

    asyncio.run(run())


def _login(client: TestClient, email: str, password: str) -> None:
    send_csrf_token(client)
    client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=False,
    )


class TestAdminRoleFor:
    def test_superuser_is_superadmin(self) -> None:
        assert admin_role_for({"user", "superuser"}, "admin") == AdminRole.SUPERADMIN

    def test_required_role_is_admin(self) -> None:
        assert admin_role_for({"staff"}, "staff") == AdminRole.ADMIN

    def test_other_roles_get_no_access(self) -> None:
        assert admin_role_for({"user"}, "admin") is None


class TestAnonymousAccess:
    @pytest.mark.parametrize("path", ["/", "/users", "/users/export", "/audit"])
    def test_admin_routes_redirect_to_login(self, path: str) -> None:
        app = create_admin_app(
            AdminConfig(db_url="sqlite+aiosqlite:///:memory:", secret_key="k")
        )
        with TestClient(app=app, base_url=BASE_URL) as client:
            response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"

    def test_mutating_route_is_refused(self) -> None:
        app = create_admin_app(
            AdminConfig(db_url="sqlite+aiosqlite:///:memory:", secret_key="k")
        )
        with TestClient(app=app, base_url=BASE_URL) as client:
            response = client.post("/users/some-id/delete", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"

    def test_login_page_is_public(self) -> None:
        app = create_admin_app(
            AdminConfig(db_url="sqlite+aiosqlite:///:memory:", secret_key="k")
        )
        with TestClient(app=app, base_url=BASE_URL) as client:
            response = client.get("/login")
        assert response.status_code == 200
        assert "admin123" not in response.text

    def test_serve_health_endpoints_are_public(self) -> None:
        app = build_serve_app(
            ServeConfig(
                db_url="sqlite+aiosqlite:///:memory:",
                secret_key="test-secret-not-default",
                bootstrap_admin=False,
            )
        )
        with TestClient(app=app, base_url=BASE_URL) as client:
            assert client.get("/healthz").status_code == 200
            assert client.get("/readyz").status_code == 200
            response = client.get("/users", follow_redirects=False)
        assert response.status_code == 303


class TestLogin:
    def test_bootstrap_credentials_log_in(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        app = build_serve_app(
            ServeConfig(
                db_url=_db_url(tmp_path),
                secret_key="test-secret-not-default",
                bootstrap_admin=True,
                bootstrap_admin_email="ops@example.com",
            )
        )
        with TestClient(app=app, base_url=BASE_URL) as client:
            match = re.search(r"password: (\S+)", capsys.readouterr().out)
            assert match is not None
            _login(client, "ops@example.com", match.group(1))
            response = client.get("/users", follow_redirects=False)
        assert response.status_code == 200

    def test_old_demo_credentials_are_rejected(self) -> None:
        app = create_admin_app(
            AdminConfig(db_url="sqlite+aiosqlite:///:memory:", secret_key="k")
        )
        with TestClient(app=app, base_url=BASE_URL) as client:
            _login(client, "admin@admin.local", "admin123")
            response = client.get("/users", follow_redirects=False)
        assert response.status_code == 303

    def test_wrong_password_is_rejected(self, tmp_path: Path) -> None:
        app = create_admin_app(AdminConfig(db_url=_db_url(tmp_path), secret_key="k"))
        with TestClient(app=app, base_url=BASE_URL) as client:
            _create_subject(_db_url(tmp_path), "a@example.com", "right", "admin")
            _login(client, "a@example.com", "wrong")
            response = client.get("/users", follow_redirects=False)
        assert response.status_code == 303

    def test_subject_without_admin_role_is_rejected(self, tmp_path: Path) -> None:
        app = create_admin_app(AdminConfig(db_url=_db_url(tmp_path), secret_key="k"))
        with TestClient(app=app, base_url=BASE_URL) as client:
            _create_subject(_db_url(tmp_path), "u@example.com", "secret", "user")
            _login(client, "u@example.com", "secret")
            response = client.get("/users", follow_redirects=False)
        assert response.status_code == 303

    def test_subject_with_admin_role_logs_in(self, tmp_path: Path) -> None:
        app = create_admin_app(AdminConfig(db_url=_db_url(tmp_path), secret_key="k"))
        with TestClient(app=app, base_url=BASE_URL) as client:
            _create_subject(_db_url(tmp_path), "a@example.com", "secret", "admin")
            _login(client, "a@example.com", "secret")
            response = client.get("/users", follow_redirects=False)
        assert response.status_code == 200


class TestPermissionToggleEscaping:
    def test_client_values_are_escaped(self) -> None:
        payload = """x' onmouseover='alert(1)' "><script>alert(1)</script>"""
        app = create_admin_app(
            AdminConfig(db_url="sqlite+aiosqlite:///:memory:", secret_key="k")
        )
        with superadmin_client(app) as client:
            client.post(
                "/roles/create",
                data={"name": "editor", "permissions": "post:read"},
                follow_redirects=False,
            )
            response = client.post(
                "/permissions/toggle",
                data={"role_name": "editor", "permission": payload, "enabled": "true"},
            )
        assert response.status_code == 200
        assert "<script>" not in response.text
        assert "onmouseover='" not in response.text

    def test_unknown_role_shows_generic_message(self) -> None:
        app = create_admin_app(
            AdminConfig(db_url="sqlite+aiosqlite:///:memory:", secret_key="k")
        )
        with superadmin_client(app) as client:
            response = client.post(
                "/permissions/toggle",
                data={"role_name": "<b>nope</b>", "permission": "x", "enabled": "true"},
            )
        assert "Role not found" in response.text
        assert "<b>" not in response.text


def _deactivate(db_url: str, email: str) -> None:
    async def run() -> None:
        engine = create_async_engine(db_url)
        async with async_sessionmaker(engine)() as session:
            service = AdminService(session)
            subject = await service.subject_repo.get_one_by(email=email)
            await service.subject_repo.update_obj(subject, is_active=False)
            await session.commit()
        await engine.dispose()

    asyncio.run(run())


class TestSessionLifecycle:
    def test_login_issues_a_new_session_id(self, tmp_path: Path) -> None:
        """An ID planted before login must not become an admin session."""
        app = create_admin_app(AdminConfig(db_url=_db_url(tmp_path), secret_key="k"))
        with TestClient(app=app, base_url=BASE_URL) as client:
            _create_subject(_db_url(tmp_path), "a@example.com", "secret", "admin")
            _login(client, "a@example.com", "wrong")  # creates a session (flash)
            planted = client.cookies.get("neozen_admin_session")
            assert planted
            _login(client, "a@example.com", "secret")
            assert client.cookies.get("neozen_admin_session") != planted

            client.cookies.set("neozen_admin_session", planted)
            response = client.get("/users", follow_redirects=False)
        assert response.status_code == 303

    def test_deactivated_admin_loses_access_at_once(self, tmp_path: Path) -> None:
        app = create_admin_app(AdminConfig(db_url=_db_url(tmp_path), secret_key="k"))
        with TestClient(app=app, base_url=BASE_URL) as client:
            _create_subject(_db_url(tmp_path), "a@example.com", "secret", "admin")
            _login(client, "a@example.com", "secret")
            assert client.get("/users", follow_redirects=False).status_code == 200

            _deactivate(_db_url(tmp_path), "a@example.com")
            response = client.get("/users", follow_redirects=False)
        assert response.status_code == 303


class TestCSRF:
    def _app(self) -> Litestar:
        return create_admin_app(
            AdminConfig(db_url="sqlite+aiosqlite:///:memory:", secret_key="k")
        )

    def test_post_without_token_is_refused(self) -> None:
        with superadmin_client(self._app()) as client:
            del client.headers["x-csrftoken"]
            response = client.post(
                "/roles/create",
                data={"name": "editor", "permissions": "post:read"},
                follow_redirects=False,
            )
        assert response.status_code == 403

    def test_pages_carry_the_token(self) -> None:
        with superadmin_client(self._app()) as client:
            body = client.get("/roles/create").text
        token = re.search(r'name="_csrf_token" value="([^"]+)"', body)
        assert token
        assert f'"x-csrftoken": "{token.group(1)}"' in body


class TestErrorMessages:
    def test_duplicate_user_gets_a_plain_message(self) -> None:
        app = create_admin_app(
            AdminConfig(db_url="sqlite+aiosqlite:///:memory:", secret_key="k")
        )
        with superadmin_client(app) as client:
            form = {"email": "dup@example.com"}
            client.post("/users/create", data=form, follow_redirects=False)
            response = client.post("/users/create", data=form)
        assert "conflicts with an existing record" in response.text
        assert "UNIQUE" not in response.text
        assert "INSERT" not in response.text

    def test_readyz_hides_database_errors(self) -> None:
        app = build_serve_app(
            ServeConfig(
                db_url="sqlite+aiosqlite:///:memory:",
                secret_key="test-secret-not-default",
                bootstrap_admin=False,
            )
        )
        with TestClient(app=app) as client:
            broken = create_async_engine("sqlite+aiosqlite:////nonexistent/dir/x.db")
            app.state.session_factory = async_sessionmaker(broken)
            response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json() == {"status": "unavailable"}


def _static_get_paths() -> list[str]:
    return sorted({
        path
        for handler in ROUTE_HANDLERS
        if "GET" in (handler.http_methods or ())
        for path in handler.paths
        if "{" not in path
    })


@pytest.mark.parametrize("path", _static_get_paths())
def test_every_admin_page_renders(path: str) -> None:
    """Catches broken templates (a missing macro import broke four pages)."""
    app = create_admin_app(
        AdminConfig(db_url="sqlite+aiosqlite:///:memory:", secret_key="k")
    )
    with superadmin_client(app) as client:
        response = client.get(path, follow_redirects=False)
    assert response.status_code < 500


def test_detail_pages_render() -> None:
    app = create_admin_app(
        AdminConfig(db_url="sqlite+aiosqlite:///:memory:", secret_key="k")
    )
    admin = superadmin_client(app)
    with admin as client:
        for path in (f"/users/{admin.subject_id}", "/roles/superuser"):
            assert client.get(path, follow_redirects=False).status_code == 200, path
