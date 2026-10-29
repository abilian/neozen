"""Admin console hardening: framing headers, POST-only logout, bounded params."""

from __future__ import annotations

from pathlib import Path

import pytest
from litestar.testing import TestClient

from neozen.admin.app import SECURITY_HEADERS, create_admin_app
from neozen.admin.config import AdminConfig
from neozen.admin.services import AdminService
from neozen.core.audit.types import AuditActions

from .conftest import BASE_URL, superadmin_client


def _app(tmp_path: Path):
    return create_admin_app(
        AdminConfig(db_url=f"sqlite+aiosqlite:///{tmp_path / 'a.db'}", secret_key="k")
    )


def test_every_response_forbids_framing(tmp_path: Path) -> None:
    with TestClient(app=_app(tmp_path), base_url=BASE_URL) as client:
        response = client.get("/login")
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value


def test_logout_needs_a_post(tmp_path: Path) -> None:
    with superadmin_client(_app(tmp_path)) as client:
        assert client.get("/logout", follow_redirects=False).status_code == 405
        response = client.post("/logout", follow_redirects=False)
        assert response.headers["location"] == "/login"
        assert client.get("/", follow_redirects=False).status_code == 303


@pytest.mark.parametrize(
    "query", ["page=abc", "page=0", "per_page=0", "per_page=100000"]
)
def test_bad_pagination_is_a_client_error(tmp_path: Path, query: str) -> None:
    with superadmin_client(_app(tmp_path)) as client:
        response = client.get(f"/users?{query}")
    assert response.status_code == 400


def test_audit_page_must_be_a_number(tmp_path: Path) -> None:
    with superadmin_client(_app(tmp_path)) as client:
        assert client.get("/audit?page=x").status_code == 400


def test_impersonation_is_audited(tmp_path: Path) -> None:
    app = _app(tmp_path)
    admin = superadmin_client(app)

    async def create_target() -> str:
        async with app.state.session_factory() as session:
            subject = await AdminService(session).create_subject(email="u@x.org")
            await session.commit()
            return subject.id

    async def audit_entries() -> list[tuple[str, str | None, str | None]]:
        async with app.state.session_factory() as session:
            logs = await AdminService(session).list_audit_logs(event_type="admin")
            return [(e.action, e.actor_id, e.subject_id) for e in logs]

    with admin as client, client.portal() as portal:
        target = portal.call(create_target)
        client.post(f"/users/{target}/impersonate")
        client.post("/stop-impersonation")
        entries = portal.call(audit_entries)

    assert sorted(entries) == [
        (AuditActions.ADMIN_IMPERSONATE, admin.subject_id, target),
        (AuditActions.ADMIN_IMPERSONATE_END, admin.subject_id, target),
    ]


def test_detail_pages_render_and_writes_commit(tmp_path: Path) -> None:
    app = _app(tmp_path)

    async def seed() -> dict[str, str]:
        async with app.state.session_factory() as session:
            service = AdminService(session)
            user = await service.create_subject(email="u@x.org")
            group = await service.create_group("team")
            org = await service.create_organization("Acme", "acme")
            await service.create_role("editor", ["doc:write"])
            await service.assign_role_to_subject(user.id, "editor")
            await session.commit()
            return {"user": user.id, "group": group.id, "org": org.id}

    async def user_exists(user_id: str) -> bool:
        async with app.state.session_factory() as session:
            return await AdminService(session).subject_repo.exists(id=user_id)

    with superadmin_client(app) as client, client.portal() as portal:
        ids = portal.call(seed)
        for path in [
            f"/users/{ids['user']}",
            "/roles/editor",
            f"/groups/{ids['group']}",
            f"/organizations/{ids['org']}",
            "/sessions",
        ]:
            assert client.get(path).status_code == 200, path
        client.post(f"/users/{ids['user']}/delete")
        assert not portal.call(user_exists, ids["user"])


def test_expired_session_sends_htmx_polls_to_login(tmp_path: Path) -> None:
    with TestClient(app=_app(tmp_path), base_url=BASE_URL) as client:
        response = client.get(
            "/dashboard/stats", headers={"HX-Request": "true"}, follow_redirects=False
        )
    assert response.headers["HX-Redirect"] == "/login"
