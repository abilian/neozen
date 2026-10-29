"""A plain admin can't make itself, or anyone, superadmin."""

from __future__ import annotations

from pathlib import Path

import pytest
from litestar import Litestar

from neozen.admin.app import create_admin_app
from neozen.admin.auth import SUPERUSER_ROLE
from neozen.admin.config import AdminConfig
from neozen.admin.services import AdminService

from .conftest import SuperadminClient, admin_client, superadmin_client


def _app(tmp_path: Path) -> Litestar:
    return create_admin_app(
        AdminConfig(db_url=f"sqlite+aiosqlite:///{tmp_path / 'a.db'}", secret_key="k")
    )


async def _roles(app: Litestar, subject_id: str) -> set[str]:
    async with app.state.session_factory() as session:
        roles = await AdminService(session).get_subject_roles(subject_id)
        return {r.name for r in roles}


async def _create(app: Litestar, email: str, role: str | None = None) -> str:
    async with app.state.session_factory() as session:
        service = AdminService(session)
        subject = await service.create_subject(email=email)
        if role:
            await service.assign_role_to_subject(subject.id, role)
        await session.commit()
        return subject.id


async def _role_permissions(app: Litestar, name: str) -> list[str]:
    async with app.state.session_factory() as session:
        role = await AdminService(session).get_role(name)
        return role.get_permissions_list()


def test_admin_cannot_grant_superuser(tmp_path: Path) -> None:
    app = _app(tmp_path)
    admin = admin_client(app)
    with admin as client, client.portal() as portal:
        client.post(
            f"/users/{admin.subject_id}/roles/add", data={"role_name": SUPERUSER_ROLE}
        )
        roles = portal.call(_roles, app, admin.subject_id)
    assert SUPERUSER_ROLE not in roles


def test_superadmin_can_grant_superuser(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with superadmin_client(app) as client, client.portal() as portal:
        other = portal.call(_create, app, "other@example.com")
        client.post(f"/users/{other}/roles/add", data={"role_name": SUPERUSER_ROLE})
        roles = portal.call(_roles, app, other)
    assert SUPERUSER_ROLE in roles


@pytest.mark.parametrize("action", ["delete", "deactivate", "revoke-sessions"])
def test_admin_cannot_act_on_a_superadmin(tmp_path: Path, action: str) -> None:
    app = _app(tmp_path)

    async def is_active(subject_id: str) -> bool | None:
        async with app.state.session_factory() as session:
            repo = AdminService(session).subject_repo
            if not await repo.exists(id=subject_id):
                return None
            return (await repo.get_one_by(id=subject_id)).is_active

    with admin_client(app) as client, client.portal() as portal:
        boss = portal.call(_create, app, "boss@example.com", SUPERUSER_ROLE)
        response = client.post(f"/users/{boss}/{action}", follow_redirects=False)
        assert response.status_code == 403
        assert portal.call(is_active, boss) is True


def test_admin_cannot_edit_role_permissions(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with admin_client(app) as client, client.portal() as portal:
        response = client.post(
            "/permissions/toggle", data={"role": "user", "permission": "*"}
        )
        assert response.status_code == 403
        assert "*" not in portal.call(_role_permissions, app, "user")


@pytest.mark.parametrize(
    ("path", "data"),
    [
        ("/roles/create", {"name": "boss", "permissions": "*"}),
        ("/roles/user/delete", {}),
        ("/permissions/role-builder", {"name": "boss", "permissions": "*"}),
    ],
)
def test_admin_cannot_define_roles(
    tmp_path: Path, path: str, data: dict[str, str]
) -> None:
    with admin_client(_app(tmp_path)) as client:
        assert client.post(path, data=data, follow_redirects=False).status_code == 403


def test_admin_cannot_update_users_by_import(tmp_path: Path) -> None:
    csv = b"email,is_active\nboss@example.com,false\n"
    with admin_client(_app(tmp_path)) as client:
        response = client.post(
            "/users/import",
            files={"csv_file": ("u.csv", csv, "text/csv")},
            data={"action": "apply", "update_existing": "on"},
        )
    assert response.status_code == 403


def test_superadmin_keeps_full_access(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with superadmin_client(app) as client:
        response = client.post(
            "/permissions/toggle", data={"role": "user", "permission": "doc:read"}
        )
    assert response.status_code == 200


def test_admin_still_manages_ordinary_users(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with admin_client(app) as client, client.portal() as portal:
        user = portal.call(_create, app, "u@example.com")
        response = client.post(f"/users/{user}/deactivate", follow_redirects=False)
        assert response.status_code == 303


__all__ = ["SuperadminClient"]
