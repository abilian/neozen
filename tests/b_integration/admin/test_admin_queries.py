"""Admin console data access: the query count must not grow with the data."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from neozen.admin.services import AdminService, UserListFilters
from neozen.core.authz.services import AuthorizationService
from neozen.storage.sqlalchemy.base import Base

pytestmark = pytest.mark.anyio


@pytest.fixture
async def engine() -> AsyncGenerator[AsyncEngine, None]:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


async def _seed(service: AdminService, n: int) -> dict[str, str]:
    """n subjects, groups and roles.

    The first subject and group hold every role, and every subject holds r0.
    """
    await service.ensure_builtin_roles()
    first: dict[str, str] = {}
    for i in range(n):
        role = await service.create_role(f"r{i}", ["doc:write"])
        subject = await service.create_subject(email=f"u{i}@example.com")
        group = await service.create_group(f"g{i}")
        first.setdefault("subject", subject.id)
        first.setdefault("group", group.id)
        for subject_id in {subject.id, first["subject"]}:
            await service.assign_role_to_subject(subject_id, role.name)
            await service.add_group_member(group.id, subject_id)
        for group_id in {group.id, first["group"]}:
            await service.assign_role_to_group(group_id, role.name)
        if group.id != first["group"]:
            await service.add_group_member(first["group"], subject.id)
            await service.assign_role_to_subject(subject.id, "r0")
    return first


async def _count_queries(
    engine: AsyncEngine,
    n: int,
    call: Callable[[AdminService, dict[str, str]], Awaitable[Any]],
) -> int:
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        service = AdminService(session)
        ids = await _seed(service, n)
        await session.commit()

        statements: list[str] = []

        def record(*args: Any) -> None:
            statements.append(args[2])

        event.listen(engine.sync_engine, "before_cursor_execute", record)
        try:
            await call(service, ids)
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", record)
        return len(statements)


async def _role_assignments(service: AdminService, name: str) -> object:
    return await service.get_role_assignments_with_subjects(
        await service.get_role(name)
    )


CALLS: dict[str, Callable[[AdminService, dict[str, str]], Awaitable[Any]]] = {
    "dashboard_stats": lambda s, _: s.get_dashboard_stats(),
    "security_counts": lambda s, _: s.get_security_counts(),
    "subjects_page": lambda s, _: s.list_subjects_paginated(
        UserListFilters(search="example", per_page=2)
    ),
    "subject_roles": lambda s, ids: s.get_subject_roles(ids["subject"]),
    "effective_permissions": lambda s, ids: s.get_effective_permissions(ids["subject"]),
    "subjects_with_permission": lambda s, _: s.get_subjects_with_permission(
        "doc:write"
    ),
    "role_assignments": lambda s, _: _role_assignments(s, "r0"),
    "group_members": lambda s, ids: s.get_group_members(ids["group"]),
    "group_roles": lambda s, ids: s.get_group_roles(ids["group"]),
    "login_activity": lambda s, _: s.get_login_activity(days=7),
    "permission_check": lambda s, ids: AuthorizationService(
        s.role_service
    ).has_permission(ids["subject"], "doc:delete"),
}


@pytest.mark.parametrize("name", CALLS)
async def test_query_count_does_not_grow_with_the_data(
    engine: AsyncEngine, name: str
) -> None:
    small = await _count_queries(engine, 2, CALLS[name])
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    large = await _count_queries(engine, 6, CALLS[name])
    assert large == small


# -----------------------------------------------------------------------------
# What the queries return
# -----------------------------------------------------------------------------


@pytest.fixture
async def service(engine: AsyncEngine) -> AsyncGenerator[AdminService, None]:
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        service = AdminService(session)
        await service.ensure_builtin_roles()
        yield service


async def test_subject_list_filters_sorts_and_pages(service: AdminService) -> None:
    for email in ["carol@x.org", "Alice@x.org", "bob@y.org", "dave@x.org"]:
        await service.create_subject(email=email, is_active=email != "dave@x.org")

    page = await service.list_subjects_paginated(
        UserListFilters(
            search="X.ORG",
            status=["active"],
            sort_by="email",
            sort_order="asc",
            per_page=1,
            page=2,
        )
    )

    assert page.total == 2
    assert [s.email for s in page.items] == ["carol@x.org"]


async def test_search_treats_wildcards_literally(service: AdminService) -> None:
    await service.create_subject(email="a_b@x.org")
    await service.create_subject(email="axb@x.org")

    page = await service.list_subjects_paginated(UserListFilters(search="a_b"))

    assert [s.email for s in page.items] == ["a_b@x.org"]


async def test_permission_sources(service: AdminService) -> None:
    await service.create_role("editor", ["doc:write"])
    await service.create_role("reviewer", ["doc:*"])
    alice = await service.create_subject(email="alice@x.org")
    bob = await service.create_subject(email="bob@x.org")
    group = await service.create_group("writers")
    await service.assign_role_to_subject(alice.id, "editor")
    await service.assign_role_to_group(group.id, "reviewer")
    await service.add_group_member(group.id, bob.id)

    holders = await service.get_subjects_with_permission("doc:write")
    effective = await service.get_effective_permissions(bob.id)

    assert {(h["subject"].email, h["source_name"]) for h in holders} == {
        ("alice@x.org", "editor"),
        ("bob@x.org", "writers (reviewer)"),
    }
    assert [(e["permission"], e["source_name"]) for e in effective] == [
        ("doc:*", "writers (reviewer)")
    ]


async def test_login_activity_counts_per_day(service: AdminService) -> None:
    now = datetime.now(UTC)
    for i, (action, outcome, days_ago) in enumerate([
        ("login", "success", 0),
        ("login", "success", 0),
        ("login_failed", "failure", 0),
        ("login", "success", 1),
        ("login", "success", 9),  # outside the window
    ]):
        await service.audit_log_repo.create(
            id=f"log-{i}",
            timestamp=now - timedelta(days=days_ago),
            event_type="auth",
            action=action,
            outcome=outcome,
        )

    activity = await service.get_login_activity(days=7)

    assert len(activity) == 7
    assert (activity[-1]["success"], activity[-1]["failed"]) == (2, 1)
    assert (activity[-2]["success"], activity[-2]["failed"]) == (1, 0)
    assert sum(day["success"] for day in activity) == 3


async def test_audit_search_covers_every_page(service: AdminService) -> None:
    now = datetime.now(UTC)
    for i in range(60):
        await service.audit_log_repo.create(
            id=f"log-{i}",
            timestamp=now - timedelta(minutes=i),
            event_type="auth",
            action="login",
            outcome="success",
            ip_address="10.0.0.99" if i == 59 else "10.0.0.1",
        )

    found = await service.list_audit_logs(search="10.0.0.99", limit=50)

    assert [e.id for e in found] == ["log-59"]
    assert await service.count_audit_logs(search="10.0.0.99") == 1
