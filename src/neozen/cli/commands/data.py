"""Data management commands: dump, restore, populate.

Provides JSON-based data export/import and test data generation.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from neozen.cli.database import DatabaseContext, get_database_url


def _to_iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _from_iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


# =============================================================================
# Dump
# =============================================================================


async def _dump_subjects(session: AsyncSession) -> list[dict[str, Any]]:
    from neozen.storage.sqlalchemy import Subject  # noqa: PLC0415

    result = await session.execute(select(Subject))
    return [
        {
            "id": s.id,
            "email": s.email,
            "username": s.username,
            "hashed_password": s.hashed_password,
            "is_active": s.is_active,
            "is_verified": s.is_verified,
            "created_at": _to_iso(s.created_at),
        }
        for s in result.scalars().all()
    ]


async def _dump_roles(session: AsyncSession) -> list[dict[str, Any]]:
    from neozen.storage.sqlalchemy.repositories import RoleRepository  # noqa: PLC0415

    repo = RoleRepository(session=session)
    roles = await repo.get_many_by()
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "permissions": r.permissions,
            "is_system": r.is_system,
        }
        for r in roles
    ]


async def _dump_role_assignments(session: AsyncSession) -> list[dict[str, Any]]:
    from neozen.storage.sqlalchemy.repositories import (  # noqa: PLC0415
        RoleAssignmentRepository,
    )

    repo = RoleAssignmentRepository(session=session)
    assignments = await repo.get_many_by()
    return [
        {
            "id": a.id,
            "subject_id": a.subject_id,
            "role_id": a.role_id,
            "scope_type": a.scope_type,
            "scope_id": a.scope_id,
            "granted_by": a.granted_by,
            "granted_at": _to_iso(a.granted_at),
            "expires_at": _to_iso(a.expires_at),
        }
        for a in assignments
    ]


def dump(args: argparse.Namespace) -> int:
    """Export all subjects, roles, and role assignments to JSON."""
    output_path = Path(args.output) if args.output else None

    async def run() -> int:
        db_url = get_database_url()
        async with DatabaseContext(db_url) as session:
            data = {
                "version": 1,
                "exported_at": datetime.now(UTC).isoformat(),
                "subjects": await _dump_subjects(session),
                "roles": await _dump_roles(session),
                "role_assignments": await _dump_role_assignments(session),
            }

        text = json.dumps(data, indent=2, default=str)
        if output_path:
            output_path.write_text(text)
            print(
                f"Dumped {len(data['subjects'])} subjects, "
                f"{len(data['roles'])} roles, "
                f"{len(data['role_assignments'])} assignments "
                f"to {output_path}"
            )
        else:
            print(text)
        return 0

    return asyncio.run(run())


# =============================================================================
# Restore
# =============================================================================


async def _restore_subjects(
    session: AsyncSession, subjects: list[dict[str, Any]]
) -> int:
    from neozen.storage import DoesNotExist  # noqa: PLC0415
    from neozen.storage.sqlalchemy import SubjectRepository  # noqa: PLC0415

    repo = SubjectRepository(session=session)
    count = 0
    for s in subjects:
        try:
            await repo.get_one_by(id=s["id"])
            continue  # Already exists, skip
        except DoesNotExist:
            pass

        await repo.create(
            id=s["id"],
            email=s["email"],
            username=s.get("username"),
            hashed_password=s.get("hashed_password"),
            is_active=s.get("is_active", True),
            is_verified=s.get("is_verified", False),
        )
        count += 1
    return count


async def _restore_roles(session: AsyncSession, roles: list[dict[str, Any]]) -> int:
    from neozen.storage import DoesNotExist  # noqa: PLC0415
    from neozen.storage.sqlalchemy.repositories import RoleRepository  # noqa: PLC0415

    repo = RoleRepository(session=session)
    count = 0
    for r in roles:
        try:
            await repo.get_one_by(id=r["id"])
            continue
        except DoesNotExist:
            pass

        await repo.create(
            id=r["id"],
            name=r["name"],
            description=r.get("description", ""),
            permissions=r.get("permissions", ""),
            is_system=r.get("is_system", False),
        )
        count += 1
    return count


async def _restore_role_assignments(
    session: AsyncSession, assignments: list[dict[str, Any]]
) -> int:
    from neozen.storage import DoesNotExist  # noqa: PLC0415
    from neozen.storage.sqlalchemy.repositories import (  # noqa: PLC0415
        RoleAssignmentRepository,
    )

    repo = RoleAssignmentRepository(session=session)
    count = 0
    for a in assignments:
        try:
            await repo.get_one_by(id=a["id"])
            continue
        except DoesNotExist:
            pass

        await repo.create(
            id=a["id"],
            subject_id=a["subject_id"],
            role_id=a["role_id"],
            scope_type=a.get("scope_type", "global"),
            scope_id=a.get("scope_id"),
            granted_by=a.get("granted_by"),
            granted_at=_from_iso(a.get("granted_at")),
            expires_at=_from_iso(a.get("expires_at")),
        )
        count += 1
    return count


def restore(args: argparse.Namespace) -> int:
    """Restore subjects, roles, and role assignments from a JSON dump."""
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: file not found: {input_path}", file=sys.stderr)
        return 1

    try:
        data = json.loads(input_path.read_text())
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {e}", file=sys.stderr)
        return 1

    if data.get("version") != 1:
        print(
            f"Error: unsupported dump version: {data.get('version')}", file=sys.stderr
        )
        return 1

    async def run() -> int:
        db_url = get_database_url()
        async with DatabaseContext(db_url) as session:
            subjects_added = await _restore_subjects(session, data.get("subjects", []))
            roles_added = await _restore_roles(session, data.get("roles", []))
            assignments_added = await _restore_role_assignments(
                session, data.get("role_assignments", [])
            )
            await session.commit()

        print(
            f"Restored {subjects_added} new subjects, "
            f"{roles_added} new roles, "
            f"{assignments_added} new role assignments "
            f"(existing records skipped)"
        )
        return 0

    return asyncio.run(run())


# =============================================================================
# Populate (test data generation)
# =============================================================================


_FIRST_NAMES = [
    "alice",
    "bob",
    "carol",
    "dave",
    "eve",
    "frank",
    "grace",
    "henry",
    "iris",
    "jack",
    "kate",
    "leo",
    "mia",
    "noah",
    "olivia",
    "peter",
]
_LAST_NAMES = [
    "smith",
    "jones",
    "brown",
    "wilson",
    "taylor",
    "davies",
    "evans",
    "thomas",
    "roberts",
    "walker",
    "wright",
    "white",
    "edwards",
    "hughes",
]


def _random_user(index: int) -> dict[str, Any]:
    first = _FIRST_NAMES[index % len(_FIRST_NAMES)]
    last = _LAST_NAMES[(index // len(_FIRST_NAMES)) % len(_LAST_NAMES)]
    suffix = secrets.token_hex(3)
    return {
        "id": f"subj_{secrets.token_hex(12)}",
        "email": f"{first}.{last}.{suffix}@example.com",
        "username": f"{first}{last}{suffix}",
    }


async def _populate_users(session: AsyncSession, count: int) -> int:
    from pwdlib import PasswordHash  # noqa: PLC0415

    from neozen.storage.sqlalchemy import SubjectRepository  # noqa: PLC0415

    repo = SubjectRepository(session=session)
    hasher = PasswordHash.recommended()
    default_hash = hasher.hash("password123")

    for i in range(count):
        user = _random_user(i)
        await repo.create(
            id=user["id"],
            email=user["email"],
            username=user["username"],
            hashed_password=default_hash,
            is_active=True,
            is_verified=True,
        )
    await session.commit()
    return count


def populate(args: argparse.Namespace) -> int:
    """Generate test data (fake users)."""
    count = args.count

    async def run() -> int:
        db_url = get_database_url()
        async with DatabaseContext(db_url) as session:
            created = await _populate_users(session, count)
        print(f"Created {created} test users with password 'password123'")
        return 0

    return asyncio.run(run())
