"""Role management commands."""

from __future__ import annotations

import argparse
import asyncio
import json

from sqlalchemy.ext.asyncio import AsyncSession

from neozen.cli.database import DatabaseContext, get_database_url


async def _create_role(
    session: AsyncSession,
    name: str,
    permissions: list[str],
    description: str,
) -> dict:
    """Create a new role in the database."""
    from neozen.core.authz.services import RoleService  # noqa: PLC0415
    from neozen.storage.sqlalchemy.repositories import (  # noqa: PLC0415
        RoleAssignmentRepository,
        RoleRepository,
    )

    role_repo = RoleRepository(session=session)
    assignment_repo = RoleAssignmentRepository(session=session)
    service = RoleService(
        role_repository=role_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        role_assignment_repository=assignment_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )

    role = await service.create_role(
        name=name,
        permissions=permissions,
        description=description,
    )

    return {
        "id": role.id,
        "name": role.name,
        "description": role.description,
        "permissions": role.permissions.split(",") if role.permissions else [],
        "is_system": role.is_system,
    }


async def _list_roles(session: AsyncSession) -> list[dict]:
    """List all roles from the database."""
    from neozen.core.authz.services import RoleService  # noqa: PLC0415
    from neozen.storage.sqlalchemy.repositories import (  # noqa: PLC0415
        RoleAssignmentRepository,
        RoleRepository,
    )

    role_repo = RoleRepository(session=session)
    assignment_repo = RoleAssignmentRepository(session=session)
    service = RoleService(
        role_repository=role_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        role_assignment_repository=assignment_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )

    roles = await service.list_roles()

    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "permissions": r.permissions.split(",") if r.permissions else [],
            "is_system": r.is_system,
        }
        for r in roles
    ]


async def _delete_role(session: AsyncSession, name: str) -> None:
    """Delete a role from the database."""
    from neozen.core.authz.services import RoleService  # noqa: PLC0415
    from neozen.storage.sqlalchemy.repositories import (  # noqa: PLC0415
        RoleAssignmentRepository,
        RoleRepository,
    )

    role_repo = RoleRepository(session=session)
    assignment_repo = RoleAssignmentRepository(session=session)
    service = RoleService(
        role_repository=role_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        role_assignment_repository=assignment_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )

    await service.delete_role(name)


async def _assign_role(
    session: AsyncSession,
    subject_id: str,
    role_name: str,
    scope_type: str | None,
    scope_id: str | None,
) -> dict:
    """Assign a role to a subject."""
    from neozen.core.authz.models import ScopeType  # noqa: PLC0415
    from neozen.core.authz.services import RoleService  # noqa: PLC0415
    from neozen.storage.sqlalchemy.repositories import (  # noqa: PLC0415
        RoleAssignmentRepository,
        RoleRepository,
    )

    role_repo = RoleRepository(session=session)
    assignment_repo = RoleAssignmentRepository(session=session)
    service = RoleService(
        role_repository=role_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        role_assignment_repository=assignment_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )

    st = ScopeType(scope_type) if scope_type else ScopeType.GLOBAL

    assignment = await service.assign_role(
        subject_id=subject_id,
        role_name=role_name,
        scope_type=st,
        scope_id=scope_id,
    )

    return {
        "id": assignment.id,
        "subject_id": assignment.subject_id,
        "role_id": assignment.role_id,
        "scope_type": str(assignment.scope_type),
        "scope_id": assignment.scope_id,
    }


async def _revoke_role(
    session: AsyncSession,
    subject_id: str,
    role_name: str,
    scope_type: str | None,
    scope_id: str | None,
) -> None:
    """Revoke a role from a subject."""
    from neozen.core.authz.models import ScopeType  # noqa: PLC0415
    from neozen.core.authz.services import RoleService  # noqa: PLC0415
    from neozen.storage.sqlalchemy.repositories import (  # noqa: PLC0415
        RoleAssignmentRepository,
        RoleRepository,
    )

    role_repo = RoleRepository(session=session)
    assignment_repo = RoleAssignmentRepository(session=session)
    service = RoleService(
        role_repository=role_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        role_assignment_repository=assignment_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )

    st = ScopeType(scope_type) if scope_type else ScopeType.GLOBAL

    await service.revoke_role(
        subject_id=subject_id,
        role_name=role_name,
        scope_type=st,
        scope_id=scope_id,
    )


async def _list_subject_roles(session: AsyncSession, subject_id: str) -> list[dict]:
    """List roles assigned to a subject."""
    from neozen.core.authz.services import RoleService  # noqa: PLC0415
    from neozen.storage.sqlalchemy.repositories import (  # noqa: PLC0415
        RoleAssignmentRepository,
        RoleRepository,
    )

    role_repo = RoleRepository(session=session)
    assignment_repo = RoleAssignmentRepository(session=session)
    service = RoleService(
        role_repository=role_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        role_assignment_repository=assignment_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )

    roles = await service.get_subject_roles(subject_id)

    return [
        {
            "id": r.id,
            "name": r.name,
            "permissions": list(r.permissions),
            "is_system": r.is_system,
        }
        for r in roles
    ]


async def _init_builtin_roles(session: AsyncSession) -> list[str]:
    """Initialize built-in roles."""
    from neozen.core.authz.services import RoleService  # noqa: PLC0415
    from neozen.storage.sqlalchemy.repositories import (  # noqa: PLC0415
        RoleAssignmentRepository,
        RoleRepository,
    )

    role_repo = RoleRepository(session=session)
    assignment_repo = RoleAssignmentRepository(session=session)
    service = RoleService(
        role_repository=role_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        role_assignment_repository=assignment_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )

    await service.ensure_builtin_roles()

    roles = await service.list_roles()
    return [r.name for r in roles if r.is_system]


def create(args: argparse.Namespace) -> int:
    """Create a new role."""
    name = args.name
    permissions = args.permissions or []
    description = args.description or ""

    if not permissions:
        print("Error: At least one permission is required.")
        return 1

    async def run() -> int:
        db_url = get_database_url()
        async with DatabaseContext(db_url) as session:
            try:
                result = await _create_role(session, name, permissions, description)
                print("Role created successfully!")
                print(f"  ID:          {result['id']}")
                print(f"  Name:        {result['name']}")
                print(f"  Description: {result['description'] or '(none)'}")
                print(f"  Permissions: {', '.join(result['permissions'])}")
                return 0
            except ValueError as e:
                print(f"Error: {e}")
                return 1

    return asyncio.run(run())


def list_roles(args: argparse.Namespace) -> int:
    """List all roles."""
    output_format = args.format

    async def run() -> int:
        db_url = get_database_url()
        async with DatabaseContext(db_url) as session:
            roles = await _list_roles(session)

            if output_format == "json":
                print(json.dumps({"roles": roles}, indent=2, default=str))
            else:
                print("Roles")
                print("-" * 80)
                if not roles:
                    print("(No roles found)")
                else:
                    print(
                        f"{'Name':<20} {'Description':<30} {'System':<8} {'Permissions'}"
                    )
                    print("-" * 80)
                    for r in roles:
                        system = "Yes" if r["is_system"] else "No"
                        perms = ", ".join(r["permissions"][:3])
                        if len(r["permissions"]) > 3:
                            perms += f" (+{len(r['permissions']) - 3} more)"
                        print(
                            f"{r['name']:<20} {(r['description'] or '-')[:30]:<30} {system:<8} {perms}"
                        )
                print()
                print(f"Total: {len(roles)} role(s)")

            return 0

    return asyncio.run(run())


def delete(args: argparse.Namespace) -> int:
    """Delete a role."""
    name = args.name

    async def run() -> int:
        db_url = get_database_url()
        async with DatabaseContext(db_url) as session:
            try:
                await _delete_role(session, name)
                print(f"Role '{name}' deleted successfully.")
                return 0
            except Exception as e:
                print(f"Error: {e}")
                return 1

    return asyncio.run(run())


def assign(args: argparse.Namespace) -> int:
    """Assign a role to a subject."""
    subject_id = args.subject_id
    role_name = args.role
    scope_type = args.scope_type
    scope_id = args.scope_id

    async def run() -> int:
        db_url = get_database_url()
        async with DatabaseContext(db_url) as session:
            try:
                result = await _assign_role(
                    session, subject_id, role_name, scope_type, scope_id
                )
                print("Role assigned successfully!")
                print(f"  Subject: {result['subject_id']}")
                print(f"  Role:    {result['role_id']}")
                print(f"  Scope:   {result['scope_type']}")
                if result["scope_id"]:
                    print(f"  Scope ID: {result['scope_id']}")
                return 0
            except Exception as e:
                print(f"Error: {e}")
                return 1

    return asyncio.run(run())


def revoke(args: argparse.Namespace) -> int:
    """Revoke a role from a subject."""
    subject_id = args.subject_id
    role_name = args.role
    scope_type = args.scope_type
    scope_id = args.scope_id

    async def run() -> int:
        db_url = get_database_url()
        async with DatabaseContext(db_url) as session:
            try:
                await _revoke_role(session, subject_id, role_name, scope_type, scope_id)
                print(f"Role '{role_name}' revoked from subject '{subject_id}'.")
                return 0
            except Exception as e:
                print(f"Error: {e}")
                return 1

    return asyncio.run(run())


def show_subject(args: argparse.Namespace) -> int:
    """Show roles for a subject."""
    subject_id = args.subject_id
    output_format = args.format

    async def run() -> int:
        db_url = get_database_url()
        async with DatabaseContext(db_url) as session:
            roles = await _list_subject_roles(session, subject_id)

            if output_format == "json":
                print(json.dumps({"subject_id": subject_id, "roles": roles}, indent=2))
            else:
                print(f"Roles for subject: {subject_id}")
                print("-" * 60)
                if not roles:
                    print("(No roles assigned)")
                else:
                    for r in roles:
                        system = " (system)" if r["is_system"] else ""
                        print(f"  - {r['name']}{system}")
                        print(f"    Permissions: {', '.join(r['permissions'])}")
                print()
                print(f"Total: {len(roles)} role(s)")

            return 0

    return asyncio.run(run())


def init(args: argparse.Namespace) -> int:
    """Initialize built-in roles."""

    async def run() -> int:
        db_url = get_database_url()
        async with DatabaseContext(db_url) as session:
            try:
                roles = await _init_builtin_roles(session)
                print("Built-in roles initialized successfully!")
                for name in roles:
                    print(f"  - {name}")
                return 0
            except Exception as e:
                print(f"Error: {e}")
                return 1

    return asyncio.run(run())
