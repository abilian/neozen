"""Admin services for managing subjects, roles, and sessions."""

from __future__ import annotations

import contextlib
import json
import operator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, cast, overload

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from neozen.core.audit.types import AuditLogEntry, AuditOutcome
from neozen.core.authz.services import RoleService
from neozen.core.utils import generate_id
from neozen.storage.sqlalchemy.models import (
    Group,
    GroupMembership,
    GroupRoleAssignment,
    Organization,
    Role,
    RoleAssignment,
    Session,
    Subject,
)
from neozen.storage.sqlalchemy.repositories import (
    GroupMembershipRepository,
    GroupRepository,
    GroupRoleAssignmentRepository,
    OrganizationRepository,
    RoleAssignmentRepository,
    RoleRepository,
    SessionRepository,
    SubjectRepository,
)
from neozen.storage.sqlalchemy.security_models import AuditLog
from neozen.storage.sqlalchemy.security_repositories import AuditLogRepository


@overload
def _ensure_aware(dt: datetime) -> datetime: ...


@overload
def _ensure_aware(dt: None) -> None: ...


def _ensure_aware(dt: datetime | None) -> datetime | None:
    """Ensure datetime is timezone-aware (assumes UTC if naive)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _subject_conditions(filters: UserListFilters) -> list[Any]:
    """SQL conditions for the user list filters."""
    conditions: list[Any] = []
    if filters.search:
        term = filters.search.lower()
        conditions.append(
            func.lower(Subject.email).contains(term, autoescape=True)
            | func.lower(Subject.username).contains(term, autoescape=True)
            | func.lower(Subject.id).contains(term, autoescape=True)
        )
    if filters.status:
        if "active" in filters.status and "inactive" not in filters.status:
            conditions.append(Subject.is_active.is_(True))
        elif "inactive" in filters.status and "active" not in filters.status:
            conditions.append(Subject.is_active.is_(False))
    if filters.mfa_enabled is not None:
        conditions.append(Subject.totp_enabled.is_(filters.mfa_enabled))
    if filters.is_verified is not None:
        conditions.append(Subject.is_verified.is_(filters.is_verified))
    if filters.created_after:
        conditions.append(Subject.created_at >= filters.created_after)
    if filters.created_before:
        conditions.append(Subject.created_at <= filters.created_before)
    return conditions


def _audit_conditions(
    *,
    search: str | None,
    event_type: str | None,
    action: str | None,
    outcome: str | None,
    subject_id: str | None,
    start_date: datetime | None,
    end_date: datetime | None,
) -> list[Any]:
    """SQL conditions for the audit log filters."""
    equal = {
        AuditLog.event_type: event_type,
        AuditLog.action: action,
        AuditLog.outcome: outcome,
        AuditLog.subject_id: subject_id,
    }
    conditions: list[Any] = [col == value for col, value in equal.items() if value]
    if start_date:
        conditions.append(AuditLog.timestamp >= start_date)
    if end_date:
        conditions.append(AuditLog.timestamp <= end_date)
    if search:
        term = search.lower()
        conditions.append(
            or_(
                *(
                    func.lower(col).contains(term, autoescape=True)
                    for col in (
                        AuditLog.action,
                        AuditLog.ip_address,
                        AuditLog.user_agent,
                        AuditLog.subject_id,
                    )
                )
            )
        )
    return conditions


def _subject_order(sort_by: str, sort_order: str) -> Any:
    """SQL ordering for the user list: by email or by creation date."""
    column = func.lower(Subject.email) if sort_by == "email" else Subject.created_at
    return column.desc() if sort_order == "desc" else column.asc()


def _role_has_permission(role_permissions: list[str], permission: str) -> bool:
    """Check if a role's permissions cover a specific permission."""
    if permission in role_permissions:
        return True
    # Check wildcard patterns
    for rp in role_permissions:
        if rp == "*:*":
            return True
        parts = permission.split(":")
        rp_parts = rp.split(":")
        if len(rp_parts) >= 2 and rp_parts[1] == "*" and parts[0] == rp_parts[0]:
            return True
    return False


@dataclass(frozen=True)
class DashboardStats:
    """Dashboard statistics."""

    total_subjects: int
    active_subjects: int
    verified_subjects: int
    total_roles: int
    system_roles: int
    active_sessions: int
    recent_registrations: int  # Last 7 days
    role_assignments: int = 0


@dataclass
class UserListFilters:
    """Filters for user list queries."""

    search: str | None = None
    status: list[str] | None = None  # active, inactive
    mfa_enabled: bool | None = None
    is_verified: bool | None = None
    created_after: datetime | None = None
    created_before: datetime | None = None
    sort_by: str = "created_at"
    sort_order: str = "desc"
    page: int = 1
    per_page: int = 50


@dataclass(frozen=True)
class SecurityCounts:
    """Counters shown on the security dashboard."""

    total_users: int
    mfa_enabled_users: int
    mfa_adoption: float
    active_session_count: int


@dataclass(frozen=True)
class PaginatedResult:
    """Paginated query result."""

    items: list[Any] = field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = 50

    @property
    def total_pages(self) -> int:
        return -(-self.total // self.per_page) if self.per_page > 0 else 0


class AdminService:
    """Admin operations service.

    Provides high-level admin operations that wrap the underlying
    repositories and services.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize admin service with database session.

        Args:
            session: SQLAlchemy async session
        """
        self.session = session
        self.subject_repo = SubjectRepository(session=session)
        self.session_repo = SessionRepository(session=session)
        self.role_repo = RoleRepository(session=session)
        self.role_assignment_repo = RoleAssignmentRepository(session=session)
        self.group_repo = GroupRepository(session=session)
        self.group_membership_repo = GroupMembershipRepository(session=session)
        self.group_role_assignment_repo = GroupRoleAssignmentRepository(session=session)
        self.organization_repo = OrganizationRepository(session=session)
        self.audit_log_repo = AuditLogRepository(session=session)
        self.role_service = RoleService(
            role_repository=self.role_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
            role_assignment_repository=self.role_assignment_repo,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        )

    # -------------------------------------------------------------------------
    # Dashboard
    # -------------------------------------------------------------------------

    async def get_dashboard_stats(self) -> DashboardStats:
        """Get dashboard statistics, counted in the database."""
        now = datetime.now(UTC)
        total_subjects = await self._count(Subject)
        return DashboardStats(
            total_subjects=total_subjects,
            active_subjects=await self._count(Subject, Subject.is_active.is_(True)),
            verified_subjects=await self._count(Subject, Subject.is_verified.is_(True)),
            total_roles=await self._count(Role),
            system_roles=await self._count(Role, Role.is_system.is_(True)),
            active_sessions=await self.count_active_sessions(),
            recent_registrations=await self._count(
                Subject, Subject.created_at > now - timedelta(days=7)
            ),
            role_assignments=await self._count(RoleAssignment),
        )

    async def get_security_counts(self) -> SecurityCounts:
        """Users, users with TOTP, and active sessions, for the security pages."""
        total = await self._count(Subject)
        with_mfa = await self._count(Subject, Subject.totp_enabled.is_(True))
        return SecurityCounts(
            total_users=total,
            mfa_enabled_users=with_mfa,
            mfa_adoption=with_mfa / total * 100 if total else 0,
            active_session_count=await self.count_active_sessions(),
        )

    async def count_active_sessions(self) -> int:
        """Sessions neither revoked nor expired."""
        return await self._count(Session, *self._active_session(active_only=True))

    async def _count(self, model: type[Any], *conditions: Any) -> int:
        stmt = select(func.count()).select_from(model).where(*conditions)
        return (await self.session.execute(stmt)).scalar_one()

    # -------------------------------------------------------------------------
    # Subject Management
    # -------------------------------------------------------------------------

    async def list_subjects(
        self,
        *,
        offset: int = 0,
        limit: int | None = 50,
        search: str | None = None,
    ) -> list[Subject]:
        """List subjects with pagination and optional search.

        Args:
            offset: Number of records to skip
            limit: Maximum number of records to return (None for all)
            search: Optional search term (matches email)

        Returns:
            List of subjects
        """
        # For now, get all and filter in memory
        # TODO: Add proper search to repository
        subjects = await self.subject_repo.get_many_by(offset=offset, limit=limit)

        if search:
            search_lower = search.lower()
            subjects = [
                s
                for s in subjects
                if search_lower in s.email.lower()
                or (s.username and search_lower in s.username.lower())
            ]

        return subjects

    async def get_subject(self, subject_id: str) -> Subject:
        """Get a subject by ID.

        Args:
            subject_id: The subject ID

        Returns:
            The subject

        Raises:
            DoesNotExist: If subject not found
        """
        return await self.subject_repo.get_one_by(id=subject_id)

    async def activate_subject(self, subject_id: str) -> Subject:
        """Activate a subject.

        Args:
            subject_id: The subject ID

        Returns:
            The updated subject
        """
        subject = await self.get_subject(subject_id)
        return await self.subject_repo.update_obj(subject, is_active=True)

    async def deactivate_subject(self, subject_id: str) -> Subject:
        """Deactivate a subject.

        Args:
            subject_id: The subject ID

        Returns:
            The updated subject
        """
        subject = await self.get_subject(subject_id)
        return await self.subject_repo.update_obj(subject, is_active=False)

    async def get_subject_roles(self, subject_id: str) -> list[Role]:
        """Get roles assigned to a subject.

        Args:
            subject_id: The subject ID

        Returns:
            List of roles
        """
        stmt = (
            select(Role)
            .join(RoleAssignment, RoleAssignment.role_id == Role.id)
            .where(RoleAssignment.subject_id == subject_id)
        )
        return list((await self.session.scalars(stmt)).all())

    async def list_subjects_paginated(
        self,
        filters: UserListFilters | None = None,
    ) -> PaginatedResult:
        """List subjects with filtering and pagination, done in the database.

        Args:
            filters: Filter and pagination options

        Returns:
            Paginated result with subjects
        """
        if filters is None:
            filters = UserListFilters()

        conditions = _subject_conditions(filters)
        total = await self._count(Subject, *conditions)
        stmt = (
            select(Subject)
            .where(*conditions)
            .order_by(_subject_order(filters.sort_by, filters.sort_order))
            .offset((filters.page - 1) * filters.per_page)
            .limit(filters.per_page)
        )
        return PaginatedResult(
            items=list((await self.session.scalars(stmt)).all()),
            total=total,
            page=filters.page,
            per_page=filters.per_page,
        )

    async def create_subject(
        self,
        email: str,
        *,
        username: str | None = None,
        password: str | None = None,
        is_active: bool = True,
        is_verified: bool = False,
    ) -> Subject:
        """Create a new subject.

        Args:
            email: Email address
            username: Optional username
            password: Optional hashed password
            is_active: Whether the subject is active
            is_verified: Whether email is verified

        Returns:
            The created subject
        """
        subject = Subject(
            id=generate_id(),
            email=email,
            username=username,
            hashed_password=password,
            is_active=is_active,
            is_verified=is_verified,
        )
        return await self.subject_repo.add(subject)

    async def update_subject(
        self,
        subject_id: str,
        *,
        email: str | None = None,
        username: str | None = None,
        is_active: bool | None = None,
        is_verified: bool | None = None,
    ) -> Subject:
        """Update a subject.

        Args:
            subject_id: The subject ID
            email: New email (if changing)
            username: New username (if changing)
            is_active: New active status (if changing)
            is_verified: New verified status (if changing)

        Returns:
            The updated subject
        """
        subject = await self.get_subject(subject_id)

        updates: dict[str, Any] = {}
        if email is not None:
            updates["email"] = email
        if username is not None:
            updates["username"] = username
        if is_active is not None:
            updates["is_active"] = is_active
        if is_verified is not None:
            updates["is_verified"] = is_verified

        if updates:
            return await self.subject_repo.update_obj(subject, **updates)
        return subject

    async def delete_subject(self, subject_id: str) -> None:
        """Delete a subject (hard delete).

        Args:
            subject_id: The subject ID
        """
        subject = await self.get_subject(subject_id)
        await self.subject_repo.delete(subject)

    async def get_subject_sessions(
        self,
        subject_id: str,
        *,
        active_only: bool = True,
    ) -> list[Session]:
        """Get sessions for a subject.

        Args:
            subject_id: The subject ID
            active_only: Only return active sessions

        Returns:
            List of sessions
        """
        sessions = await self.session_repo.get_many_by(subject_id=subject_id)

        if active_only:
            now = datetime.now(UTC)
            sessions = [
                s
                for s in sessions
                if s.revoked_at is None and _ensure_aware(s.expires_at) > now
            ]

        return sessions

    async def revoke_all_subject_sessions(self, subject_id: str) -> int:
        """Revoke all sessions for a subject.

        Args:
            subject_id: The subject ID

        Returns:
            Number of sessions revoked
        """
        sessions = await self.get_subject_sessions(subject_id, active_only=True)
        now = datetime.now(UTC)
        count = 0
        for session in sessions:
            await self.session_repo.update_obj(session, revoked_at=now)
            count += 1
        return count

    async def assign_role_to_subject(
        self,
        subject_id: str,
        role_name: str,
        *,
        granted_by: str | None = None,
    ) -> RoleAssignment:
        """Assign a role to a subject.

        Args:
            subject_id: The subject ID
            role_name: The role name
            granted_by: ID of admin granting the role

        Returns:
            The role assignment
        """
        role = await self.get_role(role_name)

        # Check if already assigned
        existing = await self.role_assignment_repo.get_many_by(
            subject_id=subject_id, role_id=role.id
        )
        if existing:
            return existing[0]

        assignment = RoleAssignment(
            id=generate_id(),
            subject_id=subject_id,
            role_id=role.id,
            granted_by=granted_by,
            granted_at=datetime.now(UTC),
        )
        return await self.role_assignment_repo.add(assignment)

    async def remove_role_from_subject(
        self,
        subject_id: str,
        role_name: str,
    ) -> None:
        """Remove a role from a subject.

        Args:
            subject_id: The subject ID
            role_name: The role name
        """
        role = await self.get_role(role_name)
        assignments = await self.role_assignment_repo.get_many_by(
            subject_id=subject_id, role_id=role.id
        )
        for assignment in assignments:
            await self.role_assignment_repo.delete(assignment)

    # -------------------------------------------------------------------------
    # Role Management
    # -------------------------------------------------------------------------

    async def list_roles(self) -> list[Role]:
        """List all roles.

        Returns:
            List of roles
        """
        return await self.role_repo.get_many_by()

    async def get_role(self, name: str) -> Role:
        """Get a role by name.

        Args:
            name: The role name

        Returns:
            The role

        Raises:
            DoesNotExist: If role not found
        """
        return await self.role_repo.get_one_by(name=name)

    async def create_role(
        self,
        name: str,
        permissions: list[str],
        description: str = "",
    ) -> Role:
        """Create a new role.

        Args:
            name: Role name
            permissions: List of permission strings
            description: Role description

        Returns:
            The created role
        """
        role = await self.role_service.create_role(
            name=name,
            permissions=permissions,
            description=description,
        )
        return cast(Role, role)

    async def delete_role(self, name: str) -> None:
        """Delete a role.

        Args:
            name: Role name

        Raises:
            SystemRoleError: If trying to delete a system role
        """
        await self.role_service.delete_role(name)

    async def get_role_assignments(self, role_name: str) -> list[RoleAssignment]:
        """Get all assignments for a role.

        Args:
            role_name: The role name

        Returns:
            List of role assignments
        """
        role = await self.get_role(role_name)
        return await self.role_assignment_repo.get_many_by(role_id=role.id)

    async def get_role_assignments_with_subjects(
        self, role: Role
    ) -> list[tuple[RoleAssignment, Subject | None]]:
        """A role's assignments, each with its subject (None if it is gone)."""
        stmt = (
            select(RoleAssignment, Subject)
            .outerjoin(Subject, Subject.id == RoleAssignment.subject_id)
            .where(RoleAssignment.role_id == role.id)
            .order_by(RoleAssignment.granted_at)
        )
        return [(a, subject) for a, subject in await self.session.execute(stmt)]

    async def ensure_builtin_roles(self) -> None:
        """Ensure built-in roles exist."""
        await self.role_service.ensure_builtin_roles()

    async def update_role_permissions(
        self, role_name: str, permissions: list[str]
    ) -> Role:
        """Update a role's permissions.

        Args:
            role_name: The role name
            permissions: New list of permissions

        Returns:
            The updated role
        """
        role = await self.get_role(role_name)
        role.set_permissions_list(permissions)
        return await self.role_repo.update(role)

    async def toggle_role_permission(
        self, role_name: str, permission: str, *, enabled: bool
    ) -> Role:
        """Toggle a permission for a role.

        Args:
            role_name: The role name
            permission: The permission to toggle
            enabled: Whether to enable or disable the permission

        Returns:
            The updated role
        """
        role = await self.get_role(role_name)
        permissions = set(role.get_permissions_list())

        if enabled:
            permissions.add(permission)
        else:
            permissions.discard(permission)

        role.set_permissions_list(sorted(permissions))
        return await self.role_repo.update(role)

    async def get_all_permissions(self) -> list[str]:
        """Get all unique permissions across all roles.

        Returns:
            Sorted list of unique permission strings
        """
        roles = await self.list_roles()
        all_permissions: set[str] = set()
        for role in roles:
            all_permissions.update(role.get_permissions_list())

        # Add standard permissions that should be available
        standard_permissions = {
            "user:read",
            "user:write",
            "user:delete",
            "user:read:own",
            "user:update:own",
            "role:read",
            "role:write",
            "role:delete",
            "group:read",
            "group:write",
            "group:delete",
            "session:read",
            "session:revoke",
            "audit:read",
            "settings:read",
            "settings:write",
        }
        all_permissions.update(standard_permissions)

        # Remove wildcard patterns from display
        return sorted([p for p in all_permissions if "*" not in p])

    async def get_effective_permissions(self, subject_id: str) -> list[dict[str, Any]]:
        """Get all effective permissions for a subject.

        Returns permissions with their source (direct role or group).

        Args:
            subject_id: The subject ID

        Returns:
            List of dicts with permission, source_type, source_id, source_name
        """
        result: list[dict[str, Any]] = []
        seen_permissions: set[str] = set()

        # Get direct role assignments
        roles = await self.get_subject_roles(subject_id)
        for role in roles:
            for perm in role.get_permissions_list():
                if perm not in seen_permissions:
                    result.append({
                        "permission": perm,
                        "source_type": "role",
                        "source_id": role.id,
                        "source_name": role.name,
                    })
                    seen_permissions.add(perm)

        # Roles held through the subject's groups
        stmt = (
            select(Group, Role)
            .join(GroupMembership, GroupMembership.group_id == Group.id)
            .join(GroupRoleAssignment, GroupRoleAssignment.group_id == Group.id)
            .join(Role, Role.id == GroupRoleAssignment.role_id)
            .where(GroupMembership.subject_id == subject_id)
        )
        for group, role in await self.session.execute(stmt):
            for perm in role.get_permissions_list():
                if perm not in seen_permissions:
                    result.append({
                        "permission": perm,
                        "source_type": "group",
                        "source_id": group.id,
                        "source_name": f"{group.name} ({role.name})",
                    })
                    seen_permissions.add(perm)

        return result

    async def get_subjects_with_permission(
        self, permission: str
    ) -> list[dict[str, Any]]:
        """Find all subjects who have a specific permission.

        Args:
            permission: The permission to search for

        Returns:
            List of dicts with subject, source_type, source_name
        """
        result: list[dict[str, Any]] = []
        seen_subjects: set[str] = set()

        # Wildcards are matched here, so the roles are filtered in Python.
        names = {
            role.id: role.name
            for role in await self.list_roles()
            if _role_has_permission(role.get_permissions_list(), permission)
        }
        if names:
            role_ids = list(names)
            await self._add_role_subjects(role_ids, names, result, seen_subjects)
            await self._add_group_role_subjects(role_ids, names, result, seen_subjects)
        return result

    async def _add_role_subjects(
        self,
        role_ids: list[str],
        names: dict[str, str],
        result: list[dict[str, Any]],
        seen: set[str],
    ) -> None:
        """Add subjects with a direct assignment of one of the roles."""
        stmt = (
            select(Subject, RoleAssignment.role_id)
            .join(RoleAssignment, RoleAssignment.subject_id == Subject.id)
            .where(RoleAssignment.role_id.in_(role_ids))
            .order_by(RoleAssignment.granted_at)
        )
        for subject, role_id in (await self.session.execute(stmt)).all():
            if subject.id in seen:
                continue
            result.append({
                "subject": subject,
                "source_type": "role",
                "source_name": names[role_id],
            })
            seen.add(subject.id)

    async def _add_group_role_subjects(
        self,
        role_ids: list[str],
        names: dict[str, str],
        result: list[dict[str, Any]],
        seen: set[str],
    ) -> None:
        """Add members of groups that hold one of the roles."""
        stmt = (
            select(Subject, Group.name, GroupRoleAssignment.role_id)
            .join(GroupMembership, GroupMembership.subject_id == Subject.id)
            .join(Group, Group.id == GroupMembership.group_id)
            .join(GroupRoleAssignment, GroupRoleAssignment.group_id == Group.id)
            .where(GroupRoleAssignment.role_id.in_(role_ids))
            .order_by(GroupRoleAssignment.granted_at, GroupMembership.added_at)
        )
        for member, group_name, role_id in (await self.session.execute(stmt)).all():
            if member.id in seen:
                continue
            result.append({
                "subject": member,
                "source_type": "group",
                "source_name": f"{group_name} ({names[role_id]})",
            })
            seen.add(member.id)

    # -------------------------------------------------------------------------
    # Session Management
    # -------------------------------------------------------------------------

    async def list_sessions(
        self,
        *,
        active_only: bool = True,
    ) -> list[Session]:
        """List sessions.

        Args:
            active_only: Only return active (non-revoked, non-expired) sessions

        Returns:
            List of sessions
        """
        stmt = select(Session).where(*self._active_session(active_only=active_only))
        return list((await self.session.scalars(stmt)).all())

    async def list_sessions_with_subjects(
        self, *, page: int = 1, per_page: int = 50
    ) -> PaginatedResult:
        """A page of active sessions, most recently used first.

        Each item is ``(session, subject)``; the subject is None if it is gone.
        """
        stmt = (
            select(Session, Subject)
            .outerjoin(Subject, Subject.id == Session.subject_id)
            .where(*self._active_session(active_only=True))
            .order_by(Session.last_activity_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
        )
        rows = [(sess, subject) for sess, subject in await self.session.execute(stmt)]
        return PaginatedResult(
            items=rows,
            total=await self.count_active_sessions(),
            page=page,
            per_page=per_page,
        )

    @staticmethod
    def _active_session(*, active_only: bool) -> list[Any]:
        if not active_only:
            return []
        return [Session.revoked_at.is_(None), Session.expires_at > datetime.now(UTC)]

    async def revoke_session(self, token_hash: str) -> None:
        """Revoke a session by token hash.

        Args:
            token_hash: The session token hash
        """
        session = await self.session_repo.get_one_by(token_hash=token_hash)
        await self.session_repo.update_obj(session, revoked_at=datetime.now(UTC))

    # -------------------------------------------------------------------------
    # Group Management
    # -------------------------------------------------------------------------

    async def list_groups(
        self,
        *,
        search: str | None = None,
        organization_id: str | None = None,
    ) -> list[Group]:
        """List all groups.

        Args:
            search: Optional search term
            organization_id: Filter by organization

        Returns:
            List of groups
        """
        if organization_id:
            groups = await self.group_repo.get_many_by(organization_id=organization_id)
        else:
            groups = await self.group_repo.get_many_by()

        if search:
            search_lower = search.lower()
            groups = [
                g
                for g in groups
                if search_lower in g.name.lower()
                or search_lower in g.description.lower()
            ]

        return groups

    async def get_group(self, group_id: str) -> Group:
        """Get a group by ID.

        Args:
            group_id: The group ID

        Returns:
            The group

        Raises:
            DoesNotExist: If group not found
        """
        return await self.group_repo.get_one_by(id=group_id)

    async def create_group(
        self,
        name: str,
        *,
        description: str = "",
        parent_id: str | None = None,
        organization_id: str | None = None,
    ) -> Group:
        """Create a new group.

        Args:
            name: Group name
            description: Group description
            parent_id: Parent group ID for nested groups
            organization_id: Organization ID for multi-tenant

        Returns:
            The created group
        """
        group = Group(
            id=generate_id(),
            name=name,
            description=description,
            parent_id=parent_id,
            organization_id=organization_id,
            is_active=True,
        )
        return await self.group_repo.add(group)

    async def update_group(
        self,
        group_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        is_active: bool | None = None,
    ) -> Group:
        """Update a group.

        Args:
            group_id: The group ID
            name: New name
            description: New description
            is_active: New active status

        Returns:
            The updated group
        """
        group = await self.get_group(group_id)
        updates: dict[str, Any] = {}
        if name is not None:
            updates["name"] = name
        if description is not None:
            updates["description"] = description
        if is_active is not None:
            updates["is_active"] = is_active
        if updates:
            return await self.group_repo.update_obj(group, **updates)
        return group

    async def delete_group(self, group_id: str) -> None:
        """Delete a group.

        Args:
            group_id: The group ID
        """
        group = await self.get_group(group_id)
        await self.group_repo.delete(group)

    async def get_group_members(self, group_id: str) -> list[tuple[Subject, str]]:
        """Get the members of a group, with their membership role."""
        stmt = (
            select(Subject, GroupMembership.role)
            .join(GroupMembership, GroupMembership.subject_id == Subject.id)
            .where(GroupMembership.group_id == group_id)
            .order_by(GroupMembership.added_at)
        )
        return [(subject, role) for subject, role in await self.session.execute(stmt)]

    async def add_group_member(
        self,
        group_id: str,
        subject_id: str,
        *,
        role: str = "member",
        added_by: str | None = None,
    ) -> GroupMembership:
        """Add a member to a group.

        Args:
            group_id: The group ID
            subject_id: The subject ID to add
            role: Membership role (member, admin, owner)
            added_by: ID of admin adding the member

        Returns:
            The group membership
        """
        # Check if already a member
        existing = await self.group_membership_repo.get_many_by(
            group_id=group_id, subject_id=subject_id
        )
        if existing:
            return existing[0]

        membership = GroupMembership(
            id=generate_id(),
            group_id=group_id,
            subject_id=subject_id,
            role=role,
            added_by=added_by,
            added_at=datetime.now(UTC),
        )
        return await self.group_membership_repo.add(membership)

    async def remove_group_member(self, group_id: str, subject_id: str) -> None:
        """Remove a member from a group.

        Args:
            group_id: The group ID
            subject_id: The subject ID to remove
        """
        memberships = await self.group_membership_repo.get_many_by(
            group_id=group_id, subject_id=subject_id
        )
        for m in memberships:
            await self.group_membership_repo.delete(m)

    async def get_group_roles(self, group_id: str) -> list[Role]:
        """Get the roles assigned to a group."""
        stmt = (
            select(Role)
            .join(GroupRoleAssignment, GroupRoleAssignment.role_id == Role.id)
            .where(GroupRoleAssignment.group_id == group_id)
        )
        return list((await self.session.scalars(stmt)).all())

    async def assign_role_to_group(
        self,
        group_id: str,
        role_name: str,
        *,
        granted_by: str | None = None,
    ) -> GroupRoleAssignment:
        """Assign a role to a group.

        Args:
            group_id: The group ID
            role_name: The role name
            granted_by: ID of admin granting the role

        Returns:
            The group role assignment
        """
        role = await self.get_role(role_name)

        existing = await self.group_role_assignment_repo.get_many_by(
            group_id=group_id, role_id=role.id
        )
        if existing:
            return existing[0]

        assignment = GroupRoleAssignment(
            id=generate_id(),
            group_id=group_id,
            role_id=role.id,
            granted_by=granted_by,
            granted_at=datetime.now(UTC),
        )
        return await self.group_role_assignment_repo.add(assignment)

    async def remove_role_from_group(self, group_id: str, role_name: str) -> None:
        """Remove a role from a group.

        Args:
            group_id: The group ID
            role_name: The role name
        """
        role = await self.get_role(role_name)
        assignments = await self.group_role_assignment_repo.get_many_by(
            group_id=group_id, role_id=role.id
        )
        for a in assignments:
            await self.group_role_assignment_repo.delete(a)

    # -------------------------------------------------------------------------
    # Organization Management
    # -------------------------------------------------------------------------

    async def list_organizations(
        self, *, search: str | None = None
    ) -> list[Organization]:
        """List all organizations.

        Args:
            search: Optional search term

        Returns:
            List of organizations
        """
        orgs = await self.organization_repo.get_many_by()
        if search:
            search_lower = search.lower()
            orgs = [
                o
                for o in orgs
                if search_lower in o.name.lower() or search_lower in o.slug.lower()
            ]
        return orgs

    async def get_organization(self, org_id: str) -> Organization:
        """Get an organization by ID.

        Args:
            org_id: The organization ID

        Returns:
            The organization

        Raises:
            DoesNotExist: If organization not found
        """
        return await self.organization_repo.get_one_by(id=org_id)

    async def get_organization_by_slug(self, slug: str) -> Organization:
        """Get an organization by slug.

        Args:
            slug: The organization slug

        Returns:
            The organization

        Raises:
            DoesNotExist: If organization not found
        """
        return await self.organization_repo.get_one_by(slug=slug)

    async def create_organization(
        self,
        name: str,
        slug: str,
        *,
        domain: str | None = None,
        plan: str = "free",
    ) -> Organization:
        """Create a new organization.

        Args:
            name: Organization name
            slug: URL-safe identifier
            domain: Optional domain for SSO
            plan: Subscription plan

        Returns:
            The created organization
        """
        org = Organization(
            id=generate_id(),
            name=name,
            slug=slug,
            domain=domain,
            plan=plan,
            is_active=True,
            settings_json="{}",
        )
        return await self.organization_repo.add(org)

    async def update_organization(
        self,
        org_id: str,
        *,
        name: str | None = None,
        domain: str | None = None,
        plan: str | None = None,
        is_active: bool | None = None,
    ) -> Organization:
        """Update an organization.

        Args:
            org_id: The organization ID
            name: New name
            domain: New domain
            plan: New plan
            is_active: New active status

        Returns:
            The updated organization
        """
        org = await self.get_organization(org_id)
        updates: dict[str, Any] = {}
        if name is not None:
            updates["name"] = name
        if domain is not None:
            updates["domain"] = domain
        if plan is not None:
            updates["plan"] = plan
        if is_active is not None:
            updates["is_active"] = is_active
        if updates:
            return await self.organization_repo.update_obj(org, **updates)
        return org

    async def delete_organization(self, org_id: str) -> None:
        """Delete an organization.

        Args:
            org_id: The organization ID
        """
        org = await self.get_organization(org_id)
        await self.organization_repo.delete(org)

    # -------------------------------------------------------------------------
    # Audit Log Management
    # -------------------------------------------------------------------------

    async def list_audit_logs(
        self,
        *,
        search: str | None = None,
        event_type: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        subject_id: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> list[AuditLogEntry]:
        """List audit log entries with filters, most recent first.

        Args:
            search: Search term (matches action, IP, user agent, subject)
            event_type: Filter by event type
            action: Filter by action
            outcome: Filter by outcome
            subject_id: Filter by subject
            start_date: Filter by start date
            end_date: Filter by end date
            offset: Pagination offset
            limit: Maximum entries to return
        """
        stmt = (
            select(AuditLog)
            .where(
                *_audit_conditions(
                    search=search,
                    event_type=event_type,
                    action=action,
                    outcome=outcome,
                    subject_id=subject_id,
                    start_date=start_date,
                    end_date=end_date,
                )
            )
            .order_by(AuditLog.timestamp.desc())
            .offset(offset)
            .limit(limit)
        )
        logs = (await self.session.scalars(stmt)).all()
        return [self._audit_log_to_entry(log) for log in logs]

    async def count_audit_logs(
        self,
        *,
        search: str | None = None,
        event_type: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        subject_id: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> int:
        """Count audit log entries with the same filters as `list_audit_logs`."""
        return await self._count(
            AuditLog,
            *_audit_conditions(
                search=search,
                event_type=event_type,
                action=action,
                outcome=outcome,
                subject_id=subject_id,
                start_date=start_date,
                end_date=end_date,
            ),
        )

    async def audit_filter_choices(self) -> tuple[list[str], list[str]]:
        """The event types and actions found in the audit log, sorted."""
        event_types = await self.session.scalars(
            select(AuditLog.event_type).distinct().order_by(AuditLog.event_type)
        )
        actions = await self.session.scalars(
            select(AuditLog.action).distinct().order_by(AuditLog.action)
        )
        return list(event_types), list(actions)

    async def get_audit_log(self, entry_id: str) -> AuditLogEntry | None:
        """Get a specific audit log entry."""
        stmt = select(AuditLog).where(AuditLog.id == entry_id)
        result = await self.session.execute(stmt)
        log = result.scalar_one_or_none()
        if log is None:
            return None
        return self._audit_log_to_entry(log)

    async def get_audit_stats(
        self,
        *,
        days: int = 7,
    ) -> dict[str, Any]:
        """Get audit log statistics for the security dashboard.

        Args:
            days: Number of days to analyze

        Returns:
            Dict with various security metrics
        """
        now = datetime.now(UTC)
        start_date = now - timedelta(days=days)

        # Count by outcome
        success_count = await self.count_audit_logs(
            outcome="success", start_date=start_date
        )
        failure_count = await self.count_audit_logs(
            outcome="failure", start_date=start_date
        )
        error_count = await self.count_audit_logs(
            outcome="error", start_date=start_date
        )

        # Count logins
        login_success = await self.count_audit_logs(
            action="login", outcome="success", start_date=start_date
        )
        login_failed = await self.count_audit_logs(
            action="login_failed", start_date=start_date
        )

        # MFA events
        mfa_enabled = await self.count_audit_logs(
            action="mfa_enable", start_date=start_date
        )
        mfa_verify_failed = await self.count_audit_logs(
            action="mfa_verify_failed", start_date=start_date
        )

        # Password events
        password_changes = await self.count_audit_logs(
            action="password_change", start_date=start_date
        )
        password_resets = await self.count_audit_logs(
            action="password_reset_complete", start_date=start_date
        )

        # Session events
        sessions_created = await self.count_audit_logs(
            action="session_create", start_date=start_date
        )
        sessions_revoked = await self.count_audit_logs(
            action="session_revoke", start_date=start_date
        )

        # Recent failed logins (for top IPs)
        failed_login_logs = await self.list_audit_logs(
            action="login_failed", start_date=start_date, limit=100
        )
        ip_failure_counts: dict[str, int] = {}
        for entry in failed_login_logs:
            if entry.ip_address:
                ip_failure_counts[entry.ip_address] = (
                    ip_failure_counts.get(entry.ip_address, 0) + 1
                )
        top_failed_ips = sorted(
            ip_failure_counts.items(), key=operator.itemgetter(1), reverse=True
        )[:5]

        return {
            "period_days": days,
            "total_events": success_count + failure_count + error_count,
            "success_count": success_count,
            "failure_count": failure_count,
            "error_count": error_count,
            "login_success": login_success,
            "login_failed": login_failed,
            "mfa_enabled": mfa_enabled,
            "mfa_verify_failed": mfa_verify_failed,
            "password_changes": password_changes,
            "password_resets": password_resets,
            "sessions_created": sessions_created,
            "sessions_revoked": sessions_revoked,
            "top_failed_ips": top_failed_ips,
        }

    async def get_login_activity(self, *, days: int = 7) -> list[dict[str, Any]]:
        """Get daily login activity for charts, in one query.

        Returns list of {date, day, success, failed} dicts, oldest first.
        """
        today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        start = today - timedelta(days=days - 1)
        day = func.date(AuditLog.timestamp)
        succeeded = (AuditLog.action == "login") & (AuditLog.outcome == "success")
        stmt = (
            select(day, succeeded, func.count())
            .where(
                AuditLog.timestamp >= start,
                succeeded | (AuditLog.action == "login_failed"),
            )
            .group_by(day, succeeded)
        )
        counts = {
            (str(date), bool(ok)): n for date, ok, n in await self.session.execute(stmt)
        }
        activity = []
        for i in range(days):
            date = start + timedelta(days=i)
            key = date.strftime("%Y-%m-%d")
            activity.append({
                "date": key,
                "day": date.strftime("%a"),
                "success": counts.get((key, True), 0),
                "failed": counts.get((key, False), 0),
            })
        return activity

    async def record_admin_action(
        self,
        *,
        action: str,
        actor_id: str,
        subject_id: str | None = None,
        ip_address: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Write an audit entry for an admin action (on a subject, if any)."""
        await self.audit_log_repo.create(
            id=generate_id(),
            timestamp=datetime.now(UTC),
            event_type="admin",
            action=action,
            outcome=AuditOutcome.SUCCESS,
            subject_id=subject_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details=json.dumps(details) if details else None,
        )

    async def commit(self) -> None:
        """Commit the request's changes."""
        await self.session.commit()

    def _audit_log_to_entry(self, log: AuditLog) -> AuditLogEntry:
        """Convert AuditLog model to AuditLogEntry."""
        details = {}
        if log.details:
            with contextlib.suppress(json.JSONDecodeError):
                details = json.loads(log.details)

        return AuditLogEntry(
            id=log.id,
            timestamp=log.timestamp,
            event_type=log.event_type,
            action=log.action,
            outcome=log.outcome,
            subject_id=log.subject_id,
            actor_id=log.actor_id,
            ip_address=log.ip_address,
            user_agent=log.user_agent,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            details=details,
            request_id=log.request_id,
        )


__all__ = ["AdminService", "DashboardStats", "PaginatedResult", "UserListFilters"]
