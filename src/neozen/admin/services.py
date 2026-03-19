"""Admin services for managing subjects, roles, and sessions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from neozen.core.authz.services import RoleService
from neozen.storage.sqlalchemy.models import Role, RoleAssignment, Session, Subject
from neozen.storage.sqlalchemy.repositories import (
    RoleAssignmentRepository,
    RoleRepository,
    SessionRepository,
    SubjectRepository,
)


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
        self.role_service = RoleService(
            role_repository=self.role_repo,
            role_assignment_repository=self.role_assignment_repo,
        )

    # -------------------------------------------------------------------------
    # Dashboard
    # -------------------------------------------------------------------------

    async def get_dashboard_stats(self) -> DashboardStats:
        """Get dashboard statistics."""
        # Count subjects
        total_subjects = await self.subject_repo.count()
        active_subjects = await self.subject_repo.count(is_active=True)
        verified_subjects = await self.subject_repo.count(is_verified=True)

        # Count roles
        roles = await self.role_repo.get_many_by()
        total_roles = len(roles)
        system_roles = sum(1 for r in roles if r.is_system)

        # Count active sessions (not expired, not revoked)
        now = datetime.now(UTC)
        all_sessions = await self.session_repo.get_many_by()
        active_sessions = sum(
            1 for s in all_sessions if s.revoked_at is None and s.expires_at > now
        )

        # Recent registrations (last 7 days)
        week_ago = now - timedelta(days=7)
        all_subjects = await self.subject_repo.get_many_by()
        recent_registrations = sum(
            1 for s in all_subjects if s.created_at and s.created_at > week_ago
        )

        return DashboardStats(
            total_subjects=total_subjects,
            active_subjects=active_subjects,
            verified_subjects=verified_subjects,
            total_roles=total_roles,
            system_roles=system_roles,
            active_sessions=active_sessions,
            recent_registrations=recent_registrations,
        )

    # -------------------------------------------------------------------------
    # Subject Management
    # -------------------------------------------------------------------------

    async def list_subjects(
        self,
        *,
        offset: int = 0,
        limit: int = 50,
        search: str | None = None,
    ) -> list[Subject]:
        """List subjects with pagination and optional search.

        Args:
            offset: Number of records to skip
            limit: Maximum number of records to return
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
        assignments = await self.role_assignment_repo.get_many_by(subject_id=subject_id)
        roles = []
        for assignment in assignments:
            try:
                role = await self.role_repo.get_one_by(id=assignment.role_id)
                roles.append(role)
            except Exception:
                pass  # Role may have been deleted
        return roles

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
        return await self.role_service.create_role(
            name=name,
            permissions=permissions,
            description=description,
        )

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

    async def ensure_builtin_roles(self) -> None:
        """Ensure built-in roles exist."""
        await self.role_service.ensure_builtin_roles()

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
        sessions = await self.session_repo.get_many_by()

        if active_only:
            now = datetime.now(UTC)
            sessions = [
                s for s in sessions if s.revoked_at is None and s.expires_at > now
            ]

        return sessions

    async def revoke_session(self, token_hash: str) -> None:
        """Revoke a session by token hash.

        Args:
            token_hash: The session token hash
        """
        session = await self.session_repo.get_one_by(token_hash=token_hash)
        await self.session_repo.update_obj(session, revoked_at=datetime.now(UTC))


__all__ = ["AdminService", "DashboardStats"]
