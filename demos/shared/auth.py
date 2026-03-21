"""Shared authentication utilities for NeoZen demo applications."""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from neozen.core.authz.models import ScopeType
from neozen.core.session.service import SessionService
from neozen.storage.base import DoesNotExist
from neozen.storage.sqlalchemy.models import RoleAssignment, Session, Subject
from neozen.storage.sqlalchemy.repositories import (
    RoleAssignmentRepository,
    RoleRepository,
    SessionRepository,
    SubjectRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import async_sessionmaker


class SessionServiceFactory:
    """Factory for creating SessionService instances per request.

    The SessionService requires a repository, but repositories need database
    sessions. This factory creates services lazily with proper session scope.
    """

    def __init__(self, session_factory: async_sessionmaker, secret_key: str) -> None:
        """Initialize the factory.

        Args:
            session_factory: SQLAlchemy async session factory.
            secret_key: Secret key for session token hashing.
        """
        self.session_factory = session_factory
        self.secret_key = secret_key

    async def create_session(
        self,
        subject_id: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> str:
        """Create a new session for a subject.

        Args:
            subject_id: The subject ID.
            ip_address: Client IP address.
            user_agent: Client user agent.

        Returns:
            The plaintext session token.
        """
        async with self.session_factory() as db_session:
            repo = SessionRepository(session=db_session)
            service = SessionService[Session](storage=repo, hash_key=self.secret_key)
            token = await service.create_session(
                subject_id,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            await db_session.commit()
            return token

    async def validate_session(
        self,
        token: str,
        *,
        update_activity: bool = True,
    ) -> Session | None:
        """Validate a session token.

        Args:
            token: The plaintext session token.
            update_activity: Whether to update last activity timestamp.

        Returns:
            The session record if valid, None otherwise.
        """
        async with self.session_factory() as db_session:
            repo = SessionRepository(session=db_session)
            service = SessionService[Session](storage=repo, hash_key=self.secret_key)
            try:
                session = await service.validate_session(
                    token, update_activity=update_activity
                )
                if update_activity:
                    await db_session.commit()
                return session
            except Exception:
                return None

    async def revoke_session_by_token(self, token: str) -> None:
        """Revoke a session by its token.

        Args:
            token: The plaintext session token.
        """
        async with self.session_factory() as db_session:
            repo = SessionRepository(session=db_session)
            service = SessionService[Session](storage=repo, hash_key=self.secret_key)
            await service.revoke_session_by_token(token)
            await db_session.commit()


class RoleServiceFactory:
    """Factory for role-related operations."""

    def __init__(self, session_factory: async_sessionmaker) -> None:
        """Initialize the factory.

        Args:
            session_factory: SQLAlchemy async session factory.
        """
        self.session_factory = session_factory

    async def assign_role(
        self,
        subject_id: str,
        role_name: str,
        *,
        granted_by: str | None = None,
    ) -> RoleAssignment:
        """Assign a role to a subject.

        Args:
            subject_id: The subject ID.
            role_name: The role name to assign.
            granted_by: The subject ID who granted the role.

        Returns:
            The role assignment record.
        """
        async with self.session_factory() as db_session:
            role_repo = RoleRepository(session=db_session)
            assignment_repo = RoleAssignmentRepository(session=db_session)

            # Get role by name
            role = await role_repo.get_one_by(name=role_name)

            # Create assignment
            assignment = await assignment_repo.create(
                id=f"ra_{secrets.token_hex(8)}",
                subject_id=subject_id,
                role_id=role.id,
                scope_type=ScopeType.GLOBAL,
                scope_id=None,
                granted_by=granted_by,
            )
            await db_session.commit()
            return assignment

    async def revoke_role(self, subject_id: str, role_name: str) -> None:
        """Revoke a role from a subject.

        Args:
            subject_id: The subject ID.
            role_name: The role name to revoke.
        """
        async with self.session_factory() as db_session:
            role_repo = RoleRepository(session=db_session)
            assignment_repo = RoleAssignmentRepository(session=db_session)

            # Get role by name
            role = await role_repo.get_one_by(name=role_name)

            # Find and delete assignment
            try:
                assignment = await assignment_repo.get_one_by(
                    subject_id=subject_id,
                    role_id=role.id,
                )
                await assignment_repo.delete(assignment)
                await db_session.commit()
            except DoesNotExist:
                pass

    async def get_subject_roles(self, subject_id: str) -> list[str]:
        """Get role names for a subject.

        Args:
            subject_id: The subject ID.

        Returns:
            List of role names.
        """
        async with self.session_factory() as db_session:
            assignment_repo = RoleAssignmentRepository(session=db_session)
            role_repo = RoleRepository(session=db_session)

            # Get all assignments for this subject
            assignments = await assignment_repo.get_many_by(subject_id=subject_id)

            # Get role names
            role_names = []
            for assignment in assignments:
                try:
                    role = await role_repo.get_one_by(id=assignment.role_id)
                    role_names.append(role.name)
                except DoesNotExist:
                    pass

            return role_names

    async def has_role(self, subject_id: str, role_name: str) -> bool:
        """Check if a subject has a specific role.

        Args:
            subject_id: The subject ID.
            role_name: The role name to check.

        Returns:
            True if subject has the role.
        """
        roles = await self.get_subject_roles(subject_id)
        return role_name in roles


def create_subject_loader(
    session_factory: async_sessionmaker,
) -> Callable[[str], Awaitable[Subject | None]]:
    """Create a subject loader function.

    Args:
        session_factory: SQLAlchemy async session factory.

    Returns:
        Async function that loads a subject by ID.
    """

    async def load_subject(subject_id: str) -> Subject | None:
        async with session_factory() as db_session:
            repo = SubjectRepository(session=db_session)
            try:
                return await repo.get_one_by(id=subject_id)
            except DoesNotExist:
                return None

    return load_subject


async def get_subject_roles(
    session_factory: async_sessionmaker, subject_id: str
) -> list[str]:
    """Get role names for a subject.

    Convenience function that creates a RoleServiceFactory and fetches roles.

    Args:
        session_factory: SQLAlchemy async session factory.
        subject_id: The subject ID.

    Returns:
        List of role names.
    """
    factory = RoleServiceFactory(session_factory)
    return await factory.get_subject_roles(subject_id)


__all__ = [
    "RoleServiceFactory",
    "SessionServiceFactory",
    "create_subject_loader",
    "get_subject_roles",
]
