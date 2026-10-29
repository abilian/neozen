"""SQLAlchemy session-scoped service factories for NeoZen.

These factories handle the lifecycle of SQLAlchemy async sessions when using
NeoZen's core services. They create services lazily with proper session scope,
solving the integration challenge between stateless core services and
session-per-request database patterns.

Example usage:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from neozen.storage.sqlalchemy import SessionServiceFactory, RoleServiceFactory

    engine = create_async_engine("sqlite+aiosqlite:///app.db")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    session_service = SessionServiceFactory(session_factory, secret_key="...")
    role_service = RoleServiceFactory(session_factory)

    # Create a session for a user
    token = await session_service.create_session(subject_id)

    # Assign a role
    await role_service.assign_role(subject_id, "admin")
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from neozen.core.authz.exceptions import RoleAssignmentNotFound
from neozen.core.authz.models import ScopeType
from neozen.core.authz.services import RoleAssignmentModelProtocol, RoleService
from neozen.core.session.service import SessionError, SessionService
from neozen.storage.base import DoesNotExist
from neozen.storage.sqlalchemy.models import Session, Subject
from neozen.storage.sqlalchemy.repositories import (
    RoleAssignmentRepository,
    RoleRepository,
    SessionRepository,
    SubjectRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


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

    def _service(self, db_session: AsyncSession) -> SessionService[Any]:
        # SessionService isn't generic over its storage yet (planned for 0.10).
        repo = SessionRepository(session=db_session)
        # pyrefly: ignore [bad-specialization]
        return SessionService(storage=repo, hash_key=self.secret_key)

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
            service = self._service(db_session)
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
            service = self._service(db_session)
            try:
                session = await service.validate_session(
                    token, update_activity=update_activity
                )
                if update_activity:
                    await db_session.commit()
                return session
            except SessionError:
                return None

    async def revoke_session_by_token(self, token: str) -> None:
        """Revoke a session by its token.

        Args:
            token: The plaintext session token.
        """
        async with self.session_factory() as db_session:
            service = self._service(db_session)
            await service.revoke_session_by_token(token)
            await db_session.commit()


def role_service(session: AsyncSession) -> RoleService:
    """A `RoleService` on the SQLAlchemy repositories, in one session."""
    # RoleService isn't generic over its repositories yet (planned for 0.10).
    return RoleService(
        role_repository=RoleRepository(session=session),  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        role_assignment_repository=RoleAssignmentRepository(session=session),  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )


class RoleServiceFactory:
    """`RoleService` operations, each in its own database session.

    Roles are global: scoped and expired assignments don't count.
    """

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
    ) -> RoleAssignmentModelProtocol:
        """Assign a role to a subject.

        Args:
            subject_id: The subject ID.
            role_name: The role name to assign.
            granted_by: The subject ID who granted the role.

        Returns:
            The role assignment record.
        """
        async with self.session_factory() as db_session:
            assignment = await role_service(db_session).assign_role(
                subject_id, role_name, granted_by=granted_by
            )
            await db_session.commit()
            return assignment

    async def revoke_role(self, subject_id: str, role_name: str) -> None:
        """Revoke a role from a subject; a role it doesn't hold is a no-op.

        Args:
            subject_id: The subject ID.
            role_name: The role name to revoke.
        """
        async with self.session_factory() as db_session:
            try:
                await role_service(db_session).revoke_role(subject_id, role_name)
            except RoleAssignmentNotFound:
                return
            await db_session.commit()

    async def get_subject_roles(self, subject_id: str) -> list[str]:
        """Names of the subject's global, unexpired roles.

        Args:
            subject_id: The subject ID.

        Returns:
            List of role names.
        """
        async with self.session_factory() as db_session:
            roles = await role_service(db_session).get_subject_roles(
                subject_id, scope_type=ScopeType.GLOBAL
            )
            return [role.name for role in roles]

    async def has_role(self, subject_id: str, role_name: str) -> bool:
        """Check if a subject has a specific role.

        Args:
            subject_id: The subject ID.
            role_name: The role name to check.

        Returns:
            True if subject has the role.
        """
        return role_name in await self.get_subject_roles(subject_id)


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
    "role_service",
]
