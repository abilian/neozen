"""Integration tests for SQLAlchemy service factories.

Tests for SessionServiceFactory, RoleServiceFactory, create_subject_loader,
and get_subject_roles from neozen.storage.sqlalchemy.factories.
"""

from __future__ import annotations

import secrets

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from neozen.storage.sqlalchemy import (
    RoleServiceFactory,
    SessionServiceFactory,
    create_subject_loader,
    get_subject_roles,
)
from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.repositories import (
    RoleRepository,
    SubjectRepository,
)


@pytest.fixture
async def session_factory():
    """Create an in-memory SQLite database and session factory."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    await engine.dispose()


@pytest.fixture
async def subject_id(session_factory: async_sessionmaker) -> str:
    """Create a test subject and return its ID."""
    subject_id = f"user_{secrets.token_hex(8)}"
    async with session_factory() as session:
        repo = SubjectRepository(session=session)
        await repo.create(
            id=subject_id,
            email=f"{subject_id}@test.com",
            hashed_password="hashed_pw",
            is_active=True,
            is_verified=False,
        )
        await session.commit()
    return subject_id


@pytest.fixture
async def roles_created(session_factory: async_sessionmaker) -> list[str]:
    """Create test roles and return their names."""
    role_names = ["admin", "user", "moderator"]
    async with session_factory() as session:
        repo = RoleRepository(session=session)
        for name in role_names:
            await repo.create(
                id=f"role_{name}",
                name=name,
                description=f"{name} role",
            )
        await session.commit()
    return role_names


# =============================================================================
# SessionServiceFactory Tests
# =============================================================================


@pytest.mark.anyio
class TestSessionServiceFactory:
    """Tests for SessionServiceFactory."""

    async def test_create_session_returns_token(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
    ) -> None:
        """create_session should return a session token."""
        service = SessionServiceFactory(session_factory, secret_key="test-secret")

        token = await service.create_session(subject_id)

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    async def test_create_session_with_metadata(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
    ) -> None:
        """create_session should store IP and user agent."""
        service = SessionServiceFactory(session_factory, secret_key="test-secret")

        token = await service.create_session(
            subject_id,
            ip_address="192.168.1.1",
            user_agent="Test Browser/1.0",
        )

        # Validate the session to check metadata was stored
        session = await service.validate_session(token)
        assert session is not None
        assert session.ip_address == "192.168.1.1"
        assert session.user_agent == "Test Browser/1.0"

    async def test_validate_session_returns_session_for_valid_token(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
    ) -> None:
        """validate_session should return session for valid token."""
        service = SessionServiceFactory(session_factory, secret_key="test-secret")
        token = await service.create_session(subject_id)

        session = await service.validate_session(token)

        assert session is not None
        assert session.subject_id == subject_id

    async def test_validate_session_returns_none_for_invalid_token(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,  # noqa: ARG002
    ) -> None:
        """validate_session should return None for invalid token."""
        service = SessionServiceFactory(session_factory, secret_key="test-secret")

        session = await service.validate_session("invalid-token")

        assert session is None

    async def test_validate_session_updates_activity(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
    ) -> None:
        """validate_session should update last_activity_at when update_activity=True."""
        service = SessionServiceFactory(session_factory, secret_key="test-secret")
        token = await service.create_session(subject_id)

        # Get initial activity time
        session1 = await service.validate_session(token, update_activity=False)
        initial_activity = session1.last_activity_at

        # Validate again with update
        session2 = await service.validate_session(token, update_activity=True)

        # Activity should be updated (or at least not earlier)
        assert session2.last_activity_at >= initial_activity

    async def test_revoke_session_by_token(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
    ) -> None:
        """revoke_session_by_token should invalidate the session."""
        service = SessionServiceFactory(session_factory, secret_key="test-secret")
        token = await service.create_session(subject_id)

        # Verify session is valid
        session = await service.validate_session(token)
        assert session is not None

        # Revoke
        await service.revoke_session_by_token(token)

        # Session should now be invalid
        session = await service.validate_session(token)
        assert session is None

    async def test_multiple_sessions_per_subject(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
    ) -> None:
        """A subject can have multiple active sessions."""
        service = SessionServiceFactory(session_factory, secret_key="test-secret")

        token1 = await service.create_session(subject_id)
        token2 = await service.create_session(subject_id)

        # Both should be valid
        session1 = await service.validate_session(token1)
        session2 = await service.validate_session(token2)

        assert session1 is not None
        assert session2 is not None
        assert token1 != token2


# =============================================================================
# RoleServiceFactory Tests
# =============================================================================


@pytest.mark.anyio
class TestRoleServiceFactory:
    """Tests for RoleServiceFactory."""

    async def test_assign_role(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
        roles_created: list[str],  # noqa: ARG002
    ) -> None:
        """assign_role should create a role assignment."""
        service = RoleServiceFactory(session_factory)

        assignment = await service.assign_role(subject_id, "admin")

        assert assignment is not None
        assert assignment.subject_id == subject_id

    async def test_assign_role_with_granted_by(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
        roles_created: list[str],  # noqa: ARG002
    ) -> None:
        """assign_role should record who granted the role."""
        service = RoleServiceFactory(session_factory)

        assignment = await service.assign_role(
            subject_id, "user", granted_by="admin_user"
        )

        assert assignment.granted_by == "admin_user"

    async def test_get_subject_roles_returns_assigned_roles(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
        roles_created: list[str],  # noqa: ARG002
    ) -> None:
        """get_subject_roles should return all assigned role names."""
        service = RoleServiceFactory(session_factory)
        await service.assign_role(subject_id, "admin")
        await service.assign_role(subject_id, "user")

        roles = await service.get_subject_roles(subject_id)

        assert "admin" in roles
        assert "user" in roles
        assert len(roles) == 2

    async def test_get_subject_roles_returns_empty_list_when_no_roles(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
        roles_created: list[str],  # noqa: ARG002
    ) -> None:
        """get_subject_roles should return empty list for subject without roles."""
        service = RoleServiceFactory(session_factory)

        roles = await service.get_subject_roles(subject_id)

        assert roles == []

    async def test_has_role_returns_true_when_assigned(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
        roles_created: list[str],  # noqa: ARG002
    ) -> None:
        """has_role should return True when subject has the role."""
        service = RoleServiceFactory(session_factory)
        await service.assign_role(subject_id, "admin")

        result = await service.has_role(subject_id, "admin")

        assert result is True

    async def test_has_role_returns_false_when_not_assigned(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
        roles_created: list[str],  # noqa: ARG002
    ) -> None:
        """has_role should return False when subject doesn't have the role."""
        service = RoleServiceFactory(session_factory)

        result = await service.has_role(subject_id, "admin")

        assert result is False

    async def test_revoke_role(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
        roles_created: list[str],  # noqa: ARG002
    ) -> None:
        """revoke_role should remove the role assignment."""
        service = RoleServiceFactory(session_factory)
        await service.assign_role(subject_id, "admin")

        # Verify role is assigned
        assert await service.has_role(subject_id, "admin")

        # Revoke
        await service.revoke_role(subject_id, "admin")

        # Role should no longer be assigned
        assert not await service.has_role(subject_id, "admin")

    async def test_revoke_role_ignores_nonexistent_assignment(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
        roles_created: list[str],  # noqa: ARG002
    ) -> None:
        """revoke_role should not raise when assignment doesn't exist."""
        service = RoleServiceFactory(session_factory)

        # Should not raise
        await service.revoke_role(subject_id, "admin")


# =============================================================================
# create_subject_loader Tests
# =============================================================================


@pytest.mark.anyio
class TestCreateSubjectLoader:
    """Tests for create_subject_loader function."""

    async def test_loader_returns_subject_for_valid_id(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
    ) -> None:
        """Subject loader should return subject for valid ID."""
        loader = create_subject_loader(session_factory)

        subject = await loader(subject_id)

        assert subject is not None
        assert subject.id == subject_id

    async def test_loader_returns_none_for_invalid_id(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,  # noqa: ARG002
    ) -> None:
        """Subject loader should return None for invalid ID."""
        loader = create_subject_loader(session_factory)

        subject = await loader("nonexistent-id")

        assert subject is None

    async def test_loader_is_reusable(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
    ) -> None:
        """Subject loader can be called multiple times."""
        loader = create_subject_loader(session_factory)

        subject1 = await loader(subject_id)
        subject2 = await loader(subject_id)

        assert subject1 is not None
        assert subject2 is not None
        assert subject1.id == subject2.id


# =============================================================================
# get_subject_roles Function Tests
# =============================================================================


@pytest.mark.anyio
class TestGetSubjectRolesFunction:
    """Tests for get_subject_roles convenience function."""

    async def test_returns_roles_for_subject(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
        roles_created: list[str],  # noqa: ARG002
    ) -> None:
        """get_subject_roles should return role names for subject."""
        # Assign roles using factory
        role_factory = RoleServiceFactory(session_factory)
        await role_factory.assign_role(subject_id, "admin")
        await role_factory.assign_role(subject_id, "moderator")

        # Use convenience function
        roles = await get_subject_roles(session_factory, subject_id)

        assert "admin" in roles
        assert "moderator" in roles
        assert len(roles) == 2

    async def test_returns_empty_list_for_subject_without_roles(
        self,
        session_factory: async_sessionmaker,
        subject_id: str,
        roles_created: list[str],  # noqa: ARG002
    ) -> None:
        """get_subject_roles should return empty list when no roles assigned."""
        roles = await get_subject_roles(session_factory, subject_id)

        assert roles == []


# =============================================================================
# Integration Tests
# =============================================================================


@pytest.mark.anyio
class TestFactoriesIntegration:
    """Integration tests combining multiple factories."""

    async def test_full_auth_workflow(
        self,
        session_factory: async_sessionmaker,
        roles_created: list[str],  # noqa: ARG002
    ) -> None:
        """Test a complete authentication and authorization workflow."""
        # Create a subject
        subject_id = f"user_{secrets.token_hex(8)}"
        async with session_factory() as session:
            repo = SubjectRepository(session=session)
            await repo.create(
                id=subject_id,
                email=f"{subject_id}@test.com",
                hashed_password="hashed",
                is_active=True,
                is_verified=True,
            )
            await session.commit()

        # Create session
        session_service = SessionServiceFactory(session_factory, "secret")
        token = await session_service.create_session(
            subject_id,
            ip_address="10.0.0.1",
            user_agent="Integration Test",
        )

        # Validate session
        auth_session = await session_service.validate_session(token)
        assert auth_session is not None
        assert auth_session.subject_id == subject_id

        # Load subject
        loader = create_subject_loader(session_factory)
        subject = await loader(auth_session.subject_id)
        assert subject is not None
        assert subject.email == f"{subject_id}@test.com"

        # Assign roles
        role_service = RoleServiceFactory(session_factory)
        await role_service.assign_role(subject_id, "user")
        await role_service.assign_role(subject_id, "admin")

        # Check roles
        roles = await get_subject_roles(session_factory, subject_id)
        assert "user" in roles
        assert "admin" in roles

        # Check specific role
        assert await role_service.has_role(subject_id, "admin")
        assert not await role_service.has_role(subject_id, "moderator")

        # Revoke admin
        await role_service.revoke_role(subject_id, "admin")
        assert not await role_service.has_role(subject_id, "admin")
        assert await role_service.has_role(subject_id, "user")

        # Logout
        await session_service.revoke_session_by_token(token)
        assert await session_service.validate_session(token) is None
