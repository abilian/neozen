"""Integration tests for authorization services."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from neozen.core.authz.exceptions import (
    RoleAlreadyExists,
    RoleAssignmentNotFound,
    RoleNotFound,
    SystemRoleError,
)
from neozen.core.authz.models import BUILTIN_ROLES, ScopeType
from neozen.core.authz.services import AuthorizationService, RoleService
from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.repositories import (
    RoleAssignmentRepository,
    RoleRepository,
)


@pytest.fixture
async def async_engine():
    """Create async SQLite engine for tests."""
    from sqlalchemy.pool import StaticPool

    # Use StaticPool for in-memory SQLite to maintain single connection
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest.fixture
async def session(async_engine):
    """Create async session for tests."""
    session_maker = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with session_maker() as session:
        yield session


@pytest.fixture
def role_repo(session: AsyncSession) -> RoleRepository:
    """Create role repository."""
    return RoleRepository(session=session)


@pytest.fixture
def role_assignment_repo(session: AsyncSession) -> RoleAssignmentRepository:
    """Create role assignment repository."""
    return RoleAssignmentRepository(session=session)


@pytest.fixture
def role_service(
    role_repo: RoleRepository, role_assignment_repo: RoleAssignmentRepository
) -> RoleService:
    """Create role service."""
    return RoleService(
        role_repository=role_repo,
        role_assignment_repository=role_assignment_repo,
    )


@pytest.fixture
def authz_service(role_service: RoleService) -> AuthorizationService:
    """Create authorization service."""
    return AuthorizationService(role_service=role_service)


class TestRoleServiceCRUD:
    """Tests for RoleService CRUD operations."""

    @pytest.mark.anyio
    async def test_create_role(self, role_service: RoleService) -> None:
        """Test creating a new role."""
        role = await role_service.create_role(
            name="editor",
            permissions=["post:read", "post:write"],
            description="Can read and write posts",
        )

        assert role.name == "editor"
        assert role.description == "Can read and write posts"
        assert "post:read" in role.permissions
        assert "post:write" in role.permissions
        assert role.is_system is False

    @pytest.mark.anyio
    async def test_create_role_duplicate_raises(
        self, role_service: RoleService
    ) -> None:
        """Test creating duplicate role raises error."""
        await role_service.create_role(name="editor", permissions=["post:read"])

        with pytest.raises(RoleAlreadyExists):
            await role_service.create_role(name="editor", permissions=["post:write"])

    @pytest.mark.anyio
    async def test_create_role_invalid_permission_raises(
        self, role_service: RoleService
    ) -> None:
        """Test creating role with invalid permission raises error."""
        with pytest.raises(ValueError, match="Invalid permission format"):
            await role_service.create_role(
                name="invalid", permissions=["not-valid-format"]
            )

    @pytest.mark.anyio
    async def test_get_role(self, role_service: RoleService) -> None:
        """Test getting a role by name."""
        await role_service.create_role(name="viewer", permissions=["post:read"])

        role = await role_service.get_role("viewer")
        assert role.name == "viewer"

    @pytest.mark.anyio
    async def test_get_role_not_found(self, role_service: RoleService) -> None:
        """Test getting non-existent role raises error."""
        with pytest.raises(RoleNotFound):
            await role_service.get_role("nonexistent")

    @pytest.mark.anyio
    async def test_get_role_by_id(self, role_service: RoleService) -> None:
        """Test getting a role by ID."""
        created = await role_service.create_role(
            name="viewer", permissions=["post:read"]
        )

        role = await role_service.get_role_by_id(created.id)
        assert role.name == "viewer"
        assert role.id == created.id

    @pytest.mark.anyio
    async def test_list_roles(self, role_service: RoleService) -> None:
        """Test listing all roles."""
        await role_service.create_role(name="editor", permissions=["post:write"])
        await role_service.create_role(name="viewer", permissions=["post:read"])

        roles = await role_service.list_roles()
        names = [r.name for r in roles]
        assert "editor" in names
        assert "viewer" in names

    @pytest.mark.anyio
    async def test_update_role(self, role_service: RoleService) -> None:
        """Test updating a role."""
        await role_service.create_role(
            name="editor", permissions=["post:read"], description="Original"
        )

        updated = await role_service.update_role(
            "editor",
            permissions=["post:read", "post:write"],
            description="Updated",
        )

        assert updated.description == "Updated"
        assert "post:write" in updated.permissions

    @pytest.mark.anyio
    async def test_delete_role(self, role_service: RoleService) -> None:
        """Test deleting a role."""
        await role_service.create_role(name="temp", permissions=["temp:read"])

        await role_service.delete_role("temp")

        with pytest.raises(RoleNotFound):
            await role_service.get_role("temp")


class TestRoleServiceSystemRoles:
    """Tests for system role protection."""

    @pytest.mark.anyio
    async def test_ensure_builtin_roles(self, role_service: RoleService) -> None:
        """Test ensuring built-in roles exist."""
        await role_service.ensure_builtin_roles()

        for name in BUILTIN_ROLES:
            role = await role_service.get_role(name)
            assert role.is_system is True

    @pytest.mark.anyio
    async def test_update_system_role_raises(self, role_service: RoleService) -> None:
        """Test updating system role raises error."""
        await role_service.ensure_builtin_roles()

        with pytest.raises(SystemRoleError):
            await role_service.update_role("superuser", description="Modified")

    @pytest.mark.anyio
    async def test_delete_system_role_raises(self, role_service: RoleService) -> None:
        """Test deleting system role raises error."""
        await role_service.ensure_builtin_roles()

        with pytest.raises(SystemRoleError):
            await role_service.delete_role("admin")


class TestRoleServiceAssignments:
    """Tests for role assignment operations."""

    @pytest.mark.anyio
    async def test_assign_role(self, role_service: RoleService) -> None:
        """Test assigning a role to a subject."""
        await role_service.create_role(name="editor", permissions=["post:write"])

        assignment = await role_service.assign_role(
            subject_id="user123",
            role_name="editor",
        )

        assert assignment.subject_id == "user123"
        assert assignment.scope_type == ScopeType.GLOBAL

    @pytest.mark.anyio
    async def test_assign_role_with_scope(self, role_service: RoleService) -> None:
        """Test assigning a role with team scope."""
        await role_service.create_role(name="team_lead", permissions=["team:manage"])

        assignment = await role_service.assign_role(
            subject_id="user123",
            role_name="team_lead",
            scope_type=ScopeType.TEAM,
            scope_id="team_456",
        )

        assert assignment.scope_type == ScopeType.TEAM
        assert assignment.scope_id == "team_456"

    @pytest.mark.anyio
    async def test_assign_role_with_expiry(self, role_service: RoleService) -> None:
        """Test assigning a role with expiration."""
        await role_service.create_role(name="temp_admin", permissions=["*:*"])
        now = datetime.now(UTC)
        expires = now + timedelta(hours=24)

        assignment = await role_service.assign_role(
            subject_id="user123",
            role_name="temp_admin",
            expires_at=expires,
        )

        assert assignment.expires_at is not None
        # SQLite may lose timezone info, so just check it's in the future
        # by comparing naive datetimes
        expires_naive = assignment.expires_at.replace(tzinfo=None)
        now_naive = now.replace(tzinfo=None)
        assert expires_naive > now_naive

    @pytest.mark.anyio
    async def test_revoke_role(self, role_service: RoleService) -> None:
        """Test revoking a role from a subject."""
        await role_service.create_role(name="editor", permissions=["post:write"])
        await role_service.assign_role(subject_id="user123", role_name="editor")

        await role_service.revoke_role(subject_id="user123", role_name="editor")

        roles = await role_service.get_subject_roles("user123")
        assert len(roles) == 0

    @pytest.mark.anyio
    async def test_revoke_nonexistent_assignment_raises(
        self, role_service: RoleService
    ) -> None:
        """Test revoking non-existent assignment raises error."""
        await role_service.create_role(name="editor", permissions=["post:write"])

        with pytest.raises(RoleAssignmentNotFound):
            await role_service.revoke_role(subject_id="user123", role_name="editor")

    @pytest.mark.anyio
    async def test_get_subject_roles(self, role_service: RoleService) -> None:
        """Test getting all roles for a subject."""
        await role_service.create_role(name="editor", permissions=["post:write"])
        await role_service.create_role(name="viewer", permissions=["post:read"])

        await role_service.assign_role(subject_id="user123", role_name="editor")
        await role_service.assign_role(subject_id="user123", role_name="viewer")

        roles = await role_service.get_subject_roles("user123")
        role_names = [r.name for r in roles]

        assert len(roles) == 2
        assert "editor" in role_names
        assert "viewer" in role_names

    @pytest.mark.anyio
    async def test_get_subject_roles_excludes_expired(
        self, role_service: RoleService
    ) -> None:
        """Test expired roles are excluded by default."""
        await role_service.create_role(name="temp", permissions=["temp:read"])
        past = datetime.now(UTC) - timedelta(hours=1)

        await role_service.assign_role(
            subject_id="user123",
            role_name="temp",
            expires_at=past,
        )

        roles = await role_service.get_subject_roles("user123")
        assert len(roles) == 0

    @pytest.mark.anyio
    async def test_get_subject_roles_includes_expired(
        self, role_service: RoleService
    ) -> None:
        """Test expired roles are included when requested."""
        await role_service.create_role(name="temp", permissions=["temp:read"])
        past = datetime.now(UTC) - timedelta(hours=1)

        await role_service.assign_role(
            subject_id="user123",
            role_name="temp",
            expires_at=past,
        )

        roles = await role_service.get_subject_roles("user123", include_expired=True)
        assert len(roles) == 1


class TestAuthorizationService:
    """Tests for AuthorizationService."""

    @pytest.mark.anyio
    async def test_has_permission_granted(
        self, role_service: RoleService, authz_service: AuthorizationService
    ) -> None:
        """Test checking permission that is granted."""
        await role_service.create_role(name="editor", permissions=["post:write"])
        await role_service.assign_role(subject_id="user123", role_name="editor")

        has_perm = await authz_service.has_permission("user123", "post:write")
        assert has_perm is True

    @pytest.mark.anyio
    async def test_has_permission_denied(
        self, role_service: RoleService, authz_service: AuthorizationService
    ) -> None:
        """Test checking permission that is not granted."""
        await role_service.create_role(name="viewer", permissions=["post:read"])
        await role_service.assign_role(subject_id="user123", role_name="viewer")

        has_perm = await authz_service.has_permission("user123", "post:delete")
        assert has_perm is False

    @pytest.mark.anyio
    async def test_has_permission_no_roles(
        self, authz_service: AuthorizationService
    ) -> None:
        """Test checking permission with no roles assigned."""
        has_perm = await authz_service.has_permission("user123", "post:read")
        assert has_perm is False

    @pytest.mark.anyio
    async def test_has_permission_wildcard(
        self, role_service: RoleService, authz_service: AuthorizationService
    ) -> None:
        """Test wildcard permission matching."""
        await role_service.create_role(name="admin", permissions=["post:*"])
        await role_service.assign_role(subject_id="user123", role_name="admin")

        assert await authz_service.has_permission("user123", "post:read") is True
        assert await authz_service.has_permission("user123", "post:write") is True
        assert await authz_service.has_permission("user123", "post:delete") is True
        assert await authz_service.has_permission("user123", "user:read") is False

    @pytest.mark.anyio
    async def test_has_permission_superuser(
        self, role_service: RoleService, authz_service: AuthorizationService
    ) -> None:
        """Test superuser has all permissions."""
        await role_service.ensure_builtin_roles()
        await role_service.assign_role(subject_id="admin", role_name="superuser")

        assert await authz_service.has_permission("admin", "anything:here") is True
        assert await authz_service.has_permission("admin", "user:delete") is True

    @pytest.mark.anyio
    async def test_require_permission_passes(
        self, role_service: RoleService, authz_service: AuthorizationService
    ) -> None:
        """Test require_permission passes when permission granted."""
        await role_service.create_role(name="editor", permissions=["post:write"])
        await role_service.assign_role(subject_id="user123", role_name="editor")

        # Should not raise
        await authz_service.require_permission("user123", "post:write")

    @pytest.mark.anyio
    async def test_require_permission_raises(
        self, role_service: RoleService, authz_service: AuthorizationService
    ) -> None:
        """Test require_permission raises when permission denied."""
        await role_service.create_role(name="viewer", permissions=["post:read"])
        await role_service.assign_role(subject_id="user123", role_name="viewer")

        from neozen.core.authz.exceptions import PermissionDenied

        with pytest.raises(PermissionDenied) as exc_info:
            await authz_service.require_permission("user123", "post:delete")

        assert exc_info.value.permission == "post:delete"
        assert exc_info.value.subject_id == "user123"

    @pytest.mark.anyio
    async def test_can_shorthand(
        self, role_service: RoleService, authz_service: AuthorizationService
    ) -> None:
        """Test can() shorthand method."""
        await role_service.create_role(name="editor", permissions=["post:write"])
        await role_service.assign_role(subject_id="user123", role_name="editor")

        assert await authz_service.can("user123", "post:write") is True
        assert await authz_service.can("user123", "post:delete") is False

    @pytest.mark.anyio
    async def test_require_shorthand(
        self, role_service: RoleService, authz_service: AuthorizationService
    ) -> None:
        """Test require() shorthand method."""
        await role_service.create_role(name="editor", permissions=["post:write"])
        await role_service.assign_role(subject_id="user123", role_name="editor")

        # Should not raise
        await authz_service.require("user123", "post:write")

        from neozen.core.authz.exceptions import PermissionDenied

        with pytest.raises(PermissionDenied):
            await authz_service.require("user123", "post:delete")
