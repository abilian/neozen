"""Authorization services.

Provides business logic for role management and authorization checking.
"""

from __future__ import annotations

import typing
from datetime import UTC, datetime

from neozen.core.authz.exceptions import (
    PermissionDenied,
    RoleAlreadyExists,
    RoleAssignmentNotFound,
    RoleNotFound,
    SystemRoleError,
)
from neozen.core.authz.models import (
    BUILTIN_ROLES,
    Permission,
    Role,
    ScopeType,
)
from neozen.core.authz.policy import Policy, PolicyChain, PolicyResult, RolePolicy
from neozen.core.crypto import generate_token
from neozen.core.repository import DoesNotExist, RepositoryProtocol


class RoleModelProtocol(typing.Protocol):
    """Protocol for role storage models."""

    id: str
    name: str
    description: str
    permissions: str  # Comma-separated permission strings
    is_system: bool
    created_at: datetime

    def get_permissions_list(self) -> list[str]:
        """Return permissions as a list."""
        ...


class RoleAssignmentModelProtocol(typing.Protocol):
    """Protocol for role assignment storage models."""

    id: str
    subject_id: str
    role_id: str
    scope_type: ScopeType
    scope_id: str | None
    granted_by: str | None
    granted_at: datetime
    expires_at: datetime | None


class RoleService:
    """Service for managing roles.

    Provides CRUD operations for roles and role assignments.
    """

    def __init__(
        self,
        role_repository: RepositoryProtocol[RoleModelProtocol],
        role_assignment_repository: RepositoryProtocol[RoleAssignmentModelProtocol],
        *,
        id_generator: typing.Callable[[], str] | None = None,
    ) -> None:
        """Initialize the role service.

        Args:
            role_repository: Repository for role storage
            role_assignment_repository: Repository for role assignments
            id_generator: Function to generate unique IDs (defaults to token generator)
        """
        self.role_repository = role_repository
        self.role_assignment_repository = role_assignment_repository
        self._id_generator = id_generator or (lambda: generate_token(prefix="role_"))

    # -------------------------------------------------------------------------
    # Role CRUD
    # -------------------------------------------------------------------------

    async def create_role(
        self,
        name: str,
        permissions: list[str],
        *,
        description: str = "",
    ) -> RoleModelProtocol:
        """Create a new role.

        Args:
            name: Unique role name
            permissions: List of permission strings
            description: Human-readable description

        Returns:
            The created role

        Raises:
            RoleAlreadyExists: If a role with this name already exists
        """
        # Check for existing role
        if await self.role_repository.exists(name=name):
            raise RoleAlreadyExists(name)

        # Validate permissions format
        for perm in permissions:
            Permission.parse(perm)  # Raises ValueError if invalid

        role = await self.role_repository.create(
            id=self._id_generator(),
            name=name,
            description=description,
            permissions=",".join(permissions),
            is_system=False,
        )
        return role

    async def get_role(self, name: str) -> RoleModelProtocol:
        """Get a role by name.

        Args:
            name: The role name

        Returns:
            The role

        Raises:
            RoleNotFound: If the role does not exist
        """
        try:
            return await self.role_repository.get_one_by(name=name)
        except DoesNotExist as e:
            raise RoleNotFound(name) from e

    async def get_role_by_id(self, role_id: str) -> RoleModelProtocol:
        """Get a role by ID.

        Args:
            role_id: The role ID

        Returns:
            The role

        Raises:
            RoleNotFound: If the role does not exist
        """
        try:
            return await self.role_repository.get_one_by(id=role_id)
        except DoesNotExist as e:
            raise RoleNotFound(role_id) from e

    async def list_roles(self) -> list[RoleModelProtocol]:
        """List all roles.

        Returns:
            List of all roles
        """
        return await self.role_repository.get_many_by()

    async def update_role(
        self,
        name: str,
        *,
        permissions: list[str] | None = None,
        description: str | None = None,
    ) -> RoleModelProtocol:
        """Update a role.

        Args:
            name: The role name
            permissions: New permissions (optional)
            description: New description (optional)

        Returns:
            The updated role

        Raises:
            RoleNotFound: If the role does not exist
            SystemRoleError: If trying to modify a system role
        """
        role = await self.get_role(name)

        if role.is_system:
            raise SystemRoleError(name, "update")

        updates: dict[str, typing.Any] = {}
        if permissions is not None:
            # Validate permissions format
            for perm in permissions:
                Permission.parse(perm)
            updates["permissions"] = ",".join(permissions)
        if description is not None:
            updates["description"] = description

        if updates:
            return await self.role_repository.update_obj(role, **updates)
        return role

    async def delete_role(self, name: str) -> None:
        """Delete a role.

        Args:
            name: The role name

        Raises:
            RoleNotFound: If the role does not exist
            SystemRoleError: If trying to delete a system role
        """
        role = await self.get_role(name)

        if role.is_system:
            raise SystemRoleError(name, "delete")

        await self.role_repository.delete(role)

    # -------------------------------------------------------------------------
    # Role Assignment
    # -------------------------------------------------------------------------

    async def assign_role(
        self,
        subject_id: str,
        role_name: str,
        *,
        scope_type: ScopeType = ScopeType.GLOBAL,
        scope_id: str | None = None,
        granted_by: str | None = None,
        expires_at: datetime | None = None,
    ) -> RoleAssignmentModelProtocol:
        """Assign a role to a subject.

        Args:
            subject_id: The subject receiving the role
            role_name: The role to assign
            scope_type: How the role is scoped
            scope_id: ID of the team or resource (if scoped)
            granted_by: Who granted the role
            expires_at: When the assignment expires

        Returns:
            The role assignment

        Raises:
            RoleNotFound: If the role does not exist
        """
        role = await self.get_role(role_name)

        assignment = await self.role_assignment_repository.create(
            id=self._id_generator(),
            subject_id=subject_id,
            role_id=role.id,
            scope_type=scope_type,
            scope_id=scope_id,
            granted_by=granted_by,
            granted_at=datetime.now(UTC),
            expires_at=expires_at,
        )
        return assignment

    async def revoke_role(
        self,
        subject_id: str,
        role_name: str,
        *,
        scope_type: ScopeType = ScopeType.GLOBAL,
        scope_id: str | None = None,
    ) -> None:
        """Revoke a role from a subject.

        Args:
            subject_id: The subject losing the role
            role_name: The role to revoke
            scope_type: The scope of the assignment
            scope_id: The scope ID (if applicable)

        Raises:
            RoleNotFound: If the role does not exist
            RoleAssignmentNotFound: If the assignment does not exist
        """
        role = await self.get_role(role_name)

        filters: dict[str, typing.Any] = {
            "subject_id": subject_id,
            "role_id": role.id,
            "scope_type": scope_type,
        }
        if scope_id is not None:
            filters["scope_id"] = scope_id

        try:
            assignment = await self.role_assignment_repository.get_one_by(**filters)
        except DoesNotExist as e:
            raise RoleAssignmentNotFound(subject_id, role_name) from e

        await self.role_assignment_repository.delete(assignment)

    async def get_subject_roles(
        self,
        subject_id: str,
        *,
        scope_type: ScopeType | None = None,
        scope_id: str | None = None,
        include_expired: bool = False,
    ) -> list[Role]:
        """Get all roles assigned to a subject.

        Args:
            subject_id: The subject ID
            scope_type: Filter by scope type (optional)
            scope_id: Filter by scope ID (optional)
            include_expired: Include expired assignments

        Returns:
            List of roles assigned to the subject
        """
        filters: dict[str, typing.Any] = {"subject_id": subject_id}
        if scope_type is not None:
            filters["scope_type"] = scope_type
        if scope_id is not None:
            filters["scope_id"] = scope_id

        assignments = await self.role_assignment_repository.get_many_by(**filters)

        # Filter out expired assignments
        now = datetime.now(UTC)
        valid_assignments = []
        for a in assignments:
            if include_expired or a.expires_at is None:
                valid_assignments.append(a)
            else:
                # Handle both timezone-aware and naive datetimes
                expires_at = a.expires_at
                if expires_at.tzinfo is None:
                    # Naive datetime - assume UTC
                    expires_at = expires_at.replace(tzinfo=UTC)
                if expires_at > now:
                    valid_assignments.append(a)

        if not valid_assignments:
            return []

        # One query for the roles, whatever the number of assignments.
        # ponytail: loads every role; filter by id when the repository
        # protocol grows an "in" lookup, if role tables get large.
        role_models = {r.id: r for r in await self.role_repository.get_many_by()}
        roles: list[Role] = []
        for assignment in valid_assignments:
            role_model = role_models.get(assignment.role_id)
            if role_model is None:  # deleted role, dangling assignment
                continue
            roles.append(
                Role(
                    id=role_model.id,
                    name=role_model.name,
                    permissions=frozenset(role_model.get_permissions_list()),
                    description=role_model.description,
                    is_system=role_model.is_system,
                    created_at=role_model.created_at,
                )
            )

        return roles

    async def get_subject_role_assignments(
        self,
        subject_id: str,
    ) -> list[RoleAssignmentModelProtocol]:
        """Get all role assignments for a subject.

        Args:
            subject_id: The subject ID

        Returns:
            List of role assignments
        """
        return await self.role_assignment_repository.get_many_by(subject_id=subject_id)

    # -------------------------------------------------------------------------
    # Built-in Role Management
    # -------------------------------------------------------------------------

    async def ensure_builtin_roles(self) -> None:
        """Ensure all built-in roles exist in the database."""
        for name, role in BUILTIN_ROLES.items():
            if not await self.role_repository.exists(name=name):
                await self.role_repository.create(
                    id=role.id,
                    name=role.name,
                    description=role.description,
                    permissions=",".join(role.permissions),
                    is_system=True,
                )


class AuthorizationService:
    """Service for checking authorization.

    Provides methods to check if a subject has permission to perform
    an action, using roles and policies.
    """

    def __init__(
        self,
        role_service: RoleService,
        *,
        policies: list[Policy] | None = None,
        default_deny: bool = True,
    ) -> None:
        """Initialize the authorization service.

        Args:
            role_service: Service for role management
            policies: List of policies to evaluate (optional)
            default_deny: Deny if no permission or policy matches
        """
        self.role_service = role_service
        self.policy_chain = PolicyChain(
            policies=policies or [],
            default_deny=default_deny,
        )

    def add_policy(self, policy: Policy) -> None:
        """Add a policy to the chain."""
        self.policy_chain.add_policy(policy)

    async def has_permission(
        self,
        subject_id: str,
        permission: str,
        *,
        resource: typing.Any | None = None,
        scope_type: ScopeType | None = None,
        scope_id: str | None = None,
        context: dict[str, typing.Any] | None = None,
    ) -> bool:
        """Check if a subject has a specific permission.

        Args:
            subject_id: The subject attempting the action
            permission: The permission required (e.g., "user:read")
            resource: The resource being accessed (optional)
            scope_type: Filter roles by scope type (optional)
            scope_id: Filter roles by scope ID (optional)
            context: Additional context for policy evaluation

        Returns:
            True if the subject has the permission
        """
        # Get the subject's roles
        roles = await self.role_service.get_subject_roles(
            subject_id,
            scope_type=scope_type,
            scope_id=scope_id,
        )

        # Check role-based permissions
        required = Permission.parse(permission)
        for role in roles:
            if role.has_permission(required):
                return True

        # Evaluate policies
        if self.policy_chain.policies:
            # Pre-populate roles for sync policy evaluation
            for policy in self.policy_chain.policies:
                if isinstance(policy, RolePolicy):
                    policy.set_roles(subject_id, roles)

            result = self.policy_chain.evaluate(
                subject_id=subject_id,
                action=permission,
                resource=resource,
                context=context,
            )
            return result == PolicyResult.ALLOW

        return False

    async def require_permission(
        self,
        subject_id: str,
        permission: str,
        *,
        resource: typing.Any | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        scope_type: ScopeType | None = None,
        scope_id: str | None = None,
        context: dict[str, typing.Any] | None = None,
    ) -> None:
        """Require that a subject has a specific permission.

        Args:
            subject_id: The subject attempting the action
            permission: The permission required
            resource: The resource being accessed (optional)
            resource_type: Type of resource for error message (optional)
            resource_id: ID of resource for error message (optional)
            scope_type: Filter roles by scope type (optional)
            scope_id: Filter roles by scope ID (optional)
            context: Additional context for policy evaluation

        Raises:
            PermissionDenied: If the subject lacks the permission
        """
        has_perm = await self.has_permission(
            subject_id,
            permission,
            resource=resource,
            scope_type=scope_type,
            scope_id=scope_id,
            context=context,
        )

        if not has_perm:
            raise PermissionDenied(
                permission=permission,
                subject_id=subject_id,
                resource_type=resource_type,
                resource_id=resource_id,
            )

    async def can(
        self,
        subject_id: str,
        permission: str,
        resource: typing.Any | None = None,
    ) -> bool:
        """Shorthand for has_permission.

        Args:
            subject_id: The subject attempting the action
            permission: The permission required
            resource: The resource being accessed (optional)

        Returns:
            True if the subject has the permission
        """
        return await self.has_permission(subject_id, permission, resource=resource)

    async def require(
        self,
        subject_id: str,
        permission: str,
        resource: typing.Any | None = None,
    ) -> None:
        """Shorthand for require_permission.

        Args:
            subject_id: The subject attempting the action
            permission: The permission required
            resource: The resource being accessed (optional)

        Raises:
            PermissionDenied: If the subject lacks the permission
        """
        await self.require_permission(subject_id, permission, resource=resource)
