"""Authorization domain models.

Defines the core models for role-based access control:
- Permission: A string representing an action on a resource
- Role: A named collection of permissions
- RoleAssignment: Links a subject to a role with optional scoping
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Self


class ScopeType(StrEnum):
    """Scope types for role assignments."""

    GLOBAL = "global"  # Role applies everywhere
    TEAM = "team"  # Role applies within a specific team
    RESOURCE = "resource"  # Role applies to a specific resource


@dataclass(frozen=True)
class Permission:
    """A permission representing an action on a resource.

    Format: resource:action[:scope]

    Examples:
        - "user:read" - Read any user
        - "user:read:own" - Read only own profile
        - "post:delete:own" - Delete own posts only
        - "team:manage" - Full control over team settings
        - "*:*" - Superuser (all permissions)

    Attributes:
        resource: The resource type (e.g., "user", "post", "team", or "*")
        action: The action (e.g., "read", "write", "delete", or "*")
        scope: Optional scope qualifier (e.g., "own", "team", "all")
    """

    resource: str
    action: str
    scope: str | None = None

    # Regex pattern for permission strings
    _PATTERN: re.Pattern[str] = field(
        default=re.compile(r"^([a-z_*]+):([a-z_*]+)(?::([a-z_]+))?$"),
        repr=False,
        compare=False,
    )

    def __str__(self) -> str:
        """Return the string representation of the permission."""
        if self.scope:
            return f"{self.resource}:{self.action}:{self.scope}"
        return f"{self.resource}:{self.action}"

    @classmethod
    def parse(cls, permission_str: str) -> Self:
        """Parse a permission string into a Permission object.

        Args:
            permission_str: A permission string like "user:read:own"

        Returns:
            A Permission object

        Raises:
            ValueError: If the permission string is invalid
        """
        match = cls._PATTERN.match(permission_str.lower())
        if not match:
            msg = f"Invalid permission format: {permission_str}"
            raise ValueError(msg)

        resource, action, scope = match.groups()
        return cls(resource=resource, action=action, scope=scope)

    def matches(self, required: Permission) -> bool:
        """Check if this permission grants the required permission.

        Supports wildcard matching:
        - "*" matches any value in that position
        - A permission without scope matches any scope

        Args:
            required: The permission being checked

        Returns:
            True if this permission grants the required permission
        """
        # Check resource
        if self.resource != "*" and self.resource != required.resource:
            return False

        # Check action
        if self.action != "*" and self.action != required.action:
            return False

        # Check scope - if we have a scope, it must match
        # If we don't have a scope, we match any scope (more permissive)
        return not (self.scope is not None and self.scope != required.scope)


@dataclass(frozen=True)
class Role:
    """A named collection of permissions.

    Attributes:
        id: Unique identifier
        name: Role name (e.g., "admin", "editor", "viewer")
        description: Human-readable description
        permissions: Set of permissions granted by this role
        is_system: Whether this is a built-in role that cannot be deleted
        created_at: When the role was created
    """

    id: str
    name: str
    permissions: frozenset[str]
    description: str = ""
    is_system: bool = False
    created_at: datetime | None = None

    def has_permission(self, permission: str | Permission) -> bool:
        """Check if this role has a specific permission.

        Args:
            permission: The permission to check (string or Permission object)

        Returns:
            True if the role grants this permission
        """
        if isinstance(permission, str):
            required = Permission.parse(permission)
        else:
            required = permission

        for perm_str in self.permissions:
            perm = Permission.parse(perm_str)
            if perm.matches(required):
                return True
        return False


@dataclass(frozen=True)
class RoleAssignment:
    """Links a subject to a role with optional scoping.

    Attributes:
        id: Unique identifier
        subject_id: The subject receiving the role
        role_id: The role being assigned
        scope_type: How the role is scoped (global, team, resource)
        scope_id: ID of the team or resource (if scoped)
        granted_by: Subject who granted the role (None for system)
        granted_at: When the role was granted
        expires_at: When the assignment expires (None for permanent)
    """

    id: str
    subject_id: str
    role_id: str
    scope_type: ScopeType = ScopeType.GLOBAL
    scope_id: str | None = None
    granted_by: str | None = None
    granted_at: datetime | None = None
    expires_at: datetime | None = None

    def is_expired(self) -> bool:
        """Check if this assignment has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(tz=self.expires_at.tzinfo) > self.expires_at

    def is_valid(self) -> bool:
        """Check if this assignment is currently valid (not expired)."""
        return not self.is_expired()


# Built-in role definitions
BUILTIN_ROLES = {
    "superuser": Role(
        id="builtin:superuser",
        name="superuser",
        description="Full system access",
        permissions=frozenset(["*:*"]),
        is_system=True,
    ),
    "admin": Role(
        id="builtin:admin",
        name="admin",
        description="Administrative access",
        permissions=frozenset(["user:*", "role:*", "client:*"]),
        is_system=True,
    ),
    "user": Role(
        id="builtin:user",
        name="user",
        description="Basic authenticated user",
        permissions=frozenset(["user:read:own", "user:update:own"]),
        is_system=True,
    ),
}
