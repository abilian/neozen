"""Shared permission checking utilities.

Provides common permission checking functionality used by framework-specific guards/decorators.
"""

from __future__ import annotations

import typing

from neozen.core.authz import Permission


def check_user_permission(user: typing.Any, required_permission: str) -> bool:
    """Check if a user has a specific permission.

    This function handles permission checking in a consistent way across frameworks.
    It first tries the `has_permission` method if available, then falls back to
    checking the `permissions` attribute.

    Args:
        user: The user/subject object to check permissions for.
        required_permission: The permission string to check (e.g., "users:read").

    Returns:
        True if the user has the permission, False otherwise.
    """
    required = Permission.parse(required_permission)

    # Try has_permission method first
    if hasattr(user, "has_permission"):
        return user.has_permission(required)

    # Fall back to checking permissions attribute
    user_perms = getattr(user, "permissions", [])
    for user_perm_str in user_perms:
        user_perm = Permission.parse(user_perm_str)
        if user_perm.matches(required):
            return True

    return False


def check_user_permissions(
    user: typing.Any, required_permissions: typing.Iterable[str]
) -> str | None:
    """Check if a user has all required permissions.

    Args:
        user: The user/subject object to check permissions for.
        required_permissions: Iterable of permission strings to check.

    Returns:
        The first missing permission string, or None if all permissions are granted.
    """
    for perm_str in required_permissions:
        if not check_user_permission(user, perm_str):
            return perm_str
    return None


def check_user_role(user: typing.Any, required_role: str) -> bool:
    """Check if a user has a specific role.

    Args:
        user: The user/subject object to check roles for.
        required_role: The role name to check.

    Returns:
        True if the user has the role, False otherwise.
    """
    # Try has_role method first
    if hasattr(user, "has_role"):
        return user.has_role(required_role)

    # Fall back to checking roles attribute
    user_roles = getattr(user, "roles", [])
    return required_role in user_roles


def check_user_roles_any(
    user: typing.Any, required_roles: typing.Iterable[str]
) -> bool:
    """Check if a user has at least one of the required roles.

    Args:
        user: The user/subject object to check roles for.
        required_roles: Iterable of role names (user needs at least one).

    Returns:
        True if the user has at least one role, False otherwise.
    """
    return any(check_user_role(user, role) for role in required_roles)


__all__ = [
    "check_user_permission",
    "check_user_permissions",
    "check_user_role",
    "check_user_roles_any",
]
