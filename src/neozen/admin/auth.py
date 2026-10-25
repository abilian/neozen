"""Admin authentication and authorization."""

from __future__ import annotations

import functools
from collections.abc import Callable, Collection, Coroutine
from dataclasses import dataclass
from enum import Enum
from typing import Any

from litestar import Request, Response
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException
from litestar.middleware import AbstractAuthenticationMiddleware, AuthenticationResult
from litestar.status_codes import HTTP_303_SEE_OTHER


class AdminRole(Enum):
    """Admin role types."""

    SUPERADMIN = "superadmin"  # Full access to everything
    ADMIN = "admin"  # User/role management
    SUPPORT = "support"  # Read + limited actions
    AUDITOR = "auditor"  # Read-only + audit logs


@dataclass
class AdminUser:
    """Authenticated admin user."""

    id: str
    email: str
    name: str
    role: AdminRole
    organization_id: str | None = None

    @property
    def is_superadmin(self) -> bool:
        """Check if user is superadmin."""
        return self.role == AdminRole.SUPERADMIN

    @property
    def can_manage_users(self) -> bool:
        """Check if user can manage users."""
        return self.role in (AdminRole.SUPERADMIN, AdminRole.ADMIN)

    @property
    def can_manage_roles(self) -> bool:
        """Check if user can manage roles."""
        return self.role in (AdminRole.SUPERADMIN, AdminRole.ADMIN)

    @property
    def can_view_audit(self) -> bool:
        """Check if user can view audit logs."""
        return self.role in (AdminRole.SUPERADMIN, AdminRole.ADMIN, AdminRole.AUDITOR)

    @property
    def can_modify(self) -> bool:
        """Check if user can make modifications."""
        return self.role != AdminRole.AUDITOR

    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        permissions_map = {
            AdminRole.SUPERADMIN: {"*"},  # All permissions
            AdminRole.ADMIN: {
                "users:read",
                "users:write",
                "users:delete",
                "roles:read",
                "roles:write",
                "sessions:read",
                "sessions:revoke",
                "audit:read",
            },
            AdminRole.SUPPORT: {
                "users:read",
                "sessions:read",
                "sessions:revoke",
            },
            AdminRole.AUDITOR: {
                "users:read",
                "roles:read",
                "sessions:read",
                "audit:read",
            },
        }
        allowed = permissions_map.get(self.role, set())
        return "*" in allowed or permission in allowed


# NeoZen role that grants full admin console access (see BUILTIN_ROLES).
SUPERUSER_ROLE = "superuser"


def admin_role_for(role_names: Collection[str], require_role: str) -> AdminRole | None:
    """Map a subject's NeoZen role names to an admin console role.

    ``superuser`` grants SUPERADMIN and ``require_role`` grants ADMIN.
    Returns None when the subject may not use the admin console.
    """
    if SUPERUSER_ROLE in role_names:
        return AdminRole.SUPERADMIN
    if require_role in role_names:
        return AdminRole.ADMIN
    return None


# Session key for storing admin user
ADMIN_SESSION_KEY = "admin_user"
# Session key for storing impersonation state
IMPERSONATION_KEY = "impersonating_user"


def get_current_admin(request: Request) -> AdminUser | None:
    """Get current admin user from session.

    Args:
        request: The request object

    Returns:
        AdminUser if authenticated, None otherwise
    """
    admin_data = request.session.get(ADMIN_SESSION_KEY)
    if not admin_data:
        return None

    try:
        return AdminUser(
            id=admin_data["id"],
            email=admin_data["email"],
            name=admin_data["name"],
            role=AdminRole(admin_data["role"]),
            organization_id=admin_data.get("organization_id"),
        )
    except (KeyError, ValueError):
        return None


def set_current_admin(request: Request, admin: AdminUser) -> None:
    """Set current admin user in session.

    Args:
        request: The request object
        admin: The admin user to store
    """
    request.session[ADMIN_SESSION_KEY] = {
        "id": admin.id,
        "email": admin.email,
        "name": admin.name,
        "role": admin.role.value,
        "organization_id": admin.organization_id,
    }


def clear_current_admin(request: Request) -> None:
    """Clear current admin user from session.

    Args:
        request: The request object
    """
    request.session.pop(ADMIN_SESSION_KEY, None)
    request.session.pop(IMPERSONATION_KEY, None)


def start_impersonation(
    request: Request, user_id: str, user_email: str, user_name: str | None = None
) -> None:
    """Start impersonating a user.

    Args:
        request: The request object
        user_id: ID of the user to impersonate
        user_email: Email of the user to impersonate
        user_name: Optional name of the user
    """
    request.session[IMPERSONATION_KEY] = {
        "user_id": user_id,
        "user_email": user_email,
        "user_name": user_name or user_email,
    }


def stop_impersonation(request: Request) -> None:
    """Stop impersonating a user.

    Args:
        request: The request object
    """
    request.session.pop(IMPERSONATION_KEY, None)


def get_impersonation(request: Request) -> dict[str, str] | None:
    """Get current impersonation state.

    Args:
        request: The request object

    Returns:
        Dict with user_id, user_email, user_name if impersonating, None otherwise
    """
    return request.session.get(IMPERSONATION_KEY)


def redirect_to_login() -> Response:
    """Create redirect response to login page."""
    return Response(
        content=None,
        status_code=HTTP_303_SEE_OTHER,
        headers={"Location": "/login"},
    )


class AdminAuthMiddleware(AbstractAuthenticationMiddleware):
    """Middleware to authenticate admin users.

    Every route requires an authenticated admin unless its handler sets
    ``exclude_from_auth=True``. Unauthenticated requests raise
    ``NotAuthorizedException``; ``redirect_to_login_handler`` turns that
    into a redirect to the login page.
    """

    async def authenticate_request(
        self, connection: ASGIConnection
    ) -> AuthenticationResult:
        """Authenticate the request.

        Args:
            connection: The ASGI connection

        Returns:
            AuthenticationResult with user if authenticated
        """
        # Get admin from session
        admin_data = connection.session.get(ADMIN_SESSION_KEY)
        if not admin_data:
            # Not authenticated - will be handled by exception handler
            raise NotAuthorizedException(detail="Not authenticated")

        try:
            admin = AdminUser(
                id=admin_data["id"],
                email=admin_data["email"],
                name=admin_data["name"],
                role=AdminRole(admin_data["role"]),
                organization_id=admin_data.get("organization_id"),
            )
            return AuthenticationResult(user=admin, auth=None)
        except (KeyError, ValueError) as e:
            raise NotAuthorizedException(detail="Invalid session") from e


def redirect_to_login_handler(
    request: Request, exc: NotAuthorizedException
) -> Response:
    """Exception handler sending unauthenticated admin requests to login."""
    return redirect_to_login()


def require_permission(
    permission: str,
) -> Callable[
    [Callable[..., Coroutine[Any, Any, Response]]],
    Callable[..., Coroutine[Any, Any, Response]],
]:
    """Decorator to require a specific permission.

    Args:
        permission: The permission string (e.g., "users:write")

    Returns:
        Decorator function
    """

    def decorator(
        func: Callable[..., Coroutine[Any, Any, Response]],
    ) -> Callable[..., Coroutine[Any, Any, Response]]:
        @functools.wraps(func)
        async def wrapper(request: Request, *args: Any, **kwargs: Any) -> Response:
            admin = get_current_admin(request)
            if not admin:
                return redirect_to_login()
            if not admin.has_permission(permission):
                raise PermissionDeniedException(
                    detail=f"Permission denied: {permission}"
                )
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator


def require_admin(
    func: Callable[..., Coroutine[Any, Any, Response]],
) -> Callable[..., Coroutine[Any, Any, Response]]:
    """Decorator to require admin authentication.

    Redirects to login if not authenticated.
    """

    @functools.wraps(func)
    async def wrapper(request: Request, *args: Any, **kwargs: Any) -> Response:
        admin = get_current_admin(request)
        if not admin:
            return redirect_to_login()
        return await func(request, *args, **kwargs)

    return wrapper


__all__ = [
    "ADMIN_SESSION_KEY",
    "SUPERUSER_ROLE",
    "AdminAuthMiddleware",
    "AdminRole",
    "AdminUser",
    "admin_role_for",
    "clear_current_admin",
    "get_current_admin",
    "get_impersonation",
    "redirect_to_login",
    "redirect_to_login_handler",
    "require_admin",
    "require_permission",
    "set_current_admin",
    "start_impersonation",
    "stop_impersonation",
]
