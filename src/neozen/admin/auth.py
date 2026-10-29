"""Admin authentication and authorization."""

from __future__ import annotations

import functools
from collections.abc import Callable, Collection, Coroutine
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

from litestar import Request, Response
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException
from litestar.middleware import AbstractAuthenticationMiddleware, AuthenticationResult
from litestar.middleware.session.server_side import (
    ServerSideSessionBackend,
    ServerSideSessionConfig,
)
from litestar.status_codes import HTTP_303_SEE_OTHER

from neozen.admin.services import AdminService
from neozen.storage import DoesNotExist

if TYPE_CHECKING:
    from litestar.types import Message, ScopeSession

    from neozen.storage.sqlalchemy.models import Subject


class AdminRole(Enum):
    """Admin role types."""

    SUPERADMIN = "superadmin"  # Full access to everything
    ADMIN = "admin"  # User/role management
    SUPPORT = "support"  # Read + limited actions
    AUDITOR = "auditor"  # Read-only + audit logs


@dataclass(frozen=True)
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


async def admin_for_subject(
    service: AdminService, subject: Subject, require_role: str
) -> AdminUser | None:
    """The admin console identity of `subject`, or None if it has no access."""
    if not subject.is_active:
        return None
    roles = await service.get_subject_roles(subject.id)
    role = admin_role_for({r.name for r in roles}, require_role)
    if role is None:
        return None
    return AdminUser(
        id=subject.id,
        email=subject.email,
        name=subject.username or subject.email,
        role=role,
    )


# Session key for storing admin user
ADMIN_SESSION_KEY = "admin_user"
# Scope state keys: the request asks for a fresh session ID; the new ID
_ROTATE_SESSION_ID = "neozen_admin_rotate_session_id"
_NEW_SESSION_ID = "neozen_admin_new_session_id"


class RotatingSessionBackend(ServerSideSessionBackend):
    """Server-side sessions that get a fresh ID at login.

    Litestar keeps the ID from the incoming cookie for the life of a
    session, so an ID planted before login would stay valid after it
    (session fixation). `set_current_admin` flags the request, and the
    response then carries a new ID; the old entry is dropped.
    """

    def get_session_id(self, connection: ASGIConnection) -> str:
        new_id = connection.scope.get("state", {}).get(_NEW_SESSION_ID)
        return new_id or super().get_session_id(connection)

    async def store_in_message(
        self,
        scope_session: ScopeSession,
        message: Message,
        connection: ASGIConnection,
    ) -> None:
        state = connection.scope.setdefault("state", {})
        if state.pop(_ROTATE_SESSION_ID, False):
            store = self.config.get_store_from_app(connection.scope["app"])
            await self.delete(super().get_session_id(connection), store=store)
            state[_NEW_SESSION_ID] = self.generate_session_id()
        await super().store_in_message(scope_session, message, connection)


@dataclass
class RotatingSessionConfig(ServerSideSessionConfig):
    """`ServerSideSessionConfig` using `RotatingSessionBackend`."""

    _backend_class = RotatingSessionBackend


# Session key for storing impersonation state
IMPERSONATION_KEY = "impersonating_user"


def get_current_admin(request: Request) -> AdminUser | None:
    """The admin that `AdminAuthMiddleware` verified for this request.

    None on routes excluded from authentication (login, logout, health).
    """
    user = request.scope.get("user")
    return user if isinstance(user, AdminUser) else None


def set_current_admin(request: Request, admin: AdminUser) -> None:
    """Log `admin` in: store its ID and give the session a fresh ID.

    Only the ID is kept; `AdminAuthMiddleware` reloads the subject and its
    roles on every request.
    """
    request.session[ADMIN_SESSION_KEY] = {"id": admin.id}
    request.scope.setdefault("state", {})[_ROTATE_SESSION_ID] = True


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
        # Not authenticated: redirect_to_login_handler sends them to login.
        admin_data = connection.session.get(ADMIN_SESSION_KEY)
        if not admin_data:
            raise NotAuthorizedException(detail="Not authenticated")

        # Reload the subject so deactivation and role changes apply at once.
        state = connection.app.state
        async with state.session_factory() as session:
            service = AdminService(session)
            try:
                subject = await service.subject_repo.get_one_by(id=admin_data["id"])
            except DoesNotExist as e:
                raise NotAuthorizedException(detail="Unknown admin") from e
            admin = await admin_for_subject(service, subject, state.config.require_role)
        if admin is None:
            raise NotAuthorizedException(detail="No admin access")
        return AuthenticationResult(user=admin, auth=None)


def redirect_to_login_handler(
    request: Request, exc: NotAuthorizedException
) -> Response:
    """Exception handler sending unauthenticated admin requests to login.

    An HTMX request (a polled widget, say) gets ``HX-Redirect`` instead:
    HTMX would follow a 303 and swap the login page into the widget.
    """
    if request.headers.get("HX-Request") == "true":
        return Response(
            content=None, status_code=204, headers={"HX-Redirect": "/login"}
        )
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
    "RotatingSessionBackend",
    "RotatingSessionConfig",
    "admin_for_subject",
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
