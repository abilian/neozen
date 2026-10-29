"""Admin authentication and authorization."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from litestar import Request, Response
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException
from litestar.handlers import BaseRouteHandler
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
    """Admin console roles.

    SUPERADMIN (the ``superuser`` role) can do everything. ADMIN (the
    configured ``require_role``) manages users, sessions and groups, but
    can't define roles or touch superadmins and the ``superuser`` role.
    """

    SUPERADMIN = "superadmin"
    ADMIN = "admin"


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


SUPERADMIN_ONLY = "Only a superadmin can do this."


def require_superadmin(admin: AdminUser | None) -> None:
    """Refuse anyone but a superadmin."""
    if not (admin and admin.is_superadmin):
        raise PermissionDeniedException(SUPERADMIN_ONLY)


def superadmin_only(connection: ASGIConnection, _: BaseRouteHandler) -> None:
    """Route guard: superadmins only (defining roles and permissions)."""
    admin = connection.scope.get("user")
    require_superadmin(admin if isinstance(admin, AdminUser) else None)


async def require_power_over(
    service: AdminService, admin: AdminUser | None, subject_id: str
) -> None:
    """Refuse a plain admin's action on a superadmin's account."""
    roles = await service.get_subject_roles(subject_id)
    if SUPERUSER_ROLE in {r.name for r in roles}:
        require_superadmin(admin)


def require_superadmin_for_role(admin: AdminUser | None, role_name: str) -> None:
    """Only a superadmin grants or removes the ``superuser`` role."""
    if role_name == SUPERUSER_ROLE:
        require_superadmin(admin)


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
    "require_power_over",
    "require_superadmin",
    "require_superadmin_for_role",
    "set_current_admin",
    "start_impersonation",
    "stop_impersonation",
    "superadmin_only",
]
