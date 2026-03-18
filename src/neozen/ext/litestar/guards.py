"""Guards for NeoZen Litestar extension."""

from __future__ import annotations

import typing

from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException
from litestar.handlers import BaseRouteHandler

if typing.TYPE_CHECKING:
    from .config import NeoZenConfig


class AuthenticationRequiredError(NotAuthorizedException):
    """Exception raised when authentication is required.

    This exception includes redirect information that can be used by
    an exception handler to redirect unauthenticated users.

    Attributes:
        redirect_to: The URL to redirect to (if redirect was requested)
    """

    def __init__(
        self,
        detail: str = "Authentication required",
        redirect_to: str | None = None,
    ) -> None:
        super().__init__(detail=detail)
        self.redirect_to = redirect_to


class LoginRequiredGuard:
    """Guard that requires authentication.

    This guard checks if the user is authenticated and raises
    AuthenticationRequiredError if not. The error includes redirect
    information that can be used by an exception handler.

    Note: For redirect functionality, configure an exception handler
    at the app level to handle AuthenticationRequiredError.

    Example:
        @get("/dashboard", guards=[LoginRequiredGuard()])
        async def dashboard(current_user: CurrentUser) -> Template:
            return Template("dashboard.html", context={"user": current_user})

        @get("/api/me", guards=[LoginRequiredGuard(redirect=False)])
        async def api_me(current_user: CurrentUser) -> dict:
            return {"id": current_user.id}

        # To handle redirects, add an exception handler:
        async def handle_auth_error(request: Request, exc: AuthenticationRequiredError):
            if exc.redirect_to:
                return Redirect(exc.redirect_to)
            return Response({"error": exc.detail}, status_code=401)

        app = Litestar(
            exception_handlers={AuthenticationRequiredError: handle_auth_error},
        )
    """

    __slots__ = ("redirect", "scopes")

    def __init__(
        self,
        *,
        redirect: bool = True,
        scopes: list[str] | None = None,
    ) -> None:
        """Initialize guard.

        Args:
            redirect: Include redirect URL in exception (default True)
            scopes: Required permission scopes (future use)
        """
        self.redirect = redirect
        self.scopes = scopes or []

    async def __call__(
        self,
        connection: ASGIConnection[typing.Any, typing.Any, typing.Any, typing.Any],
        _: BaseRouteHandler,
    ) -> None:
        """Check if user is authenticated.

        Args:
            connection: The ASGI connection
            _: The route handler (unused)

        Raises:
            AuthenticationRequiredError: If user is not authenticated
        """
        # Get session from state
        state = connection.scope.get("state", {})
        session = state.get("neozen_session")

        if session is None:
            redirect_to = None

            if self.redirect:
                # Get login path from config
                config: NeoZenConfig | None = state.get("neozen_config")
                login_path = config.login_path if config else "/login"

                if login_path:
                    # Include next parameter for post-login redirect
                    next_url = str(connection.url)
                    separator = "&" if "?" in login_path else "?"
                    redirect_to = f"{login_path}{separator}next={next_url}"

            raise AuthenticationRequiredError(
                detail="Authentication required",
                redirect_to=redirect_to,
            )


def login_required(
    *,
    redirect: bool = True,
    scopes: list[str] | None = None,
) -> LoginRequiredGuard:
    """Create a login required guard.

    This is a convenience function to create a LoginRequiredGuard.

    Args:
        redirect: Redirect to login page if unauthorized (default True)
        scopes: Required permission scopes (future use)

    Returns:
        A LoginRequiredGuard instance

    Example:
        @get("/dashboard", guards=[login_required()])
        async def dashboard(current_user: CurrentUser) -> Template:
            return Template("dashboard.html", context={"user": current_user})

        @get("/api/me", guards=[login_required(redirect=False)])
        async def api_me(current_user: CurrentUser) -> dict:
            return {"id": current_user.id}
    """
    return LoginRequiredGuard(redirect=redirect, scopes=scopes)


class PermissionDeniedError(NotAuthorizedException):
    """Exception raised when a permission check fails.

    Attributes:
        permission: The permission that was required
    """

    def __init__(
        self,
        permission: str,
        detail: str = "Permission denied",
    ) -> None:
        super().__init__(detail=detail)
        self.permission = permission


class RolesRequiredGuard:
    """Guard that requires specific roles.

    Checks if the user has at least one of the specified roles.
    Requires authentication middleware to populate the session.

    Example:
        @get("/admin", guards=[RolesRequiredGuard("admin", "superuser")])
        async def admin_panel(current_user: CurrentUser) -> Template:
            return Template("admin.html", context={"user": current_user})
    """

    __slots__ = ("roles",)

    def __init__(self, *roles: str) -> None:
        """Initialize guard.

        Args:
            *roles: Role names - user must have at least one of these
        """
        self.roles = roles

    async def __call__(
        self,
        connection: ASGIConnection[typing.Any, typing.Any, typing.Any, typing.Any],
        _: BaseRouteHandler,
    ) -> None:
        """Check if user has required roles.

        Args:
            connection: The ASGI connection
            _: The route handler (unused)

        Raises:
            AuthenticationRequiredError: If user is not authenticated
            PermissionDeniedError: If user lacks required roles
        """
        state = connection.scope.get("state", {})
        session = state.get("neozen_session")

        if session is None:
            raise AuthenticationRequiredError(detail="Authentication required")

        # Get user from state
        user = state.get("neozen_user")
        if user is None:
            raise AuthenticationRequiredError(detail="Authentication required")

        # Check roles
        user_roles = getattr(user, "roles", [])
        if not any(role in user_roles for role in self.roles):
            raise PermissionDeniedError(
                permission=f"roles:{','.join(self.roles)}",
                detail="Insufficient permissions",
            )


class PermissionsRequiredGuard:
    """Guard that requires specific permissions.

    Checks if the user has all of the specified permissions.
    Requires authentication middleware to populate the session.

    Permission format: "resource:action" or "resource:action:scope"
    Examples: "user:read", "post:delete:own", "*:*" (superuser)

    Example:
        @get("/users", guards=[PermissionsRequiredGuard("user:read")])
        async def list_users(current_user: CurrentUser) -> list[dict]:
            return [...]

        @delete("/users/{id}", guards=[PermissionsRequiredGuard("user:delete")])
        async def delete_user(id: str) -> None:
            ...
    """

    __slots__ = ("permissions",)

    def __init__(self, *permissions: str) -> None:
        """Initialize guard.

        Args:
            *permissions: Permission strings - user must have ALL of these
        """
        self.permissions = permissions

    async def __call__(
        self,
        connection: ASGIConnection[typing.Any, typing.Any, typing.Any, typing.Any],
        _: BaseRouteHandler,
    ) -> None:
        """Check if user has required permissions.

        Args:
            connection: The ASGI connection
            _: The route handler (unused)

        Raises:
            AuthenticationRequiredError: If user is not authenticated
            PermissionDeniedError: If user lacks required permissions
        """
        from neozen.core.authz.models import Permission  # noqa: PLC0415

        state = connection.scope.get("state", {})
        session = state.get("neozen_session")

        if session is None:
            raise AuthenticationRequiredError(detail="Authentication required")

        # Get user from state
        user = state.get("neozen_user")
        if user is None:
            raise AuthenticationRequiredError(detail="Authentication required")

        # Check permissions
        for perm_str in self.permissions:
            required = Permission.parse(perm_str)
            has_perm = False

            # Try has_permission method first
            if hasattr(user, "has_permission"):
                has_perm = user.has_permission(required)
            else:
                # Fall back to checking permissions attribute
                user_perms = getattr(user, "permissions", [])
                for user_perm_str in user_perms:
                    user_perm = Permission.parse(user_perm_str)
                    if user_perm.matches(required):
                        has_perm = True
                        break

            if not has_perm:
                raise PermissionDeniedError(
                    permission=perm_str,
                    detail=f"Missing permission: {perm_str}",
                )


def roles_required(*roles: str) -> RolesRequiredGuard:
    """Create a roles required guard.

    Convenience function to create a RolesRequiredGuard.

    Args:
        *roles: Role names - user must have at least one of these

    Returns:
        A RolesRequiredGuard instance

    Example:
        @get("/admin", guards=[roles_required("admin", "superuser")])
        async def admin_panel(current_user: CurrentUser) -> Template:
            return Template("admin.html", context={"user": current_user})
    """
    return RolesRequiredGuard(*roles)


def permissions_required(*permissions: str) -> PermissionsRequiredGuard:
    """Create a permissions required guard.

    Convenience function to create a PermissionsRequiredGuard.

    Args:
        *permissions: Permission strings - user must have ALL of these

    Returns:
        A PermissionsRequiredGuard instance

    Example:
        @get("/users", guards=[permissions_required("user:read")])
        async def list_users(current_user: CurrentUser) -> list[dict]:
            return [...]
    """
    return PermissionsRequiredGuard(*permissions)


__all__ = [
    "AuthenticationRequiredError",
    "LoginRequiredGuard",
    "PermissionDeniedError",
    "PermissionsRequiredGuard",
    "RolesRequiredGuard",
    "login_required",
    "permissions_required",
    "roles_required",
]
