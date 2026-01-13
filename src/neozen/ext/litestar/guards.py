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


__all__ = ["AuthenticationRequiredError", "LoginRequiredGuard", "login_required"]
