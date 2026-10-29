"""Decorators for NeoZen Starlette extension."""

from __future__ import annotations

import typing
from collections.abc import Awaitable, Callable
from functools import wraps
from urllib.parse import urlencode

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from .helpers import is_authenticated

if typing.TYPE_CHECKING:
    pass

# Type for async route handlers
RouteHandler = Callable[..., Awaitable[Response]]


def login_required(
    func: RouteHandler | None = None,
    *,
    redirect_url: str | None = None,
    on_unauthorized: Callable[[Request], Awaitable[Response]] | None = None,
) -> RouteHandler | Callable[[RouteHandler], RouteHandler]:
    """Decorator to require authentication for a route.

    Args:
        func: The route handler (when used without parentheses)
        redirect_url: URL to redirect unauthenticated users (e.g., "/login")
        on_unauthorized: Custom async handler for unauthorized access

    Returns:
        Decorated route handler

    Examples:
        @app.route("/dashboard")
        @login_required
        async def dashboard(request: Request) -> Response:
            user = await get_current_user(request)
            return templates.TemplateResponse("dashboard.html", {"user": user})

        @app.route("/api/me")
        @login_required(on_unauthorized=lambda r: JSONResponse({"error": "Unauthorized"}, 401))
        async def api_me(request: Request) -> Response:
            user = await get_current_user(request)
            return JSONResponse({"id": user.id})

        @app.route("/profile")
        @login_required(redirect_url="/login")
        async def profile(request: Request) -> Response:
            ...
    """

    def decorator(f: RouteHandler) -> RouteHandler:
        @wraps(f)
        async def decorated_function(
            request: Request, *args: typing.Any, **kwargs: typing.Any
        ) -> Response:
            if not is_authenticated(request):
                # Custom handler takes precedence
                if on_unauthorized is not None:
                    return await on_unauthorized(request)

                # Redirect if URL provided
                if redirect_url is not None:
                    # Include 'next' parameter for post-login redirect
                    next_url = str(request.url)
                    separator = "&" if "?" in redirect_url else "?"
                    return RedirectResponse(
                        f"{redirect_url}{separator}{urlencode({'next': next_url})}",
                        status_code=303,
                    )

                # Default: return 401 JSON response
                return JSONResponse(
                    {"error": "Unauthorized", "detail": "Authentication required"},
                    status_code=401,
                )

            return await f(request, *args, **kwargs)

        return decorated_function

    # Support both @login_required and @login_required()
    if func is not None:
        return decorator(func)
    return decorator


def roles_required(
    *roles: str,
    on_forbidden: Callable[[Request], Awaitable[Response]] | None = None,
) -> Callable[[RouteHandler], RouteHandler]:
    """Decorator to require specific roles.

    Checks if the current user has at least one of the specified roles.
    Requires @login_required to be applied first (authentication check).

    Args:
        *roles: Role names - user must have at least one of these
        on_forbidden: Custom async handler for forbidden access (403)

    Returns:
        Decorated route handler

    Example:
        @app.route("/admin")
        @login_required
        @roles_required("admin", "superuser")
        async def admin_panel(request: Request) -> Response:
            return templates.TemplateResponse("admin.html", {})
    """

    def decorator(f: RouteHandler) -> RouteHandler:
        @wraps(f)
        async def decorated_function(
            request: Request, *args: typing.Any, **kwargs: typing.Any
        ) -> Response:
            # Get user from request state
            user = getattr(request.state, "user", None)
            if user is None:
                # User should be authenticated first
                return JSONResponse(
                    {"error": "Forbidden", "detail": "Authentication required"},
                    status_code=403,
                )

            # Check roles
            user_roles = getattr(user, "roles", [])
            if not any(role in user_roles for role in roles):
                if on_forbidden is not None:
                    return await on_forbidden(request)
                return JSONResponse(
                    {"error": "Forbidden", "detail": "Insufficient permissions"},
                    status_code=403,
                )

            return await f(request, *args, **kwargs)

        return decorated_function

    return decorator


def permissions_required(
    *permissions: str,
    on_forbidden: Callable[[Request], Awaitable[Response]] | None = None,
) -> Callable[[RouteHandler], RouteHandler]:
    """Decorator to require specific permissions.

    Checks if the current user has all of the specified permissions.
    Requires @login_required to be applied first (authentication check).

    Permission format: "resource:action" or "resource:action:scope"
    Examples: "user:read", "post:delete:own", "*:*" (superuser)

    Args:
        *permissions: Permission strings - user must have ALL of these
        on_forbidden: Custom async handler for forbidden access (403)

    Returns:
        Decorated route handler

    Example:
        @app.route("/users")
        @login_required
        @permissions_required("user:read")
        async def list_users(request: Request) -> Response:
            return JSONResponse({"users": [...]})

        @app.route("/users/{id}", methods=["DELETE"])
        @login_required
        @permissions_required("user:delete")
        async def delete_user(request: Request) -> Response:
            ...
    """
    from neozen.web.auth import check_user_permissions  # noqa: PLC0415

    def decorator(f: RouteHandler) -> RouteHandler:
        @wraps(f)
        async def decorated_function(
            request: Request, *args: typing.Any, **kwargs: typing.Any
        ) -> Response:
            # Get user from request state
            user = getattr(request.state, "user", None)
            if user is None:
                return JSONResponse(
                    {"error": "Forbidden", "detail": "Authentication required"},
                    status_code=403,
                )

            # Check permissions
            missing = check_user_permissions(user, permissions)
            if missing:
                if on_forbidden is not None:
                    return await on_forbidden(request)
                return JSONResponse(
                    {"error": "Forbidden", "detail": f"Missing permission: {missing}"},
                    status_code=403,
                )

            return await f(request, *args, **kwargs)

        return decorated_function

    return decorator


__all__ = ["login_required", "permissions_required", "roles_required"]
