"""Decorators for NeoZen Starlette extension."""

from __future__ import annotations

import typing
from collections.abc import Awaitable, Callable
from functools import wraps

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
                        f"{redirect_url}{separator}next={next_url}",
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


__all__ = ["login_required"]
