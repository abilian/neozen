"""Helper functions for NeoZen Starlette extension."""

from __future__ import annotations

import typing

from starlette.requests import Request
from starlette.responses import Response

from .backend import NeoZenBackend

if typing.TYPE_CHECKING:
    from neozen.core.subject import Subject


def get_backend(request: Request) -> NeoZenBackend:
    """Get the NeoZen backend from request state.

    Args:
        request: The Starlette request

    Returns:
        The NeoZenBackend instance

    Raises:
        RuntimeError: If middleware is not configured
    """
    backend = getattr(request.state, "neozen_backend", None)
    if backend is None:
        msg = (
            "NeoZen backend not found in request.state. "
            "Did you forget to add NeoZenMiddleware?"
        )
        raise RuntimeError(msg)
    return backend


async def get_current_user(request: Request) -> Subject | None:
    """Get the current authenticated user from request state.

    This function lazily loads the user from the session on first access.

    Args:
        request: The Starlette request

    Returns:
        The authenticated Subject or None if not authenticated

    Example:
        @app.route("/dashboard")
        async def dashboard(request: Request) -> Response:
            user = await get_current_user(request)
            if not user:
                return RedirectResponse("/login")
            return templates.TemplateResponse("dashboard.html", {"user": user})
    """
    # Check if already loaded
    if getattr(request.state, "neozen_user_loaded", False):
        return request.state.neozen_user

    # Mark as loaded
    request.state.neozen_user_loaded = True

    # Get session
    session = getattr(request.state, "neozen_session", None)
    if not session:
        request.state.neozen_user = None
        return None

    # Load user
    backend = get_backend(request)
    user = await backend.get_subject(session.subject_id)
    request.state.neozen_user = user
    return user


async def login_user(
    request: Request,
    response: Response,
    subject: Subject,
    *,
    remember: bool = False,
) -> str:
    """Log in a user and set the session cookie.

    Args:
        request: The Starlette request
        response: The Starlette response (cookie will be set on this)
        subject: The Subject to log in
        remember: If True, use longer cookie lifetime (not yet implemented)

    Returns:
        The session token

    Example:
        @app.route("/login", methods=["POST"])
        async def login_submit(request: Request) -> Response:
            form = await request.form()
            subject = await authenticate(form["email"], form["password"])

            response = RedirectResponse("/dashboard", status_code=303)
            await login_user(request, response, subject)
            return response
    """
    backend = get_backend(request)

    # Get request info
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    # Create session
    token = await backend.create_session(
        subject_id=subject.id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Set cookie
    backend.set_session_cookie(response, token)

    # Update request state
    request.state.neozen_user = subject
    request.state.neozen_user_loaded = True

    return token


async def logout_user(request: Request, response: Response) -> None:
    """Log out the current user and clear the session cookie.

    Args:
        request: The Starlette request
        response: The Starlette response (cookie will be cleared on this)

    Example:
        @app.route("/logout", methods=["POST"])
        async def logout_submit(request: Request) -> Response:
            response = RedirectResponse("/", status_code=303)
            await logout_user(request, response)
            return response
    """
    backend = get_backend(request)

    # Revoke session if exists
    token = request.cookies.get(backend.cookie_name)
    if token:
        await backend.revoke_session(token)

    # Clear cookie
    backend.delete_session_cookie(response)

    # Update request state
    request.state.neozen_session = None
    request.state.neozen_user = None
    request.state.neozen_user_loaded = True


def is_authenticated(request: Request) -> bool:
    """Check if the request has an authenticated session.

    This is a quick check that doesn't load the user.

    Args:
        request: The Starlette request

    Returns:
        True if there's a valid session, False otherwise
    """
    return getattr(request.state, "neozen_session", None) is not None


__all__ = [
    "get_backend",
    "get_current_user",
    "is_authenticated",
    "login_user",
    "logout_user",
]
