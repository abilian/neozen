"""Helper functions for NeoZen Litestar extension."""

from __future__ import annotations

import typing

from litestar import Request, Response

if typing.TYPE_CHECKING:
    from neozen.core.subject import Subject

    from .config import NeoZenConfig


def get_config(request: Request[typing.Any, typing.Any, typing.Any]) -> NeoZenConfig:
    """Get the NeoZen config from request state.

    Args:
        request: The Litestar request

    Returns:
        The NeoZenConfig instance

    Raises:
        RuntimeError: If plugin is not configured
    """
    config = request.scope.get("state", {}).get("neozen_config")
    if config is None:
        msg = (
            "NeoZen config not found in request state. "
            "Did you forget to add NeoZenPlugin?"
        )
        raise RuntimeError(msg)
    return config


async def get_current_user(
    request: Request[typing.Any, typing.Any, typing.Any],
) -> Subject | None:
    """Get the current authenticated user from request state.

    This function lazily loads the user from the session on first access.

    Args:
        request: The Litestar request

    Returns:
        The authenticated Subject or None if not authenticated

    Example:
        @get("/dashboard")
        async def dashboard(request: Request) -> Response:
            user = await get_current_user(request)
            if not user:
                return Redirect("/login")
            return Template("dashboard.html", context={"user": user})
    """
    state = request.scope.get("state", {})

    # Check if already loaded
    if state.get("neozen_user_loaded", False):
        return state.get("neozen_user")

    # Mark as loaded
    state["neozen_user_loaded"] = True

    # Get session
    session = state.get("neozen_session")
    if not session:
        state["neozen_user"] = None
        return None

    # Load user
    config = get_config(request)
    user = await config.get_subject(session.subject_id)
    state["neozen_user"] = user
    return user


async def login_user(
    request: Request[typing.Any, typing.Any, typing.Any],
    response: Response[typing.Any],
    subject: Subject,
    *,
    remember: bool = False,
) -> str:
    """Log in a user and set the session cookie.

    Args:
        request: The Litestar request
        response: The Litestar response (cookie will be set on this)
        subject: The Subject to log in
        remember: If True, use longer cookie lifetime (not yet implemented)

    Returns:
        The session token

    Example:
        @post("/login")
        async def login_submit(request: Request, data: LoginSchema) -> Response:
            subject = await authenticate(data.email, data.password)
            response = Redirect("/dashboard")
            await login_user(request, response, subject)
            return response
    """
    config = get_config(request)

    # Get request info
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    # Create session
    token = await config.create_session(
        subject_id=subject.id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Set cookie
    config.set_session_cookie(response, token)

    # Update request state
    state = request.scope.get("state", {})
    state["neozen_user"] = subject
    state["neozen_user_loaded"] = True

    return token


async def logout_user(
    request: Request[typing.Any, typing.Any, typing.Any],
    response: Response[typing.Any],
) -> None:
    """Log out the current user and clear the session cookie.

    Args:
        request: The Litestar request
        response: The Litestar response (cookie will be cleared on this)

    Example:
        @post("/logout")
        async def logout_submit(request: Request) -> Response:
            response = Redirect("/")
            await logout_user(request, response)
            return response
    """
    config = get_config(request)

    # Revoke session if exists
    token = request.cookies.get(config.cookie_name)
    if token:
        await config.revoke_session(token)

    # Clear cookie
    config.delete_session_cookie(response)

    # Update request state
    state = request.scope.get("state", {})
    state["neozen_session"] = None
    state["neozen_user"] = None
    state["neozen_user_loaded"] = True


def is_authenticated(request: Request[typing.Any, typing.Any, typing.Any]) -> bool:
    """Check if the request has an authenticated session.

    This is a quick check that doesn't load the user.

    Args:
        request: The Litestar request

    Returns:
        True if there's a valid session, False otherwise
    """
    state = request.scope.get("state", {})
    return state.get("neozen_session") is not None


__all__ = [
    "get_config",
    "get_current_user",
    "is_authenticated",
    "login_user",
    "logout_user",
]
