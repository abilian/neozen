"""Helper functions for NeoZen Flask extension."""

from __future__ import annotations

import contextlib
import typing
from datetime import timedelta

from flask import g, request
from werkzeug.local import LocalProxy

from .mixins import AnonymousUser

if typing.TYPE_CHECKING:
    from neozen.core.subject import Subject


def _get_current_user() -> Subject | AnonymousUser:
    """Get the current user from request context.

    This function is called by the current_user proxy on each access.
    It lazily loads the user from the session.
    """
    from .extension import _get_neozen  # noqa: PLC0415

    try:
        neozen = _get_neozen()
        return neozen._load_subject()
    except RuntimeError:
        # Extension not initialized or outside request context
        return AnonymousUser()


# LocalProxy for accessing current user
# This allows `current_user` to work like Flask-Login's current_user
current_user: Subject | AnonymousUser = LocalProxy(_get_current_user)  # type: ignore[assignment]


def login_user(
    subject: Subject,
    *,
    remember: bool = False,
    duration: timedelta | None = None,
    fresh: bool = True,
) -> bool:
    """Log in a user by creating a NeoZen session.

    This function schedules a session to be created and a cookie to be set
    after the current request completes.

    Args:
        subject: The authenticated Subject to log in
        remember: If True, use longer cookie lifetime
        duration: Custom session duration (overrides default) - not yet implemented
        fresh: Mark session as fresh (for sensitive operations) - not yet implemented

    Returns:
        True if login was scheduled successfully

    Example:
        @app.route("/login", methods=["POST"])
        def login():
            user = authenticate(request.form)
            if user:
                login_user(user, remember=True)
                return redirect(url_for("dashboard"))
            flash("Invalid credentials", "error")
            return render_template("login.html")
    """
    from .extension import _get_neozen  # noqa: PLC0415

    neozen = _get_neozen()
    state = neozen._get_state()

    if not state.session_service:
        msg = "SessionService not configured. Set session_service when initializing NeoZen."
        raise RuntimeError(msg)

    # Get request info for session
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent")

    # Create session token
    token = neozen._run_async(
        state.session_service.create_session(
            subject_id=subject.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    )

    # Store login info for after_request hook
    g._neozen_login_user = (subject, token, remember)
    g._neozen_user = subject
    g._neozen_user_loaded = True

    return True


def logout_user() -> bool:
    """Log out the current user by revoking their session.

    This function schedules the session to be revoked and the cookie
    to be cleared after the current request completes.

    Returns:
        True if logout was scheduled, False if no user was logged in

    Example:
        @app.route("/logout", methods=["POST"])
        @login_required
        def logout():
            logout_user()
            flash("You have been logged out.", "info")
            return redirect(url_for("index"))
    """
    from .extension import _get_neozen  # noqa: PLC0415

    neozen = _get_neozen()
    state = neozen._get_state()

    # Check if user is logged in
    session = getattr(g, "_neozen_session", None)
    if not session:
        return False

    # Revoke the session if we have a session service
    if state.session_service:
        token = request.cookies.get(neozen.cookie_name)
        if token:
            with contextlib.suppress(Exception):
                neozen._run_async(state.session_service.revoke_session_by_token(token))

    # Clear user from request context
    g._neozen_user = None
    g._neozen_session = None
    g._neozen_user_loaded = True
    g._neozen_logout = True
    g._neozen_login_user = None  # Cancel any pending login

    return True


def confirm_login() -> None:
    """Mark the current session as fresh.

    Call this after verifying the user's credentials for sensitive
    operations like changing password or viewing sensitive data.

    Note: This is a placeholder for future implementation.
    """
    # TODO: Implement fresh session marking


def is_authenticated() -> bool:
    """Check if the current user is authenticated.

    Returns:
        True if a user is logged in, False otherwise

    Example:
        if is_authenticated():
            return redirect(url_for("dashboard"))
    """
    user = _get_current_user()
    return getattr(user, "is_authenticated", False)


__all__ = [
    "confirm_login",
    "current_user",
    "is_authenticated",
    "login_user",
    "logout_user",
]
