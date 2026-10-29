"""Decorators for NeoZen Flask extension.

Each works on sync and ``async def`` views alike.
"""

from __future__ import annotations

import inspect
import typing
from datetime import UTC, datetime, timedelta
from functools import wraps

from flask import abort, g, jsonify

from neozen.core.utils import ensure_utc
from neozen.web.auth.permissions import check_user_permissions
from neozen.web.auth.responses import unauthorized_body

from .helpers import current_user

if typing.TYPE_CHECKING:
    from collections.abc import Callable

    from flask.typing import ResponseReturnValue

    type Refusal = Callable[[], ResponseReturnValue | None]

# How recent a sign-in `fresh_login_required` accepts by default.
FRESH_LOGIN_MAX_AGE = timedelta(minutes=15)


def _guard[V: Callable[..., typing.Any]](view: V, refusal: Refusal) -> V:
    """Wrap ``view``: answer with ``refusal()`` when it returns a response."""
    if inspect.iscoroutinefunction(view):

        @wraps(view)
        async def async_view(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
            if (response := refusal()) is not None:
                return response
            return await view(*args, **kwargs)

        return typing.cast("V", async_view)

    @wraps(view)
    def sync_view(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        if (response := refusal()) is not None:
            return response
        return view(*args, **kwargs)

    return typing.cast("V", sync_view)


def _signed_in() -> bool:
    return bool(getattr(current_user, "is_authenticated", False))


def _turn_away(*, redirect: bool) -> ResponseReturnValue:
    """The answer to a visitor who isn't (or no longer) signed in."""
    if redirect:
        from .extension import _get_neozen  # noqa: PLC0415  # ken: import cycle

        return _get_neozen().handle_unauthorized()
    return jsonify(unauthorized_body()), 401


def login_required[V: Callable[..., typing.Any]](
    func: V | None = None,
    *,
    redirect: bool = True,
) -> V | Callable[[V], V]:
    """Decorator to require authentication for a view.

    Args:
        func: The view function (when used without arguments)
        redirect: If True (default), redirect to login_view.
                  If False, return a 401 JSON response (for APIs).

    Examples:
        @app.route("/dashboard")
        @login_required
        def dashboard():
            return render_template("dashboard.html")

        @app.route("/api/me")
        @login_required(redirect=False)
        async def api_me():
            return jsonify({"id": current_user.id})
    """

    def refusal() -> ResponseReturnValue | None:
        return None if _signed_in() else _turn_away(redirect=redirect)

    def decorator(view: V) -> V:
        return _guard(view, refusal)

    return decorator(func) if func is not None else decorator


def fresh_login_required[V: Callable[..., typing.Any]](
    func: V | None = None,
    *,
    redirect: bool = True,
    max_age: timedelta = FRESH_LOGIN_MAX_AGE,
) -> V | Callable[[V], V]:
    """Decorator to require a recent sign-in, for sensitive operations.

    Like `login_required`, but the session must have started less than
    ``max_age`` ago; an older one is sent to sign in again.

    Example:
        @app.route("/change-password", methods=["POST"])
        @fresh_login_required
        def change_password():
            ...
    """

    def refusal() -> ResponseReturnValue | None:
        session = g.get("_neozen_session")
        fresh = (
            _signed_in()
            and session is not None
            and datetime.now(UTC) - ensure_utc(session.created_at) <= max_age
        )
        return None if fresh else _turn_away(redirect=redirect)

    def decorator(view: V) -> V:
        return _guard(view, refusal)

    return decorator(func) if func is not None else decorator


def roles_required[V: Callable[..., typing.Any]](*roles: str) -> Callable[[V], V]:
    """Decorator to require at least one of ``roles``.

    The user object must have a `roles` attribute listing role names. A
    user without them gets the app's 403 (``abort(403)``).

    Example:
        @app.route("/admin")
        @roles_required("admin", "superuser")
        def admin_panel():
            return render_template("admin.html")
    """

    def refusal() -> ResponseReturnValue | None:
        if not _signed_in():
            return _turn_away(redirect=True)
        if not any(role in getattr(current_user, "roles", []) for role in roles):
            abort(403)
        return None

    def decorator(view: V) -> V:
        return _guard(view, refusal)

    return decorator


def permissions_required[V: Callable[..., typing.Any]](
    *permissions: str,
) -> Callable[[V], V]:
    """Decorator to require all of ``permissions``.

    The user object must have a `permissions` attribute or a
    `has_permission` method. Format: "resource:action" or
    "resource:action:scope", e.g. "user:read", "*:*". A user without them
    gets the app's 403 (``abort(403)``).

    Example:
        @app.route("/users/<id>", methods=["DELETE"])
        @permissions_required("user:delete")
        def delete_user(id):
            ...
    """

    def refusal() -> ResponseReturnValue | None:
        if not _signed_in():
            return _turn_away(redirect=True)
        if check_user_permissions(current_user, permissions) is not None:
            abort(403)
        return None

    def decorator(view: V) -> V:
        return _guard(view, refusal)

    return decorator


__all__ = [
    "FRESH_LOGIN_MAX_AGE",
    "fresh_login_required",
    "login_required",
    "permissions_required",
    "roles_required",
]
