"""Decorators for NeoZen Flask extension."""

from __future__ import annotations

import typing
from functools import wraps

from flask import jsonify

from neozen.web.auth.permissions import check_user_permissions

from .helpers import current_user

if typing.TYPE_CHECKING:
    from collections.abc import Callable

    F = typing.TypeVar("F", bound=Callable[..., typing.Any])


def login_required[F: Callable[..., typing.Any]](
    func: F | None = None,
    *,
    redirect: bool = True,
) -> F | Callable[[F], F]:
    """Decorator to require authentication for a view.

    When applied to a view function, it checks if the current user is
    authenticated. If not, it either redirects to the login page or
    returns a 401 response.

    Args:
        func: The view function (when used without arguments)
        redirect: If True (default), redirect to login_view.
                  If False, return 401 JSON response (for APIs).

    Returns:
        Decorated function or decorator

    Examples:
        # Basic usage - redirects to login
        @app.route("/dashboard")
        @login_required
        def dashboard():
            return render_template("dashboard.html")

        # For API endpoints - returns 401
        @app.route("/api/me")
        @login_required(redirect=False)
        def api_me():
            return jsonify({"id": current_user.id})

        # Can also be used with parentheses
        @app.route("/profile")
        @login_required()
        def profile():
            return render_template("profile.html")
    """

    def decorator(f: F) -> F:
        @wraps(f)
        def decorated_function(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
            if not getattr(current_user, "is_authenticated", False):
                if redirect:
                    from .extension import _get_neozen  # noqa: PLC0415

                    neozen = _get_neozen()
                    return neozen.handle_unauthorized()
                return jsonify({"error": "Unauthorized"}), 401
            return f(*args, **kwargs)

        return decorated_function  # type: ignore[return-value]  # ty: ignore[invalid-return-type]

    if func is not None:
        # Called without arguments: @login_required
        return decorator(func)

    # Called with arguments: @login_required() or @login_required(redirect=False)
    return decorator


def fresh_login_required[F: Callable[..., typing.Any]](
    func: F | None = None,
    *,
    redirect: bool = True,
) -> F | Callable[[F], F]:
    """Decorator to require a fresh login for sensitive operations.

    Similar to login_required, but also checks that the session is "fresh"
    (i.e., the user recently authenticated, not just resumed a session).

    Note: This is a placeholder for future implementation. Currently
    behaves the same as login_required.

    Args:
        func: The view function
        redirect: If True, redirect to login; if False, return 401

    Returns:
        Decorated function or decorator

    Example:
        @app.route("/change-password", methods=["POST"])
        @fresh_login_required
        def change_password():
            # Only allow if user recently logged in
            ...
    """
    # TODO: Implement fresh session checking
    # For now, just use regular login_required
    return login_required(func, redirect=redirect)  # pyrefly: ignore[bad-return]


def roles_required(*roles: str) -> Callable[[F], F]:
    """Decorator to require specific roles.

    Checks if the current user has at least one of the specified roles.
    The user object must have a `roles` attribute containing a list of
    role names.

    Args:
        *roles: Role names - user must have at least one of these

    Returns:
        Decorator function

    Example:
        @app.route("/admin")
        @login_required
        @roles_required("admin", "superuser")
        def admin_panel():
            return render_template("admin.html")
    """

    def decorator(f: F) -> F:
        @wraps(f)
        def decorated_function(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
            # Check authentication first
            if not getattr(current_user, "is_authenticated", False):
                from .extension import _get_neozen  # noqa: PLC0415

                neozen = _get_neozen()
                return neozen.handle_unauthorized()

            # Check roles
            user_roles = getattr(current_user, "roles", [])
            if not any(role in user_roles for role in roles):
                from flask import abort  # noqa: PLC0415

                abort(403)

            return f(*args, **kwargs)

        return decorated_function  # type: ignore[return-value]  # ty: ignore[invalid-return-type]

    return decorator


def permissions_required(*permissions: str) -> Callable[[F], F]:
    """Decorator to require specific permissions.

    Checks if the current user has all of the specified permissions.
    The user object must have a `permissions` attribute containing
    a set/list of permission strings, or a `has_permission` method.

    Permission format: "resource:action" or "resource:action:scope"
    Examples: "user:read", "post:delete:own", "*:*" (superuser)

    Args:
        *permissions: Permission strings - user must have ALL of these

    Returns:
        Decorator function

    Example:
        @app.route("/users")
        @login_required
        @permissions_required("user:read")
        def list_users():
            return render_template("users.html")

        @app.route("/users/<id>", methods=["DELETE"])
        @login_required
        @permissions_required("user:delete")
        def delete_user(id):
            ...
    """

    def decorator(f: F) -> F:
        @wraps(f)
        def decorated_function(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
            # Check authentication first
            if not getattr(current_user, "is_authenticated", False):
                from .extension import _get_neozen  # noqa: PLC0415

                neozen = _get_neozen()
                return neozen.handle_unauthorized()

            if check_user_permissions(current_user, permissions) is not None:
                from flask import abort  # noqa: PLC0415

                abort(403)

            return f(*args, **kwargs)

        return decorated_function  # type: ignore[return-value]  # ty: ignore[invalid-return-type]

    return decorator


__all__ = [
    "fresh_login_required",
    "login_required",
    "permissions_required",
    "roles_required",
]
