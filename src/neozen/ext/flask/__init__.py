"""NeoZen Flask Extension.

Provides Flask-Login-style authentication using NeoZen's session management
and authentication factors.

Quick Start:
    from flask import Flask
    from neozen.ext.flask import NeoZen, login_required, current_user, login_user, logout_user

    app = Flask(__name__)
    app.secret_key = "your-secret-key"

    neozen = NeoZen(app, session_service=session_service)

    @neozen.subject_loader
    def load_user(subject_id: str):
        return User.query.get(subject_id)

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return f"Hello, {current_user.email}!"

    @app.route("/login", methods=["POST"])
    def login():
        user = authenticate(...)
        login_user(user)
        return redirect("/dashboard")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        logout_user()
        return redirect("/")

Configuration:
    The following Flask config keys are supported:

    - NEOZEN_COOKIE_NAME: Session cookie name (default: "neozen_session")
    - NEOZEN_COOKIE_MAX_AGE: Cookie lifetime in seconds (default: 604800 / 7 days)
    - NEOZEN_COOKIE_SECURE: Set Secure flag (default: True)
    - NEOZEN_COOKIE_HTTPONLY: Set HttpOnly flag (default: True)
    - NEOZEN_COOKIE_SAMESITE: SameSite policy (default: "Lax")
    - NEOZEN_LOGIN_VIEW: Endpoint for login redirect (default: None)
    - NEOZEN_LOGIN_MESSAGE: Flash message for unauthorized access
    - NEOZEN_LOGIN_MESSAGE_CATEGORY: Flash category (default: "error")
"""

from __future__ import annotations

from .decorators import fresh_login_required, login_required, roles_required
from .extension import NeoZen, NeoZenState
from .helpers import (
    confirm_login,
    current_user,
    is_authenticated,
    login_user,
    logout_user,
)
from .mixins import AnonymousUser, UserMixin

__all__ = [
    # Extension
    "NeoZen",
    "NeoZenState",
    # Decorators
    "fresh_login_required",
    "login_required",
    "roles_required",
    # Helpers
    "confirm_login",
    "current_user",
    "is_authenticated",
    "login_user",
    "logout_user",
    # Mixins
    "AnonymousUser",
    "UserMixin",
]
