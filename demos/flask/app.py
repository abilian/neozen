"""NeoZen Flask Demo Application.

A demo application using the NeoZen Flask extension for authentication.
Comparable in simplicity to Flask-Login demos.

Run with: flask run --port 8002
"""

from __future__ import annotations

import secrets
from pathlib import Path

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from pwdlib import PasswordHash

from neozen.ext.flask import (
    NeoZen,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)

# =============================================================================
# Application Setup
# =============================================================================

TEMPLATES_DIR = Path(__file__).parent / "templates"

app = Flask(__name__, template_folder=str(TEMPLATES_DIR))
app.secret_key = "demo-secret-key-change-in-production"
hasher = PasswordHash.recommended()


# =============================================================================
# In-Memory Session Service (implements SessionService protocol)
# =============================================================================

sessions_db: dict[str, dict] = {}


class InMemorySession:
    """Simple session object."""

    def __init__(self, token: str, subject_id: str) -> None:
        self.token = token
        self.subject_id = subject_id
        self.is_active = True


class InMemorySessionService:
    """Simple in-memory session service."""

    async def create_session(
        self,
        subject_id: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> str:
        token = secrets.token_urlsafe(32)
        sessions_db[token] = {
            "token": token,
            "subject_id": subject_id,
            "is_active": True,
        }
        return token

    async def validate_session(self, token: str) -> InMemorySession | None:
        data = sessions_db.get(token)
        if data and data["is_active"]:
            return InMemorySession(data["token"], data["subject_id"])
        return None

    async def revoke_session_by_token(self, token: str) -> None:
        if token in sessions_db:
            sessions_db[token]["is_active"] = False


session_service = InMemorySessionService()
neozen = NeoZen(app, session_service=session_service, login_view="login")

# =============================================================================
# Simple In-Memory User Store (like Flask-Login demo)
# =============================================================================

users_db: dict[str, dict] = {}


class User(UserMixin):
    """User model with NeoZen UserMixin."""

    def __init__(self, id: str, email: str, password_hash: str) -> None:
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.is_active = True
        self.is_verified = False
        self.created_at = None

    @staticmethod
    def get(user_id: str) -> User | None:
        data = users_db.get(user_id)
        return User(**data) if data else None

    @staticmethod
    def get_by_email(email: str) -> User | None:
        for data in users_db.values():
            if data["email"] == email.lower():
                return User(**data)
        return None

    def check_password(self, password: str) -> bool:
        valid, _ = hasher.verify_and_update(password, self.password_hash)
        return valid


@neozen.subject_loader
def load_user(user_id: str) -> User | None:
    """Load user by ID."""
    return User.get(user_id)


# =============================================================================
# Routes
# =============================================================================


@app.route("/")
def index():
    """Home page."""
    return render_template("index.html", current_user=current_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")

        user = User.get_by_email(email)
        if user and user.check_password(password):
            login_user(user, remember=True)
            flash("Login successful!", "success")
            return redirect(request.args.get("next") or url_for("dashboard"))

        flash("Invalid email or password", "error")

    return render_template("login.html", current_user=None)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Registration page."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").lower()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")

        # Validation
        if not email or not password:
            flash("Email and password are required", "error")
        elif "@" not in email:
            flash("Invalid email format", "error")
        elif password != password_confirm:
            flash("Passwords do not match", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters", "error")
        elif User.get_by_email(email):
            flash("Email already registered", "error")
        else:
            # Create user
            user_id = f"user_{secrets.token_hex(8)}"
            users_db[user_id] = {
                "id": user_id,
                "email": email,
                "password_hash": hasher.hash(password),
            }
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html", current_user=None)


@app.route("/dashboard")
@login_required
def dashboard():
    """Protected dashboard."""
    return render_template("dashboard.html", current_user=current_user)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    """Logout."""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# =============================================================================
# JSON API
# =============================================================================


@app.route("/api/register", methods=["POST"])
def api_register():
    """Register (JSON API)."""
    body = request.get_json() or {}
    email = body.get("email", "").lower()
    password = body.get("password", "")

    if not email or not password:
        return jsonify({"error": "email and password required"}), 400
    if "@" not in email:
        return jsonify({"error": "Invalid email"}), 400
    if User.get_by_email(email):
        return jsonify({"error": "Email already registered"}), 409

    user_id = f"user_{secrets.token_hex(8)}"
    users_db[user_id] = {
        "id": user_id,
        "email": email,
        "password_hash": hasher.hash(password),
    }
    return jsonify({"message": "Registered", "user_id": user_id}), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    """Login (JSON API)."""
    body = request.get_json() or {}
    email = body.get("email", "")
    password = body.get("password", "")

    user = User.get_by_email(email)
    if user and user.check_password(password):
        login_user(user)
        return jsonify({"message": "Logged in", "user_id": user.id})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/logout", methods=["POST"])
@login_required(redirect=False)
def api_logout():
    """Logout (JSON API)."""
    logout_user()
    return jsonify({"message": "Logged out"})


@app.route("/api/me")
@login_required(redirect=False)
def api_me():
    """Current user (JSON API)."""
    return jsonify({"id": current_user.id, "email": current_user.email})


if __name__ == "__main__":
    import os

    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=8002)
