"""NeoZen Flask Demo Application.

A demo application using the NeoZen Flask extension for authentication
with SQLAlchemy persistence.

Run with: flask run --port 8002
"""

from __future__ import annotations

import asyncio
import secrets
from functools import wraps
from pathlib import Path
from typing import Any

from pwdlib import PasswordHash

from demos.shared.auth import (
    RoleServiceFactory,
    SessionServiceFactory,
    get_subject_roles,
)
from demos.shared.database import create_database, init_database
from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from neozen.admin.services import AdminService
from neozen.ext.flask import (
    NeoZen,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from neozen.storage.base import DoesNotExist
from neozen.storage.sqlalchemy.repositories import SubjectRepository

# =============================================================================
# Application Setup
# =============================================================================

TEMPLATES_DIR = Path(__file__).parent / "templates"
DATA_DIR = Path(__file__).parent / "data"
DB_PATH = DATA_DIR / "neozen.db"

# Ensure data directory exists
DATA_DIR.mkdir(exist_ok=True)

app = Flask(__name__, template_folder=str(TEMPLATES_DIR))
app.secret_key = "demo-secret-key-change-in-production"
hasher = PasswordHash.recommended()

# Database setup
engine, session_factory = create_database(str(DB_PATH))

# Session service factory
session_service = SessionServiceFactory(session_factory, app.secret_key)

# Role service factory
role_service = RoleServiceFactory(session_factory)


# =============================================================================
# Async Helper
# =============================================================================


def run_async(coro: Any) -> Any:
    """Run an async coroutine from sync code.

    Creates a new event loop for each call to handle Flask's threaded mode.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# =============================================================================
# User Model Wrapper
# =============================================================================


class User(UserMixin):
    """User model wrapping SQLAlchemy Subject."""

    def __init__(
        self,
        id: str,
        email: str,
        hashed_password: str | None = None,
        is_active: bool = True,
        is_verified: bool = False,
        created_at: Any = None,
        username: str | None = None,
    ) -> None:
        self.id = id
        self.email = email
        self.hashed_password = hashed_password
        self.is_active = is_active
        self.is_verified = is_verified
        self.created_at = created_at
        self.username = username
        self._roles: list[str] | None = None

    @property
    def roles(self) -> list[str]:
        """Get roles (lazy loaded)."""
        if self._roles is None:
            self._roles = run_async(get_subject_roles(session_factory, self.id))
        return self._roles

    def check_password(self, password: str) -> bool:
        """Check password."""
        if not self.hashed_password:
            return False
        valid, _ = hasher.verify_and_update(password, self.hashed_password)
        return valid

    def has_role(self, role: str) -> bool:
        """Check if user has role."""
        return role in self.roles

    @staticmethod
    def get(user_id: str) -> User | None:
        """Get user by ID."""

        async def _get() -> User | None:
            async with session_factory() as db_session:
                repo = SubjectRepository(session=db_session)
                try:
                    subject = await repo.get_one_by(id=user_id)
                    return User(
                        id=subject.id,
                        email=subject.email,
                        hashed_password=subject.hashed_password,
                        is_active=subject.is_active,
                        is_verified=subject.is_verified,
                        created_at=subject.created_at,
                        username=subject.username,
                    )
                except DoesNotExist:
                    return None

        return run_async(_get())

    @staticmethod
    def get_by_email(email: str) -> User | None:
        """Get user by email."""

        async def _get() -> User | None:
            async with session_factory() as db_session:
                repo = SubjectRepository(session=db_session)
                try:
                    subject = await repo.get_one_by(email=email.lower())
                    return User(
                        id=subject.id,
                        email=subject.email,
                        hashed_password=subject.hashed_password,
                        is_active=subject.is_active,
                        is_verified=subject.is_verified,
                        created_at=subject.created_at,
                        username=subject.username,
                    )
                except DoesNotExist:
                    return None

        return run_async(_get())


# =============================================================================
# NeoZen Setup
# =============================================================================

neozen = NeoZen(app, session_service=session_service, login_view="login")


@neozen.subject_loader
def load_user(user_id: str) -> User | None:
    """Load user by ID."""
    return User.get(user_id)


# =============================================================================
# Initialization
# =============================================================================


@app.before_request
def ensure_initialized() -> None:
    """Ensure database is initialized."""
    if not getattr(g, "_db_initialized", False):
        run_async(init_database(engine))

        # Ensure built-in roles exist
        async def ensure_roles() -> None:
            async with session_factory() as db_session:
                service = AdminService(db_session)
                await service.ensure_builtin_roles()
                await db_session.commit()

        run_async(ensure_roles())
        g._db_initialized = True


# =============================================================================
# Admin Guard
# =============================================================================


def admin_required(f):
    """Decorator requiring admin role."""

    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.has_role("admin"):
            flash("Admin access required", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)

    return decorated_function


# =============================================================================
# Routes
# =============================================================================


@app.route("/")
def index():
    """Home page."""
    roles = []
    if current_user.is_authenticated:
        roles = current_user.roles
    return render_template("index.html", current_user=current_user, roles=roles)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").lower()
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

            async def create_user() -> tuple[str, bool]:
                async with session_factory() as db_session:
                    repo = SubjectRepository(session=db_session)

                    subject_id = f"user_{secrets.token_hex(8)}"
                    is_first_user = await repo.count() == 0

                    await repo.create(
                        id=subject_id,
                        email=email,
                        hashed_password=hasher.hash(password),
                        is_active=True,
                        is_verified=False,
                    )
                    await db_session.commit()
                    return subject_id, is_first_user

            subject_id, is_first_user = run_async(create_user())

            # Assign roles
            if is_first_user:
                run_async(role_service.assign_role(subject_id, "admin"))
                run_async(role_service.assign_role(subject_id, "user"))
                flash(
                    "Registration successful! You are the first user and have been granted admin privileges.",
                    "success",
                )
            else:
                run_async(role_service.assign_role(subject_id, "user"))
                flash("Registration successful! Please log in.", "success")

            return redirect(url_for("login"))

    return render_template("register.html", current_user=None)


@app.route("/dashboard")
@login_required
def dashboard():
    """Protected dashboard."""
    roles = current_user.roles
    return render_template("dashboard.html", current_user=current_user, roles=roles)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    """Logout."""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# =============================================================================
# Admin Routes (Flask-native)
# =============================================================================


@app.route("/admin")
@admin_required
def admin_dashboard():
    """Admin dashboard."""

    async def get_stats():
        async with session_factory() as db_session:
            service = AdminService(db_session)
            return await service.get_dashboard_stats()

    stats = run_async(get_stats())
    return render_template(
        "admin/dashboard.html", current_user=current_user, stats=stats
    )


@app.route("/admin/users")
@admin_required
def admin_users():
    """List all users."""

    async def get_users():
        async with session_factory() as db_session:
            service = AdminService(db_session)
            return await service.list_subjects()

    users = run_async(get_users())
    return render_template("admin/users.html", current_user=current_user, users=users)


@app.route("/admin/users/<user_id>")
@admin_required
def admin_user_detail(user_id: str):
    """View user details."""

    async def get_user_with_roles():
        async with session_factory() as db_session:
            service = AdminService(db_session)
            try:
                subject = await service.get_subject(user_id)
                roles = await service.get_subject_roles(user_id)
                return subject, roles
            except Exception:
                return None, []

    target_user, user_roles = run_async(get_user_with_roles())
    if not target_user:
        flash(f"User not found: {user_id}", "error")
        return redirect(url_for("admin_users"))

    return render_template(
        "admin/user_detail.html",
        current_user=current_user,
        target_user=target_user,
        user_roles=user_roles,
    )


@app.route("/admin/users/<user_id>/toggle-role/<role>", methods=["POST"])
@admin_required
def admin_toggle_role(user_id: str, role: str):
    """Toggle a role for a user."""
    if user_id == current_user.id and role == "admin":
        flash("Cannot remove admin role from yourself", "error")
        return redirect(url_for("admin_user_detail", user_id=user_id))

    async def toggle():
        roles = await get_subject_roles(session_factory, user_id)
        if role in roles:
            await role_service.revoke_role(user_id, role)
            return False
        else:
            await role_service.assign_role(user_id, role)
            return True

    added = run_async(toggle())
    if added:
        flash(f"Added '{role}' role to user", "success")
    else:
        flash(f"Removed '{role}' role from user", "success")

    return redirect(url_for("admin_user_detail", user_id=user_id))


@app.route("/admin/sessions")
@admin_required
def admin_sessions():
    """List all active sessions."""

    async def get_sessions():
        async with session_factory() as db_session:
            service = AdminService(db_session)
            sessions = await service.list_sessions(active_only=True)

            sessions_with_subjects = []
            for sess in sessions:
                try:
                    subject = await service.get_subject(sess.subject_id)
                    sessions_with_subjects.append((sess, subject))
                except Exception:
                    sessions_with_subjects.append((sess, None))

            return sessions_with_subjects

    sessions = run_async(get_sessions())
    return render_template(
        "admin/sessions.html", current_user=current_user, sessions=sessions
    )


@app.route("/admin/sessions/<token_hash>/revoke", methods=["POST"])
@admin_required
def admin_revoke_session(token_hash: str):
    """Revoke a session."""

    async def revoke():
        async with session_factory() as db_session:
            service = AdminService(db_session)
            await service.revoke_session(token_hash)
            await db_session.commit()

    try:
        run_async(revoke())
        flash("Session revoked", "success")
    except Exception as e:
        flash(f"Error revoking session: {e}", "error")

    return redirect(url_for("admin_sessions"))


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

    async def create_user() -> tuple[str, bool]:
        async with session_factory() as db_session:
            repo = SubjectRepository(session=db_session)

            subject_id = f"user_{secrets.token_hex(8)}"
            is_first_user = await repo.count() == 0

            await repo.create(
                id=subject_id,
                email=email,
                hashed_password=hasher.hash(password),
                is_active=True,
                is_verified=False,
            )
            await db_session.commit()
            return subject_id, is_first_user

    subject_id, is_first_user = run_async(create_user())

    # Assign roles
    if is_first_user:
        run_async(role_service.assign_role(subject_id, "admin"))
        run_async(role_service.assign_role(subject_id, "user"))
        roles = ["admin", "user"]
    else:
        run_async(role_service.assign_role(subject_id, "user"))
        roles = ["user"]

    return jsonify({
        "message": "Registered",
        "user_id": subject_id,
        "roles": roles,
    }), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    """Login (JSON API)."""
    body = request.get_json() or {}
    email = body.get("email", "").lower()
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
    return jsonify({
        "id": current_user.id,
        "email": current_user.email,
        "roles": current_user.roles,
    })


if __name__ == "__main__":
    import os

    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=8002)
