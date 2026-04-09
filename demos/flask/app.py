"""NeoZen Flask Demo Application.

A demo application using the NeoZen Flask extension for authentication
with SQLAlchemy persistence.

Run with: flask run --port 8002
"""

from __future__ import annotations

import asyncio
import base64
import io
import os
import secrets
from functools import wraps
from pathlib import Path
from typing import Any

from pwdlib import PasswordHash

from demos.shared.database import create_database, init_database
from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from neozen.admin.services import AdminService
from neozen.core.email.console import ConsoleEmailSender
from neozen.core.factors.magic_link import MagicLinkConfig, MagicLinkFactor
from neozen.ext.flask import (
    NeoZen,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from neozen.storage.base import DoesNotExist
from neozen.storage.sqlalchemy import (
    RoleServiceFactory,
    SessionServiceFactory,
    get_subject_roles,
)
from neozen.storage.sqlalchemy.repositories import (
    BackupCodeRepository,
    SocialAccountRepository,
    SubjectRepository,
    WebAuthnChallengeRepository,
    WebAuthnCredentialRepository,
)

# Optional imports for Stage 5 features
try:
    from neozen.core.factors.totp import TOTPConfig, TOTPFactor

    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False

try:
    from neozen.core.factors.webauthn import WebAuthnConfig, WebAuthnFactor

    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False

try:
    from neozen.core.oauth_client.providers.github import create_github_config
    from neozen.core.oauth_client.providers.google import create_google_config
    from neozen.core.oauth_client.service import OAuthClientService
    from neozen.storage.sqlalchemy.repositories import OAuthStateRepository

    OAUTH_AVAILABLE = True
except ImportError:
    OAUTH_AVAILABLE = False

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
# Magic Link Authentication
# =============================================================================


class SubjectEmailLookupAdapter:
    def __init__(self, sf):
        self._sf = sf

    async def get_email(self, subject_id: str) -> str | None:
        async with self._sf() as s:
            repo = SubjectRepository(session=s)
            try:
                subject = await repo.get_one_by(id=subject_id)
                return subject.email
            except DoesNotExist:
                return None

    async def subject_exists(self, subject_id: str) -> bool:
        async with self._sf() as s:
            repo = SubjectRepository(session=s)
            return await repo.exists(id=subject_id)


class InMemoryMagicLinkTokenRepository:
    """Simple in-memory token repository for the demo."""

    def __init__(self):
        self._tokens = {}
        self._by_hash = {}
        self._counter = 0

    async def create(self, **kwargs):
        from types import SimpleNamespace

        self._counter += 1
        token_id = f"mlt_{self._counter}"
        token = SimpleNamespace(id=token_id, **kwargs)
        self._tokens[token_id] = token
        self._by_hash[kwargs["token_hash"]] = token_id
        return token

    async def get_by_hash(self, token_hash):
        token_id = self._by_hash.get(token_hash)
        return self._tokens.get(token_id) if token_id else None

    async def mark_used(self, token_id, used_at):
        if token_id in self._tokens:
            self._tokens[token_id].used_at = used_at

    async def count_pending(self, subject_id, since):
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        return sum(
            1
            for t in self._tokens.values()
            if t.subject_id == subject_id
            and t.created_at >= since
            and t.used_at is None
            and t.expires_at > now
        )

    async def invalidate_all(self, subject_id):
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        count = 0
        for t in self._tokens.values():
            if t.subject_id == subject_id and t.used_at is None:
                t.used_at = now
                count += 1
        return count


email_sender = ConsoleEmailSender()
magic_link_factor = MagicLinkFactor(
    config=MagicLinkConfig(link_base_url=""),  # Will be set dynamically
    token_repository=InMemoryMagicLinkTokenRepository(),
    subject_email_lookup=SubjectEmailLookupAdapter(session_factory),
    email_sender=email_sender,
    token_hash_key=app.secret_key,
)

# =============================================================================
# Stage 5: Advanced Authentication Configuration
# =============================================================================

# OAuth configuration (set environment variables to enable)
OAUTH_PROVIDERS: list[str] = []

if OAUTH_AVAILABLE:
    GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
    GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")

    if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
        OAUTH_PROVIDERS.append("google")
    if GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET:
        OAUTH_PROVIDERS.append("github")

# TOTP configuration
TOTP_CONFIG = (
    TOTPConfig(
        issuer="NeoZen Demo",
        digits=6,
        interval=30,
        backup_code_count=8,
        backup_code_length=8,
    )
    if TOTP_AVAILABLE
    else None
)

# WebAuthn configuration
WEBAUTHN_CONFIG = (
    WebAuthnConfig(
        rp_id="localhost",
        rp_name="NeoZen Demo",
        origin="http://localhost:8002",
        challenge_timeout_seconds=300,
    )
    if WEBAUTHN_AVAILABLE
    else None
)


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
        totp_enabled: bool = False,
        totp_secret: str | None = None,
    ) -> None:
        self.id = id
        self.email = email
        self.hashed_password = hashed_password
        self.is_active = is_active
        self.is_verified = is_verified
        self.created_at = created_at
        self.username = username
        self.totp_enabled = totp_enabled
        self.totp_secret = totp_secret
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
                        totp_enabled=getattr(subject, "totp_enabled", False),
                        totp_secret=getattr(subject, "totp_secret", None),
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
                        totp_enabled=getattr(subject, "totp_enabled", False),
                        totp_secret=getattr(subject, "totp_secret", None),
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
            # Check if TOTP is enabled
            if user.totp_enabled and TOTP_AVAILABLE:
                # Store user ID in session for 2FA verification
                session["pending_2fa_user_id"] = user.id
                session["pending_2fa_next"] = request.args.get("next")
                return redirect(url_for("login_totp"))

            login_user(user, remember=True)
            flash("Login successful!", "success")
            return redirect(request.args.get("next") or url_for("dashboard"))

        flash("Invalid email or password", "error")

    return render_template(
        "login.html",
        current_user=None,
        oauth_providers=OAUTH_PROVIDERS,
        webauthn_enabled=WEBAUTHN_AVAILABLE,
    )


@app.route("/magic-login", methods=["GET", "POST"])
def magic_login_request():
    """Request a magic link."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").lower()
        if not email or "@" not in email:
            flash("Please enter a valid email address", "error")
        else:
            # Look up subject by email
            user = User.get_by_email(email)
            if user:
                # Set the base URL dynamically
                base_url = request.url_root.rstrip("/")
                magic_link_factor.config = MagicLinkConfig(
                    link_base_url=f"{base_url}/magic-login/verify",
                    token_lifetime=magic_link_factor.config.token_lifetime,
                    max_pending_per_subject=magic_link_factor.config.max_pending_per_subject,
                    rate_limit_window=magic_link_factor.config.rate_limit_window,
                    token_prefix=magic_link_factor.config.token_prefix,
                )
                run_async(
                    magic_link_factor.begin_authentication(
                        user.id, ip_address=request.remote_addr
                    )
                )
            # Always show success (prevents email enumeration)
            flash(
                "If an account exists with that email, a magic link has been sent."
                " Check your console output.",
                "success",
            )
            return redirect(url_for("magic_login_request"))

    return render_template("magic_login.html", current_user=None)


@app.route("/magic-login/verify")
def magic_login_verify():
    """Verify a magic link token and log in."""
    token = request.args.get("token", "")
    if not token:
        flash("Invalid magic link", "error")
        return redirect(url_for("login"))

    # Find which subject this token belongs to
    from neozen.core.crypto import get_token_hash

    token_hash = get_token_hash(token, app.secret_key)
    token_record = run_async(magic_link_factor.token_repository.get_by_hash(token_hash))

    if not token_record:
        flash("Invalid or expired magic link", "error")
        return redirect(url_for("login"))

    # Complete authentication
    valid = run_async(
        magic_link_factor.complete_authentication(
            token_record.subject_id, response=token
        )
    )

    if valid:
        user = User.get(token_record.subject_id)
        if user:
            login_user(user, remember=True)
            flash("Login successful via magic link!", "success")
            return redirect(url_for("dashboard"))

    flash("Invalid or expired magic link", "error")
    return redirect(url_for("login"))


@app.route("/api/test/last-magic-link")
def api_last_magic_link():
    """Test endpoint: return the last magic link URL sent (dev only)."""
    if email_sender.sent_messages:
        last = email_sender.sent_messages[-1]
        # Extract URL from body text
        for line in last.body_text.splitlines():
            if "magic-login/verify?token=" in line:
                return jsonify({"url": line.strip()})
    return jsonify({"url": None})


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

    async def toggle() -> bool:
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

    async def revoke() -> None:
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


# =============================================================================
# Stage 5: TOTP Two-Factor Authentication Routes
# =============================================================================


@app.route("/login/totp", methods=["GET", "POST"])
def login_totp():
    """TOTP verification page for 2FA."""
    if not TOTP_AVAILABLE:
        flash("2FA is not available", "error")
        return redirect(url_for("login"))

    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "")
        user = User.get(user_id)

        if user and user.totp_secret:

            async def verify_totp():
                async with session_factory() as db_session:
                    repo = SubjectRepository(session=db_session)
                    subject = await repo.get_one_by(id=user_id)
                    backup_repo = BackupCodeRepository(session=db_session)
                    totp_factor = TOTPFactor(
                        config=TOTP_CONFIG,
                        subject_repository=repo,
                        backup_code_repository=backup_repo,
                        hasher=hasher,
                    )
                    return await totp_factor.authenticate(subject, code)

            try:
                if run_async(verify_totp()):
                    session.pop("pending_2fa_user_id", None)
                    next_url = session.pop("pending_2fa_next", None)
                    login_user(user, remember=True)
                    flash("Login successful!", "success")
                    return redirect(next_url or url_for("dashboard"))
            except Exception:
                pass

        flash("Invalid authentication code", "error")

    return render_template("login_totp.html", current_user=None)


@app.route("/login/backup-code", methods=["POST"])
def login_backup_code():
    """Use backup code for 2FA."""
    if not TOTP_AVAILABLE:
        flash("2FA is not available", "error")
        return redirect(url_for("login"))

    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("login"))

    backup_code = request.form.get("backup_code", "")
    user = User.get(user_id)

    if user:

        async def use_backup():
            async with session_factory() as db_session:
                repo = SubjectRepository(session=db_session)
                subject = await repo.get_one_by(id=user_id)
                backup_repo = BackupCodeRepository(session=db_session)
                totp_factor = TOTPFactor(
                    config=TOTP_CONFIG,
                    subject_repository=repo,
                    backup_code_repository=backup_repo,
                    hasher=hasher,
                )
                result = await totp_factor.use_backup_code(subject, backup_code)
                await db_session.commit()
                return result

        try:
            if run_async(use_backup()):
                session.pop("pending_2fa_user_id", None)
                next_url = session.pop("pending_2fa_next", None)
                login_user(user, remember=True)
                flash("Login successful! (Backup code used)", "success")
                return redirect(next_url or url_for("dashboard"))
        except Exception:
            pass

    flash("Invalid backup code", "error")
    return redirect(url_for("login_totp"))


@app.route("/security")
@login_required
def security_settings():
    """Security settings page."""
    # Get TOTP status
    totp_enabled = current_user.totp_enabled if TOTP_AVAILABLE else False
    backup_codes_remaining = 0

    if totp_enabled:

        async def get_backup_count():
            async with session_factory() as db_session:
                backup_repo = BackupCodeRepository(session=db_session)
                codes = await backup_repo.get_many_by(subject_id=current_user.id)
                return len([c for c in codes if not getattr(c, "used_at", None)])

        backup_codes_remaining = run_async(get_backup_count())

    # Get passkeys
    passkeys = []
    if WEBAUTHN_AVAILABLE:

        async def get_passkeys():
            async with session_factory() as db_session:
                repo = WebAuthnCredentialRepository(session=db_session)
                return await repo.get_many_by(subject_id=current_user.id)

        passkeys = run_async(get_passkeys())

    # Get linked social accounts
    social_accounts = []
    has_google = False
    has_github = False
    if OAUTH_AVAILABLE:

        async def get_social_accounts():
            async with session_factory() as db_session:
                repo = SocialAccountRepository(session=db_session)
                return await repo.get_many_by(subject_id=current_user.id)

        social_accounts = run_async(get_social_accounts())
        has_google = any(a.provider_id == "google" for a in social_accounts)
        has_github = any(a.provider_id == "github" for a in social_accounts)

    return render_template(
        "security.html",
        current_user=current_user,
        roles=current_user.roles,
        totp_enabled=totp_enabled,
        backup_codes_remaining=backup_codes_remaining,
        passkeys=passkeys,
        social_accounts=social_accounts,
        has_google=has_google,
        has_github=has_github,
    )


@app.route("/security/totp/setup", methods=["GET", "POST"])
@login_required
def security_setup_totp():
    """Set up TOTP 2FA."""
    if not TOTP_AVAILABLE:
        flash("TOTP is not available", "error")
        return redirect(url_for("security_settings"))

    if current_user.totp_enabled:
        flash("TOTP is already enabled", "error")
        return redirect(url_for("security_settings"))

    if request.method == "POST":
        step = request.form.get("step")

        if step == "verify":
            code = request.form.get("code", "")

            async def confirm_enrollment():
                async with session_factory() as db_session:
                    repo = SubjectRepository(session=db_session)
                    subject = await repo.get_one_by(id=current_user.id)
                    backup_repo = BackupCodeRepository(session=db_session)
                    totp_factor = TOTPFactor(
                        config=TOTP_CONFIG,
                        subject_repository=repo,
                        backup_code_repository=backup_repo,
                        hasher=hasher,
                    )
                    _, backup_codes = await totp_factor.confirm_enrollment(
                        subject, code
                    )
                    await db_session.commit()
                    return backup_codes

            try:
                backup_codes = run_async(confirm_enrollment())
                flash("Two-factor authentication enabled!", "success")
                return render_template(
                    "security_totp_setup.html",
                    current_user=current_user,
                    roles=current_user.roles,
                    step="backup_codes",
                    backup_codes=backup_codes,
                )
            except Exception as e:
                flash(f"Invalid code: {e}", "error")

    # Begin enrollment
    async def begin_enrollment():
        async with session_factory() as db_session:
            repo = SubjectRepository(session=db_session)
            subject = await repo.get_one_by(id=current_user.id)
            backup_repo = BackupCodeRepository(session=db_session)
            totp_factor = TOTPFactor(
                config=TOTP_CONFIG,
                subject_repository=repo,
                backup_code_repository=backup_repo,
                hasher=hasher,
            )
            result = await totp_factor.begin_enrollment(subject)
            await db_session.commit()
            return result

    result = run_async(begin_enrollment())

    # Generate QR code as data URL
    qr_code_url = ""
    try:
        import qrcode

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(result.provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code_url = (
            f"data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}"
        )
    except ImportError:
        pass

    return render_template(
        "security_totp_setup.html",
        current_user=current_user,
        roles=current_user.roles,
        step="scan",
        secret=result.secret,
        qr_code_url=qr_code_url,
    )


@app.route("/security/totp/disable", methods=["POST"])
@login_required
def security_disable_totp():
    """Disable TOTP 2FA."""
    if not TOTP_AVAILABLE:
        flash("TOTP is not available", "error")
        return redirect(url_for("security_settings"))

    async def disable_totp() -> None:
        async with session_factory() as db_session:
            repo = SubjectRepository(session=db_session)
            subject = await repo.get_one_by(id=current_user.id)
            backup_repo = BackupCodeRepository(session=db_session)
            totp_factor = TOTPFactor(
                config=TOTP_CONFIG,
                subject_repository=repo,
                backup_code_repository=backup_repo,
                hasher=hasher,
            )
            await totp_factor.disable(subject)
            await db_session.commit()

    run_async(disable_totp())
    flash("Two-factor authentication disabled", "success")
    return redirect(url_for("security_settings"))


@app.route("/security/totp/regenerate-backup-codes", methods=["POST"])
@login_required
def security_regenerate_backup_codes():
    """Regenerate backup codes."""
    if not TOTP_AVAILABLE:
        flash("TOTP is not available", "error")
        return redirect(url_for("security_settings"))

    async def regenerate():
        async with session_factory() as db_session:
            repo = SubjectRepository(session=db_session)
            subject = await repo.get_one_by(id=current_user.id)
            backup_repo = BackupCodeRepository(session=db_session)
            totp_factor = TOTPFactor(
                config=TOTP_CONFIG,
                subject_repository=repo,
                backup_code_repository=backup_repo,
                hasher=hasher,
            )
            codes = await totp_factor.regenerate_backup_codes(subject)
            await db_session.commit()
            return codes

    backup_codes = run_async(regenerate())
    return render_template(
        "security_backup_codes.html",
        current_user=current_user,
        roles=current_user.roles,
        backup_codes=backup_codes,
    )


# =============================================================================
# Stage 5: WebAuthn/Passkey Routes
# =============================================================================


@app.route("/security/passkey/register")
@login_required
def security_register_passkey():
    """Register a new passkey."""
    if not WEBAUTHN_AVAILABLE:
        flash("WebAuthn is not available", "error")
        return redirect(url_for("security_settings"))

    async def begin_registration():
        async with session_factory() as db_session:
            repo = SubjectRepository(session=db_session)
            subject = await repo.get_one_by(id=current_user.id)
            cred_repo = WebAuthnCredentialRepository(session=db_session)
            challenge_repo = WebAuthnChallengeRepository(session=db_session)
            webauthn_factor = WebAuthnFactor(
                config=WEBAUTHN_CONFIG,
                credential_repository=cred_repo,
                challenge_repository=challenge_repo,
            )
            options = await webauthn_factor.begin_registration(
                subject,
                user_name=current_user.email,
                user_display_name=current_user.username or current_user.email,
            )
            await db_session.commit()
            return options

    options = run_async(begin_registration())

    return render_template(
        "security_passkey_register.html",
        current_user=current_user,
        roles=current_user.roles,
        registration_options=options.options_json,
    )


@app.route("/security/passkey/register/complete", methods=["POST"])
@login_required
def security_register_passkey_complete():
    """Complete passkey registration."""
    if not WEBAUTHN_AVAILABLE:
        return jsonify({"success": False, "error": "WebAuthn not available"}), 400

    data = request.get_json()
    credential = data.get("credential")
    name = data.get("name", "My Passkey")
    challenge = data.get("challenge")

    async def complete_registration():
        async with session_factory() as db_session:
            repo = SubjectRepository(session=db_session)
            subject = await repo.get_one_by(id=current_user.id)
            cred_repo = WebAuthnCredentialRepository(session=db_session)
            challenge_repo = WebAuthnChallengeRepository(session=db_session)
            webauthn_factor = WebAuthnFactor(
                config=WEBAUTHN_CONFIG,
                credential_repository=cred_repo,
                challenge_repository=challenge_repo,
            )
            cred = await webauthn_factor.complete_registration(
                subject, credential, challenge, credential_name=name
            )
            await db_session.commit()
            return cred

    try:
        run_async(complete_registration())
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/security/passkey/<credential_id>/delete", methods=["POST"])
@login_required
def security_delete_passkey(credential_id: str):
    """Delete a passkey."""
    if not WEBAUTHN_AVAILABLE:
        flash("WebAuthn is not available", "error")
        return redirect(url_for("security_settings"))

    async def delete_credential() -> None:
        async with session_factory() as db_session:
            repo = SubjectRepository(session=db_session)
            subject = await repo.get_one_by(id=current_user.id)
            cred_repo = WebAuthnCredentialRepository(session=db_session)
            challenge_repo = WebAuthnChallengeRepository(session=db_session)
            webauthn_factor = WebAuthnFactor(
                config=WEBAUTHN_CONFIG,
                credential_repository=cred_repo,
                challenge_repository=challenge_repo,
            )
            await webauthn_factor.delete_credential(subject, credential_id)
            await db_session.commit()

    try:
        run_async(delete_credential())
        flash("Passkey deleted", "success")
    except Exception as e:
        flash(f"Error: {e}", "error")

    return redirect(url_for("security_settings"))


@app.route("/webauthn/begin-auth")
def webauthn_begin_auth():
    """Begin WebAuthn authentication (for passkey login)."""
    if not WEBAUTHN_AVAILABLE:
        return jsonify({"success": False, "error": "WebAuthn not available"}), 400

    async def begin_auth():
        async with session_factory() as db_session:
            cred_repo = WebAuthnCredentialRepository(session=db_session)
            challenge_repo = WebAuthnChallengeRepository(session=db_session)
            webauthn_factor = WebAuthnFactor(
                config=WEBAUTHN_CONFIG,
                credential_repository=cred_repo,
                challenge_repository=challenge_repo,
            )
            # Discoverable credential flow (no subject required)
            options = await webauthn_factor.begin_authentication()
            await db_session.commit()
            return options

    try:
        options = run_async(begin_auth())
        return jsonify({"success": True, "options": options.options_json})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/webauthn/complete-auth", methods=["POST"])
def webauthn_complete_auth():
    """Complete WebAuthn authentication."""
    if not WEBAUTHN_AVAILABLE:
        return jsonify({"success": False, "error": "WebAuthn not available"}), 400

    data = request.get_json()
    credential = data.get("credential")
    challenge = data.get("challenge")

    async def complete_auth():
        async with session_factory() as db_session:
            cred_repo = WebAuthnCredentialRepository(session=db_session)
            challenge_repo = WebAuthnChallengeRepository(session=db_session)
            webauthn_factor = WebAuthnFactor(
                config=WEBAUTHN_CONFIG,
                credential_repository=cred_repo,
                challenge_repository=challenge_repo,
            )
            subject_id, _ = await webauthn_factor.complete_authentication(
                credential, challenge
            )
            await db_session.commit()
            return subject_id

    try:
        subject_id = run_async(complete_auth())
        user = User.get(subject_id)
        if user:
            login_user(user, remember=True)
            return jsonify({"success": True, "redirect": url_for("dashboard")})
        return jsonify({"success": False, "error": "User not found"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


# =============================================================================
# Stage 5: OAuth/Social Login Routes
# =============================================================================


@app.route("/oauth/<provider>/begin")
def oauth_begin(provider: str):
    """Begin OAuth flow."""
    if not OAUTH_AVAILABLE:
        flash("OAuth is not available", "error")
        return redirect(url_for("login"))

    if provider not in OAUTH_PROVIDERS:
        flash(f"Provider {provider} is not configured", "error")
        return redirect(url_for("login"))

    async def begin_oauth():
        async with session_factory() as db_session:
            state_repo = OAuthStateRepository(session=db_session)
            social_repo = SocialAccountRepository(session=db_session)

            # Create OAuth service
            oauth_service = OAuthClientService(
                state_repository=state_repo,
                social_account_repository=social_repo,
            )

            # Register provider
            if provider == "google":
                config = create_google_config(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
            else:
                config = create_github_config(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET)
            oauth_service.register_provider(config)

            # Get existing subject ID if logged in (for account linking)
            existing_subject_id = (
                current_user.id if current_user.is_authenticated else None
            )

            # Begin authorization
            redirect_uri = url_for("oauth_callback", provider=provider, _external=True)
            result = await oauth_service.begin_authorization(
                provider_id=provider,
                redirect_uri=redirect_uri,
                existing_subject_id=existing_subject_id,
            )
            await db_session.commit()
            return result

    result = run_async(begin_oauth())
    return redirect(result.authorization_url)


@app.route("/oauth/<provider>/callback")
def oauth_callback(provider: str):
    """Handle OAuth callback."""
    if not OAUTH_AVAILABLE:
        flash("OAuth is not available", "error")
        return redirect(url_for("login"))

    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")

    if error:
        flash(f"OAuth error: {error}", "error")
        return redirect(url_for("login"))

    if not code or not state:
        flash("Invalid OAuth callback", "error")
        return redirect(url_for("login"))

    async def handle_callback():
        async with session_factory() as db_session:
            state_repo = OAuthStateRepository(session=db_session)
            social_repo = SocialAccountRepository(session=db_session)
            subject_repo = SubjectRepository(session=db_session)

            # Create OAuth service
            oauth_service = OAuthClientService(
                state_repository=state_repo,
                social_account_repository=social_repo,
            )

            # Register provider
            if provider == "google":
                config = create_google_config(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
            else:
                config = create_github_config(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET)
            oauth_service.register_provider(config)

            # Handle callback
            result = await oauth_service.handle_callback(
                provider_id=provider,
                code=code,
                state=state,
            )

            # Check if this is account linking or login/registration
            if result.existing_subject_id:
                # Account linking
                await social_repo.create(
                    id=secrets.token_hex(16),
                    subject_id=result.existing_subject_id,
                    provider_id=provider,
                    provider_user_id=result.user_info.get("id", ""),
                    email=result.user_info.get("email"),
                    display_name=result.user_info.get("name"),
                    access_token=result.access_token,
                    refresh_token=result.refresh_token,
                    token_expires_at=result.token_expires_at,
                )
                await db_session.commit()
                return ("linked", result.existing_subject_id)

            # Check if user exists by provider account
            try:
                existing_account = await social_repo.get_one_by(
                    provider_id=provider,
                    provider_user_id=result.user_info.get("id", ""),
                )
                # Update tokens
                await social_repo.update_obj(
                    existing_account,
                    access_token=result.access_token,
                    refresh_token=result.refresh_token,
                    token_expires_at=result.token_expires_at,
                )
                await db_session.commit()
                return ("login", existing_account.subject_id)
            except DoesNotExist:
                pass

            # Check if user exists by email
            email = result.user_info.get("email")
            if email:
                try:
                    existing_subject = await subject_repo.get_one_by(
                        email=email.lower()
                    )
                    # Link account to existing user
                    await social_repo.create(
                        id=secrets.token_hex(16),
                        subject_id=existing_subject.id,
                        provider_id=provider,
                        provider_user_id=result.user_info.get("id", ""),
                        email=email,
                        display_name=result.user_info.get("name"),
                        access_token=result.access_token,
                        refresh_token=result.refresh_token,
                        token_expires_at=result.token_expires_at,
                    )
                    await db_session.commit()
                    return ("login", existing_subject.id)
                except DoesNotExist:
                    pass

            # Create new user
            is_first_user = await subject_repo.count() == 0
            subject_id = f"user_{secrets.token_hex(8)}"
            await subject_repo.create(
                id=subject_id,
                email=email.lower()
                if email
                else f"{provider}_{result.user_info.get('id')}@oauth.local",
                hashed_password=None,  # No password for OAuth users
                is_active=True,
                is_verified=True,  # Verified via OAuth
                username=result.user_info.get("name"),
            )

            # Create social account
            await social_repo.create(
                id=secrets.token_hex(16),
                subject_id=subject_id,
                provider_id=provider,
                provider_user_id=result.user_info.get("id", ""),
                email=email,
                display_name=result.user_info.get("name"),
                access_token=result.access_token,
                refresh_token=result.refresh_token,
                token_expires_at=result.token_expires_at,
            )
            await db_session.commit()

            return ("register", subject_id, is_first_user)

    try:
        result = run_async(handle_callback())

        if result[0] == "linked":
            flash(f"Successfully linked {provider} account!", "success")
            return redirect(url_for("security_settings"))

        subject_id = result[1]
        user = User.get(subject_id)

        if result[0] == "register":
            is_first_user = result[2]
            if is_first_user:
                run_async(role_service.assign_role(subject_id, "admin"))
                run_async(role_service.assign_role(subject_id, "user"))
            else:
                run_async(role_service.assign_role(subject_id, "user"))
            flash("Account created successfully!", "success")
        else:
            flash("Login successful!", "success")

        login_user(user, remember=True)
        return redirect(url_for("dashboard"))

    except Exception as e:
        flash(f"OAuth error: {e}", "error")
        return redirect(url_for("login"))


@app.route("/security/social/<provider_id>/unlink", methods=["POST"])
@login_required
def security_unlink_account(provider_id: str):
    """Unlink a social account."""
    if not OAUTH_AVAILABLE:
        flash("OAuth is not available", "error")
        return redirect(url_for("security_settings"))

    # Don't allow unlinking if it's the only auth method
    if not current_user.hashed_password:

        async def count_social():
            async with session_factory() as db_session:
                repo = SocialAccountRepository(session=db_session)
                accounts = await repo.get_many_by(subject_id=current_user.id)
                return len(accounts)

        if run_async(count_social()) <= 1:
            flash(
                "Cannot unlink the only authentication method. Set a password first.",
                "error",
            )
            return redirect(url_for("security_settings"))

    async def unlink() -> None:
        async with session_factory() as db_session:
            repo = SocialAccountRepository(session=db_session)
            try:
                account = await repo.get_one_by(
                    subject_id=current_user.id,
                    provider_id=provider_id,
                )
                await repo.delete(account)
                await db_session.commit()
            except DoesNotExist:
                pass

    run_async(unlink())
    flash(f"Unlinked {provider_id} account", "success")
    return redirect(url_for("security_settings"))


if __name__ == "__main__":
    import os

    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=8002)
