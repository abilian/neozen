"""NeoZen Litestar Demo Application.

A demo application using the NeoZen Litestar extension for authentication
with SQLAlchemy persistence.

Run with: uvicorn demos.litestar.app:app --reload --port 8003
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader
from pwdlib import PasswordHash

from demos.shared.database import create_database, init_database
from litestar import Litestar, Request, Response, get, post
from litestar.connection import ASGIConnection
from litestar.datastructures import State
from litestar.exceptions import NotAuthorizedException
from litestar.handlers import BaseRouteHandler
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.response import Redirect
from litestar.stores.memory import MemoryStore
from neozen.admin.services import AdminService
from neozen.core.email.console import ConsoleEmailSender
from neozen.core.factors.magic_link import MagicLinkConfig, MagicLinkFactor
from neozen.ext.litestar import (
    NeoZenConfig,
    NeoZenPlugin,
    get_current_user,
    is_authenticated,
    login_required,
    login_user,
    logout_user,
)
from neozen.storage.base import DoesNotExist
from neozen.storage.sqlalchemy import (
    RoleServiceFactory,
    SessionServiceFactory,
    create_subject_loader,
    get_subject_roles,
)
from neozen.storage.sqlalchemy.repositories import (
    SubjectRepository,
)

if TYPE_CHECKING:
    pass

# =============================================================================
# Application Setup
# =============================================================================

SECRET_KEY = "demo-secret-key-change-in-production"
TEMPLATES_DIR = Path(__file__).parent / "templates"
DATA_DIR = Path(__file__).parent / "data"
DB_PATH = DATA_DIR / "neozen.db"

# Ensure data directory exists
DATA_DIR.mkdir(exist_ok=True)

templates = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=True)
hasher = PasswordHash.recommended()

# Database setup
engine, session_factory = create_database(str(DB_PATH))

# Session service factory
session_service = SessionServiceFactory(session_factory, SECRET_KEY)

# Role service factory
role_service = RoleServiceFactory(session_factory)


# Magic link setup
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
        now = datetime.now(UTC)
        count = 0
        for t in self._tokens.values():
            if t.subject_id == subject_id and t.used_at is None:
                t.used_at = now
                count += 1
        return count


email_sender = ConsoleEmailSender()
magic_link_factor = MagicLinkFactor(
    config=MagicLinkConfig(link_base_url=""),  # Set dynamically per request
    token_repository=InMemoryMagicLinkTokenRepository(),
    subject_email_lookup=SubjectEmailLookupAdapter(session_factory),
    email_sender=email_sender,
    token_hash_key=SECRET_KEY,
)


# =============================================================================
# NeoZen Config Setup
# =============================================================================

neozen_config = NeoZenConfig(
    session_service=session_service,
    subject_loader=create_subject_loader(session_factory),
    cookie_secure=False,  # Allow HTTP for demo
    login_path="/login",
)


# =============================================================================
# Template Helpers
# =============================================================================


def render_template(
    request: Request,
    template_name: str,
    context: dict | None = None,
    status_code: int = 200,
) -> Response:
    """Render a Jinja2 template."""
    ctx = context or {}
    ctx["messages"] = request.session.pop("messages", [])
    ctx["request"] = request
    content = templates.get_template(template_name).render(**ctx)
    return Response(content=content, status_code=status_code, media_type="text/html")


def flash(request: Request, message: str, category: str = "info") -> None:
    """Add a flash message."""
    if "messages" not in request.session:
        request.session["messages"] = []
    request.session["messages"].append((category, message))


def json_response(data: dict, status_code: int = 200) -> Response:
    """Return JSON response."""
    return Response(
        content=data, status_code=status_code, media_type="application/json"
    )


def json_error(message: str, status_code: int = 400) -> Response:
    """Return JSON error response."""
    return json_response({"error": message}, status_code=status_code)


def admin_required() -> Callable:
    """Guard that requires admin role."""

    async def guard(connection: ASGIConnection, _: BaseRouteHandler) -> None:
        # Get user from NeoZen state
        state = connection.scope.get("state", {})
        user = state.get("neozen_user")

        # If user not loaded yet, load it
        if user is None and state.get("neozen_session"):
            from neozen.ext.litestar import get_config

            config = get_config(connection)  # type: ignore[arg-type]
            user = await config.get_subject(state["neozen_session"].subject_id)
            state["neozen_user"] = user
            state["neozen_user_loaded"] = True

        if not user:
            msg = "Admin access required"
            raise NotAuthorizedException(msg)

        # Check roles from database
        roles = await get_subject_roles(session_factory, user.id)
        if "admin" not in roles:
            msg = "Admin access required"
            raise NotAuthorizedException(msg)

    return guard


# =============================================================================
# Routes
# =============================================================================


@get("/")
async def index(request: Request) -> Response:
    """Home page."""
    user = await get_current_user(request)
    roles = []
    if user:
        roles = await get_subject_roles(session_factory, user.id)
    return render_template(
        request, "index.html", {"current_user": user, "roles": roles}
    )


@get("/login", sync_to_thread=False)
def login_page(request: Request) -> Response:
    """Login page (GET)."""
    if is_authenticated(request):
        return Redirect(path="/dashboard")
    return render_template(request, "login.html", {"current_user": None})


@post("/login")
async def login_submit(request: Request) -> Response:
    """Login form submission (POST)."""
    if is_authenticated(request):
        return Redirect(path="/dashboard")

    form = await request.form()
    email = str(form.get("email", "")).lower()
    password = str(form.get("password", ""))

    async with session_factory() as db_session:
        repo = SubjectRepository(session=db_session)
        try:
            subject = await repo.get_one_by(email=email)
            if subject.hashed_password:
                valid, _ = hasher.verify_and_update(password, subject.hashed_password)
                if valid:
                    response = Redirect(path="/dashboard")
                    await login_user(request, response, subject)
                    flash(request, "Login successful!", "success")
                    return response
        except DoesNotExist:
            pass

    flash(request, "Invalid email or password", "error")
    return render_template(
        request, "login.html", {"current_user": None, "email": email}
    )


@get("/magic-login", sync_to_thread=False)
def magic_login_page(request: Request) -> Response:
    """Magic link request page."""
    if is_authenticated(request):
        return Redirect(path="/dashboard")
    return render_template(request, "magic_login.html", {"current_user": None})


@post("/magic-login")
async def magic_login_submit(request: Request) -> Response:
    """Handle magic link request."""
    if is_authenticated(request):
        return Redirect(path="/dashboard")

    form = await request.form()
    email = str(form.get("email", "")).lower()

    if not email or "@" not in email:
        flash(request, "Please enter a valid email address", "error")
        return render_template(request, "magic_login.html", {"current_user": None})

    # Look up subject by email
    async with session_factory() as db_session:
        repo = SubjectRepository(session=db_session)
        try:
            subject = await repo.get_one_by(email=email)
            # Set base URL dynamically
            base_url = str(request.base_url).rstrip("/")
            magic_link_factor.config = MagicLinkConfig(
                link_base_url=f"{base_url}/magic-login/verify",
                token_lifetime=magic_link_factor.config.token_lifetime,
                max_pending_per_subject=magic_link_factor.config.max_pending_per_subject,
                rate_limit_window=magic_link_factor.config.rate_limit_window,
                token_prefix=magic_link_factor.config.token_prefix,
            )
            await magic_link_factor.begin_authentication(subject.id)
        except DoesNotExist:
            pass  # Don't reveal whether email exists

    flash(
        request,
        "If an account exists with that email, a magic link has been sent. Check your console output.",
        "success",
    )
    return Redirect(path="/magic-login")


@get("/magic-login/verify")
async def magic_login_verify(request: Request) -> Response:
    """Verify magic link token and log in."""
    token = request.query_params.get("token", "")
    if not token:
        flash(request, "Invalid magic link", "error")
        return Redirect(path="/login")

    from neozen.core.crypto import get_token_hash

    token_hash = get_token_hash(token, SECRET_KEY)
    token_record = await magic_link_factor.token_repository.get_by_hash(token_hash)

    if not token_record:
        flash(request, "Invalid or expired magic link", "error")
        return Redirect(path="/login")

    valid = await magic_link_factor.complete_authentication(
        token_record.subject_id, response=token
    )

    if valid:
        async with session_factory() as db_session:
            repo = SubjectRepository(session=db_session)
            try:
                subject = await repo.get_one_by(id=token_record.subject_id)
                response = Redirect(path="/dashboard")
                await login_user(request, response, subject)
                flash(request, "Login successful via magic link!", "success")
                return response
            except DoesNotExist:
                pass

    flash(request, "Invalid or expired magic link", "error")
    return Redirect(path="/login")


@get("/api/test/last-magic-link", sync_to_thread=False)
def api_last_magic_link(request: Request) -> Response:
    """Test endpoint: return the last magic link URL sent (dev only)."""
    if email_sender.sent_messages:
        last = email_sender.sent_messages[-1]
        for line in last.body_text.splitlines():
            if "magic-login/verify?token=" in line:
                return json_response({"url": line.strip()})
    return json_response({"url": None})


@get("/register", sync_to_thread=False)
def register_page(request: Request) -> Response:
    """Registration page (GET)."""
    if is_authenticated(request):
        return Redirect(path="/dashboard")
    return render_template(request, "register.html", {"current_user": None})


@post("/register")
async def register_submit(request: Request) -> Response:
    """Registration form submission (POST)."""
    if is_authenticated(request):
        return Redirect(path="/dashboard")

    form = await request.form()
    email = str(form.get("email", "")).lower()
    password = str(form.get("password", ""))
    password_confirm = str(form.get("password_confirm", ""))

    # Validation
    if not email or not password:
        flash(request, "Email and password are required", "error")
    elif "@" not in email:
        flash(request, "Invalid email format", "error")
    elif password != password_confirm:
        flash(request, "Passwords do not match", "error")
    elif len(password) < 8:
        flash(request, "Password must be at least 8 characters", "error")
    else:
        async with session_factory() as db_session:
            repo = SubjectRepository(session=db_session)

            # Check if email exists
            if await repo.exists(email=email):
                flash(request, "Email already registered", "error")
            else:
                # Create subject
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

                # First user gets admin role
                if is_first_user:
                    # Assign admin and user roles
                    await role_service.assign_role(subject_id, "admin")
                    await role_service.assign_role(subject_id, "user")
                    flash(
                        request,
                        "Registration successful! You are the first user and have been granted admin privileges.",
                        "success",
                    )
                else:
                    # Assign user role
                    await role_service.assign_role(subject_id, "user")
                    flash(request, "Registration successful! Please log in.", "success")

                return Redirect(path="/login")

    return render_template(
        request, "register.html", {"current_user": None, "email": email}
    )


@get("/dashboard", guards=[login_required()])
async def dashboard(request: Request) -> Response:
    """Protected dashboard."""
    user = await get_current_user(request)
    roles = await get_subject_roles(session_factory, user.id)
    return render_template(
        request, "dashboard.html", {"current_user": user, "roles": roles}
    )


@post("/logout")
async def logout_submit(request: Request) -> Response:
    """Logout form submission (POST)."""
    response = Redirect(path="/")
    await logout_user(request, response)
    flash(request, "You have been logged out.", "info")
    return response


# =============================================================================
# Admin Routes
# =============================================================================


@get("/admin", guards=[login_required(), admin_required()])
async def admin_dashboard(request: Request) -> Response:
    """Admin dashboard."""
    user = await get_current_user(request)
    roles = await get_subject_roles(session_factory, user.id)
    async with session_factory() as db_session:
        service = AdminService(db_session)
        stats = await service.get_dashboard_stats()
    return render_template(
        request,
        "admin/dashboard.html",
        {"current_user": user, "stats": stats, "roles": roles},
    )


@get("/admin/users", guards=[login_required(), admin_required()])
async def admin_users(request: Request) -> Response:
    """List all users."""
    user = await get_current_user(request)
    roles = await get_subject_roles(session_factory, user.id)
    async with session_factory() as db_session:
        service = AdminService(db_session)
        users = await service.list_subjects()
    return render_template(
        request,
        "admin/users.html",
        {"current_user": user, "users": users, "roles": roles},
    )


@get("/admin/users/{user_id:str}", guards=[login_required(), admin_required()])
async def admin_user_detail(request: Request, user_id: str) -> Response:
    """View user details."""
    current = await get_current_user(request)
    roles = await get_subject_roles(session_factory, current.id)
    async with session_factory() as db_session:
        service = AdminService(db_session)
        try:
            target_user = await service.get_subject(user_id)
            user_roles = await service.get_subject_roles(user_id)
        except Exception:
            flash(request, f"User not found: {user_id}", "error")
            return Redirect(path="/admin/users")
    return render_template(
        request,
        "admin/user_detail.html",
        {
            "current_user": current,
            "target_user": target_user,
            "user_roles": user_roles,
            "roles": roles,
        },
    )


@post(
    "/admin/users/{user_id:str}/toggle-role/{role:str}",
    guards=[login_required(), admin_required()],
)
async def admin_toggle_role(request: Request, user_id: str, role: str) -> Response:
    """Toggle a role for a user."""
    current = await get_current_user(request)

    # Don't allow removing admin from yourself
    if role == "admin" and user_id == current.id:
        flash(request, "Cannot remove admin role from yourself", "error")
        return Redirect(path=f"/admin/users/{user_id}")

    user_roles = await get_subject_roles(session_factory, user_id)
    if role in user_roles:
        await role_service.revoke_role(user_id, role)
        flash(request, f"Removed '{role}' role from user", "success")
    else:
        await role_service.assign_role(user_id, role)
        flash(request, f"Added '{role}' role to user", "success")

    return Redirect(path=f"/admin/users/{user_id}")


@get("/admin/sessions", guards=[login_required(), admin_required()])
async def admin_sessions(request: Request) -> Response:
    """List all sessions."""
    user = await get_current_user(request)
    roles = await get_subject_roles(session_factory, user.id)
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

    return render_template(
        request,
        "admin/sessions.html",
        {"current_user": user, "sessions": sessions_with_subjects, "roles": roles},
    )


@post(
    "/admin/sessions/{token_hash:str}/revoke",
    guards=[login_required(), admin_required()],
)
async def admin_revoke_session(request: Request, token_hash: str) -> Response:
    """Revoke a session."""
    try:
        async with session_factory() as db_session:
            service = AdminService(db_session)
            await service.revoke_session(token_hash)
            await db_session.commit()
        flash(request, "Session revoked", "success")
    except Exception as e:
        flash(request, f"Error revoking session: {e}", "error")
    return Redirect(path="/admin/sessions")


# =============================================================================
# JSON API
# =============================================================================


@post("/api/register")
async def api_register(request: Request) -> Response:
    """Register (JSON API)."""
    body = await request.json()
    email = body.get("email", "").lower()
    password = body.get("password", "")

    if not email or not password:
        return json_error("email and password required")
    if "@" not in email:
        return json_error("Invalid email")

    async with session_factory() as db_session:
        repo = SubjectRepository(session=db_session)

        if await repo.exists(email=email):
            return json_error("Email already registered", status_code=409)

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

        # Assign roles
        if is_first_user:
            await role_service.assign_role(subject_id, "admin")
            await role_service.assign_role(subject_id, "user")
            roles = ["admin", "user"]
        else:
            await role_service.assign_role(subject_id, "user")
            roles = ["user"]

        return json_response(
            {"message": "Registered", "user_id": subject_id, "roles": roles},
            status_code=201,
        )


@post("/api/login")
async def api_login(request: Request) -> Response:
    """Login (JSON API)."""
    body = await request.json()
    email = body.get("email", "").lower()
    password = body.get("password", "")

    async with session_factory() as db_session:
        repo = SubjectRepository(session=db_session)
        try:
            subject = await repo.get_one_by(email=email)
            if subject.hashed_password:
                valid, _ = hasher.verify_and_update(password, subject.hashed_password)
                if valid:
                    response = json_response({
                        "message": "Logged in",
                        "user_id": subject.id,
                    })
                    await login_user(request, response, subject)
                    return response
        except DoesNotExist:
            pass

    return json_error("Invalid credentials", status_code=401)


@post("/api/logout", guards=[login_required(redirect=False)])
async def api_logout(request: Request) -> Response:
    """Logout (JSON API)."""
    response = json_response({"message": "Logged out"})
    await logout_user(request, response)
    return response


@get("/api/me", guards=[login_required(redirect=False)])
async def api_me(request: Request) -> Response:
    """Current user (JSON API)."""
    user = await get_current_user(request)
    roles = await get_subject_roles(session_factory, user.id)
    return json_response({"id": user.id, "email": user.email, "roles": roles})


# =============================================================================
# Application Factory
# =============================================================================


async def on_startup() -> None:
    """Initialize database on startup."""
    await init_database(engine)

    # Ensure built-in roles exist
    async with session_factory() as db_session:
        service = AdminService(db_session)
        await service.ensure_builtin_roles()
        await db_session.commit()


def create_app() -> Litestar:
    """Create the demo Litestar application."""
    session_config = ServerSideSessionConfig(
        key="neozen_flash_session",
        max_age=86400 * 7,
    )

    return Litestar(
        route_handlers=[
            # HTML routes
            index,
            login_page,
            login_submit,
            magic_login_page,
            magic_login_submit,
            magic_login_verify,
            register_page,
            register_submit,
            dashboard,
            logout_submit,
            # Admin routes
            admin_dashboard,
            admin_users,
            admin_user_detail,
            admin_toggle_role,
            admin_sessions,
            admin_revoke_session,
            # JSON API routes
            api_last_magic_link,
            api_register,
            api_login,
            api_logout,
            api_me,
        ],
        plugins=[NeoZenPlugin(neozen_config)],
        middleware=[session_config.middleware],
        stores={"sessions": MemoryStore()},
        on_startup=[on_startup],
        state=State({"session_factory": session_factory}),
    )


app = create_app()
