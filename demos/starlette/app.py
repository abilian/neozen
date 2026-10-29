"""NeoZen Starlette Demo Application.

A demo application using the NeoZen Starlette extension for authentication
with SQLAlchemy persistence.

Run with: uvicorn demos.starlette.app:app --reload --port 8001
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from pwdlib import PasswordHash

from demos.shared.database import create_database, init_database
from neozen.admin.app import create_admin_app
from neozen.admin.config import AdminConfig
from neozen.admin.services import AdminService
from neozen.core.factors.totp import (
    InvalidTOTPCodeError,
    TOTPAlreadyEnabledError,
    TOTPConfig,
    TOTPFactor,
    TOTPNotEnabledError,
)
from neozen.ext.starlette import (
    NeoZenBackend,
    NeoZenMiddleware,
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
from neozen.storage.sqlalchemy.repositories import SubjectRepository
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

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


# =============================================================================
# NeoZen Backend Setup
# =============================================================================

backend = NeoZenBackend(
    session_service=session_service,
    subject_loader=create_subject_loader(session_factory),
    cookie_secure=False,  # Allow HTTP for demo
)


# =============================================================================
# TOTP setup (mirrors the Litestar demo)
# =============================================================================


class TOTPSubjectRepoAdapter:
    """Satisfies TOTPFactor's subject_repository protocol.

    Each call opens a fresh session, refetches the subject by id, applies
    the update, commits, and propagates the new field values back onto
    the caller's local subject object.
    """

    def __init__(self, sf):
        self._sf = sf

    async def update_obj(self, obj, **data):
        async with self._sf() as s:
            repo = SubjectRepository(session=s)
            fresh = await repo.get_one_by(id=obj.id)
            updated = await repo.update_obj(fresh, **data)
            await s.commit()
            for key, value in data.items():
                setattr(obj, key, value)
            return updated


totp_factor: TOTPFactor = TOTPFactor(
    config=TOTPConfig(issuer="NeoZen Demo (Starlette)"),
    subject_repository=TOTPSubjectRepoAdapter(session_factory),
    backup_code_repository=None,
)

PENDING_TOTP_SUBJECT_KEY = "pending_totp_subject_id"


# =============================================================================
# Template Helpers
# =============================================================================


def render_template(
    template_name: str,
    request: Request,
    context: dict | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    """Render a Jinja2 template."""
    ctx = context or {}
    ctx["messages"] = request.session.pop("messages", [])
    ctx["request"] = request
    ctx["csrf_token"] = csrf_token(request)
    content = templates.get_template(template_name).render(**ctx)
    return HTMLResponse(content=content, status_code=status_code)


# =============================================================================
# CSRF Protection
# =============================================================================


def csrf_token(request: Request) -> str:
    """The session's CSRF token, which every form posts back."""
    return request.session.setdefault("csrf_token", secrets.token_urlsafe(32))


class CSRFMiddleware:
    """Refuse a form POST that doesn't carry the session's CSRF token.

    Starlette has no CSRF support of its own. The JSON API, called by
    scripts and tests, and the admin console, which checks its own token,
    are left out. Must run inside `SessionMiddleware`.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] in {"GET", "HEAD", "OPTIONS"}
            or scope["path"].startswith(("/api/", "/admin"))
        ):
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        body = await request.body()
        sent = (await request.form()).get("csrf_token")
        expected = request.session.get("csrf_token")
        if not (
            isinstance(sent, str)
            and expected
            and secrets.compare_digest(sent, expected)
        ):
            response = PlainTextResponse("CSRF token missing or invalid", 403)
            await response(scope, receive, send)
            return

        # The body was read here: hand it to the app again.
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)


async def _verify_credentials(session: Any, email: str, password: str) -> Any:
    """Look up subject by email + verify password.

    Returns the subject on a match, None on no-such-email or password
    mismatch. Shared by the form-based login and the JSON API login.
    """
    repo = SubjectRepository(session=session)
    try:
        subject = await repo.get_one_by(email=email)
    except DoesNotExist:
        return None
    if not subject.hashed_password:
        return None
    valid, _ = hasher.verify_and_update(password, subject.hashed_password)
    return subject if valid else None


def flash(request: Request, message: str, category: str = "info") -> None:
    """Add a flash message."""
    if "messages" not in request.session:
        request.session["messages"] = []
    request.session["messages"].append((category, message))


# =============================================================================
# Routes
# =============================================================================


async def index(request: Request) -> Response:
    """Home page."""
    user = await get_current_user(request)
    roles = []
    if user:
        roles = await get_subject_roles(session_factory, user.id)
    return render_template(
        "index.html", request, {"current_user": user, "roles": roles}
    )


async def login_page(request: Request) -> Response:
    """Login page (GET)."""
    if is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return render_template("login.html", request, {"current_user": None})


async def login_submit(request: Request) -> Response:
    """Login form submission (POST).

    Two-step when TOTP is enabled: password verification here, then
    TOTP code at /totp/verify. The pending subject id is stashed in
    the session under PENDING_TOTP_SUBJECT_KEY between the two steps.
    """
    if is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=303)

    form = await request.form()
    email = str(form.get("email", "")).lower()
    password = str(form.get("password", ""))

    async with session_factory() as db_session:
        subject = await _verify_credentials(db_session, email, password)

    if subject is None:
        flash(request, "Invalid email or password", "error")
        return render_template(
            "login.html", request, {"current_user": None, "email": email}
        )

    if subject.totp_enabled:
        request.session[PENDING_TOTP_SUBJECT_KEY] = subject.id
        return RedirectResponse(url="/totp/verify", status_code=303)
    response = RedirectResponse(url="/dashboard", status_code=303)
    await login_user(request, response, subject)
    flash(request, "Login successful!", "success")
    return response


async def register_page(request: Request) -> Response:
    """Registration page (GET)."""
    if is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return render_template("register.html", request, {"current_user": None})


async def register_submit(request: Request) -> Response:
    """Registration form submission (POST)."""
    if is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=303)

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
                    await role_service.assign_role(subject_id, "admin")
                    await role_service.assign_role(subject_id, "user")
                    flash(
                        request,
                        "Registration successful! You are the first user and have been granted admin privileges.",
                        "success",
                    )
                else:
                    await role_service.assign_role(subject_id, "user")
                    flash(request, "Registration successful! Please log in.", "success")

                return RedirectResponse(url="/login", status_code=303)

    return render_template(
        "register.html", request, {"current_user": None, "email": email}
    )


@login_required(redirect_url="/login")
async def dashboard(request: Request) -> Response:
    """Protected dashboard."""
    user = await get_current_user(request)
    roles = await get_subject_roles(session_factory, user.id)
    return render_template(
        "dashboard.html", request, {"current_user": user, "roles": roles}
    )


async def logout_submit(request: Request) -> Response:
    """Logout form submission (POST)."""
    response = RedirectResponse(url="/", status_code=303)
    await logout_user(request, response)
    flash(request, "You have been logged out.", "info")
    return response


# =============================================================================
# TOTP routes (mirror the Litestar demo)
# =============================================================================


@login_required(redirect_url="/login")
async def totp_enroll_page(request: Request) -> Response:
    """Show TOTP enrollment page (QR code + verify form)."""
    user = await get_current_user(request)
    if user.totp_enabled:
        flash(request, "TOTP is already enabled for this account.", "info")
        return RedirectResponse(url="/dashboard", status_code=303)
    try:
        result = await totp_factor.begin_enrollment(user, account_name=user.email)
    except TOTPAlreadyEnabledError:
        flash(request, "TOTP is already enabled for this account.", "info")
        return RedirectResponse(url="/dashboard", status_code=303)
    return render_template(
        "totp_enroll.html",
        request,
        {
            "current_user": user,
            "secret": result.secret,
            "provisioning_uri": result.provisioning_uri,
            "qr_code_data_uri": result.qr_code_data_uri,
        },
    )


@login_required(redirect_url="/login")
async def totp_enroll_confirm(request: Request) -> Response:
    """Confirm TOTP enrollment by verifying the first code."""
    user = await get_current_user(request)
    form = await request.form()
    code = str(form.get("code", "")).strip()
    if not code:
        flash(request, "Please enter the 6-digit code.", "error")
        return RedirectResponse(url="/totp/enroll", status_code=303)
    try:
        await totp_factor.confirm_enrollment(user, code)
    except InvalidTOTPCodeError:
        flash(request, "Invalid TOTP code. Try again.", "error")
        return RedirectResponse(url="/totp/enroll", status_code=303)
    except TOTPAlreadyEnabledError:
        flash(request, "TOTP is already enabled.", "info")
        return RedirectResponse(url="/dashboard", status_code=303)
    flash(request, "Two-factor authentication enabled.", "success")
    return RedirectResponse(url="/dashboard", status_code=303)


async def totp_verify_page(request: Request) -> Response:
    """Second-factor verification page after a successful password step."""
    pending_id = request.session.get(PENDING_TOTP_SUBJECT_KEY)
    if not pending_id:
        flash(request, "No pending login. Sign in again.", "error")
        return RedirectResponse(url="/login", status_code=303)
    return render_template("totp_verify.html", request, {"current_user": None})


async def totp_verify_submit(request: Request) -> Response:
    """Verify the TOTP code and complete the login."""
    pending_id = request.session.get(PENDING_TOTP_SUBJECT_KEY)
    if not pending_id:
        flash(request, "No pending login. Sign in again.", "error")
        return RedirectResponse(url="/login", status_code=303)

    form = await request.form()
    code = str(form.get("code", "")).strip()
    if not code:
        flash(request, "Please enter your 6-digit code.", "error")
        return RedirectResponse(url="/totp/verify", status_code=303)

    async with session_factory() as db_session:
        repo = SubjectRepository(session=db_session)
        try:
            subject = await repo.get_one_by(id=pending_id)
        except DoesNotExist:
            request.session.pop(PENDING_TOTP_SUBJECT_KEY, None)
            flash(request, "Invalid login state. Sign in again.", "error")
            return RedirectResponse(url="/login", status_code=303)

    try:
        await totp_factor.authenticate(subject, code)
    except (InvalidTOTPCodeError, TOTPNotEnabledError):
        flash(request, "Invalid TOTP code. Try again.", "error")
        return RedirectResponse(url="/totp/verify", status_code=303)

    request.session.pop(PENDING_TOTP_SUBJECT_KEY, None)
    response = RedirectResponse(url="/dashboard", status_code=303)
    await login_user(request, response, subject)
    flash(request, "Two-factor authentication successful.", "success")
    return response


@login_required(redirect_url="/login")
async def totp_disable(request: Request) -> Response:
    """Disable TOTP for the current user."""
    user = await get_current_user(request)
    if not user.totp_enabled:
        flash(request, "TOTP is not enabled.", "info")
        return RedirectResponse(url="/dashboard", status_code=303)
    async with session_factory() as db_session:
        repo = SubjectRepository(session=db_session)
        fresh = await repo.get_one_by(id=user.id)
        await repo.update_obj(
            fresh,
            totp_enabled=False,
            totp_secret=None,
            totp_confirmed_at=None,
        )
        await db_session.commit()
    flash(request, "Two-factor authentication disabled.", "success")
    return RedirectResponse(url="/dashboard", status_code=303)


# =============================================================================
# JSON API
# =============================================================================


async def api_register(request: Request) -> Response:
    """Register (JSON API)."""
    body = await request.json()
    email = body.get("email", "").lower()
    password = body.get("password", "")

    if not email or not password:
        return JSONResponse({"error": "email and password required"}, status_code=400)
    if "@" not in email:
        return JSONResponse({"error": "Invalid email"}, status_code=400)

    async with session_factory() as db_session:
        repo = SubjectRepository(session=db_session)

        if await repo.exists(email=email):
            return JSONResponse({"error": "Email already registered"}, status_code=409)

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

        return JSONResponse(
            {"message": "Registered", "user_id": subject_id, "roles": roles},
            status_code=201,
        )


async def api_login(request: Request) -> Response:
    """Login (JSON API)."""
    body = await request.json()
    email = body.get("email", "").lower()
    password = body.get("password", "")

    async with session_factory() as db_session:
        subject = await _verify_credentials(db_session, email, password)

    if subject is None:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    response = JSONResponse({"message": "Logged in", "user_id": subject.id})
    await login_user(request, response, subject)
    return response


@login_required
async def api_logout(request: Request) -> Response:
    """Logout (JSON API)."""
    response = JSONResponse({"message": "Logged out"})
    await logout_user(request, response)
    return response


@login_required
async def api_me(request: Request) -> Response:
    """Current user (JSON API)."""
    user = await get_current_user(request)
    roles = await get_subject_roles(session_factory, user.id)
    return JSONResponse({"id": user.id, "email": user.email, "roles": roles})


# =============================================================================
# Application Factory
# =============================================================================


@asynccontextmanager
async def lifespan(app: Starlette) -> AsyncGenerator[None, None]:
    """Application lifespan context manager."""
    # Startup
    await init_database(engine)

    # Ensure built-in roles exist
    async with session_factory() as db_session:
        service = AdminService(db_session)
        await service.ensure_builtin_roles()
        await db_session.commit()

    yield
    # Shutdown (nothing to do)


def create_app() -> Starlette:
    """Create the demo Starlette application."""
    # Create admin app with same database URL
    admin_config = AdminConfig(
        db_url=f"sqlite+aiosqlite:///{DB_PATH}",
        secret_key=SECRET_KEY,
    )
    admin_app = create_admin_app(admin_config)

    routes = [
        # HTML routes
        Route("/", index, methods=["GET"]),
        Route("/login", login_page, methods=["GET"]),
        Route("/login", login_submit, methods=["POST"]),
        Route("/register", register_page, methods=["GET"]),
        Route("/register", register_submit, methods=["POST"]),
        Route("/dashboard", dashboard, methods=["GET"]),
        Route("/logout", logout_submit, methods=["POST"]),
        # TOTP routes
        Route("/totp/enroll", totp_enroll_page, methods=["GET"]),
        Route("/totp/enroll", totp_enroll_confirm, methods=["POST"]),
        Route("/totp/verify", totp_verify_page, methods=["GET"]),
        Route("/totp/verify", totp_verify_submit, methods=["POST"]),
        Route("/totp/disable", totp_disable, methods=["POST"]),
        # JSON API routes
        Route("/api/register", api_register, methods=["POST"]),
        Route("/api/login", api_login, methods=["POST"]),
        Route("/api/logout", api_logout, methods=["POST"]),
        Route("/api/me", api_me, methods=["GET"]),
        # Admin UI (mounted as sub-application)
        Mount("/admin", app=admin_app),
    ]

    middleware = [
        Middleware(SessionMiddleware, secret_key=SECRET_KEY),
        Middleware(CSRFMiddleware),
        Middleware(NeoZenMiddleware, backend=backend),
    ]

    return Starlette(routes=routes, middleware=middleware, lifespan=lifespan)


app = create_app()
