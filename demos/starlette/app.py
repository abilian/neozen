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

from jinja2 import Environment, FileSystemLoader
from pwdlib import PasswordHash

from demos.shared.database import create_database, init_database
from neozen.admin.app import create_admin_app
from neozen.admin.config import AdminConfig
from neozen.admin.services import AdminService
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
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route

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
    content = templates.get_template(template_name).render(**ctx)
    return HTMLResponse(content=content, status_code=status_code)


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
    """Login form submission (POST)."""
    if is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=303)

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
                    response = RedirectResponse(url="/dashboard", status_code=303)
                    await login_user(request, response, subject)
                    flash(request, "Login successful!", "success")
                    return response
        except DoesNotExist:
            pass

    flash(request, "Invalid email or password", "error")
    return render_template(
        "login.html", request, {"current_user": None, "email": email}
    )


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
        repo = SubjectRepository(session=db_session)
        try:
            subject = await repo.get_one_by(email=email)
            if subject.hashed_password:
                valid, _ = hasher.verify_and_update(password, subject.hashed_password)
                if valid:
                    response = JSONResponse({
                        "message": "Logged in",
                        "user_id": subject.id,
                    })
                    await login_user(request, response, subject)
                    return response
        except DoesNotExist:
            pass

    return JSONResponse({"error": "Invalid credentials"}, status_code=401)


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
        Middleware(NeoZenMiddleware, backend=backend),
    ]

    return Starlette(routes=routes, middleware=middleware, lifespan=lifespan)


app = create_app()
