"""NeoZen Starlette Demo Application.

A demo application using the NeoZen Starlette extension for authentication.
Comparable in simplicity to Flask-Login demos.

Run with: uvicorn demos.starlette.app:app --reload --port 8001
"""

from __future__ import annotations

import secrets
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from pwdlib import PasswordHash
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from neozen.ext.starlette import (
    NeoZenBackend,
    NeoZenMiddleware,
    get_current_user,
    is_authenticated,
    login_required,
    login_user,
    logout_user,
)

# =============================================================================
# Application Setup
# =============================================================================

SECRET_KEY = "demo-secret-key-change-in-production"
TEMPLATES_DIR = Path(__file__).parent / "templates"

templates = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=True)
hasher = PasswordHash.recommended()

# =============================================================================
# Simple In-Memory User Store
# =============================================================================

users_db: dict[str, dict] = {}
sessions_db: dict[str, dict] = {}


class User:
    """Simple user model."""

    def __init__(self, id: str, email: str, password_hash: str) -> None:
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.is_active = True
        self.is_verified = False

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


# =============================================================================
# In-Memory Session Service (implements SessionService protocol)
# =============================================================================


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


# =============================================================================
# NeoZen Backend Setup
# =============================================================================

session_service = InMemorySessionService()


async def load_subject(subject_id: str) -> User | None:
    """Load user by ID."""
    return User.get(subject_id)


backend = NeoZenBackend(
    session_service=session_service,
    subject_loader=load_subject,
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
    return render_template("index.html", request, {"current_user": user})


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
    email = str(form.get("email", ""))
    password = str(form.get("password", ""))

    user = User.get_by_email(email)
    if user and user.check_password(password):
        response = RedirectResponse(url="/dashboard", status_code=303)
        await login_user(request, response, user)
        flash(request, "Login successful!", "success")
        return response

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
    elif User.get_by_email(email):
        flash(request, "Email already registered", "error")
    else:
        # Create user
        user_id = f"user_{secrets.token_hex(8)}"
        users_db[user_id] = {
            "id": user_id,
            "email": email,
            "password_hash": hasher.hash(password),
        }
        flash(request, "Registration successful! Please log in.", "success")
        return RedirectResponse(url="/login", status_code=303)

    return render_template(
        "register.html", request, {"current_user": None, "email": email}
    )


@login_required(redirect_url="/login")
async def dashboard(request: Request) -> Response:
    """Protected dashboard."""
    user = await get_current_user(request)
    return render_template("dashboard.html", request, {"current_user": user})


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
    if User.get_by_email(email):
        return JSONResponse({"error": "Email already registered"}, status_code=409)

    user_id = f"user_{secrets.token_hex(8)}"
    users_db[user_id] = {
        "id": user_id,
        "email": email,
        "password_hash": hasher.hash(password),
    }
    return JSONResponse({"message": "Registered", "user_id": user_id}, status_code=201)


async def api_login(request: Request) -> Response:
    """Login (JSON API)."""
    body = await request.json()
    email = body.get("email", "")
    password = body.get("password", "")

    user = User.get_by_email(email)
    if user and user.check_password(password):
        response = JSONResponse({"message": "Logged in", "user_id": user.id})
        await login_user(request, response, user)
        return response
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
    return JSONResponse({"id": user.id, "email": user.email})


# =============================================================================
# Application Factory
# =============================================================================


def create_app() -> Starlette:
    """Create the demo Starlette application."""
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
    ]

    middleware = [
        Middleware(SessionMiddleware, secret_key=SECRET_KEY),
        Middleware(NeoZenMiddleware, backend=backend),
    ]

    return Starlette(routes=routes, middleware=middleware)


app = create_app()
