"""NeoZen Litestar Demo Application.

A demo application using the NeoZen Litestar extension for authentication.
Comparable in simplicity to Flask-Login demos.

Run with: uvicorn demos.litestar.app:app --reload --port 8003
"""

from __future__ import annotations

import secrets
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from litestar import Litestar, Request, Response, get, post
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.response import Redirect
from litestar.stores.memory import MemoryStore
from pwdlib import PasswordHash

from neozen.ext.litestar import (
    NeoZenConfig,
    NeoZenPlugin,
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

    def __init__(
        self,
        id: str,
        email: str,
        password_hash: str,
        roles: list[str] | None = None,
    ) -> None:
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.roles = roles or ["user"]
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

    def has_role(self, role: str) -> bool:
        return role in self.roles


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
# NeoZen Config Setup
# =============================================================================

session_service = InMemorySessionService()


async def load_subject(subject_id: str) -> User | None:
    """Load user by ID."""
    return User.get(subject_id)


neozen_config = NeoZenConfig(
    session_service=session_service,
    subject_loader=load_subject,
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


# =============================================================================
# Routes
# =============================================================================


@get("/")
async def index(request: Request) -> Response:
    """Home page."""
    user = await get_current_user(request)
    return render_template(request, "index.html", {"current_user": user})


@get("/login")
async def login_page(request: Request) -> Response:
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
    email = str(form.get("email", ""))
    password = str(form.get("password", ""))

    user = User.get_by_email(email)
    if user and user.check_password(password):
        response = Redirect(path="/dashboard")
        await login_user(request, response, user)
        flash(request, "Login successful!", "success")
        return response

    flash(request, "Invalid email or password", "error")
    return render_template(
        request, "login.html", {"current_user": None, "email": email}
    )


@get("/register")
async def register_page(request: Request) -> Response:
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
    elif User.get_by_email(email):
        flash(request, "Email already registered", "error")
    else:
        # Create user - first user gets admin role
        user_id = f"user_{secrets.token_hex(8)}"
        is_first_user = len(users_db) == 0
        roles = ["admin", "user"] if is_first_user else ["user"]
        users_db[user_id] = {
            "id": user_id,
            "email": email,
            "password_hash": hasher.hash(password),
            "roles": roles,
        }
        if is_first_user:
            flash(
                request,
                "Registration successful! You are the first user and have been granted admin privileges.",
                "success",
            )
        else:
            flash(request, "Registration successful! Please log in.", "success")
        return Redirect(path="/login")

    return render_template(
        request, "register.html", {"current_user": None, "email": email}
    )


@get("/dashboard", guards=[login_required()])
async def dashboard(request: Request) -> Response:
    """Protected dashboard."""
    user = await get_current_user(request)
    return render_template(request, "dashboard.html", {"current_user": user})


@post("/logout")
async def logout_submit(request: Request) -> Response:
    """Logout form submission (POST)."""
    response = Redirect(path="/")
    await logout_user(request, response)
    flash(request, "You have been logged out.", "info")
    return response


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
    if User.get_by_email(email):
        return json_error("Email already registered", status_code=409)

    user_id = f"user_{secrets.token_hex(8)}"
    is_first_user = len(users_db) == 0
    roles = ["admin", "user"] if is_first_user else ["user"]
    users_db[user_id] = {
        "id": user_id,
        "email": email,
        "password_hash": hasher.hash(password),
        "roles": roles,
    }
    return json_response(
        {"message": "Registered", "user_id": user_id, "roles": roles}, status_code=201
    )


@post("/api/login")
async def api_login(request: Request) -> Response:
    """Login (JSON API)."""
    body = await request.json()
    email = body.get("email", "")
    password = body.get("password", "")

    user = User.get_by_email(email)
    if user and user.check_password(password):
        response = json_response({"message": "Logged in", "user_id": user.id})
        await login_user(request, response, user)
        return response
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
    return json_response({"id": user.id, "email": user.email})


# =============================================================================
# Application Factory
# =============================================================================


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
            register_page,
            register_submit,
            dashboard,
            logout_submit,
            # JSON API routes
            api_register,
            api_login,
            api_logout,
            api_me,
        ],
        plugins=[NeoZenPlugin(neozen_config)],
        middleware=[session_config.middleware],
        stores={"sessions": MemoryStore()},
    )


app = create_app()
