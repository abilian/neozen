"""NeoZen Starlette Demo Application.

A demo application that validates NeoZen authentication components with a web UI.
Provides both HTML pages and JSON API endpoints.

Run with: neozen serve
Or: uvicorn demos.starlette.app:app --reload
"""

from __future__ import annotations

import json
import secrets
import typing
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlencode

from jinja2 import Environment, FileSystemLoader
from pwdlib import PasswordHash
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from neozen.cli.database import get_database_url, init_database
from neozen.core.email import ConsoleEmailSender, EmailMessage
from neozen.core.exceptions import InvalidRequestError
from neozen.core.factors.password import InvalidCredentialsError, PasswordFactor
from neozen.core.identifiers.base import (
    IdentifierProtocol,
    IdentifierVerificationError,
    InvalidIdentifierFormat,
)
from neozen.core.session import SessionService
from neozen.storage import DoesNotExist
from neozen.storage.sqlalchemy import (
    EmailVerificationToken,
    EmailVerificationTokenRepository,
    Session,
    SessionRepository,
    Subject,
    SubjectRepository,
)
from neozen.core.verification.email import EmailVerificationService

# Configuration
SECRET_KEY = "demo-secret-key-change-in-production"
SESSION_COOKIE_NAME = "neozen_session"

# Template directory
TEMPLATES_DIR = Path(__file__).parent / "templates"


# =============================================================================
# Jinja2 Templates
# =============================================================================


def get_templates() -> Environment:
    """Create Jinja2 environment."""
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )


templates = get_templates()


def render_template(
    template_name: str,
    request: Request,
    context: dict[str, typing.Any] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    """Render a Jinja2 template with context."""
    ctx = context or {}
    # Add flash messages from session
    session_messages = request.session.pop("messages", [])
    ctx["messages"] = session_messages
    ctx["current_user"] = ctx.get("current_user")
    ctx["request"] = request

    template = templates.get_template(template_name)
    content = template.render(**ctx)
    return HTMLResponse(content=content, status_code=status_code)


def flash(request: Request, message: str, category: str = "info") -> None:
    """Add a flash message to the session."""
    if "messages" not in request.session:
        request.session["messages"] = []
    request.session["messages"].append((category, message))


# =============================================================================
# Email Identifier for SQLAlchemy Subject
# =============================================================================


class DemoEmailIdentifier(IdentifierProtocol[Subject]):
    """Email identifier for demo using SQLAlchemy storage."""

    def __init__(self, storage: SubjectRepository) -> None:
        self.storage = storage

    async def get_by_identifier(self, identifier: str) -> Subject:
        return await self.storage.get_one_by(email=identifier.lower())

    async def parse_identifier(self, identifier: typing.Any) -> str:
        if not isinstance(identifier, str):
            raise InvalidIdentifierFormat
        return identifier

    async def verify_identifier(self, identifier: str) -> str:
        if "@" not in identifier:
            raise IdentifierVerificationError("Invalid email format")
        return identifier.lower()


# =============================================================================
# Application State
# =============================================================================


class AppState:
    """Application state containing database engine and services."""

    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine
        self.session_factory = async_sessionmaker(engine, expire_on_commit=False)
        self.hasher = PasswordHash.recommended()
        self.email_sender = ConsoleEmailSender()

    def get_subject_repository(self, session: AsyncSession) -> SubjectRepository:
        return SubjectRepository(session=session)

    def get_session_repository(self, session: AsyncSession) -> SessionRepository:
        return SessionRepository(session=session)

    def get_verification_repository(
        self, session: AsyncSession
    ) -> EmailVerificationTokenRepository:
        return EmailVerificationTokenRepository(session=session)

    def get_password_factor(self, session: AsyncSession) -> PasswordFactor[Subject]:
        repository = self.get_subject_repository(session)
        identifier = DemoEmailIdentifier(repository)
        return PasswordFactor(
            identifier=identifier,
            subject_storage=repository,
            hasher=self.hasher,
        )

    def get_session_service(self, session: AsyncSession) -> SessionService[Session]:
        return SessionService(
            storage=self.get_session_repository(session),
            hash_key=SECRET_KEY,
        )

    def get_verification_service(
        self, session: AsyncSession
    ) -> EmailVerificationService[EmailVerificationToken]:
        return EmailVerificationService(
            storage=self.get_verification_repository(session),
            hash_key=SECRET_KEY,
        )


@asynccontextmanager
async def lifespan(app: Starlette):
    """Application lifespan - initialize database on startup."""
    db_url = get_database_url()
    engine = await init_database(db_url)
    app.state.neozen = AppState(engine)
    yield
    await engine.dispose()


# =============================================================================
# Helper Functions
# =============================================================================


def get_state(request: Request) -> AppState:
    """Get application state from request."""
    return request.app.state.neozen


async def get_current_subject(
    request: Request, session: AsyncSession
) -> Subject | None:
    """Get current subject from session cookie."""
    state = get_state(request)
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None

    try:
        session_service = state.get_session_service(session)
        auth_session = await session_service.validate_session(token)
        repository = state.get_subject_repository(session)
        return await repository.get_one_by(id=auth_session.subject_id)
    except Exception:
        return None


def json_error(message: str, status_code: int = 400) -> JSONResponse:
    """Return JSON error response."""
    return JSONResponse({"error": message}, status_code=status_code)


# =============================================================================
# HTML Routes (Web UI)
# =============================================================================


async def index(request: Request) -> Response:
    """Home page."""
    state = get_state(request)
    async with state.session_factory() as session:
        current_user = await get_current_subject(request, session)
        return render_template("index.html", request, {"current_user": current_user})


async def login_page(request: Request) -> Response:
    """Login page (GET)."""
    state = get_state(request)
    async with state.session_factory() as session:
        current_user = await get_current_subject(request, session)
        if current_user:
            return RedirectResponse(url="/dashboard", status_code=303)
        return render_template("login.html", request, {"current_user": None})


async def login_submit(request: Request) -> Response:
    """Login form submission (POST)."""
    state = get_state(request)
    form = await request.form()
    email = form.get("email", "")
    password = form.get("password", "")

    if not email or not password:
        flash(request, "Email and password are required", "error")
        return render_template(
            "login.html", request, {"current_user": None, "email": email}
        )

    async with state.session_factory() as session:
        password_factor = state.get_password_factor(session)

        try:
            subject = await password_factor.authenticate(
                {"identifier": email, "password": password}
            )
        except (InvalidCredentialsError, InvalidRequestError):
            flash(request, "Invalid email or password", "error")
            return render_template(
                "login.html", request, {"current_user": None, "email": email}
            )

        # Create session
        ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        session_service = state.get_session_service(session)
        session_token = await session_service.create_session(
            subject_id=subject.id,
            ip_address=ip,
            user_agent=user_agent,
        )

        await session.commit()

        flash(request, "Login successful!", "success")
        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie(
            SESSION_COOKIE_NAME,
            session_token,
            httponly=True,
            samesite="lax",
            max_age=86400 * 7,
        )
        return response


async def register_page(request: Request) -> Response:
    """Registration page (GET)."""
    state = get_state(request)
    async with state.session_factory() as session:
        current_user = await get_current_subject(request, session)
        if current_user:
            return RedirectResponse(url="/dashboard", status_code=303)
        return render_template("register.html", request, {"current_user": None})


async def register_submit(request: Request) -> Response:
    """Registration form submission (POST)."""
    state = get_state(request)
    form = await request.form()
    email = form.get("email", "")
    password = form.get("password", "")
    password_confirm = form.get("password_confirm", "")

    # Validation
    if not email or not password:
        flash(request, "Email and password are required", "error")
        return render_template(
            "register.html", request, {"current_user": None, "email": email}
        )

    if password != password_confirm:
        flash(request, "Passwords do not match", "error")
        return render_template(
            "register.html", request, {"current_user": None, "email": email}
        )

    if len(password) < 8:
        flash(request, "Password must be at least 8 characters", "error")
        return render_template(
            "register.html", request, {"current_user": None, "email": email}
        )

    async with state.session_factory() as session:
        storage = state.get_subject_repository(session)
        identifier = DemoEmailIdentifier(storage)

        # Verify email format
        try:
            email = await identifier.verify_identifier(email)
        except IdentifierVerificationError as e:
            flash(request, str(e), "error")
            return render_template(
                "register.html", request, {"current_user": None, "email": email}
            )

        # Check if email already exists
        try:
            await storage.get_one_by(email=email)
            flash(request, "Email is already registered", "error")
            return render_template(
                "register.html", request, {"current_user": None, "email": email}
            )
        except DoesNotExist:
            pass

        # Create subject
        hashed_password = state.hasher.hash(password)
        subject_id = f"subj_{secrets.token_hex(12)}"

        subject = await storage.create(
            id=subject_id,
            email=email,
            username=None,
            hashed_password=hashed_password,
            is_active=True,
            is_verified=False,
        )

        # Create verification token and send email
        verification_service = state.get_verification_service(session)
        token = await verification_service.create_token(
            email=email,
            subject_id=subject.id,
            skip_cooldown=True,
        )

        # Send verification email (prints to console in demo)
        await state.email_sender.send(
            EmailMessage(
                to=email,
                subject="Verify your email",
                body_text=f"Click here to verify: http://localhost:8000/verify?token={token}",
            )
        )

        await session.commit()

        flash(
            request,
            "Registration successful! Check the console for verification email.",
            "success",
        )
        return RedirectResponse(url="/login", status_code=303)


async def dashboard(request: Request) -> Response:
    """Dashboard page (protected)."""
    state = get_state(request)
    async with state.session_factory() as session:
        current_user = await get_current_subject(request, session)
        if not current_user:
            flash(request, "Please log in to access the dashboard", "error")
            return RedirectResponse(url="/login", status_code=303)
        return render_template(
            "dashboard.html", request, {"current_user": current_user}
        )


async def logout_submit(request: Request) -> Response:
    """Logout form submission (POST)."""
    state = get_state(request)
    token = request.cookies.get(SESSION_COOKIE_NAME)

    if token:
        async with state.session_factory() as session:
            try:
                session_service = state.get_session_service(session)
                await session_service.revoke_session_by_token(token)
                await session.commit()
            except Exception:
                pass

    flash(request, "You have been logged out", "info")
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


async def verify_email(request: Request) -> Response:
    """Verify email with token."""
    state = get_state(request)
    token = request.query_params.get("token")

    if not token:
        flash(request, "Verification token is required", "error")
        return RedirectResponse(url="/", status_code=303)

    async with state.session_factory() as session:
        try:
            verification_service = state.get_verification_service(session)
            verification = await verification_service.verify_token(token)
            await session.commit()
            flash(
                request, f"Email {verification.email} verified successfully!", "success"
            )
        except Exception as e:
            flash(request, f"Verification failed: {e}", "error")

    return RedirectResponse(url="/login", status_code=303)


# =============================================================================
# JSON API Routes
# =============================================================================


async def api_register(request: Request) -> Response:
    """Register a new user (JSON API)."""
    state = get_state(request)

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return json_error("Invalid JSON body")

    email = body.get("email")
    password = body.get("password")

    if not email or not password:
        return json_error("email and password are required")

    async with state.session_factory() as session:
        storage = state.get_subject_repository(session)
        identifier = DemoEmailIdentifier(storage)

        # Verify email format
        try:
            email = await identifier.verify_identifier(email)
        except IdentifierVerificationError as e:
            return json_error(str(e))

        # Check if email already exists
        try:
            await storage.get_one_by(email=email)
            return json_error("Email already registered", status_code=409)
        except DoesNotExist:
            pass

        # Create subject
        hashed_password = state.hasher.hash(password)
        subject_id = f"subj_{secrets.token_hex(12)}"

        subject = await storage.create(
            id=subject_id,
            email=email,
            username=None,
            hashed_password=hashed_password,
            is_active=True,
            is_verified=False,
        )

        # Create verification token and send email
        verification_service = state.get_verification_service(session)
        token = await verification_service.create_token(
            email=email,
            subject_id=subject.id,
            skip_cooldown=True,
        )

        # Send verification email (prints to console in demo)
        await state.email_sender.send(
            EmailMessage(
                to=email,
                subject="Verify your email",
                body_text=f"Click here to verify: http://localhost:8000/verify?token={token}",
            )
        )

        await session.commit()

        return JSONResponse(
            {
                "message": "Registration successful. Check console for verification email.",
                "user_id": subject.id,
                "email": subject.email,
            },
            status_code=201,
        )


async def api_login(request: Request) -> Response:
    """Login with email and password (JSON API)."""
    state = get_state(request)

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return json_error("Invalid JSON body")

    email = body.get("email")
    password = body.get("password")

    if not email or not password:
        return json_error("email and password are required")

    async with state.session_factory() as session:
        password_factor = state.get_password_factor(session)

        # Authenticate
        try:
            subject = await password_factor.authenticate(
                {"identifier": email, "password": password}
            )
        except (InvalidCredentialsError, InvalidRequestError):
            return json_error("Invalid email or password", status_code=401)

        # Create session
        ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        session_service = state.get_session_service(session)
        session_token = await session_service.create_session(
            subject_id=subject.id,
            ip_address=ip,
            user_agent=user_agent,
        )

        await session.commit()

        response = JSONResponse(
            {
                "message": "Login successful",
                "user_id": subject.id,
                "email": subject.email,
            }
        )
        response.set_cookie(
            SESSION_COOKIE_NAME,
            session_token,
            httponly=True,
            samesite="lax",
            max_age=86400 * 7,
        )
        return response


async def api_logout(request: Request) -> Response:
    """Logout and revoke session (JSON API)."""
    state = get_state(request)
    token = request.cookies.get(SESSION_COOKIE_NAME)

    if token:
        async with state.session_factory() as session:
            try:
                session_service = state.get_session_service(session)
                await session_service.revoke_session_by_token(token)
                await session.commit()
            except Exception:
                pass

    response = JSONResponse({"message": "Logged out"})
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


async def api_me(request: Request) -> Response:
    """Get current user profile (JSON API)."""
    state = get_state(request)

    async with state.session_factory() as session:
        subject = await get_current_subject(request, session)
        if not subject:
            return json_error("Not authenticated", status_code=401)

        return JSONResponse(
            {
                "id": subject.id,
                "email": subject.email,
                "is_active": subject.is_active,
                "created_at": subject.created_at.isoformat()
                if subject.created_at
                else None,
            }
        )


# =============================================================================
# Application Factory
# =============================================================================


def create_app() -> Starlette:
    """Create the demo Starlette application."""
    # HTML routes (web UI)
    html_routes = [
        Route("/", index, methods=["GET"]),
        Route("/login", login_page, methods=["GET"]),
        Route("/login", login_submit, methods=["POST"]),
        Route("/register", register_page, methods=["GET"]),
        Route("/register", register_submit, methods=["POST"]),
        Route("/dashboard", dashboard, methods=["GET"]),
        Route("/logout", logout_submit, methods=["POST"]),
        Route("/verify", verify_email, methods=["GET"]),
    ]

    # JSON API routes
    api_routes = [
        Route("/api/register", api_register, methods=["POST"]),
        Route("/api/login", api_login, methods=["POST"]),
        Route("/api/logout", api_logout, methods=["POST"]),
        Route("/api/me", api_me, methods=["GET"]),
    ]

    # Static files (if needed in the future)
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        routes = (
            html_routes
            + api_routes
            + [Mount("/static", StaticFiles(directory=str(static_dir)), name="static")]
        )
    else:
        routes = html_routes + api_routes

    # Middleware
    middleware = [
        Middleware(SessionMiddleware, secret_key=SECRET_KEY),
    ]

    return Starlette(routes=routes, lifespan=lifespan, middleware=middleware)


# Default app instance for uvicorn
app = create_app()
