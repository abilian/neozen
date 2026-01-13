"""NeoZen Litestar Demo Application.

A demo application that validates NeoZen authentication components with a web UI.
Provides both HTML pages and JSON API endpoints.

Run with: uvicorn demos.litestar.app:app --reload --port 8001
"""

from __future__ import annotations

import secrets
import typing
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from litestar import Litestar, Request, Response, get, post
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.response import Redirect
from litestar.stores.memory import MemoryStore
from pwdlib import PasswordHash
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

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
from neozen.core.verification.email import EmailVerificationService
from neozen.storage import DoesNotExist
from neozen.storage.sqlalchemy import (
    EmailVerificationToken,
    EmailVerificationTokenRepository,
    Session,
    SessionRepository,
    Subject,
    SubjectRepository,
)

# Configuration
SECRET_KEY = "demo-secret-key-change-in-production"
SESSION_COOKIE_NAME = "neozen_session"

# Template directory
TEMPLATES_DIR = Path(__file__).parent / "templates"


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


@dataclass
class AppState:
    """Application state containing database engine and services."""

    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession] = field(init=False)
    hasher: PasswordHash = field(init=False)
    email_sender: ConsoleEmailSender = field(init=False)

    def __post_init__(self) -> None:
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
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


# =============================================================================
# Helper Functions
# =============================================================================


def get_state(request: Request) -> AppState:
    """Get application state from request."""
    return request.app.state.neozen


def flash(request: Request, message: str, category: str = "info") -> None:
    """Add a flash message to the session."""
    if "messages" not in request.session:
        request.session["messages"] = []
    request.session["messages"].append((category, message))


def pop_flash_messages(request: Request) -> list[tuple[str, str]]:
    """Pop and return flash messages from session."""
    messages = request.session.pop("messages", [])
    return messages


async def get_current_subject(
    request: Request, db_session: AsyncSession
) -> Subject | None:
    """Get current subject from session cookie."""
    state = get_state(request)
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None

    try:
        session_service = state.get_session_service(db_session)
        auth_session = await session_service.validate_session(token)
        repository = state.get_subject_repository(db_session)
        return await repository.get_one_by(id=auth_session.subject_id)
    except Exception:
        return None


def render_template(
    request: Request,
    template_name: str,
    context: dict[str, typing.Any] | None = None,
    status_code: int = 200,
) -> Response:
    """Render a Jinja2 template with context."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )
    ctx = context or {}
    ctx["messages"] = pop_flash_messages(request)
    ctx["current_user"] = ctx.get("current_user")
    ctx["request"] = request

    template = env.get_template(template_name)
    content = template.render(**ctx)
    return Response(content=content, status_code=status_code, media_type="text/html")


def json_response(
    data: dict[str, typing.Any], status_code: int = 200
) -> Response[dict[str, typing.Any]]:
    """Return JSON response."""
    return Response(
        content=data, status_code=status_code, media_type="application/json"
    )


def json_error(message: str, status_code: int = 400) -> Response[dict[str, typing.Any]]:
    """Return JSON error response."""
    return json_response({"error": message}, status_code=status_code)


# =============================================================================
# HTML Routes (Web UI)
# =============================================================================


@get("/")
async def index(request: Request) -> Response:
    """Home page."""
    state = get_state(request)
    async with state.session_factory() as session:
        current_user = await get_current_subject(request, session)
        return render_template(request, "index.html", {"current_user": current_user})


@get("/login")
async def login_page(request: Request) -> Response:
    """Login page (GET)."""
    state = get_state(request)
    async with state.session_factory() as session:
        current_user = await get_current_subject(request, session)
        if current_user:
            return Redirect(path="/dashboard")
        return render_template(request, "login.html", {"current_user": None})


@post("/login")
async def login_submit(request: Request) -> Response:
    """Login form submission (POST)."""
    state = get_state(request)
    form = await request.form()
    email = form.get("email", "")
    password = form.get("password", "")

    if not email or not password:
        flash(request, "Email and password are required", "error")
        return render_template(
            request, "login.html", {"current_user": None, "email": email}
        )

    async with state.session_factory() as session:
        password_factor = state.get_password_factor(session)

        try:
            subject = await password_factor.authenticate({
                "identifier": email,
                "password": password,
            })
        except (InvalidCredentialsError, InvalidRequestError):
            flash(request, "Invalid email or password", "error")
            return render_template(
                request, "login.html", {"current_user": None, "email": email}
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
        response = Redirect(path="/dashboard")
        response.set_cookie(
            SESSION_COOKIE_NAME,
            session_token,
            httponly=True,
            samesite="lax",
            max_age=86400 * 7,
        )
        return response


@get("/register")
async def register_page(request: Request) -> Response:
    """Registration page (GET)."""
    state = get_state(request)
    async with state.session_factory() as session:
        current_user = await get_current_subject(request, session)
        if current_user:
            return Redirect(path="/dashboard")
        return render_template(request, "register.html", {"current_user": None})


@post("/register")
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
            request, "register.html", {"current_user": None, "email": email}
        )

    if password != password_confirm:
        flash(request, "Passwords do not match", "error")
        return render_template(
            request, "register.html", {"current_user": None, "email": email}
        )

    if len(password) < 8:
        flash(request, "Password must be at least 8 characters", "error")
        return render_template(
            request, "register.html", {"current_user": None, "email": email}
        )

    async with state.session_factory() as session:
        storage = state.get_subject_repository(session)
        identifier = DemoEmailIdentifier(storage)

        # Verify email format
        try:
            email = await identifier.verify_identifier(str(email))
        except IdentifierVerificationError as e:
            flash(request, str(e), "error")
            return render_template(
                request, "register.html", {"current_user": None, "email": email}
            )

        # Check if email already exists
        try:
            await storage.get_one_by(email=email)
            flash(request, "Email is already registered", "error")
            return render_template(
                request, "register.html", {"current_user": None, "email": email}
            )
        except DoesNotExist:
            pass

        # Create subject
        hashed_password = state.hasher.hash(str(password))
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
                body_text=f"Click here to verify: http://localhost:8001/verify?token={token}",
            )
        )

        await session.commit()

        flash(
            request,
            "Registration successful! Check the console for verification email.",
            "success",
        )
        return Redirect(path="/login")


@get("/dashboard")
async def dashboard(request: Request) -> Response:
    """Dashboard page (protected)."""
    state = get_state(request)
    async with state.session_factory() as session:
        current_user = await get_current_subject(request, session)
        if not current_user:
            flash(request, "Please log in to access the dashboard", "error")
            return Redirect(path="/login")
        return render_template(
            request, "dashboard.html", {"current_user": current_user}
        )


@post("/logout")
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
    response = Redirect(path="/")
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@get("/verify")
async def verify_email(request: Request) -> Response:
    """Verify email with token."""
    state = get_state(request)
    token = request.query_params.get("token")

    if not token:
        flash(request, "Verification token is required", "error")
        return Redirect(path="/")

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

    return Redirect(path="/login")


# =============================================================================
# JSON API Routes
# =============================================================================


@post("/api/register")
async def api_register(request: Request) -> Response:
    """Register a new user (JSON API)."""
    state = get_state(request)

    try:
        body = await request.json()
    except Exception:
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
                body_text=f"Click here to verify: http://localhost:8001/verify?token={token}",
            )
        )

        await session.commit()

        return json_response(
            {
                "message": "Registration successful. Check console for verification email.",
                "user_id": subject.id,
                "email": subject.email,
            },
            status_code=201,
        )


@post("/api/login")
async def api_login(request: Request) -> Response:
    """Login with email and password (JSON API)."""
    state = get_state(request)

    try:
        body = await request.json()
    except Exception:
        return json_error("Invalid JSON body")

    email = body.get("email")
    password = body.get("password")

    if not email or not password:
        return json_error("email and password are required")

    async with state.session_factory() as session:
        password_factor = state.get_password_factor(session)

        # Authenticate
        try:
            subject = await password_factor.authenticate({
                "identifier": email,
                "password": password,
            })
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

        response = json_response({
            "message": "Login successful",
            "user_id": subject.id,
            "email": subject.email,
        })
        response.set_cookie(
            SESSION_COOKIE_NAME,
            session_token,
            httponly=True,
            samesite="lax",
            max_age=86400 * 7,
        )
        return response


@post("/api/logout")
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

    response = json_response({"message": "Logged out"})
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@get("/api/me")
async def api_me(request: Request) -> Response:
    """Get current user profile (JSON API)."""
    state = get_state(request)

    async with state.session_factory() as session:
        subject = await get_current_subject(request, session)
        if not subject:
            return json_error("Not authenticated", status_code=401)

        return json_response({
            "id": subject.id,
            "email": subject.email,
            "is_active": subject.is_active,
            "created_at": subject.created_at.isoformat()
            if subject.created_at
            else None,
        })


# =============================================================================
# Application Factory
# =============================================================================


@asynccontextmanager
async def lifespan(app: Litestar):
    """Application lifespan - initialize database on startup."""
    db_url = get_database_url()
    engine = await init_database(db_url)
    app.state.neozen = AppState(engine)
    yield
    await engine.dispose()


def create_app() -> Litestar:
    """Create the demo Litestar application."""
    # Session configuration using server-side sessions with memory store
    session_config = ServerSideSessionConfig(
        key=SESSION_COOKIE_NAME + "_session",
        max_age=86400 * 7,  # 7 days
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
            verify_email,
            # API routes
            api_register,
            api_login,
            api_logout,
            api_me,
        ],
        lifespan=[lifespan],
        middleware=[
            session_config.middleware,
        ],
        stores={"sessions": MemoryStore()},
    )


# Default app instance for uvicorn
app = create_app()
