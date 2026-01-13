"""NeoZen Flask Demo Application.

A demo application that validates NeoZen authentication components with a web UI.
Provides both HTML pages and JSON API endpoints.

Run with: flask run --port 8002
Or: FLASK_APP=demos.flask.app:app flask run
"""

from __future__ import annotations

import asyncio
import secrets
import typing
from dataclasses import dataclass, field
from pathlib import Path

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask.typing import ResponseReturnValue
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
    Session as AuthSession,
    SessionRepository,
    Subject,
    SubjectRepository,
)

# Configuration
SECRET_KEY = "demo-secret-key-change-in-production"
SESSION_COOKIE_NAME = "neozen_session"


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

    def get_session_service(self, session: AsyncSession) -> SessionService[AuthSession]:
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
# Flask Application
# =============================================================================

# Set up templates directory
TEMPLATES_DIR = Path(__file__).parent / "templates"

app = Flask(__name__, template_folder=str(TEMPLATES_DIR))
app.secret_key = SECRET_KEY

# Global state (initialized on first request)
_state: AppState | None = None
_loop: asyncio.AbstractEventLoop | None = None


def get_event_loop() -> asyncio.AbstractEventLoop:
    """Get or create the event loop for async operations."""
    global _loop
    if _loop is None or _loop.is_closed():
        _loop = asyncio.new_event_loop()
    return _loop


def run_async(coro: typing.Coroutine[typing.Any, typing.Any, typing.Any]) -> typing.Any:
    """Run an async coroutine in the sync Flask context."""
    loop = get_event_loop()
    return loop.run_until_complete(coro)


def get_state() -> AppState:
    """Get or initialize application state."""
    global _state
    if _state is None:
        db_url = get_database_url()
        engine = run_async(init_database(db_url))
        _state = AppState(engine)
    return _state


async def get_current_subject_async(
    state: AppState, db_session: AsyncSession
) -> Subject | None:
    """Get current subject from session cookie."""
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


def get_current_subject(state: AppState, db_session: AsyncSession) -> Subject | None:
    """Sync wrapper to get current subject."""
    return run_async(get_current_subject_async(state, db_session))


# =============================================================================
# HTML Routes (Web UI)
# =============================================================================


@app.route("/")
def index() -> ResponseReturnValue:
    """Home page."""
    state = get_state()

    async def _handler() -> Subject | None:
        async with state.session_factory() as db_session:
            return await get_current_subject_async(state, db_session)

    current_user = run_async(_handler())
    return render_template("index.html", current_user=current_user)


@app.route("/login", methods=["GET"])
def login_page() -> ResponseReturnValue:
    """Login page (GET)."""
    state = get_state()

    async def _handler() -> Subject | None:
        async with state.session_factory() as db_session:
            return await get_current_subject_async(state, db_session)

    current_user = run_async(_handler())
    if current_user:
        return redirect(url_for("dashboard"))
    return render_template("login.html", current_user=None)


@app.route("/login", methods=["POST"])
def login_submit() -> ResponseReturnValue:
    """Login form submission (POST)."""
    state = get_state()
    email = request.form.get("email", "")
    password = request.form.get("password", "")

    if not email or not password:
        flash("Email and password are required", "error")
        return render_template("login.html", current_user=None, email=email)

    async def _handler() -> tuple[Subject | None, str | None]:
        async with state.session_factory() as db_session:
            password_factor = state.get_password_factor(db_session)

            try:
                subject = await password_factor.authenticate({
                    "identifier": email,
                    "password": password,
                })
            except (InvalidCredentialsError, InvalidRequestError):
                return None, None

            # Create session
            ip = request.remote_addr
            user_agent = request.headers.get("user-agent")

            session_service = state.get_session_service(db_session)
            session_token = await session_service.create_session(
                subject_id=subject.id,
                ip_address=ip,
                user_agent=user_agent,
            )

            await db_session.commit()
            return subject, session_token

    subject, session_token = run_async(_handler())

    if not subject or not session_token:
        flash("Invalid email or password", "error")
        return render_template("login.html", current_user=None, email=email)

    flash("Login successful!", "success")
    response = redirect(url_for("dashboard"))
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        httponly=True,
        samesite="Lax",
        max_age=86400 * 7,
    )
    return response


@app.route("/register", methods=["GET"])
def register_page() -> ResponseReturnValue:
    """Registration page (GET)."""
    state = get_state()

    async def _handler() -> Subject | None:
        async with state.session_factory() as db_session:
            return await get_current_subject_async(state, db_session)

    current_user = run_async(_handler())
    if current_user:
        return redirect(url_for("dashboard"))
    return render_template("register.html", current_user=None)


@app.route("/register", methods=["POST"])
def register_submit() -> ResponseReturnValue:
    """Registration form submission (POST)."""
    state = get_state()
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    password_confirm = request.form.get("password_confirm", "")

    # Validation
    if not email or not password:
        flash("Email and password are required", "error")
        return render_template("register.html", current_user=None, email=email)

    if password != password_confirm:
        flash("Passwords do not match", "error")
        return render_template("register.html", current_user=None, email=email)

    if len(password) < 8:
        flash("Password must be at least 8 characters", "error")
        return render_template("register.html", current_user=None, email=email)

    async def _handler() -> tuple[bool, str]:
        async with state.session_factory() as db_session:
            storage = state.get_subject_repository(db_session)
            identifier = DemoEmailIdentifier(storage)

            # Verify email format
            try:
                validated_email = await identifier.verify_identifier(email)
            except IdentifierVerificationError as e:
                return False, str(e)

            # Check if email already exists
            try:
                await storage.get_one_by(email=validated_email)
                return False, "Email is already registered"
            except DoesNotExist:
                pass

            # Create subject
            hashed_password = state.hasher.hash(password)
            subject_id = f"subj_{secrets.token_hex(12)}"

            subject = await storage.create(
                id=subject_id,
                email=validated_email,
                username=None,
                hashed_password=hashed_password,
                is_active=True,
                is_verified=False,
            )

            # Create verification token and send email
            verification_service = state.get_verification_service(db_session)
            token = await verification_service.create_token(
                email=validated_email,
                subject_id=subject.id,
                skip_cooldown=True,
            )

            # Send verification email (prints to console in demo)
            await state.email_sender.send(
                EmailMessage(
                    to=validated_email,
                    subject="Verify your email",
                    body_text=f"Click here to verify: http://localhost:8002/verify?token={token}",
                )
            )

            await db_session.commit()
            return True, ""

    success, error_msg = run_async(_handler())

    if not success:
        flash(error_msg, "error")
        return render_template("register.html", current_user=None, email=email)

    flash(
        "Registration successful! Check the console for verification email.",
        "success",
    )
    return redirect(url_for("login_page"))


@app.route("/dashboard")
def dashboard() -> ResponseReturnValue:
    """Dashboard page (protected)."""
    state = get_state()

    async def _handler() -> Subject | None:
        async with state.session_factory() as db_session:
            return await get_current_subject_async(state, db_session)

    current_user = run_async(_handler())
    if not current_user:
        flash("Please log in to access the dashboard", "error")
        return redirect(url_for("login_page"))
    return render_template("dashboard.html", current_user=current_user)


@app.route("/logout", methods=["POST"])
def logout_submit() -> ResponseReturnValue:
    """Logout form submission (POST)."""
    state = get_state()
    token = request.cookies.get(SESSION_COOKIE_NAME)

    if token:

        async def _handler() -> None:
            async with state.session_factory() as db_session:
                try:
                    session_service = state.get_session_service(db_session)
                    await session_service.revoke_session_by_token(token)
                    await db_session.commit()
                except Exception:
                    pass

        run_async(_handler())

    flash("You have been logged out", "info")
    response = redirect(url_for("index"))
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@app.route("/verify")
def verify_email() -> ResponseReturnValue:
    """Verify email with token."""
    state = get_state()
    token = request.args.get("token")

    if not token:
        flash("Verification token is required", "error")
        return redirect(url_for("index"))

    async def _handler() -> tuple[bool, str]:
        async with state.session_factory() as db_session:
            try:
                verification_service = state.get_verification_service(db_session)
                verification = await verification_service.verify_token(token)
                await db_session.commit()
                return True, verification.email
            except Exception as e:
                return False, str(e)

    success, result = run_async(_handler())

    if success:
        flash(f"Email {result} verified successfully!", "success")
    else:
        flash(f"Verification failed: {result}", "error")

    return redirect(url_for("login_page"))


# =============================================================================
# JSON API Routes
# =============================================================================


@app.route("/api/register", methods=["POST"])
def api_register() -> ResponseReturnValue:
    """Register a new user (JSON API)."""
    state = get_state()

    try:
        body = request.get_json()
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    if not body:
        return jsonify({"error": "Invalid JSON body"}), 400

    email = body.get("email")
    password = body.get("password")

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    async def _handler() -> tuple[bool, dict[str, typing.Any], int]:
        async with state.session_factory() as db_session:
            storage = state.get_subject_repository(db_session)
            identifier = DemoEmailIdentifier(storage)

            # Verify email format
            try:
                validated_email = await identifier.verify_identifier(email)
            except IdentifierVerificationError as e:
                return False, {"error": str(e)}, 400

            # Check if email already exists
            try:
                await storage.get_one_by(email=validated_email)
                return False, {"error": "Email already registered"}, 409
            except DoesNotExist:
                pass

            # Create subject
            hashed_password = state.hasher.hash(password)
            subject_id = f"subj_{secrets.token_hex(12)}"

            subject = await storage.create(
                id=subject_id,
                email=validated_email,
                username=None,
                hashed_password=hashed_password,
                is_active=True,
                is_verified=False,
            )

            # Create verification token and send email
            verification_service = state.get_verification_service(db_session)
            token = await verification_service.create_token(
                email=validated_email,
                subject_id=subject.id,
                skip_cooldown=True,
            )

            # Send verification email (prints to console in demo)
            await state.email_sender.send(
                EmailMessage(
                    to=validated_email,
                    subject="Verify your email",
                    body_text=f"Click here to verify: http://localhost:8002/verify?token={token}",
                )
            )

            await db_session.commit()

            return (
                True,
                {
                    "message": "Registration successful. Check console for verification email.",
                    "user_id": subject.id,
                    "email": subject.email,
                },
                201,
            )

    success, data, status_code = run_async(_handler())
    return jsonify(data), status_code


@app.route("/api/login", methods=["POST"])
def api_login() -> ResponseReturnValue:
    """Login with email and password (JSON API)."""
    state = get_state()

    try:
        body = request.get_json()
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    if not body:
        return jsonify({"error": "Invalid JSON body"}), 400

    email = body.get("email")
    password = body.get("password")

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    async def _handler() -> tuple[bool, dict[str, typing.Any], str | None]:
        async with state.session_factory() as db_session:
            password_factor = state.get_password_factor(db_session)

            # Authenticate
            try:
                subject = await password_factor.authenticate({
                    "identifier": email,
                    "password": password,
                })
            except (InvalidCredentialsError, InvalidRequestError):
                return False, {"error": "Invalid email or password"}, None

            # Create session
            ip = request.remote_addr
            user_agent = request.headers.get("user-agent")

            session_service = state.get_session_service(db_session)
            session_token = await session_service.create_session(
                subject_id=subject.id,
                ip_address=ip,
                user_agent=user_agent,
            )

            await db_session.commit()

            return (
                True,
                {
                    "message": "Login successful",
                    "user_id": subject.id,
                    "email": subject.email,
                },
                session_token,
            )

    success, data, session_token = run_async(_handler())

    if not success:
        return jsonify(data), 401

    response = jsonify(data)
    if session_token:
        response.set_cookie(
            SESSION_COOKIE_NAME,
            session_token,
            httponly=True,
            samesite="Lax",
            max_age=86400 * 7,
        )
    return response


@app.route("/api/logout", methods=["POST"])
def api_logout() -> ResponseReturnValue:
    """Logout and revoke session (JSON API)."""
    state = get_state()
    token = request.cookies.get(SESSION_COOKIE_NAME)

    if token:

        async def _handler() -> None:
            async with state.session_factory() as db_session:
                try:
                    session_service = state.get_session_service(db_session)
                    await session_service.revoke_session_by_token(token)
                    await db_session.commit()
                except Exception:
                    pass

        run_async(_handler())

    response = jsonify({"message": "Logged out"})
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@app.route("/api/me")
def api_me() -> ResponseReturnValue:
    """Get current user profile (JSON API)."""
    state = get_state()

    async def _handler() -> Subject | None:
        async with state.session_factory() as db_session:
            return await get_current_subject_async(state, db_session)

    subject = run_async(_handler())

    if not subject:
        return jsonify({"error": "Not authenticated"}), 401

    return jsonify({
        "id": subject.id,
        "email": subject.email,
        "is_active": subject.is_active,
        "created_at": subject.created_at.isoformat() if subject.created_at else None,
    })


# =============================================================================
# Error Handlers
# =============================================================================


@app.errorhandler(404)
def not_found(e: Exception) -> ResponseReturnValue:
    """Handle 404 errors."""
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(e: Exception) -> ResponseReturnValue:
    """Handle 500 errors."""
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    import os

    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, port=8002)
