"""Demo application for NeoZen.

This demo validates that all NeoZen components work together:
- Subject registration with email + password
- Session-based authentication
- Protected routes
- Logout

Run with: neozen serve
Or: uvicorn neozen.demo.app:app --reload
"""

from __future__ import annotations

import json
import secrets
import typing
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

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
from neozen.core.sqlmodels import EmailVerificationToken, Session, Subject
from neozen.core.storage import DoesNotExist
from neozen.core.storage.sqlalchemy import SQLAlchemyStorage
from neozen.core.verification.email import EmailVerificationService

# Configuration
SECRET_KEY = "demo-secret-key-change-in-production"
SESSION_COOKIE_NAME = "neozen_session"


# =============================================================================
# Email Identifier for SQLAlchemy Subject
# =============================================================================


class DemoEmailIdentifier(IdentifierProtocol[Subject]):
    """Email identifier for demo using SQLAlchemy storage."""

    def __init__(self, storage: SQLAlchemyStorage[Subject]) -> None:
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

    def get_subject_storage(self, session: AsyncSession) -> SQLAlchemyStorage[Subject]:
        return SQLAlchemyStorage(Subject, session)

    def get_session_storage(self, session: AsyncSession) -> SQLAlchemyStorage[Session]:
        return SQLAlchemyStorage(Session, session)

    def get_verification_storage(
        self, session: AsyncSession
    ) -> SQLAlchemyStorage[EmailVerificationToken]:
        return SQLAlchemyStorage(EmailVerificationToken, session)

    def get_password_factor(
        self, session: AsyncSession
    ) -> PasswordFactor[Subject]:
        storage = self.get_subject_storage(session)
        identifier = DemoEmailIdentifier(storage)
        return PasswordFactor(
            identifier=identifier,
            subject_storage=storage,
            hasher=self.hasher,
        )

    def get_session_service(
        self, session: AsyncSession
    ) -> SessionService[Session]:
        return SessionService(
            storage=self.get_session_storage(session),
            hash_key=SECRET_KEY,
        )

    def get_verification_service(
        self, session: AsyncSession
    ) -> EmailVerificationService[EmailVerificationToken]:
        return EmailVerificationService(
            storage=self.get_verification_storage(session),
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
        storage = state.get_subject_storage(session)
        return await storage.get_one_by(id=auth_session.subject_id)
    except Exception:
        return None


def json_error(message: str, status_code: int = 400) -> JSONResponse:
    """Return JSON error response."""
    return JSONResponse({"error": message}, status_code=status_code)


# =============================================================================
# Routes
# =============================================================================


async def index(request: Request) -> JSONResponse:
    """Home page with API info."""
    return JSONResponse(
        {
            "name": "NeoZen Demo API",
            "version": "0.1.0",
            "endpoints": {
                "POST /register": "Register new user (email, password)",
                "POST /login": "Login (email, password)",
                "POST /logout": "Logout (requires auth)",
                "GET /me": "Get current user (requires auth)",
                "GET /protected": "Protected route example (requires auth)",
            },
        }
    )


async def register(request: Request) -> Response:
    """Register a new user."""
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
        storage = state.get_subject_storage(session)
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


async def login(request: Request) -> Response:
    """Login with email and password."""
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


async def logout(request: Request) -> Response:
    """Logout and revoke session."""
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


async def me(request: Request) -> Response:
    """Get current user profile."""
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
                "created_at": subject.created_at.isoformat() if subject.created_at else None,
            }
        )


async def protected(request: Request) -> Response:
    """Protected route example."""
    state = get_state(request)

    async with state.session_factory() as session:
        subject = await get_current_subject(request, session)
        if not subject:
            return json_error("Not authenticated", status_code=401)

        return JSONResponse(
            {
                "message": "You have access to this protected resource!",
                "user_id": subject.id,
            }
        )


async def verify_email(request: Request) -> Response:
    """Verify email with token."""
    state = get_state(request)
    token = request.query_params.get("token")

    if not token:
        return json_error("Token required")

    async with state.session_factory() as session:
        try:
            verification_service = state.get_verification_service(session)
            verification = await verification_service.verify_token(token)
            await session.commit()
            return JSONResponse(
                {
                    "message": "Email verified successfully",
                    "email": verification.email,
                }
            )
        except Exception as e:
            return json_error(str(e), status_code=400)


# =============================================================================
# Application Factory
# =============================================================================


def create_app() -> Starlette:
    """Create the demo Starlette application."""
    routes = [
        Route("/", index, methods=["GET"]),
        Route("/register", register, methods=["POST"]),
        Route("/login", login, methods=["POST"]),
        Route("/logout", logout, methods=["POST"]),
        Route("/me", me, methods=["GET"]),
        Route("/protected", protected, methods=["GET"]),
        Route("/verify", verify_email, methods=["GET"]),
    ]

    return Starlette(routes=routes, lifespan=lifespan)


# Default app instance for uvicorn
app = create_app()
