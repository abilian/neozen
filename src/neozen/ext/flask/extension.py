"""NeoZen Flask extension."""

from __future__ import annotations

import asyncio
import inspect
import typing
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from flask import Flask, Response, flash, g, redirect, request, url_for

from neozen.core.session import SessionService

from .mixins import AnonymousUser

if typing.TYPE_CHECKING:
    from neozen.core.subject import Subject


# Type for the subject loader callback
SubjectLoader = Callable[[str], "Subject | None"]
AsyncSubjectLoader = Callable[[str], Awaitable["Subject | None"]]


@dataclass
class NeoZenState:
    """Internal state stored on Flask app."""

    extension: NeoZen
    session_service: SessionService[typing.Any] | None = None


class NeoZen:
    """NeoZen Flask extension for authentication.

    Provides Flask-Login-style ergonomics while using NeoZen's
    session management and authentication factors under the hood.

    Example:
        app = Flask(__name__)
        neozen = NeoZen(app)

        @neozen.subject_loader
        def load_user(subject_id: str):
            return User.query.get(subject_id)

        @app.route("/dashboard")
        @login_required
        def dashboard():
            return render_template("dashboard.html")
    """

    def __init__(
        self,
        app: Flask | None = None,
        *,
        session_service: SessionService[typing.Any] | None = None,
        cookie_name: str = "neozen_session",
        cookie_max_age: int = 86400 * 7,  # 7 days
        cookie_secure: bool = True,
        cookie_httponly: bool = True,
        cookie_samesite: str = "Lax",
        login_view: str | None = None,
        login_message: str = "Please log in to access this page.",
        login_message_category: str = "error",
    ) -> None:
        """Initialize the extension.

        Args:
            app: Flask application (can also use init_app later)
            session_service: NeoZen SessionService instance
            cookie_name: Name of the session cookie
            cookie_max_age: Cookie lifetime in seconds (default: 7 days)
            cookie_secure: Set Secure flag on cookie
            cookie_httponly: Set HttpOnly flag on cookie
            cookie_samesite: SameSite cookie policy
            login_view: Endpoint name to redirect unauthenticated users
            login_message: Flash message for unauthenticated access
            login_message_category: Flash category for login message
        """
        self.session_service = session_service
        self.cookie_name = cookie_name
        self.cookie_max_age = cookie_max_age
        self.cookie_secure = cookie_secure
        self.cookie_httponly = cookie_httponly
        self.cookie_samesite = cookie_samesite
        self.login_view = login_view
        self.login_message = login_message
        self.login_message_category = login_message_category

        # Event loop for async operations
        self._loop: asyncio.AbstractEventLoop | None = None

        # Callbacks (stored on extension, not app state, so they can be set before init_app)
        self._subject_loader: SubjectLoader | AsyncSubjectLoader | None = None
        self._unauthorized_callback: Callable[[], Response] | None = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """Initialize with a Flask application (factory pattern).

        Args:
            app: Flask application instance
        """
        # Store state on app
        if not hasattr(app, "extensions"):
            app.extensions = {}

        state = NeoZenState(
            extension=self,
            session_service=self.session_service,
        )
        app.extensions["neozen"] = state

        # Load config from app.config
        self._load_config(app)

        # Register hooks
        app.before_request(self._load_user_from_request)
        app.after_request(self._handle_session_cookie)

    def _load_config(self, app: Flask) -> None:
        """Load configuration from Flask app.config."""
        config = app.config

        # Override defaults with config values
        if "NEOZEN_COOKIE_NAME" in config:
            self.cookie_name = config["NEOZEN_COOKIE_NAME"]
        if "NEOZEN_COOKIE_MAX_AGE" in config:
            self.cookie_max_age = config["NEOZEN_COOKIE_MAX_AGE"]
        if "NEOZEN_COOKIE_SECURE" in config:
            self.cookie_secure = config["NEOZEN_COOKIE_SECURE"]
        if "NEOZEN_COOKIE_HTTPONLY" in config:
            self.cookie_httponly = config["NEOZEN_COOKIE_HTTPONLY"]
        if "NEOZEN_COOKIE_SAMESITE" in config:
            self.cookie_samesite = config["NEOZEN_COOKIE_SAMESITE"]
        if "NEOZEN_LOGIN_VIEW" in config:
            self.login_view = config["NEOZEN_LOGIN_VIEW"]
        if "NEOZEN_LOGIN_MESSAGE" in config:
            self.login_message = config["NEOZEN_LOGIN_MESSAGE"]
        if "NEOZEN_LOGIN_MESSAGE_CATEGORY" in config:
            self.login_message_category = config["NEOZEN_LOGIN_MESSAGE_CATEGORY"]

    def _get_state(self) -> NeoZenState:
        """Get NeoZen state from current app."""
        from flask import current_app  # noqa: PLC0415

        if "neozen" not in current_app.extensions:
            msg = (
                "NeoZen extension not initialized. "
                "Did you forget to call neozen.init_app(app)?"
            )
            raise RuntimeError(msg)
        return current_app.extensions["neozen"]

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """Get or create event loop for async operations."""
        if self._loop is None or self._loop.is_closed():
            self._loop = asyncio.new_event_loop()
        return self._loop

    def _run_async(
        self, coro: typing.Coroutine[typing.Any, typing.Any, typing.Any]
    ) -> typing.Any:
        """Run async code in Flask's sync context."""
        loop = self._get_loop()
        return loop.run_until_complete(coro)

    def subject_loader(
        self, callback: SubjectLoader | AsyncSubjectLoader
    ) -> SubjectLoader | AsyncSubjectLoader:
        """Register a subject loader function.

        The loader receives a subject_id and should return the Subject
        or None if not found. Can be sync or async.

        Can be called before or after init_app().

        Example:
            @neozen.subject_loader
            def load_user(subject_id: str) -> User | None:
                return User.query.get(subject_id)

            # Or async:
            @neozen.subject_loader
            async def load_user(subject_id: str) -> User | None:
                async with db.session() as session:
                    return await session.get(User, subject_id)
        """
        self._subject_loader = callback
        return callback

    def unauthorized_handler(
        self, callback: Callable[[], Response]
    ) -> Callable[[], Response]:
        """Register custom unauthorized handler.

        This handler is called when an unauthenticated user tries to
        access a protected route and no login_view is configured.

        Can be called before or after init_app().

        Example:
            @neozen.unauthorized_handler
            def handle_unauthorized():
                return jsonify({"error": "Unauthorized"}), 401
        """
        self._unauthorized_callback = callback
        return callback

    def _load_user_from_request(self) -> None:
        """Before request hook to load user from session cookie."""
        # Initialize request-scoped state
        g._neozen_user = None
        g._neozen_session = None
        g._neozen_user_loaded = False
        g._neozen_login_user = None  # Subject to log in after request
        g._neozen_logout = False  # Flag to logout after request

        state = self._get_state()
        token = request.cookies.get(self.cookie_name)

        if not token or not state.session_service:
            return

        # Validate session token
        try:
            session = self._run_async(state.session_service.validate_session(token))
            g._neozen_session = session
        except Exception:
            # Invalid or expired session
            pass

    def _load_subject(self) -> Subject | AnonymousUser:
        """Lazily load the subject from the session."""
        if g._neozen_user_loaded:
            return g._neozen_user or AnonymousUser()

        g._neozen_user_loaded = True

        if not g._neozen_session or not self._subject_loader:
            g._neozen_user = None
            return AnonymousUser()

        subject_id = g._neozen_session.subject_id

        # Call subject loader (handle both sync and async)
        loader = self._subject_loader
        if inspect.iscoroutinefunction(loader):
            subject = self._run_async(loader(subject_id))
        else:
            subject = loader(subject_id)

        g._neozen_user = subject
        return subject or AnonymousUser()  # type: ignore[return-value]

    def _handle_session_cookie(self, response: Response) -> Response:
        """After request hook to set/clear session cookie."""
        # Handle login
        if g._neozen_login_user is not None:
            _subject, token, remember = g._neozen_login_user
            max_age = self.cookie_max_age if remember else None
            response.set_cookie(
                self.cookie_name,
                token,
                max_age=max_age,
                secure=self.cookie_secure,
                httponly=self.cookie_httponly,
                samesite=self.cookie_samesite,
            )

        # Handle logout
        elif g._neozen_logout:
            response.delete_cookie(
                self.cookie_name,
                samesite=self.cookie_samesite,
            )

        return response

    def handle_unauthorized(self) -> Response:
        """Handle unauthorized access.

        Returns a response for unauthenticated users trying to access
        protected routes.
        """
        # Use custom handler if registered
        if self._unauthorized_callback:
            return self._unauthorized_callback()

        # Flash message and redirect to login view
        if self.login_view:
            if self.login_message:
                flash(self.login_message, self.login_message_category)
            return typing.cast(
                Response, redirect(url_for(self.login_view, next=request.url))
            )

        # Default: return 401
        from flask import abort  # noqa: PLC0415

        abort(401)


def _get_neozen() -> NeoZen:
    """Get NeoZen extension from current app."""
    from flask import current_app  # noqa: PLC0415

    if "neozen" not in current_app.extensions:
        msg = "NeoZen extension not initialized."
        raise RuntimeError(msg)
    return current_app.extensions["neozen"].extension


__all__ = ["NeoZen", "NeoZenState"]
