"""Unit tests for NeoZen Flask extension."""

from __future__ import annotations

import asyncio
import dataclasses
import gc
import threading

from flask import Flask, jsonify

from neozen.core.session.service import SessionNotFoundError
from neozen.ext.flask import (
    AnonymousUser,
    NeoZen,
    UserMixin,
    current_user,
    login_required,
)
from neozen.ext.flask.extension import run_sync


class TestAnonymousUser:
    """Tests for AnonymousUser class."""

    def test_is_authenticated_false(self):
        user = AnonymousUser()
        assert user.is_authenticated is False

    def test_is_anonymous_true(self):
        user = AnonymousUser()
        assert user.is_anonymous is True

    def test_is_active_false(self):
        user = AnonymousUser()
        assert user.is_active is False

    def test_id_is_none(self):
        user = AnonymousUser()
        assert user.id is None

    def test_bool_false(self):
        user = AnonymousUser()
        assert bool(user) is False

    def test_repr(self):
        user = AnonymousUser()
        assert repr(user) == "<AnonymousUser>"


class TestUserMixin:
    """Tests for UserMixin class."""

    def test_is_authenticated_true(self):
        class User(UserMixin):
            pass

        user = User()
        assert user.is_authenticated is True

    def test_is_anonymous_false(self):
        class User(UserMixin):
            pass

        user = User()
        assert user.is_anonymous is False

    def test_bool_true(self):
        class User(UserMixin):
            pass

        user = User()
        assert bool(user) is True


class TestNeoZenExtension:
    """Tests for NeoZen extension initialization."""

    def test_init_with_app(self):
        app = Flask(__name__)
        app.secret_key = "test-secret"
        neozen = NeoZen(app)

        assert "neozen" in app.extensions
        assert app.extensions["neozen"].extension is neozen

    def test_earlier_hook_answering_first_is_not_an_error(self):
        """A CSRF check registered before NeoZen may refuse the request."""
        app = Flask(__name__)
        app.secret_key = "test-secret"
        app.before_request(lambda: ("refused", 400))
        NeoZen(app)

        response = app.test_client().post("/")

        assert response.status_code == 400

    def test_init_app_factory_pattern(self):
        app = Flask(__name__)
        app.secret_key = "test-secret"
        neozen = NeoZen()
        neozen.init_app(app)

        assert "neozen" in app.extensions

    def test_config_from_app(self):
        app = Flask(__name__)
        app.secret_key = "test-secret"
        app.config["NEOZEN_COOKIE_NAME"] = "my_session"
        app.config["NEOZEN_LOGIN_VIEW"] = "auth.login"

        neozen = NeoZen(app)

        assert neozen.cookie_name == "my_session"
        assert neozen.login_view == "auth.login"

    def test_subject_loader_decorator(self):
        app = _app()
        neozen = NeoZen(app, session_service=_OneSession())

        @neozen.subject_loader
        def load_user(user_id: str):
            return _User(user_id)

        assert _current_user_id(app, neozen) == "123"

    def test_subject_loader_before_init(self):
        """subject_loader can be called before init_app."""
        neozen = NeoZen(session_service=_OneSession())

        @neozen.subject_loader
        def load_user(user_id: str):
            return _User(user_id)

        app = _app()
        neozen.init_app(app)

        assert _current_user_id(app, neozen) == "123"

    def test_unauthorized_handler_decorator(self):
        app = Flask(__name__)
        app.secret_key = "test-secret"
        neozen = NeoZen(app)

        @neozen.unauthorized_handler
        def handle_unauth():
            return jsonify({"error": "Go away"}), 418

        @app.route("/protected")
        @login_required
        def protected():
            return "secret"

        response = app.test_client().get("/protected")

        assert response.status_code == 418


@dataclasses.dataclass(frozen=True)
class _User:
    id: str
    is_authenticated: bool = True


@dataclasses.dataclass(frozen=True)
class _Session:
    subject_id: str


class _OneSession:
    """A session service that knows one token, for subject "123"."""

    async def validate_session(self, token: str) -> _Session:
        if token != "the-token":
            raise SessionNotFoundError
        return _Session("123")


def _app() -> Flask:
    app = Flask(__name__)
    app.secret_key = "test-secret"
    return app


def _current_user_id(app: Flask, neozen: NeoZen) -> str:
    @app.route("/me")
    def me():
        return current_user.id

    client = app.test_client()
    client.set_cookie(neozen.cookie_name, "the-token")
    return client.get("/me").text


class TestLoginRequired:
    """Tests for login_required decorator."""

    def test_unauthenticated_redirects(self):
        app = Flask(__name__)
        app.secret_key = "test-secret"
        _neozen = NeoZen(app, login_view="login")  # noqa: F841 - needed for side effects

        @app.route("/login")
        def login():
            return "login page"

        @app.route("/protected")
        @login_required
        def protected():
            return "protected content"

        with app.test_client() as client:
            response = client.get("/protected")
            assert response.status_code == 302
            assert "/login" in response.headers["Location"]

    def test_unauthenticated_returns_401_for_api(self):
        app = Flask(__name__)
        app.secret_key = "test-secret"
        _neozen = NeoZen(app)  # noqa: F841 - needed for side effects

        @app.route("/api/protected")
        @login_required(redirect=False)
        def api_protected():
            return jsonify({"data": "secret"})

        with app.test_client() as client:
            response = client.get("/api/protected")
            assert response.status_code == 401
            data = response.get_json()
            assert data["error"] == "Unauthorized"


class TestCurrentUserProxy:
    """Tests for current_user proxy."""

    def test_outside_request_context_returns_anonymous(self):
        # Outside of request context, should return AnonymousUser
        user = current_user._get_current_object()
        assert isinstance(user, AnonymousUser)

    def test_in_request_context_without_session(self):
        app = Flask(__name__)
        app.secret_key = "test-secret"
        _neozen = NeoZen(app)  # noqa: F841 - needed for side effects

        @app.route("/test")
        def test_route():
            return jsonify({
                "is_authenticated": current_user.is_authenticated,
                "is_anonymous": current_user.is_anonymous,
            })

        with app.test_client() as client:
            response = client.get("/test")
            data = response.get_json()
            assert data["is_authenticated"] is False
            assert data["is_anonymous"] is True


def test_run_sync_is_safe_across_threads() -> None:
    # Two request threads running coroutines at the same time must not
    # share an event loop ("This event loop is already running").

    both_running = threading.Barrier(2, timeout=5)
    errors: list[BaseException] = []
    loops: list[asyncio.AbstractEventLoop] = []

    async def work() -> int:
        loops.append(asyncio.get_running_loop())
        await asyncio.to_thread(both_running.wait)
        return 1

    def request_thread() -> None:
        try:
            assert run_sync(work()) == 1
        except BaseException as e:  # ken: BLE001 collect for the main thread
            errors.append(e)

    threads = [threading.Thread(target=request_thread) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert loops[0] is not loops[1]
    # A finished thread's loop is closed, not leaked.
    del threads, t
    gc.collect()
    assert all(loop.is_closed() for loop in loops)
