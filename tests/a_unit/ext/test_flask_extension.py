"""Unit tests for NeoZen Flask extension."""

from __future__ import annotations

import asyncio
import gc
import threading

from flask import Flask, jsonify

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
        app = Flask(__name__)
        app.secret_key = "test-secret"
        neozen = NeoZen(app)

        @neozen.subject_loader
        def load_user(user_id: str):
            return {"id": user_id}

        assert neozen._subject_loader is not None
        assert neozen._subject_loader("123") == {"id": "123"}

    def test_subject_loader_before_init(self):
        """subject_loader can be called before init_app."""
        neozen = NeoZen()

        @neozen.subject_loader
        def load_user(user_id: str):
            return {"id": user_id}

        assert neozen._subject_loader is not None

        # Now init the app
        app = Flask(__name__)
        app.secret_key = "test-secret"
        neozen.init_app(app)

        assert neozen._subject_loader("123") == {"id": "123"}

    def test_unauthorized_handler_decorator(self):
        app = Flask(__name__)
        app.secret_key = "test-secret"
        neozen = NeoZen(app)

        @neozen.unauthorized_handler
        def handle_unauth():
            return jsonify({"error": "Unauthorized"}), 401

        assert neozen._unauthorized_callback is not None


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
