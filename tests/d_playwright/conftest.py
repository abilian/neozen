"""Playwright test fixtures for NeoZen demo applications.

Provides fixtures for:
- Starting demo servers (Flask, Starlette) with isolated test databases
- Playwright browser/page fixtures
- Helper functions for common operations
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess  # noqa: S404
import sys
import time
from collections.abc import Generator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.models import Role

if TYPE_CHECKING:
    from playwright.sync_api import Page

# Project root for importing demos
PROJECT_ROOT = Path(__file__).parent.parent.parent


def find_free_port() -> int:
    """Find a free port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_server(port: int, timeout: float = 10.0) -> bool:
    """Wait for server to be ready on the given port."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect(("127.0.0.1", port))
                return True
        except (ConnectionRefusedError, TimeoutError, OSError):
            time.sleep(0.1)
    return False


def init_test_database_sync(db_path: Path) -> None:
    """Initialize a test database with tables and default roles (synchronous)."""
    db_url = f"sqlite:///{db_path}"
    engine = create_engine(db_url, echo=False)

    # Create all tables
    Base.metadata.create_all(engine)

    # Create default roles
    session_factory = sessionmaker(engine, expire_on_commit=False)
    with session_factory() as session:
        builtin_roles = [
            ("admin", "Administrator with full access"),
            ("user", "Standard authenticated user"),
            ("moderator", "Content moderator"),
            ("viewer", "Read-only access"),
        ]
        for role_name, description in builtin_roles:
            existing = session.query(Role).filter_by(name=role_name).first()
            if not existing:
                role = Role(
                    id=f"role_{role_name}", name=role_name, description=description
                )
                session.add(role)
        session.commit()

    engine.dispose()


# =============================================================================
# Flask Server Fixtures
# =============================================================================


@pytest.fixture(scope="session")
def flask_port() -> int:
    """Get a free port for the Flask server."""
    return find_free_port()


@pytest.fixture(scope="session")
def flask_server(
    flask_port: int,
    tmp_path_factory: pytest.TempPathFactory,
) -> Generator[str, None, None]:
    """Start Flask demo server for the test session.

    Yields the base URL of the server.
    """
    # Create test database directory
    test_dir = tmp_path_factory.mktemp("flask_data")
    db_path = test_dir / "neozen.db"

    # Initialize database
    init_test_database_sync(db_path)

    # Set environment for Flask to use test database
    env = os.environ.copy()
    env["FLASK_APP"] = "demos.flask.app:app"
    env["FLASK_DEBUG"] = "0"
    env["NEOZEN_TEST_DB_PATH"] = str(db_path)

    # Patch the demo app's data directory via environment
    # The demo app checks for this env var in tests
    demo_data_dir = Path(PROJECT_ROOT) / "demos" / "flask" / "data"

    # Create a symlink or copy the database to the expected location
    demo_data_dir.mkdir(exist_ok=True)
    demo_db_path = demo_data_dir / "neozen.db"
    if demo_db_path.exists():
        demo_db_path.unlink()
    shutil.copy(db_path, demo_db_path)

    # Start Flask server
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "flask",
            "run",
            "--host=127.0.0.1",
            f"--port={flask_port}",
        ],
        env=env,
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for server to be ready
    if not wait_for_server(flask_port, timeout=15.0):
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        msg = (
            f"Flask server failed to start.\n"
            f"stdout: {stdout.decode()}\n"
            f"stderr: {stderr.decode()}"
        )
        raise RuntimeError(msg)

    yield f"http://127.0.0.1:{flask_port}"

    # Cleanup
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


# =============================================================================
# Starlette Server Fixtures
# =============================================================================


@pytest.fixture(scope="session")
def starlette_port() -> int:
    """Get a free port for the Starlette server."""
    return find_free_port()


@pytest.fixture(scope="session")
def starlette_server(
    starlette_port: int,
    tmp_path_factory: pytest.TempPathFactory,
) -> Generator[str, None, None]:
    """Start Starlette demo server for the test session.

    Yields the base URL of the server.
    """
    # Create test database directory
    test_dir = tmp_path_factory.mktemp("starlette_data")
    db_path = test_dir / "neozen.db"

    # Initialize database
    init_test_database_sync(db_path)

    # Copy database to demo's data directory
    demo_data_dir = Path(PROJECT_ROOT) / "demos" / "starlette" / "data"
    demo_data_dir.mkdir(exist_ok=True)
    demo_db_path = demo_data_dir / "neozen.db"
    if demo_db_path.exists():
        demo_db_path.unlink()
    shutil.copy(db_path, demo_db_path)

    env = os.environ.copy()

    # Start Starlette server via uvicorn
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "demos.starlette.app:app",
            "--host=127.0.0.1",
            f"--port={starlette_port}",
        ],
        env=env,
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for server to be ready
    if not wait_for_server(starlette_port, timeout=15.0):
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        msg = (
            f"Starlette server failed to start.\n"
            f"stdout: {stdout.decode()}\n"
            f"stderr: {stderr.decode()}"
        )
        raise RuntimeError(msg)

    yield f"http://127.0.0.1:{starlette_port}"

    # Cleanup
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


# =============================================================================
# Litestar Server Fixtures
# =============================================================================


@pytest.fixture(scope="session")
def litestar_port() -> int:
    """Get a free port for the Litestar server."""
    return find_free_port()


@pytest.fixture(scope="session")
def litestar_server(
    litestar_port: int,
    tmp_path_factory: pytest.TempPathFactory,
) -> Generator[str, None, None]:
    """Start Litestar demo server for the test session.

    Yields the base URL of the server.
    """
    # Create test database directory
    test_dir = tmp_path_factory.mktemp("litestar_data")
    db_path = test_dir / "neozen.db"

    # Initialize database
    init_test_database_sync(db_path)

    # Copy database to demo's data directory
    demo_data_dir = Path(PROJECT_ROOT) / "demos" / "litestar" / "data"
    demo_data_dir.mkdir(exist_ok=True)
    demo_db_path = demo_data_dir / "neozen.db"
    if demo_db_path.exists():
        demo_db_path.unlink()
    shutil.copy(db_path, demo_db_path)

    env = os.environ.copy()

    # Start Litestar server via uvicorn
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "demos.litestar.app:app",
            "--host=127.0.0.1",
            f"--port={litestar_port}",
        ],
        env=env,
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for server to be ready
    if not wait_for_server(litestar_port, timeout=15.0):
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        msg = (
            f"Litestar server failed to start.\n"
            f"stdout: {stdout.decode()}\n"
            f"stderr: {stderr.decode()}"
        )
        raise RuntimeError(msg)

    yield f"http://127.0.0.1:{litestar_port}"

    # Cleanup
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


# =============================================================================
# Playwright Fixtures
# =============================================================================


@pytest.fixture
def flask_page(page: Page, flask_server: str) -> Page:
    """Provide a Playwright page connected to the Flask server."""
    page.set_default_timeout(10000)  # 10 second timeout
    # Store base URL for convenience
    page.flask_base_url = flask_server  # type: ignore[attr-defined]
    return page


@pytest.fixture
def starlette_page(page: Page, starlette_server: str) -> Page:
    """Provide a Playwright page connected to the Starlette server."""
    page.set_default_timeout(10000)  # 10 second timeout
    # Store base URL for convenience
    page.starlette_base_url = starlette_server  # type: ignore[attr-defined]
    return page


@pytest.fixture
def litestar_page(page: Page, litestar_server: str) -> Page:
    """Provide a Playwright page connected to the Litestar server."""
    page.set_default_timeout(10000)  # 10 second timeout
    # Store base URL for convenience
    page.litestar_base_url = litestar_server  # type: ignore[attr-defined]
    return page


# =============================================================================
# Helper Functions
# =============================================================================


def generate_test_email() -> str:
    """Generate a unique test email address."""
    import secrets

    return f"test_{secrets.token_hex(8)}@example.com"


def register_user(page: Page, base_url: str, email: str, password: str) -> None:
    """Register a new user via the web form."""
    page.goto(f"{base_url}/register")
    page.fill('input[name="email"]', email)
    page.fill('input[name="password"]', password)
    page.fill('input[name="password_confirm"]', password)
    page.click('button[type="submit"]')
    # Wait for redirect to login page
    page.wait_for_url(f"{base_url}/login**", timeout=5000)


def login_user(page: Page, base_url: str, email: str, password: str) -> None:
    """Login a user via the web form."""
    page.goto(f"{base_url}/login")
    page.fill('input[name="email"]', email)
    page.fill('input[name="password"]', password)
    page.click('button[type="submit"]')
    # Wait for redirect to dashboard
    page.wait_for_url(f"{base_url}/dashboard**", timeout=5000)


def logout_user(page: Page, base_url: str) -> None:
    """Logout the current user."""
    # Find and click logout button/form
    page.goto(f"{base_url}/dashboard")
    logout_button = page.locator('button:has-text("Logout"), input[value="Logout"]')
    if logout_button.count() > 0:
        logout_button.first.click()
    else:
        # Try form submission
        page.locator('form[action*="logout"] button').first.click()
    page.wait_for_url(f"{base_url}/**", timeout=5000)
