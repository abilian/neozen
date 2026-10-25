"""Integration tests for `neozen serve` (Stage 17 reference deployment).

Covers:
- ServeConfig env loading (including the _FILE secret pattern)
- Bootstrap admin generation (idempotent + secure)
- Health endpoints (/healthz liveness, /readyz readiness)
- Smoke test that the unified serve app boots and admin routes work

These tests do NOT spin up uvicorn — they exercise the in-process
Litestar app directly via TestClient.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from litestar.testing import TestClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from neozen.serve import (
    BOOTSTRAP_NOTICE_BANNER,
    ServeConfig,
    bootstrap_admin_if_needed,
    build_serve_app,
    generate_bootstrap_password,
)
from neozen.serve.bootstrap import format_bootstrap_notice
from neozen.storage.sqlalchemy.base import Base

from .conftest import superadmin_client

# =============================================================================
# ServeConfig
# =============================================================================


class TestServeConfig:
    def test_defaults(self) -> None:
        config = ServeConfig.from_env(env={})
        assert config.bind_host == "0.0.0.0"  # noqa: S104
        assert config.bind_port == 8000
        assert config.workers == 1
        assert config.log_level == "INFO"
        assert config.bootstrap_admin is True
        assert config.bootstrap_admin_email == "admin@localhost"
        assert config.cookie_secure is True

    def test_cookie_secure_can_be_turned_off(self) -> None:
        config = ServeConfig.from_env(env={"NEOZEN_COOKIE_SECURE": "false"})
        assert config.cookie_secure is False

    def test_env_overrides(self) -> None:
        config = ServeConfig.from_env(
            env={
                "NEOZEN_DATABASE_URL": "postgresql+asyncpg://x/y",
                "NEOZEN_SECRET_KEY": "real-secret",
                "NEOZEN_BIND_HOST": "127.0.0.1",
                "NEOZEN_BIND_PORT": "9999",
                "NEOZEN_WORKERS": "4",
                "NEOZEN_LOG_LEVEL": "DEBUG",
                "NEOZEN_BOOTSTRAP_ADMIN": "false",
                "NEOZEN_BOOTSTRAP_ADMIN_EMAIL": "ops@example.com",
            }
        )
        assert config.db_url == "postgresql+asyncpg://x/y"
        assert config.secret_key == "real-secret"
        assert config.bind_host == "127.0.0.1"
        assert config.bind_port == 9999
        assert config.workers == 4
        assert config.log_level == "DEBUG"
        assert config.bootstrap_admin is False
        assert config.bootstrap_admin_email == "ops@example.com"

    def test_secret_file_variant(self, tmp_path: Path) -> None:
        secret_file = tmp_path / "secret"
        secret_file.write_text("from-file-secret\n", encoding="utf-8")
        config = ServeConfig.from_env(env={"NEOZEN_SECRET_KEY_FILE": str(secret_file)})
        assert config.secret_key == "from-file-secret"

    def test_env_var_takes_precedence_over_file(self, tmp_path: Path) -> None:
        secret_file = tmp_path / "secret"
        secret_file.write_text("from-file", encoding="utf-8")
        config = ServeConfig.from_env(
            env={
                "NEOZEN_SECRET_KEY": "from-env",
                "NEOZEN_SECRET_KEY_FILE": str(secret_file),
            }
        )
        assert config.secret_key == "from-env"

    def test_validate_warns_on_default_secret(self) -> None:
        config = ServeConfig.from_env(env={})
        warnings = config.validate()
        assert any("NEOZEN_SECRET_KEY" in w for w in warnings)

    def test_validate_clean_with_real_secret(self) -> None:
        config = ServeConfig.from_env(env={"NEOZEN_SECRET_KEY": "production-secret"})
        assert config.validate() == []

    def test_validate_warns_on_bad_port(self) -> None:
        config = ServeConfig.from_env(
            env={"NEOZEN_SECRET_KEY": "x", "NEOZEN_BIND_PORT": "99999"}
        )
        warnings = config.validate()
        assert any("port" in w.lower() for w in warnings)

    def test_bool_env_variants(self) -> None:
        for value in ("true", "True", "1", "yes", "on"):
            cfg = ServeConfig.from_env(env={"NEOZEN_BOOTSTRAP_ADMIN": value})
            assert cfg.bootstrap_admin is True, value
        for value in ("false", "False", "0", "no", "off"):
            cfg = ServeConfig.from_env(env={"NEOZEN_BOOTSTRAP_ADMIN": value})
            assert cfg.bootstrap_admin is False, value


# =============================================================================
# Bootstrap
# =============================================================================


class TestGenerateBootstrapPassword:
    def test_default_length(self) -> None:
        pw = generate_bootstrap_password()
        assert len(pw) == 24

    def test_custom_length(self) -> None:
        pw = generate_bootstrap_password(length=32)
        assert len(pw) == 32

    def test_rejects_too_short(self) -> None:
        with pytest.raises(ValueError, match="shorter than 16"):
            generate_bootstrap_password(length=8)

    def test_uses_alphanumeric_alphabet(self) -> None:
        pw = generate_bootstrap_password()
        assert pw.isalnum()

    def test_passwords_are_unique(self) -> None:
        passwords = {generate_bootstrap_password() for _ in range(20)}
        assert len(passwords) == 20  # collision odds are negligible


@pytest.fixture
async def session_factory() -> AsyncGenerator[async_sessionmaker, None]:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


@pytest.mark.anyio
class TestBootstrapAdminIfNeeded:
    async def test_creates_when_no_subjects_exist(
        self, session_factory: async_sessionmaker
    ) -> None:
        result = await bootstrap_admin_if_needed(
            session_factory, admin_email="admin@example.com"
        )
        assert result.created is True
        assert result.email == "admin@example.com"
        assert result.password is not None
        assert len(result.password) == 24

    async def test_idempotent_when_subjects_already_exist(
        self, session_factory: async_sessionmaker
    ) -> None:
        # First call creates
        result_1 = await bootstrap_admin_if_needed(
            session_factory, admin_email="admin@example.com"
        )
        assert result_1.created is True

        # Second call sees the existing subject and skips
        result_2 = await bootstrap_admin_if_needed(
            session_factory, admin_email="admin@example.com"
        )
        assert result_2.created is False
        assert result_2.password is None
        assert result_2.reason is not None
        assert "already exist" in result_2.reason


class TestFormatBootstrapNotice:
    def test_includes_marker_banner(self) -> None:
        from neozen.serve.bootstrap import BootstrapResult  # noqa: PLC0415

        result = BootstrapResult(created=True, email="admin@x.com", password="pw123")
        notice = format_bootstrap_notice(result)
        assert BOOTSTRAP_NOTICE_BANNER in notice
        assert "admin@x.com" in notice
        assert "pw123" in notice

    def test_empty_when_not_created(self) -> None:
        from neozen.serve.bootstrap import BootstrapResult  # noqa: PLC0415

        result = BootstrapResult(created=False, reason="exists")
        notice = format_bootstrap_notice(result)
        assert notice == ""


# =============================================================================
# Serve app
# =============================================================================


@pytest.fixture
def serve_client() -> TestClient:
    config = ServeConfig(
        db_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-not-default",
        bootstrap_admin=False,  # don't pollute test stdout
    )
    return superadmin_client(build_serve_app(config))


class TestServeAppHealthChecks:
    def test_healthz_returns_200(self, serve_client: TestClient) -> None:
        with serve_client as client:
            response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_readyz_returns_200_when_db_reachable(
        self, serve_client: TestClient
    ) -> None:
        with serve_client as client:
            response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}


class TestServeAppMountsAdmin:
    def test_session_cookie_is_secure(self, serve_client: TestClient) -> None:
        with serve_client as client:
            response = client.post(
                "/login",
                data={"email": "nobody@example.com", "password": "x"},
                follow_redirects=False,
            )
        assert "secure" in response.headers.get("set-cookie", "").lower()

    def test_admin_dashboard_reachable(self, serve_client: TestClient) -> None:
        with serve_client as client:
            response = client.get("/")
        assert response.status_code == 200
        # Dashboard polling partial should be in the response
        assert 'id="dashboard-stats"' in response.text

    def test_admin_audit_reachable(self, serve_client: TestClient) -> None:
        with serve_client as client:
            response = client.get("/audit")
        assert response.status_code == 200
        assert 'id="audit-log-table"' in response.text

    def test_admin_security_reachable(self, serve_client: TestClient) -> None:
        with serve_client as client:
            response = client.get("/security")
        assert response.status_code == 200
        assert 'id="security-stats"' in response.text

    def test_admin_users_export_reachable(self, serve_client: TestClient) -> None:
        with serve_client as client:
            response = client.get("/users/export")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")


class TestServeAppBootstrapIntegration:
    def test_first_request_after_bootstrap_finds_admin(
        self,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """Booting with bootstrap_admin=True creates an admin and prints
        the credentials to stdout exactly once."""
        config = ServeConfig(
            db_url="sqlite+aiosqlite:///:memory:",
            secret_key="test-secret-not-default",
            bootstrap_admin=True,
            bootstrap_admin_email="bootstrap@example.com",
        )
        app = build_serve_app(config)
        with TestClient(app=app, raise_server_exceptions=True) as client:
            response = client.get("/healthz")
        assert response.status_code == 200

        # Bootstrap notice should be in stdout
        captured = capsys.readouterr()
        assert BOOTSTRAP_NOTICE_BANNER in captured.out
        assert "bootstrap@example.com" in captured.out
