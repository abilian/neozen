"""Tests for the Alembic 1.0 baseline migration.

The baseline delegates to ``Base.metadata.create_all``, so the schema
it produces should match what the application code declares. These
tests verify:

1. ``alembic upgrade head`` on an empty DB succeeds
2. The resulting tables match ``Base.metadata.create_all`` (modulo
   Alembic's own ``alembic_version`` bookkeeping table)
3. ``downgrade base`` cleanly removes everything except
   ``alembic_version``
4. Upgrade is idempotent (running it twice is a no-op)
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

# Ensure all model modules are imported so Base.metadata sees every table
from neozen.storage.sqlalchemy import models, security_models  # noqa: F401
from neozen.storage.sqlalchemy.base import Base

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"


@pytest.fixture
def alembic_db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Point alembic at a fresh on-disk SQLite DB for the test.

    Uses on-disk (not :memory:) so the alembic process — which opens
    its own engine — can see the same DB.
    """
    db_path = tmp_path / "alembic_test.db"
    url = f"sqlite:///{db_path}"
    monkeypatch.setenv("NEOZEN_DATABASE_URL", url)
    return url


@pytest.fixture
def alembic_cfg() -> Config:
    return Config(str(ALEMBIC_INI))


class TestBaselineUpgrade:
    def test_upgrade_head_succeeds(
        self, alembic_db_url: str, alembic_cfg: Config
    ) -> None:
        command.upgrade(alembic_cfg, "head")
        engine = create_engine(alembic_db_url)
        tables = set(inspect(engine).get_table_names())
        # alembic bookkeeping + at least the core tables
        assert "alembic_version" in tables
        assert "subjects" in tables
        assert "sessions" in tables

    def test_baseline_matches_create_all(
        self, alembic_db_url: str, alembic_cfg: Config, tmp_path: Path
    ) -> None:
        # Run alembic on the test DB
        command.upgrade(alembic_cfg, "head")
        alembic_engine = create_engine(alembic_db_url)
        alembic_tables = set(inspect(alembic_engine).get_table_names())
        alembic_tables.discard("alembic_version")

        # Run create_all on a parallel DB
        create_all_db = tmp_path / "create_all.db"
        ca_engine = create_engine(f"sqlite:///{create_all_db}")
        Base.metadata.create_all(bind=ca_engine)
        create_all_tables = set(inspect(ca_engine).get_table_names())

        assert alembic_tables == create_all_tables, (
            f"only in alembic: {alembic_tables - create_all_tables}, "
            f"only in create_all: {create_all_tables - alembic_tables}"
        )

    def test_upgrade_is_idempotent(
        self, alembic_db_url: str, alembic_cfg: Config
    ) -> None:
        command.upgrade(alembic_cfg, "head")
        # Running again should succeed without changes
        command.upgrade(alembic_cfg, "head")
        engine = create_engine(alembic_db_url)
        assert "subjects" in set(inspect(engine).get_table_names())


class TestBaselineDowngrade:
    def test_downgrade_to_base_removes_application_tables(
        self, alembic_db_url: str, alembic_cfg: Config
    ) -> None:
        command.upgrade(alembic_cfg, "head")
        command.downgrade(alembic_cfg, "base")

        engine = create_engine(alembic_db_url)
        tables = set(inspect(engine).get_table_names())
        # alembic_version stays (its own bookkeeping)
        assert tables <= {"alembic_version"}

    def test_downgrade_then_upgrade_restores_schema(
        self, alembic_db_url: str, alembic_cfg: Config
    ) -> None:
        command.upgrade(alembic_cfg, "head")
        command.downgrade(alembic_cfg, "base")
        command.upgrade(alembic_cfg, "head")

        engine = create_engine(alembic_db_url)
        tables = set(inspect(engine).get_table_names())
        assert "subjects" in tables
        assert "alembic_version" in tables


class TestBaselineMetadata:
    def test_url_translation_async_to_sync(self) -> None:
        """env.py's _to_sync_url converts async drivers to sync."""
        # We import the function directly from the env module so the
        # behaviour is verified, not just exercised end-to-end.
        import importlib.util

        env_path = REPO_ROOT / "migrations" / "env.py"
        spec = importlib.util.spec_from_file_location("alembic_env_test", env_path)
        assert spec is not None
        # Skip module execution — we want to import the function only.
        # Read the source and exec just the helper.
        source = env_path.read_text(encoding="utf-8")
        # Extract the function block — keeps the test independent of
        # alembic.context import side effects.
        ns: dict = {}
        # Pick out the helper between its def line and the next def line
        start = source.index("def _to_sync_url")
        end = source.index("def run_migrations_offline", start)
        exec(source[start:end], ns)  # noqa: S102 — unit-extract helper
        f = ns["_to_sync_url"]

        assert f("sqlite+aiosqlite:///x.db") == "sqlite:///x.db"
        assert f("postgresql+asyncpg://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
        assert f("postgresql://u:p@h/db") == "postgresql://u:p@h/db"
