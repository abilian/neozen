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

import anyio
import pytest
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

# Ensure all model modules are imported so Base.metadata sees every table
import neozen.storage.sqlalchemy  # noqa: F401  side-effect: registers every table
from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.schema import (
    SCHEMA_REVISION,
    SchemaOutOfDateError,
    prepare_schema,
)

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


def _code_columns(url: str) -> dict[str, dict]:
    engine = create_engine(url)
    return {
        c["name"]: c for c in inspect(engine).get_columns("oauth_authorization_codes")
    }


class TestOAuthSchemaRevision:
    def test_fresh_database_has_current_oauth_schema(
        self, alembic_db_url: str, alembic_cfg: Config
    ) -> None:
        command.upgrade(alembic_cfg, "head")
        tables = set(inspect(create_engine(alembic_db_url)).get_table_names())
        assert {"oauth_clients", "oauth_authorization_codes"} <= tables
        columns = _code_columns(alembic_db_url)
        assert "nonce" in columns
        assert columns["code_challenge"]["nullable"]

    def test_older_database_is_brought_up_to_date(
        self, alembic_db_url: str, alembic_cfg: Config
    ) -> None:
        """OAuth tables made by create_all before 0.9, stamped at the baseline."""
        engine = create_engine(alembic_db_url)
        codes = Base.metadata.tables["oauth_authorization_codes"]
        Base.metadata.create_all(
            engine, tables=[t for t in Base.metadata.sorted_tables if t is not codes]
        )
        with engine.begin() as conn:
            conn.exec_driver_sql(
                "CREATE TABLE oauth_authorization_codes ("
                " code VARCHAR(64) PRIMARY KEY,"
                " client_id VARCHAR REFERENCES oauth_clients (client_id),"
                " subject_id VARCHAR(128) NOT NULL, expires_at DATETIME NOT NULL,"
                " response_type VARCHAR(128) NOT NULL, redirect_uri TEXT,"
                " scope TEXT NOT NULL, code_challenge VARCHAR(128) NOT NULL,"
                " code_challenge_method VARCHAR(128) NOT NULL)"
            )
        command.stamp(alembic_cfg, "1_0_baseline")

        command.upgrade(alembic_cfg, "head")

        columns = _code_columns(alembic_db_url)
        assert "nonce" in columns
        assert columns["code_challenge"]["nullable"]
        assert columns["code_challenge_method"]["nullable"]


class TestPrepareSchema:
    """What an app does to the database when it starts."""

    def test_revision_is_the_migrations_head(self, alembic_cfg: Config) -> None:
        assert ScriptDirectory.from_config(alembic_cfg).get_current_head() == (
            SCHEMA_REVISION
        )

    def test_new_database_is_stamped_and_stays_upgradable(
        self, alembic_db_url: str, alembic_cfg: Config
    ) -> None:
        anyio.run(prepare_schema, _async_engine(alembic_db_url))

        command.upgrade(alembic_cfg, "head")  # a no-op, not a clash

        assert _revision(alembic_db_url) == SCHEMA_REVISION

    def test_database_at_an_older_revision_is_refused(
        self, alembic_db_url: str, alembic_cfg: Config
    ) -> None:
        command.upgrade(alembic_cfg, "1_0_baseline")

        with pytest.raises(SchemaOutOfDateError, match="alembic upgrade head"):
            anyio.run(prepare_schema, _async_engine(alembic_db_url))


def _async_engine(url: str) -> AsyncEngine:
    return create_async_engine(url.replace("sqlite://", "sqlite+aiosqlite://"))


def _revision(url: str) -> str | None:
    with create_engine(url).connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()
