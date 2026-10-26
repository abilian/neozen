"""Alembic environment for NeoZen.

Reads the database URL from `NEOZEN_DATABASE_URL` (with the
NEOZEN_DATABASE_URL_FILE secret-mount variant), then runs migrations
in either offline (SQL emit) or online (live engine) mode.

Sync engine is used here on purpose: Alembic's online runner expects
a sync Connection. The application uses async engines at runtime —
this is the only place we use the sync API, and only briefly during
schema changes.
"""

from __future__ import annotations

import os
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Import all models so Base.metadata reflects every table.
# This is the entire SQLAlchemy schema NeoZen ships.
import neozen.storage.sqlalchemy  # noqa: F401  side-effect: registers every table
from neozen.storage.sqlalchemy.base import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_url() -> str:
    """Resolve the database URL from env, file, or alembic.ini."""
    # 1. NEOZEN_DATABASE_URL_FILE (secret mount)
    file_var = os.environ.get("NEOZEN_DATABASE_URL_FILE")
    if file_var:
        path = Path(file_var)
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
    # 2. NEOZEN_DATABASE_URL
    env_url = os.environ.get("NEOZEN_DATABASE_URL")
    if env_url:
        return _to_sync_url(env_url)
    # 3. Fallback to alembic.ini sqlalchemy.url (usually empty)
    ini_url = config.get_main_option("sqlalchemy.url")
    if ini_url:
        return _to_sync_url(ini_url)
    return "sqlite:///data/neozen.db"


def _to_sync_url(url: str) -> str:
    """Map an async-driver URL to its sync equivalent for Alembic.

    Alembic's online runner uses a sync engine. NeoZen normally runs
    on async drivers (`sqlite+aiosqlite`, `postgresql+asyncpg`, …).
    We translate to the sync driver names here so operators don't
    have to maintain a separate URL just for migrations.
    """
    mapping = {
        "sqlite+aiosqlite": "sqlite",
        "postgresql+asyncpg": "postgresql+psycopg",
        "postgresql+psycopg_async": "postgresql+psycopg",
        "mysql+aiomysql": "mysql+pymysql",
    }
    for async_prefix, sync_prefix in mapping.items():
        if url.startswith(async_prefix + "://"):
            return sync_prefix + url[len(async_prefix) :]
    return url


def run_migrations_offline() -> None:
    """Generate SQL without connecting to a database."""
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    cfg_section = config.get_section(config.config_ini_section, {}) or {}
    cfg_section["sqlalchemy.url"] = _get_url()

    connectable = engine_from_config(
        cfg_section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
