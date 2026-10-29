"""Create or check the database schema when an app starts."""

from __future__ import annotations

from typing import TYPE_CHECKING

from alembic.runtime.migration import MigrationContext
from sqlalchemy import Column, MetaData, PrimaryKeyConstraint, String, Table

# The package's __init__, imported with this module, registers every table.
from neozen.storage.sqlalchemy.base import Base

if TYPE_CHECKING:
    from sqlalchemy import Connection
    from sqlalchemy.ext.asyncio import AsyncEngine

# The Alembic revision the models describe. A test keeps it equal to the
# head of `migrations/versions/`.
SCHEMA_REVISION = "0_9_oauth_schema"

# Alembic's own bookkeeping table, as `alembic stamp` creates it.
_VERSION_TABLE = Table(
    "alembic_version",
    MetaData(),
    Column("version_num", String(32), nullable=False),
    PrimaryKeyConstraint("version_num", name="alembic_version_pkc"),
)


class SchemaOutOfDateError(RuntimeError):
    """The database was migrated to another revision than this NeoZen's."""


async def prepare_schema(engine: AsyncEngine) -> None:
    """Make the database ready for this version of NeoZen.

    A new database is created from the models and stamped with
    `SCHEMA_REVISION`, so `alembic upgrade head` works on it later. One
    created before the stamp existed gets its missing tables, then the
    stamp. One stamped with another revision is refused: run the
    migrations first.
    """
    async with engine.begin() as conn:
        await conn.run_sync(_prepare)


def _prepare(conn: Connection) -> None:
    current = MigrationContext.configure(conn).get_current_revision()
    if current == SCHEMA_REVISION:
        return
    if current is not None:
        msg = (
            f"The database schema is at revision {current!r}, this NeoZen "
            f"needs {SCHEMA_REVISION!r}: run `alembic upgrade head`."
        )
        raise SchemaOutOfDateError(msg)
    Base.metadata.create_all(conn)
    _VERSION_TABLE.create(conn, checkfirst=True)
    conn.execute(_VERSION_TABLE.insert().values(version_num=SCHEMA_REVISION))


__all__ = ["SCHEMA_REVISION", "SchemaOutOfDateError", "prepare_schema"]
