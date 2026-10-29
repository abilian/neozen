"""Raw SQL repository implementation using the databases library.

This provides async database access without an ORM dependency.
Models are plain dataclasses that the user defines.

Note: This module builds queries as strings. The table name and primary
key are class attributes set by the developer; column names are checked
against the model's fields before they reach a query; values are always
parameterized.
"""

from __future__ import annotations

import dataclasses
import typing

from databases import Database

from neozen.core.repository import DoesNotExist, RepositoryProtocol

if typing.TYPE_CHECKING:
    from neozen.core.utils import DataclassInstance


class SQLRepository[Model: DataclassInstance]:
    """Repository implementation using raw SQL queries.

    This is a generic repository that works with any dataclass model.
    The user must define the table name and column mappings.

    Implements RepositoryProtocol for async database access.
    """

    model_type: type[Model]
    table_name: str
    primary_key: str = "id"

    def __init__(self, database: Database) -> None:
        """Initialize with a databases.Database connection.

        Args:
            database: The databases.Database instance.
        """
        self.database = database

    def _columns(self, names: typing.Iterable[str]) -> list[str]:
        """The names, if all are fields of the model: they go into the SQL."""
        names = list(names)
        fields = {f.name for f in dataclasses.fields(self.model_type)}
        if unknown := [n for n in names if n not in fields]:
            msg = f"Not a column of {self.table_name}: {', '.join(unknown)}"
            raise ValueError(msg)
        return names

    def _row_to_model(self, row: typing.Mapping[str, typing.Any]) -> Model:
        """Convert a database row to a model instance."""
        return self.model_type(**dict(row))

    def _build_where_clause(
        self, filters: dict[str, typing.Any]
    ) -> tuple[str, dict[str, typing.Any]]:
        """Build a WHERE clause from filters.

        Returns:
            Tuple of (where_clause, params).
        """
        if not filters:
            return "", {}

        conditions = [f"{key} = :{key}" for key in self._columns(filters)]
        where_clause = " WHERE " + " AND ".join(conditions)
        return where_clause, filters

    async def get_one_by(self, **filters: typing.Any) -> Model:
        """Get one model by filters, raises DoesNotExist if not found."""
        where_clause, params = self._build_where_clause(filters)
        query = f"SELECT * FROM {self.table_name}{where_clause} LIMIT 1"  # noqa: S608  # ken: names checked by _columns

        row = await self.database.fetch_one(query, params)
        if row is None:
            raise DoesNotExist
        return self._row_to_model(row)  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]

    async def get_many_by(
        self,
        *,
        offset: int = 0,
        limit: int | None = None,
        **filters: typing.Any,
    ) -> list[Model]:
        """Get multiple models by filters with pagination support."""
        where_clause, params = self._build_where_clause(filters)
        query = f"SELECT * FROM {self.table_name}{where_clause}"  # noqa: S608  # ken: names checked by _columns

        # SQLite requires LIMIT before OFFSET, so if we have offset but no limit,
        # use a very large limit
        if limit is not None:
            query += f" LIMIT {int(limit)}"
        elif offset > 0:
            # Use -1 for unlimited in SQLite
            query += " LIMIT -1"

        if offset > 0:
            query += f" OFFSET {int(offset)}"

        rows = await self.database.fetch_all(query, params)
        return [self._row_to_model(row) for row in rows]  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]

    async def count(self, **filters: typing.Any) -> int:
        """Count models matching the given filters."""
        where_clause, params = self._build_where_clause(filters)
        query = f"SELECT COUNT(*) as cnt FROM {self.table_name}{where_clause}"  # noqa: S608  # ken: names checked by _columns

        row = await self.database.fetch_one(query, params)
        return row["cnt"] if row else 0

    async def exists(self, **filters: typing.Any) -> bool:
        """Check if any model exists matching the given filters."""
        where_clause, params = self._build_where_clause(filters)
        query = f"SELECT 1 FROM {self.table_name}{where_clause} LIMIT 1"  # noqa: S608  # ken: names checked by _columns

        row = await self.database.fetch_one(query, params)
        return row is not None

    async def create(self, **data: typing.Any) -> Model:
        """Create a new model instance."""
        columns = ", ".join(self._columns(data))
        placeholders = ", ".join(f":{key}" for key in data)
        query = f"INSERT INTO {self.table_name} ({columns}) VALUES ({placeholders})"  # noqa: S608  # ken: names checked by _columns

        await self.database.execute(query, data)
        return self.model_type(**data)

    async def update_obj(self, obj: Model, **data: typing.Any) -> Model:
        """Update an existing model instance."""
        # Get the primary key value
        pk_value = getattr(obj, self.primary_key)

        # Build SET clause
        set_clause = ", ".join(f"{key} = :{key}" for key in self._columns(data))

        # Add primary key to params
        params = {**data, "pk_value": pk_value}

        query = f"UPDATE {self.table_name} SET {set_clause} WHERE {self.primary_key} = :pk_value"  # noqa: S608  # ken: names checked by _columns
        await self.database.execute(query, params)

        # Update the object in memory
        for key, value in data.items():
            setattr(obj, key, value)

        return obj

    async def delete(self, obj: Model) -> None:
        """Delete a model instance; DoesNotExist if it was already gone.

        Uses RETURNING (SQLite 3.35+, PostgreSQL), since `databases` does not
        report a row count for DELETE.
        """
        pk_value = getattr(obj, self.primary_key)
        query = (
            f"DELETE FROM {self.table_name} WHERE {self.primary_key} = :pk_value"  # noqa: S608  # ken: names checked by _columns
            f" RETURNING {self.primary_key}"
        )
        if await self.database.fetch_one(query, {"pk_value": pk_value}) is None:
            raise DoesNotExist


# Type-check that SQLRepository implements the protocol
def _check_protocol_compliance() -> None:
    """Static check that SQLRepository implements RepositoryProtocol."""

    @dataclasses.dataclass
    class DummyModel:
        id: str

    repo: RepositoryProtocol[DummyModel] = SQLRepository(Database("sqlite:///test.db"))
    _ = repo  # Avoid unused variable warning
