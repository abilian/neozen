"""Raw SQL repository implementation using the databases library.

This provides async database access without an ORM dependency.
Models are plain dataclasses that the user defines.

Note: This module intentionally uses string-based query construction
with table_name, primary_key, and column names. These are defined as
class attributes by the developer, not user input, so SQL injection
is not a concern. The actual values are always parameterized.
"""

from __future__ import annotations

import dataclasses
import typing

from databases import Database

from neozen.core.repository import DoesNotExist, RepositoryProtocol


class SQLRepository[Model]:
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

        conditions = [f"{key} = :{key}" for key in filters]
        where_clause = " WHERE " + " AND ".join(conditions)
        return where_clause, filters

    async def get_one_by(self, **filters: typing.Any) -> Model:
        """Get one model by filters, raises DoesNotExist if not found."""
        where_clause, params = self._build_where_clause(filters)
        query = f"SELECT * FROM {self.table_name}{where_clause} LIMIT 1"  # noqa: S608

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
        query = f"SELECT * FROM {self.table_name}{where_clause}"  # noqa: S608

        # SQLite requires LIMIT before OFFSET, so if we have offset but no limit,
        # use a very large limit
        if limit is not None:
            query += f" LIMIT {limit}"
        elif offset > 0:
            # Use -1 for unlimited in SQLite
            query += " LIMIT -1"

        if offset > 0:
            query += f" OFFSET {offset}"

        rows = await self.database.fetch_all(query, params)
        return [self._row_to_model(row) for row in rows]  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]

    async def count(self, **filters: typing.Any) -> int:
        """Count models matching the given filters."""
        where_clause, params = self._build_where_clause(filters)
        query = f"SELECT COUNT(*) as cnt FROM {self.table_name}{where_clause}"  # noqa: S608

        row = await self.database.fetch_one(query, params)
        return row["cnt"] if row else 0

    async def exists(self, **filters: typing.Any) -> bool:
        """Check if any model exists matching the given filters."""
        where_clause, params = self._build_where_clause(filters)
        query = f"SELECT 1 FROM {self.table_name}{where_clause} LIMIT 1"  # noqa: S608

        row = await self.database.fetch_one(query, params)
        return row is not None

    async def create(self, **data: typing.Any) -> Model:
        """Create a new model instance."""
        columns = ", ".join(data.keys())
        placeholders = ", ".join(f":{key}" for key in data)
        query = f"INSERT INTO {self.table_name} ({columns}) VALUES ({placeholders})"  # noqa: S608

        await self.database.execute(query, data)
        return self.model_type(**data)

    async def update_obj(self, obj: Model, **data: typing.Any) -> Model:
        """Update an existing model instance."""
        # Get the primary key value
        pk_value = getattr(obj, self.primary_key)

        # Build SET clause
        set_clause = ", ".join(f"{key} = :{key}" for key in data)

        # Add primary key to params
        params = {**data, "pk_value": pk_value}

        query = f"UPDATE {self.table_name} SET {set_clause} WHERE {self.primary_key} = :pk_value"  # noqa: S608
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
            f"DELETE FROM {self.table_name} WHERE {self.primary_key} = :pk_value"  # noqa: S608
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
