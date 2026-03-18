"""Peewee repository implementation.

Peewee is a synchronous ORM, so we wrap all database operations
with asyncio.to_thread() to run them in a thread pool.
"""

from __future__ import annotations

import asyncio
import typing
from functools import partial

import peewee

from neozen.core.repository import DoesNotExist, RepositoryProtocol


class PeeweeRepository[Model: peewee.Model]:
    """Repository implementation for Peewee models.

    Implements RepositoryProtocol by wrapping Peewee's synchronous
    operations in asyncio.to_thread() calls.
    """

    model_type: type[Model]

    def __init__(self, database: peewee.Database) -> None:
        """Initialize with a Peewee database connection.

        Args:
            database: The Peewee database instance.
        """
        self.database = database

    async def _run_sync(
        self,
        func: typing.Callable[..., typing.Any],
        *args: typing.Any,
        **kwargs: typing.Any,
    ) -> typing.Any:
        """Run a synchronous function in a thread pool."""
        return await asyncio.to_thread(partial(func, *args, **kwargs))

    async def get_one_by(self, **filters: typing.Any) -> Model:
        """Get one model by filters, raises DoesNotExist if not found."""

        def _get_one() -> Model:
            try:
                return self.model_type.get(**filters)
            except peewee.DoesNotExist as e:
                raise DoesNotExist from e

        return await self._run_sync(_get_one)

    async def get_many_by(
        self,
        *,
        offset: int = 0,
        limit: int | None = None,
        **filters: typing.Any,
    ) -> list[Model]:
        """Get multiple models by filters with pagination support."""

        def _get_many() -> list[Model]:
            query = self.model_type.select()
            if filters:
                for key, value in filters.items():
                    field = getattr(self.model_type, key)
                    query = query.where(field == value)
            if offset > 0:
                query = query.offset(offset)
            if limit is not None:
                query = query.limit(limit)
            return list(query)

        return await self._run_sync(_get_many)

    async def count(self, **filters: typing.Any) -> int:
        """Count models matching the given filters."""

        def _count() -> int:
            query = self.model_type.select()
            if filters:
                for key, value in filters.items():
                    field = getattr(self.model_type, key)
                    query = query.where(field == value)
            return query.count()

        return await self._run_sync(_count)

    async def exists(self, **filters: typing.Any) -> bool:
        """Check if any model exists matching the given filters."""

        def _exists() -> bool:
            query = self.model_type.select()
            if filters:
                for key, value in filters.items():
                    field = getattr(self.model_type, key)
                    query = query.where(field == value)
            return query.exists()

        return await self._run_sync(_exists)

    async def create(self, **data: typing.Any) -> Model:
        """Create a new model instance."""

        def _create() -> Model:
            return self.model_type.create(**data)

        return await self._run_sync(_create)

    async def update_obj(self, obj: Model, **data: typing.Any) -> Model:
        """Update an existing model instance."""

        def _update() -> Model:
            for key, value in data.items():
                setattr(obj, key, value)
            obj.save()
            return obj

        return await self._run_sync(_update)

    async def delete(self, obj: Model) -> None:
        """Delete a model instance."""

        def _delete() -> None:
            obj.delete_instance()

        await self._run_sync(_delete)


# Type-check that PeeweeRepository implements the protocol
def _check_protocol_compliance() -> None:
    """Static check that PeeweeRepository implements RepositoryProtocol."""
    repo: RepositoryProtocol[peewee.Model] = PeeweeRepository(
        peewee.SqliteDatabase(":memory:")
    )
    _ = repo  # Avoid unused variable warning
