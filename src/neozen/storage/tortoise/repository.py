"""Tortoise ORM repository implementation.

Tortoise ORM is an async-native ORM, so all operations are natively async.
"""

from __future__ import annotations

import typing

from tortoise import Model
from tortoise.exceptions import DoesNotExist as TortoiseDoesNotExist

from neozen.core.repository import DoesNotExist, RepositoryProtocol


class TortoiseRepository[ModelT: Model]:
    """Repository implementation for Tortoise ORM models.

    Implements RepositoryProtocol using Tortoise ORM's native async operations.
    """

    model_type: type[ModelT]

    async def get_one_by(self, **filters: typing.Any) -> ModelT:
        """Get one model by filters, raises DoesNotExist if not found."""
        try:
            return await self.model_type.get(**filters)
        except TortoiseDoesNotExist as e:
            raise DoesNotExist from e

    async def get_many_by(
        self,
        *,
        offset: int = 0,
        limit: int | None = None,
        **filters: typing.Any,
    ) -> list[ModelT]:
        """Get multiple models by filters with pagination support."""
        query = self.model_type.filter(**filters)
        if offset > 0:
            query = query.offset(offset)
        if limit is not None:
            query = query.limit(limit)
        return await query.all()

    async def count(self, **filters: typing.Any) -> int:
        """Count models matching the given filters."""
        return await self.model_type.filter(**filters).count()

    async def exists(self, **filters: typing.Any) -> bool:
        """Check if any model exists matching the given filters."""
        return await self.model_type.filter(**filters).exists()

    async def create(self, **data: typing.Any) -> ModelT:
        """Create a new model instance."""
        return await self.model_type.create(**data)

    async def update_obj(self, obj: ModelT, **data: typing.Any) -> ModelT:
        """Update an existing model instance."""
        for key, value in data.items():
            setattr(obj, key, value)
        await obj.save()
        return obj

    async def delete(self, obj: ModelT) -> None:
        """Delete a model instance."""
        await obj.delete()


# Type-check that TortoiseRepository implements the protocol
def _check_protocol_compliance() -> None:
    """Static check that TortoiseRepository implements RepositoryProtocol."""
    # This is for static type checking only
    repo: RepositoryProtocol[Model] = TortoiseRepository()
    _ = repo  # Avoid unused variable warning
