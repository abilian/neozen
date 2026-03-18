"""Repository protocol and exceptions for NeoZen.

This module defines the repository abstraction that storage backends implement.
Core modules should import from here, not from neozen.storage.
"""

from __future__ import annotations

import typing

from neozen.core.exceptions import NeoZenException


class RepositoryError(NeoZenException):
    """Base exception for all repository-related errors."""


class DoesNotExist(RepositoryError):
    """Error raised when a requested object does not exist."""

    def __init__(self) -> None:
        message = "The requested object does not exist."
        super().__init__(message)


class RepositoryProtocol[Model](typing.Protocol):
    """Protocol for repositories.

    This protocol defines the interface that all repositories must implement.
    It's used for type checking and enables mock implementations for testing.
    """

    model_type: type[Model]

    async def get_one_by(self, **filters: typing.Any) -> Model:
        """Retrieve an object by arbitrary filters.

        Args:
            **filters: A set of key-value pairs to filter the query.

        Raises:
            DoesNotExist: If the object does not exist.

        Returns:
            The retrieved object.
        """
        ...

    async def get_many_by(
        self,
        *,
        offset: int = 0,
        limit: int | None = None,
        **filters: typing.Any,
    ) -> list[Model]:
        """Retrieve multiple objects by arbitrary filters.

        Args:
            offset: Number of records to skip (for pagination).
            limit: Maximum number of records to return (None for no limit).
            **filters: A set of key-value pairs to filter the query.

        Returns:
            A list of matching objects.
        """
        ...

    async def count(self, **filters: typing.Any) -> int:
        """Count objects matching the given filters.

        Args:
            **filters: A set of key-value pairs to filter the query.

        Returns:
            The count of matching objects.
        """
        ...

    async def exists(self, **filters: typing.Any) -> bool:
        """Check if any object exists matching the given filters.

        Args:
            **filters: A set of key-value pairs to filter the query.

        Returns:
            True if at least one matching object exists, False otherwise.
        """
        ...

    async def create(self, **data: typing.Any) -> Model:
        """Create a new object.

        Args:
            **data: The object data to create.

        Returns:
            The created object.
        """
        ...

    async def update_obj(self, obj: Model, **data: typing.Any) -> Model:
        """Update an existing object.

        Args:
            obj: The object to update.
            **data: The data to update the object with.

        Returns:
            The updated object.
        """
        ...

    async def delete(self, obj: Model) -> None:
        """Delete an object.

        Args:
            obj: The object to delete.
        """
        ...


__all__ = [
    "DoesNotExist",
    "RepositoryError",
    "RepositoryProtocol",
]
