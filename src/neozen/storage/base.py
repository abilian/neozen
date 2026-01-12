"""Base storage protocol for NeoZen.

This module defines the storage abstraction that repositories implement.
"""

from __future__ import annotations

import typing

from neozen.core.exceptions import NeoZenException


class StorageError(NeoZenException):
    """Base exception for all storage-related errors."""


class DoesNotExist(StorageError):
    """Error raised when a requested object does not exist in storage."""

    def __init__(self) -> None:
        message = "The requested object does not exist in storage."
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


# Backwards compatibility alias
StorageProtocol = RepositoryProtocol


__all__ = [
    "DoesNotExist",
    "RepositoryProtocol",
    "StorageError",
    "StorageProtocol",
]
