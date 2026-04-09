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


@typing.runtime_checkable
class ReadableRepositoryProtocol[Model](typing.Protocol):
    """Protocol for read-only repository operations.

    Consumers that only need to look up objects can depend on this
    narrower interface instead of the full RepositoryProtocol.
    """

    async def get_one_by(self, **filters: typing.Any) -> Model:
        """Retrieve an object by arbitrary filters.

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

        Returns:
            A list of matching objects.
        """
        ...

    async def count(self, **filters: typing.Any) -> int:
        """Count objects matching the given filters."""
        ...

    async def exists(self, **filters: typing.Any) -> bool:
        """Check if any object exists matching the given filters."""
        ...


@typing.runtime_checkable
class WritableRepositoryProtocol[Model](typing.Protocol):
    """Protocol for write repository operations.

    Consumers that need to create/update/delete objects can depend
    on this interface.
    """

    async def create(self, **data: typing.Any) -> Model:
        """Create a new object.

        Returns:
            The created object.
        """
        ...

    async def update_obj(self, obj: Model, **data: typing.Any) -> Model:
        """Update an existing object.

        Returns:
            The updated object.
        """
        ...

    async def delete(self, obj: Model) -> None:
        """Delete an object."""
        ...


class RepositoryProtocol[Model](
    ReadableRepositoryProtocol[Model],
    WritableRepositoryProtocol[Model],
    typing.Protocol,
):
    """Full repository protocol combining read and write operations.

    This is the original interface. Existing code that depends on
    RepositoryProtocol continues to work unchanged.
    """

    model_type: type[Model]


__all__ = [
    "DoesNotExist",
    "ReadableRepositoryProtocol",
    "RepositoryError",
    "RepositoryProtocol",
    "WritableRepositoryProtocol",
]
