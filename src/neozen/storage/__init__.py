"""Storage abstraction for NeoZen.

This package provides storage backends for NeoZen models.
The base module defines the RepositoryProtocol that all repositories implement.

Available backends:
- sqlalchemy: SQLAlchemy 2.0 with async support via Advanced-Alchemy
"""

from __future__ import annotations

from neozen.storage.base import (
    DoesNotExist,
    RepositoryProtocol,
    StorageError,
    StorageProtocol,
)

__all__ = [
    "DoesNotExist",
    "RepositoryProtocol",
    "StorageError",
    "StorageProtocol",
]
