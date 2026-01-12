"""Storage abstraction for NeoZen.

This package provides storage backends for NeoZen models.
The base module re-exports RepositoryProtocol from neozen.core.repository.

Available backends:
- sqlalchemy: SQLAlchemy 2.0 with async support via Advanced-Alchemy
"""

from __future__ import annotations

from neozen.storage.base import DoesNotExist, RepositoryError, RepositoryProtocol

__all__ = [
    "DoesNotExist",
    "RepositoryError",
    "RepositoryProtocol",
]
