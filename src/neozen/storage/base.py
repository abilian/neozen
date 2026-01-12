"""Storage base module - re-exports from neozen.core.repository.

For convenience, this module re-exports the repository abstractions.
The canonical location is neozen.core.repository.
"""

from __future__ import annotations

from neozen.core.repository import DoesNotExist, RepositoryError, RepositoryProtocol

__all__ = [
    "DoesNotExist",
    "RepositoryError",
    "RepositoryProtocol",
]
