"""Raw SQL storage backend for NeoZen.

Uses the `databases` library for async database access without an ORM.
"""

from __future__ import annotations

from neozen.storage.sql.repository import SQLRepository

__all__ = ["SQLRepository"]
