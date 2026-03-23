"""Core utilities for NeoZen."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime


def generate_id() -> str:
    """Generate a unique ID.

    Returns:
        A unique string ID.
    """
    return str(uuid.uuid4())


def ensure_utc(dt: datetime) -> datetime:
    """Ensure datetime has UTC timezone.

    Handles offset-naive datetimes from databases by assuming UTC.

    Args:
        dt: A datetime that may or may not have timezone info.

    Returns:
        Datetime with UTC timezone.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


__all__ = ["ensure_utc", "generate_id"]
