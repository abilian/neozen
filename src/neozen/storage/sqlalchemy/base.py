"""SQLAlchemy declarative base for NeoZen models using Advanced-Alchemy."""

from __future__ import annotations

from advanced_alchemy.base import CommonTableAttributes, orm_registry
from sqlalchemy.orm import DeclarativeBase


class Base(CommonTableAttributes, DeclarativeBase):
    """SQLAlchemy declarative base for NeoZen models.

    Uses Advanced-Alchemy's CommonTableAttributes for automatic table naming
    and shared registry.
    """

    registry = orm_registry


__all__ = ["Base"]
