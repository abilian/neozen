"""Recovery types for NeoZen."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RecoveryMethod(Enum):
    """Available recovery methods."""

    EMAIL = "email"
    BACKUP_CODES = "backup_codes"
    RECOVERY_KEY = "recovery_key"
    ADMIN_RESET = "admin_reset"


@dataclass(frozen=True)
class RecoveryOption:
    """A recovery option for an account.

    Attributes:
        method: The recovery method type.
        identifier: Masked identifier (e.g., masked email).
        available: Whether this option is currently available.
        hint: Optional hint about this option.
    """

    method: RecoveryMethod
    identifier: str
    available: bool
    hint: str | None = None


__all__ = [
    "RecoveryMethod",
    "RecoveryOption",
]
