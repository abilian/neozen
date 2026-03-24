"""Backwards compatibility re-exports.

This module has been moved to neozen.storage.sqlalchemy.factories.
Import from there instead:

    from neozen.storage.sqlalchemy import (
        RoleServiceFactory,
        SessionServiceFactory,
        create_subject_loader,
        get_subject_roles,
    )
"""

from __future__ import annotations

from neozen.storage.sqlalchemy.factories import (
    RoleServiceFactory,
    SessionServiceFactory,
    create_subject_loader,
    get_subject_roles,
)

__all__ = [
    "RoleServiceFactory",
    "SessionServiceFactory",
    "create_subject_loader",
    "get_subject_roles",
]
