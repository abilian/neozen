"""Web authentication utilities for NeoZen.

This package contains shared authentication functionality used by
framework-specific extensions.
"""

from __future__ import annotations

from neozen.web.auth.backend import AuthBackendBase, SameSitePolicy, SubjectLoader
from neozen.web.auth.permissions import (
    check_user_permission,
    check_user_permissions,
    check_user_role,
    check_user_roles_any,
)

__all__ = [
    "AuthBackendBase",
    "SameSitePolicy",
    "SubjectLoader",
    "check_user_permission",
    "check_user_permissions",
    "check_user_role",
    "check_user_roles_any",
]
