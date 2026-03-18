"""Authorization module for NeoZen.

Provides role-based access control (RBAC) and policy-based authorization.
"""

from __future__ import annotations

from neozen.core.authz.exceptions import (
    AuthorizationError,
    PermissionDenied,
    RoleAlreadyExists,
    RoleAssignmentNotFound,
    RoleNotFound,
    SystemRoleError,
)
from neozen.core.authz.models import (
    BUILTIN_ROLES,
    Permission,
    Role,
    RoleAssignment,
    ScopeType,
)
from neozen.core.authz.policy import (
    OwnerPolicy,
    Policy,
    PolicyChain,
    PolicyResult,
    RolePolicy,
)
from neozen.core.authz.services import (
    AuthorizationService,
    RoleService,
)

__all__ = [
    # Models
    "BUILTIN_ROLES",
    "Permission",
    "Role",
    "RoleAssignment",
    "ScopeType",
    # Exceptions
    "AuthorizationError",
    "PermissionDenied",
    "RoleAlreadyExists",
    "RoleAssignmentNotFound",
    "RoleNotFound",
    "SystemRoleError",
    # Policy
    "OwnerPolicy",
    "Policy",
    "PolicyChain",
    "PolicyResult",
    "RolePolicy",
    # Services
    "AuthorizationService",
    "RoleService",
]
