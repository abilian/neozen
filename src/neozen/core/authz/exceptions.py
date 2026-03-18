"""Authorization exceptions."""

from __future__ import annotations

from neozen.core.exceptions import NeoZenException


class AuthorizationError(NeoZenException):
    """Base exception for authorization errors."""


class PermissionDenied(AuthorizationError):
    """Raised when a subject lacks the required permission."""

    def __init__(
        self,
        permission: str,
        subject_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> None:
        self.permission = permission
        self.subject_id = subject_id
        self.resource_type = resource_type
        self.resource_id = resource_id

        if resource_type and resource_id:
            message = (
                f"Permission denied: '{permission}' on {resource_type}/{resource_id}"
            )
        else:
            message = f"Permission denied: '{permission}'"

        super().__init__(message)


class RoleNotFound(AuthorizationError):
    """Raised when a requested role does not exist."""

    def __init__(self, role_name: str) -> None:
        self.role_name = role_name
        super().__init__(f"Role not found: '{role_name}'")


class RoleAlreadyExists(AuthorizationError):
    """Raised when trying to create a role that already exists."""

    def __init__(self, role_name: str) -> None:
        self.role_name = role_name
        super().__init__(f"Role already exists: '{role_name}'")


class RoleAssignmentNotFound(AuthorizationError):
    """Raised when a role assignment does not exist."""

    def __init__(self, subject_id: str, role_name: str) -> None:
        self.subject_id = subject_id
        self.role_name = role_name
        super().__init__(f"Role '{role_name}' not assigned to subject '{subject_id}'")


class SystemRoleError(AuthorizationError):
    """Raised when trying to modify a system role."""

    def __init__(self, role_name: str, operation: str) -> None:
        self.role_name = role_name
        self.operation = operation
        super().__init__(f"Cannot {operation} system role: '{role_name}'")
