"""SCIM error types and error response formatting."""

from __future__ import annotations

from typing import Any


class SCIMError(Exception):
    """Base SCIM error.

    Attributes:
        status: HTTP status code (200-599)
        scim_type: SCIM-specific error type (RFC 7644 Section 3.12)
        detail: Human-readable description
    """

    def __init__(
        self,
        detail: str,
        *,
        status: int = 400,
        scim_type: str | None = None,
    ) -> None:
        self.detail = detail
        self.status = status
        self.scim_type = scim_type
        super().__init__(detail)

    def to_response(self) -> dict[str, Any]:
        """Format as a SCIM error response (RFC 7644 Section 3.12)."""
        body: dict[str, Any] = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": str(self.status),
            "detail": self.detail,
        }
        if self.scim_type:
            body["scimType"] = self.scim_type
        return body


class SCIMNotFoundError(SCIMError):
    """Resource not found (404)."""

    def __init__(self, detail: str = "Resource not found") -> None:
        super().__init__(detail, status=404)


class SCIMUniquenessError(SCIMError):
    """Uniqueness constraint violation (409 + scimType=uniqueness)."""

    def __init__(self, detail: str = "Resource already exists") -> None:
        super().__init__(detail, status=409, scim_type="uniqueness")


class SCIMFilterError(SCIMError):
    """Invalid filter expression (400 + scimType=invalidFilter)."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail, status=400, scim_type="invalidFilter")


class SCIMValidationError(SCIMError):
    """Invalid input (400 + scimType=invalidValue)."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail, status=400, scim_type="invalidValue")


__all__ = [
    "SCIMError",
    "SCIMFilterError",
    "SCIMNotFoundError",
    "SCIMUniquenessError",
    "SCIMValidationError",
]
