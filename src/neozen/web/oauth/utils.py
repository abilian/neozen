"""Shared OAuth utilities.

Common utilities used by framework-specific OAuth implementations.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any


def parse_basic_auth(header: str | None) -> tuple[str | None, str | None]:
    """Parse Basic auth header to get client_id and client_secret.

    Args:
        header: The Authorization header value.

    Returns:
        Tuple of (client_id, client_secret), both None if parsing fails.
    """
    if not header or not header.startswith("Basic "):
        return None, None

    try:
        encoded = header[6:]
        decoded = base64.b64decode(encoded).decode("utf-8")
        client_id, client_secret = decoded.split(":", 1)
        return client_id, client_secret
    except (ValueError, UnicodeDecodeError):
        return None, None


@dataclass(frozen=True)
class ClientCredentials:
    """OAuth client credentials extracted from request."""

    client_id: str | None
    client_secret: str | None

    @classmethod
    def from_auth_header(cls, header: str | None) -> ClientCredentials:
        """Extract credentials from Authorization header."""
        client_id, client_secret = parse_basic_auth(header)
        return cls(client_id=client_id, client_secret=client_secret)

    def with_fallback(
        self,
        client_id: str | None,
        client_secret: str | None,
    ) -> ClientCredentials:
        """Return credentials with fallback values if current are None."""
        return ClientCredentials(
            client_id=self.client_id or client_id,
            client_secret=self.client_secret or client_secret,
        )


@dataclass(frozen=True)
class OAuthErrorResponse:
    """Standard OAuth error response."""

    error: str
    error_description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: dict[str, Any] = {"error": self.error}
        if self.error_description:
            result["error_description"] = self.error_description
        return result


__all__ = [
    "ClientCredentials",
    "OAuthErrorResponse",
    "parse_basic_auth",
]
