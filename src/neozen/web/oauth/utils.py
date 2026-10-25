"""Shared OAuth utilities.

Common utilities used by framework-specific OAuth implementations.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from neozen.core.oauth.exceptions import (
    ClientAuthenticationError,
    ClientInactiveError,
    ClientNotFoundError,
    TokenInvalidClientError,
)

if TYPE_CHECKING:
    from neozen.core.oauth.client_service import OAuthClientService
    from neozen.core.oauth.models import OAuthClientModel

# RFC 6749 §5.1: responses carrying tokens or credentials must not be cached.
NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def token_error_headers(error: str) -> dict[str, str]:
    """Headers for a token endpoint error response.

    ``invalid_client`` also gets the ``WWW-Authenticate`` challenge that
    goes with its 401 status (RFC 6749 §5.2).
    """
    if error == "invalid_client":
        return {**NO_STORE_HEADERS, "WWW-Authenticate": 'Basic realm="oauth"'}
    return NO_STORE_HEADERS


def token_error_status(error: str) -> int:
    """HTTP status for a token endpoint error code (RFC 6749 §5.2)."""
    return 401 if error == "invalid_client" else 400


async def authenticate_client[OC: OAuthClientModel](
    client_service: OAuthClientService[OC],
    client_id: str | None,
    client_secret: str | None,
) -> OC:
    """Authenticate the calling client (RFC 6749 §2.3), or raise ``invalid_client``.

    Confidential clients must present their secret; public clients present
    none. Unknown and inactive clients fail the same way.
    """
    if not client_id:
        msg = "Client authentication required."
        raise TokenInvalidClientError(msg)
    try:
        return await client_service.authenticate_client(client_id, client_secret)
    except (
        ClientNotFoundError,
        ClientInactiveError,
        ClientAuthenticationError,
    ) as e:
        msg = "Client authentication failed."
        raise TokenInvalidClientError(msg) from e


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
