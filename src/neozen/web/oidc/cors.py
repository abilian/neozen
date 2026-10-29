"""CORS helpers for OIDC endpoints.

OIDC endpoints (token, userinfo, jwks, etc.) often need to be
called by browser-based clients. This module provides a helper to
derive allowed CORS origins from registered client redirect URIs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from neozen.core.oauth.client_service import OAuthClientService
    from neozen.core.oauth.models import OAuthClientModel


def origin_from_url(url: str) -> str | None:
    """Extract the origin (scheme + host + port) from a URL.

    Returns None for invalid URLs or non-http(s) schemes.

    Examples:
        >>> origin_from_url("https://app.example.com/callback")
        'https://app.example.com'
        >>> origin_from_url("https://app.example.com:8443/callback")
        'https://app.example.com:8443'
        >>> origin_from_url("custom://app/callback")
        # None (custom scheme)
    """
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:  # bad IPv6 literal or port
        return None

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None

    if port is None:
        return f"{parsed.scheme}://{parsed.hostname}"
    return f"{parsed.scheme}://{parsed.hostname}:{port}"


async def collect_allowed_origins(
    client_service: OAuthClientService[OAuthClientModel],
) -> set[str]:
    """Collect the set of CORS-allowed origins from all active clients.

    Iterates over registered clients and extracts the unique origins
    from their redirect URIs. Use this to configure CORS middleware
    for the OIDC endpoints.

    Example:
        origins = await collect_allowed_origins(client_service)
        cors_middleware = CORSMiddleware(allow_origins=list(origins))

    Returns:
        A set of origin strings (e.g., {"https://app.example.com"}).
    """
    origins: set[str] = set()
    clients = await client_service.list_clients(active_only=True)

    for client in clients:
        for uri in client.get_redirect_uris():
            origin = origin_from_url(uri)
            if origin:
                origins.add(origin)

    return origins


def is_origin_allowed(origin: str, allowed: set[str]) -> bool:
    """Check whether an origin is in the allowed set.

    Performs a case-insensitive comparison on the host while keeping
    the scheme and port case-sensitive (per RFC 6454).
    """
    if not origin:
        return False

    parsed = urlparse(origin)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False

    if parsed.port is None:
        normalized = f"{parsed.scheme}://{parsed.hostname.lower()}"
    else:
        normalized = f"{parsed.scheme}://{parsed.hostname.lower()}:{parsed.port}"

    return normalized in allowed


__all__ = [
    "collect_allowed_origins",
    "is_origin_allowed",
    "origin_from_url",
]
