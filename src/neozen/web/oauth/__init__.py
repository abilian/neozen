"""OAuth web adapters for NeoZen.

This package contains HTTP adapters for OAuth endpoints.
"""

from __future__ import annotations

from neozen.web.oauth.token_endpoint import TokenEndpoint, TokenResponse

__all__ = [
    "TokenEndpoint",
    "TokenResponse",
]
