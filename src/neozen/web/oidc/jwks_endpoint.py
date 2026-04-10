"""JWKS endpoint (RFC 7517 Section 5).

Serves the public JSON Web Key Set so relying parties can verify
ID tokens.
"""

from __future__ import annotations

from typing import Any

from neozen.core.oidc.keys import KeyManager


class JWKSEndpoint:
    """HTTP adapter for /.well-known/jwks.json.

    Example:
        endpoint = JWKSEndpoint(key_manager)
        response = await endpoint()
        # Return as application/json
    """

    def __init__(self, key_manager: KeyManager) -> None:
        self.key_manager = key_manager

    async def __call__(self) -> dict[str, Any]:
        """Return the JWKS as a dictionary suitable for JSON encoding."""
        jwks = await self.key_manager.get_jwks()
        return jwks.to_dict()


__all__ = ["JWKSEndpoint"]
