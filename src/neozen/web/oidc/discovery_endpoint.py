"""OIDC Discovery endpoint (/.well-known/openid-configuration)."""

from __future__ import annotations

from typing import Any

from neozen.core.oidc.discovery import OIDCProviderMetadata


class DiscoveryEndpoint:
    """HTTP adapter for /.well-known/openid-configuration.

    Returns the OpenID Provider Metadata document.

    Example:
        metadata = build_metadata_from_base_url(
            issuer="https://auth.example.com",
            base_url="https://auth.example.com",
        )
        endpoint = DiscoveryEndpoint(metadata)
        response = await endpoint()
        # Return as application/json
    """

    def __init__(self, metadata: OIDCProviderMetadata) -> None:
        self.metadata = metadata

    async def __call__(self) -> dict[str, Any]:
        """Return the provider metadata as a dictionary."""
        return self.metadata.to_dict()


__all__ = ["DiscoveryEndpoint"]
