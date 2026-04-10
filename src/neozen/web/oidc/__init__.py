"""HTTP adapters for OIDC endpoints (UserInfo, Discovery, JWKS)."""

from __future__ import annotations

from neozen.web.oidc.discovery_endpoint import DiscoveryEndpoint
from neozen.web.oidc.jwks_endpoint import JWKSEndpoint
from neozen.web.oidc.userinfo_endpoint import (
    UserInfoEndpoint,
    UserInfoError,
)

__all__ = [
    "DiscoveryEndpoint",
    "JWKSEndpoint",
    "UserInfoEndpoint",
    "UserInfoError",
]
