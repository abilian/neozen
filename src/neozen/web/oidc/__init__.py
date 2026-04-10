"""HTTP adapters for OIDC endpoints.

Includes:
- DiscoveryEndpoint (/.well-known/openid-configuration)
- JWKSEndpoint (/.well-known/jwks.json)
- UserInfoEndpoint (/userinfo)
- EndSessionEndpoint (/oauth/end_session) -- RP-Initiated Logout
- RegistrationEndpoint (/oauth/register) -- Dynamic Client Registration
- CORS helpers
"""

from __future__ import annotations

from neozen.web.oidc.cors import (
    collect_allowed_origins,
    is_origin_allowed,
    origin_from_url,
)
from neozen.web.oidc.discovery_endpoint import DiscoveryEndpoint
from neozen.web.oidc.end_session_endpoint import (
    EndSessionEndpoint,
    EndSessionError,
    EndSessionRequest,
    EndSessionResult,
    InvalidPostLogoutRedirectError,
)
from neozen.web.oidc.jwks_endpoint import JWKSEndpoint
from neozen.web.oidc.registration_endpoint import (
    InvalidClientMetadataError,
    InvalidRedirectUriError,
    RegistrationEndpoint,
    RegistrationError,
    RegistrationRequest,
    RegistrationResponse,
)
from neozen.web.oidc.userinfo_endpoint import (
    UserInfoEndpoint,
    UserInfoError,
)

__all__ = [
    "DiscoveryEndpoint",
    "EndSessionEndpoint",
    "EndSessionError",
    "EndSessionRequest",
    "EndSessionResult",
    "InvalidClientMetadataError",
    "InvalidPostLogoutRedirectError",
    "InvalidRedirectUriError",
    "JWKSEndpoint",
    "RegistrationEndpoint",
    "RegistrationError",
    "RegistrationRequest",
    "RegistrationResponse",
    "UserInfoEndpoint",
    "UserInfoError",
    "collect_allowed_origins",
    "is_origin_allowed",
    "origin_from_url",
]
