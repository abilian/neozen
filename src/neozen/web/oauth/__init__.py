"""OAuth web adapters for NeoZen.

This package contains HTTP adapters for OAuth endpoints.
"""

from __future__ import annotations

from neozen.web.oauth.authorization_endpoint import (
    AuthorizationEndpoint,
    AuthorizationRequest,
    AuthorizationResponse,
    ConsentData,
    ConsentRequest,
)
from neozen.web.oauth.introspection_endpoint import (
    IntrospectionEndpoint,
    IntrospectionRequest,
    IntrospectionResponse,
)
from neozen.web.oauth.revocation_endpoint import (
    RevocationEndpoint,
    RevocationRequest,
)
from neozen.web.oauth.token_endpoint import TokenEndpoint, TokenResponse
from neozen.web.oauth.utils import (
    NO_STORE_HEADERS,
    ClientCredentials,
    OAuthErrorResponse,
    parse_basic_auth,
    token_error_headers,
    token_error_status,
)

__all__ = [
    "NO_STORE_HEADERS",
    "AuthorizationEndpoint",
    "AuthorizationRequest",
    "AuthorizationResponse",
    "ConsentData",
    "ConsentRequest",
    "IntrospectionEndpoint",
    "IntrospectionRequest",
    "IntrospectionResponse",
    "RevocationEndpoint",
    "RevocationRequest",
    "TokenEndpoint",
    "TokenResponse",
    "ClientCredentials",
    "OAuthErrorResponse",
    "parse_basic_auth",
    "token_error_headers",
    "token_error_status",
]
