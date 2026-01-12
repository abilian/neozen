"""OAuth 2.1 server implementation for NeoZen."""

from __future__ import annotations

from neozen.core.oauth.authorization_code import (
    AuthorizationCodeGrant,
    AuthorizationCodeGrantConsentResponse,
    AuthorizationCodeGrantError,
    AuthorizationCodeGrantGrantedResponse,
    AuthorizationCodeGrantProvider,
    AuthorizationCodeGrantRedirectionError,
    AuthorizationCodeGrantRequest,
    MissingOrInvalidClientIDError,
    OAuthClientError,
    UnauthenticatedSubjectError,
)
from neozen.core.oauth.models import (
    OAuthAccessTokenModel,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthGrantModel,
    OAuthRefreshTokenModel,
)
from neozen.core.oauth.token_endpoint import (
    AuthorizationCodeTokenRequest,
    InvalidClientError,
    InvalidGrantError,
    InvalidRequestError,
    InvalidScopeError,
    RefreshTokenRequest,
    TokenEndpoint,
    TokenEndpointError,
    TokenResponse,
    UnauthorizedClientError,
    UnsupportedGrantTypeError,
)
from neozen.core.oauth.types import CodeChallengeMethod

__all__ = [
    # Types
    "CodeChallengeMethod",
    # Models
    "OAuthAccessTokenModel",
    "OAuthAuthorizationCodeModel",
    "OAuthClientModel",
    "OAuthGrantModel",
    "OAuthRefreshTokenModel",
    # Authorization Code Grant
    "AuthorizationCodeGrant",
    "AuthorizationCodeGrantConsentResponse",
    "AuthorizationCodeGrantError",
    "AuthorizationCodeGrantGrantedResponse",
    "AuthorizationCodeGrantProvider",
    "AuthorizationCodeGrantRedirectionError",
    "AuthorizationCodeGrantRequest",
    "MissingOrInvalidClientIDError",
    "OAuthClientError",
    "UnauthenticatedSubjectError",
    # Token Endpoint
    "AuthorizationCodeTokenRequest",
    "InvalidClientError",
    "InvalidGrantError",
    "InvalidRequestError",
    "InvalidScopeError",
    "RefreshTokenRequest",
    "TokenEndpoint",
    "TokenEndpointError",
    "TokenResponse",
    "UnauthorizedClientError",
    "UnsupportedGrantTypeError",
]
