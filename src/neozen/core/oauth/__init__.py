"""OAuth 2.1 server implementation for NeoZen.

Core business logic for OAuth. HTTP adapters are in neozen.web.oauth.
"""

from __future__ import annotations

from neozen.core.oauth.authorization_code import (
    AuthorizationCodeGrant,
    AuthorizationCodeGrantConsentResponse,
    AuthorizationCodeGrantGrantedResponse,
    AuthorizationCodeGrantProvider,
    AuthorizationCodeGrantRedirectionError,
    AuthorizationCodeGrantRequest,
    MissingOrInvalidClientIDError,
)
from neozen.core.oauth.exceptions import (
    AuthorizationCodeExpiredError,
    AuthorizationCodeNotFoundError,
    AuthorizationError,
    AuthorizationRedirectError,
    ClientMismatchError,
    InvalidClientError,
    OAuthError,
    PKCEVerificationFailedError,
    RedirectUriMismatchError,
    RefreshTokenExpiredError,
    RefreshTokenNotFoundError,
    RefreshTokenRevokedError,
    ScopeExceedsGrantError,
    TokenError,
    TokenInvalidClientError,
    TokenInvalidGrantError,
    TokenInvalidRequestError,
    TokenInvalidScopeError,
    TokenUnauthorizedClientError,
    TokenUnsupportedGrantTypeError,
    UnauthenticatedSubjectError,
)
from neozen.core.oauth.models import (
    OAuthAccessTokenModel,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthGrantModel,
    OAuthRefreshTokenModel,
)
from neozen.core.oauth.pkce import compute_s256_challenge, verify_pkce
from neozen.core.oauth.services import (
    AccessTokenResult,
    OAuthTokenService,
    TokenPair,
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
    # Services
    "AccessTokenResult",
    "OAuthTokenService",
    "TokenPair",
    # PKCE
    "compute_s256_challenge",
    "verify_pkce",
    # Authorization Code Grant
    "AuthorizationCodeGrant",
    "AuthorizationCodeGrantConsentResponse",
    "AuthorizationCodeGrantGrantedResponse",
    "AuthorizationCodeGrantProvider",
    "AuthorizationCodeGrantRedirectionError",
    "AuthorizationCodeGrantRequest",
    "MissingOrInvalidClientIDError",
    # Exceptions - Base
    "OAuthError",
    # Exceptions - Authorization
    "AuthorizationError",
    "AuthorizationRedirectError",
    "InvalidClientError",
    "UnauthenticatedSubjectError",
    # Exceptions - Token
    "TokenError",
    "TokenInvalidClientError",
    "TokenInvalidGrantError",
    "TokenInvalidRequestError",
    "TokenInvalidScopeError",
    "TokenUnauthorizedClientError",
    "TokenUnsupportedGrantTypeError",
    # Exceptions - Business Logic
    "AuthorizationCodeExpiredError",
    "AuthorizationCodeNotFoundError",
    "ClientMismatchError",
    "PKCEVerificationFailedError",
    "RedirectUriMismatchError",
    "RefreshTokenExpiredError",
    "RefreshTokenNotFoundError",
    "RefreshTokenRevokedError",
    "ScopeExceedsGrantError",
]
