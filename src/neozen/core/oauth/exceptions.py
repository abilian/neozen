"""OAuth 2.1 exceptions for NeoZen.

This module contains all OAuth-related exceptions, organized by:
- Base exceptions
- Authorization endpoint errors
- Token endpoint errors
"""

from __future__ import annotations

import typing

from neozen.core.exceptions import NeoZenException

# =============================================================================
# Base Exceptions
# =============================================================================


class OAuthError(NeoZenException):
    """Base exception for all OAuth errors."""


# =============================================================================
# OAuth Error Codes (RFC 6749)
# =============================================================================

AuthorizationErrorCode = typing.Literal[
    "invalid_request",
    "unauthorized_client",
    "access_denied",
    "unsupported_response_type",
    "invalid_scope",
    "server_error",
    "temporarily_unavailable",
]

TokenErrorCode = typing.Literal[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
]


# =============================================================================
# Authorization Endpoint Errors
# =============================================================================


class AuthorizationError(OAuthError):
    """Base exception for authorization endpoint errors."""


class UnauthenticatedSubjectError(AuthorizationError):
    """Subject is not authenticated."""

    def __init__(self) -> None:
        super().__init__("The subject is not authenticated.")


class InvalidClientError(AuthorizationError):
    """Client ID is missing or invalid."""

    def __init__(self, message: str = "The client_id is missing or invalid.") -> None:
        super().__init__(message)


class AuthorizationRedirectError(AuthorizationError):
    """Error that should be redirected to the client.

    These errors include the standard OAuth error response parameters.
    """

    def __init__(
        self,
        error: AuthorizationErrorCode,
        error_description: str | None = None,
    ) -> None:
        self.error = error
        self.error_description = error_description
        super().__init__(error_description or error)


# =============================================================================
# Token Endpoint Errors
# =============================================================================


class TokenError(OAuthError):
    """Base exception for token endpoint errors.

    All token errors have `error` and `error_description` for HTTP response.
    """

    error: TokenErrorCode
    error_description: str

    def __init__(self, error: TokenErrorCode, error_description: str) -> None:
        self.error = error
        self.error_description = error_description
        super().__init__(error_description)


class TokenInvalidRequestError(TokenError):
    """Invalid request parameters."""

    def __init__(self, description: str) -> None:
        super().__init__("invalid_request", description)


class TokenInvalidClientError(TokenError):
    """Client authentication failed."""

    def __init__(self, description: str = "Client authentication failed.") -> None:
        super().__init__("invalid_client", description)


class TokenInvalidGrantError(TokenError):
    """Invalid authorization code or refresh token."""

    def __init__(
        self, description: str = "The authorization grant is invalid or expired."
    ) -> None:
        super().__init__("invalid_grant", description)


class TokenUnauthorizedClientError(TokenError):
    """Client not authorized for this grant type."""

    def __init__(
        self, description: str = "Client not authorized for this grant."
    ) -> None:
        super().__init__("unauthorized_client", description)


class TokenUnsupportedGrantTypeError(TokenError):
    """Unsupported grant type."""

    def __init__(self, grant_type: str) -> None:
        super().__init__(
            "unsupported_grant_type",
            f"The grant type '{grant_type}' is not supported.",
        )


class TokenInvalidScopeError(TokenError):
    """Invalid scope request."""

    def __init__(self, description: str = "The requested scope is invalid.") -> None:
        super().__init__("invalid_scope", description)


# =============================================================================
# Business Logic Errors (not HTTP-specific)
# =============================================================================


class AuthorizationCodeExpiredError(OAuthError):
    """Authorization code has expired."""

    def __init__(self) -> None:
        super().__init__("Authorization code has expired.")


class AuthorizationCodeNotFoundError(OAuthError):
    """Authorization code not found."""

    def __init__(self) -> None:
        super().__init__("Authorization code not found.")


class RefreshTokenExpiredError(OAuthError):
    """Refresh token has expired."""

    def __init__(self) -> None:
        super().__init__("Refresh token has expired.")


class RefreshTokenRevokedError(OAuthError):
    """Refresh token has been revoked."""

    def __init__(self) -> None:
        super().__init__("Refresh token has been revoked.")


class RefreshTokenNotFoundError(OAuthError):
    """Refresh token not found."""

    def __init__(self) -> None:
        super().__init__("Refresh token not found.")


class PKCEVerificationFailedError(OAuthError):
    """PKCE verification failed."""

    def __init__(self) -> None:
        super().__init__("PKCE verification failed.")


class ClientMismatchError(OAuthError):
    """Token was not issued to this client."""

    def __init__(self) -> None:
        super().__init__("Token was not issued to this client.")


class RedirectUriMismatchError(OAuthError):
    """Redirect URI does not match."""

    def __init__(self) -> None:
        super().__init__("Redirect URI does not match.")


class ScopeExceedsGrantError(OAuthError):
    """Requested scope exceeds original grant scope."""

    def __init__(self) -> None:
        super().__init__("Requested scope exceeds original grant scope.")


class ClientNotFoundError(OAuthError):
    """OAuth client not found."""

    def __init__(self, client_id: str) -> None:
        self.client_id = client_id
        super().__init__(f"Client '{client_id}' not found.")


class ClientInactiveError(OAuthError):
    """OAuth client is not active."""

    def __init__(self, client_id: str) -> None:
        self.client_id = client_id
        super().__init__(f"Client '{client_id}' is inactive.")


class ClientAuthenticationError(OAuthError):
    """OAuth client authentication failed."""

    def __init__(self, message: str = "Client authentication failed.") -> None:
        super().__init__(message)


class InvalidRedirectUriError(OAuthError):
    """Redirect URI is not registered for this client."""

    def __init__(self, redirect_uri: str) -> None:
        self.redirect_uri = redirect_uri
        super().__init__(f"Redirect URI '{redirect_uri}' is not registered.")


class InvalidScopeError(OAuthError):
    """Requested scope is not allowed for this client."""

    def __init__(self, scope: str) -> None:
        self.scope = scope
        super().__init__(f"Scope '{scope}' is not allowed for this client.")


class InvalidGrantTypeError(OAuthError):
    """Grant type is not allowed for this client."""

    def __init__(self, grant_type: str) -> None:
        self.grant_type = grant_type
        super().__init__(f"Grant type '{grant_type}' is not allowed for this client.")


__all__ = [  # noqa: RUF022
    # Base
    "OAuthError",
    # Authorization
    "AuthorizationError",
    "AuthorizationErrorCode",
    "AuthorizationRedirectError",
    "InvalidClientError",
    "UnauthenticatedSubjectError",
    # Token
    "TokenError",
    "TokenErrorCode",
    "TokenInvalidClientError",
    "TokenInvalidGrantError",
    "TokenInvalidRequestError",
    "TokenInvalidScopeError",
    "TokenUnauthorizedClientError",
    "TokenUnsupportedGrantTypeError",
    # Business logic
    "AuthorizationCodeExpiredError",
    "AuthorizationCodeNotFoundError",
    "ClientMismatchError",
    "PKCEVerificationFailedError",
    "RedirectUriMismatchError",
    "RefreshTokenExpiredError",
    "RefreshTokenNotFoundError",
    "RefreshTokenRevokedError",
    "ScopeExceedsGrantError",
    # Client errors
    "ClientNotFoundError",
    "ClientInactiveError",
    "ClientAuthenticationError",
    "InvalidRedirectUriError",
    "InvalidScopeError",
    "InvalidGrantTypeError",
]
