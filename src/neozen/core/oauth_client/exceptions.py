"""Exceptions for OAuth client module."""

from __future__ import annotations

from neozen.core.exceptions import NeoZenException


class OAuthClientError(NeoZenException):
    """Base exception for OAuth client errors."""


class OAuthProviderNotFoundError(OAuthClientError):
    """Raised when an OAuth provider is not found."""

    def __init__(self, provider_id: str) -> None:
        super().__init__(f"OAuth provider not found: {provider_id}")
        self.provider_id = provider_id


class OAuthStateError(OAuthClientError):
    """Raised when OAuth state validation fails."""

    def __init__(self, message: str = "Invalid or expired OAuth state") -> None:
        super().__init__(message)


class OAuthCallbackError(OAuthClientError):
    """Raised when OAuth callback processing fails."""

    def __init__(self, message: str, error_code: str | None = None) -> None:
        super().__init__(message)
        self.error_code = error_code


class OAuthTokenError(OAuthClientError):
    """Raised when OAuth token exchange fails."""

    def __init__(self, message: str = "Failed to exchange token") -> None:
        super().__init__(message)


class OAuthUserInfoError(OAuthClientError):
    """Raised when fetching OAuth user info fails."""

    def __init__(self, message: str = "Failed to fetch user info") -> None:
        super().__init__(message)


class SocialAccountNotFoundError(OAuthClientError):
    """Raised when a social account is not found."""

    def __init__(self, provider_id: str, provider_user_id: str) -> None:
        super().__init__(f"Social account not found: {provider_id}/{provider_user_id}")
        self.provider_id = provider_id
        self.provider_user_id = provider_user_id


__all__ = [
    "OAuthCallbackError",
    "OAuthClientError",
    "OAuthProviderNotFoundError",
    "OAuthStateError",
    "OAuthTokenError",
    "OAuthUserInfoError",
    "SocialAccountNotFoundError",
]
