"""Models for OAuth client module."""

from __future__ import annotations

import typing
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class OAuthProviderConfig:
    """Configuration for an OAuth provider.

    Attributes:
        provider_id: Unique identifier for the provider (e.g., "google", "github").
        display_name: Human-readable name for the provider.
        client_id: OAuth client ID.
        client_secret: OAuth client secret.
        authorization_endpoint: URL for authorization.
        token_endpoint: URL for token exchange.
        userinfo_endpoint: URL for user info (if not using OpenID Connect).
        scopes: List of scopes to request.
        use_pkce: Whether to use PKCE (default True).

    """

    provider_id: str
    client_id: str
    client_secret: str
    authorization_endpoint: str
    token_endpoint: str
    display_name: str | None = None
    userinfo_endpoint: str | None = None
    scopes: list[str] = field(default_factory=list)
    use_pkce: bool = True


@dataclass(frozen=True)
class AuthorizationResult:
    """Result of starting an OAuth authorization flow.

    Attributes:
        authorization_url: The URL to redirect the user to.
        state: The state parameter for CSRF protection.

    """

    authorization_url: str
    state: str


@dataclass(frozen=True)
class OAuthTokens:
    """OAuth tokens received from the provider.

    Attributes:
        access_token: The access token.
        token_type: The token type (usually "Bearer").
        refresh_token: Optional refresh token.
        expires_in: Token expiration time in seconds.
        scope: The granted scopes.
        id_token: Optional OpenID Connect ID token.

    """

    access_token: str
    token_type: str = "Bearer"
    refresh_token: str | None = None
    expires_in: int | None = None
    scope: str | None = None
    id_token: str | None = None


@dataclass(frozen=True)
class OAuthUserInfo:
    """User information from an OAuth provider.

    Attributes:
        provider_id: The provider ID (e.g., "google").
        provider_user_id: The user's ID at the provider.
        email: The user's email (if available).
        email_verified: Whether the email is verified.
        display_name: The user's display name.
        avatar_url: URL to the user's avatar.
        raw_data: The raw response from the provider.

    """

    provider_id: str
    provider_user_id: str
    email: str | None = None
    email_verified: bool = False
    display_name: str | None = None
    avatar_url: str | None = None
    raw_data: dict[str, typing.Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CallbackResult:
    """Result of processing an OAuth callback.

    Attributes:
        tokens: The OAuth tokens.
        user_info: The user information.
        existing_subject_id: Subject ID if this was a linking operation.

    """

    tokens: OAuthTokens
    user_info: OAuthUserInfo
    existing_subject_id: str | None = None


class OAuthStateModel(typing.Protocol):
    """Protocol for OAuth state records."""

    state: str
    code_verifier: str
    redirect_uri: str
    provider_id: str
    existing_subject_id: str | None
    expires_at: datetime


class SocialAccountModel(typing.Protocol):
    """Protocol for social account records."""

    id: str
    subject_id: str
    provider_id: str
    provider_user_id: str
    email: str | None
    display_name: str | None
    access_token: str | None
    refresh_token: str | None
    token_expires_at: datetime | None


class OAuthStateRepositoryProtocol[Model: OAuthStateModel](typing.Protocol):
    """Protocol for OAuth state storage."""

    async def get_one_by(self, **filters: typing.Any) -> Model: ...

    async def create(self, **data: typing.Any) -> Model: ...

    async def delete(self, obj: Model) -> None: ...


class SocialAccountRepositoryProtocol[Model: SocialAccountModel](typing.Protocol):
    """Protocol for social account storage."""

    async def get_one_by(self, **filters: typing.Any) -> Model: ...

    async def get_many_by(
        self,
        *,
        offset: int = 0,
        limit: int | None = None,
        **filters: typing.Any,
    ) -> list[Model]: ...

    async def create(self, **data: typing.Any) -> Model: ...

    async def update_obj(self, obj: Model, **data: typing.Any) -> Model: ...

    async def delete(self, obj: Model) -> None: ...


__all__ = [
    "AuthorizationResult",
    "CallbackResult",
    "OAuthProviderConfig",
    "OAuthStateModel",
    "OAuthStateRepositoryProtocol",
    "OAuthTokens",
    "OAuthUserInfo",
    "SocialAccountModel",
    "SocialAccountRepositoryProtocol",
]
