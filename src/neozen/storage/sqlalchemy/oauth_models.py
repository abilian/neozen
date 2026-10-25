"""SQLAlchemy OAuth models for NeoZen."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from neozen.core.oauth.types import CodeChallengeMethod
from neozen.storage.sqlalchemy import Base


class OAuthClient(Base):
    """SQLAlchemy model for OAuth clients.

    Attributes:
        client_id: Unique identifier for the client.
        client_name: Human-readable name for the client.
        client_secret_hash: Hashed client secret (None for public clients).
        client_type: "public" or "confidential".
        redirect_uris: JSON array of allowed redirect URIs.
        allowed_scopes: Space-separated list of allowed scopes.
        allowed_grant_types: Space-separated list of allowed grant types.
        token_endpoint_auth_method: Authentication method for token endpoint.
        is_active: Whether the client is active.
        created_at: When the client was created.
        updated_at: When the client was last updated.
    """

    __tablename__ = "oauth_clients"

    client_id: Mapped[str] = mapped_column(String(64), primary_key=True, nullable=False)
    client_name: Mapped[str] = mapped_column(String(128), nullable=False)
    client_secret_hash: Mapped[str | None] = mapped_column(String(256), nullable=True)
    client_type: Mapped[str] = mapped_column(
        String(20), default="confidential", nullable=False
    )
    redirect_uris: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    allowed_scopes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    allowed_grant_types: Mapped[str] = mapped_column(
        Text, default="authorization_code refresh_token", nullable=False
    )
    token_endpoint_auth_method: Mapped[str] = mapped_column(
        String(50), default="client_secret_basic", nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def get_redirect_uris(self) -> list[str]:
        """Get redirect URIs as a list."""
        return json.loads(self.redirect_uris)

    def get_allowed_scopes(self) -> set[str]:
        """Get allowed scopes as a set."""
        if not self.allowed_scopes:
            return set()
        return set(self.allowed_scopes.split())

    def get_allowed_grant_types(self) -> set[str]:
        """Get allowed grant types as a set."""
        if not self.allowed_grant_types:
            return set()
        return set(self.allowed_grant_types.split())

    def is_redirect_uri_allowed(self, uri: str) -> bool:
        """Check if a redirect URI is allowed."""
        return uri in self.get_redirect_uris()

    def is_scope_allowed(self, scope: str) -> bool:
        """Check if a scope is allowed."""
        allowed = self.get_allowed_scopes()
        if not allowed:
            return True  # No restrictions if no scopes configured
        return scope in allowed

    def is_grant_type_allowed(self, grant_type: str) -> bool:
        """Check if a grant type is allowed."""
        return grant_type in self.get_allowed_grant_types()

    def is_public_client(self) -> bool:
        """Check if this is a public client."""
        return self.client_type == "public"

    def is_confidential_client(self) -> bool:
        """Check if this is a confidential client."""
        return self.client_type == "confidential"


class OAuthGrant(Base):
    """SQLAlchemy model for OAuth grants."""

    __tablename__ = "oauth_grants"

    client_id: Mapped[str] = mapped_column(
        ForeignKey("oauth_clients.client_id"),
        nullable=False,
        primary_key=True,
    )
    subject_id: Mapped[str] = mapped_column(
        String(128), nullable=False, primary_key=True
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(), default=datetime.now(UTC), nullable=False
    )
    scope: Mapped[str] = mapped_column(Text(), nullable=False)


class OAuthAuthorizationCode(Base):
    """SQLAlchemy model for OAuth authorization codes."""

    __tablename__ = "oauth_authorization_codes"

    code: Mapped[str] = mapped_column(String(64), primary_key=True, nullable=False)
    client_id: Mapped[str] = mapped_column(
        ForeignKey("oauth_clients.client_id"), nullable=False
    )
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    response_type: Mapped[str] = mapped_column(String(128), nullable=False)
    redirect_uri: Mapped[str | None] = mapped_column(Text(), nullable=True)
    scope: Mapped[str] = mapped_column(Text(), nullable=False)
    code_challenge: Mapped[str | None] = mapped_column(String(128), nullable=True)
    code_challenge_method: Mapped[CodeChallengeMethod | None] = mapped_column(
        String(128), nullable=True
    )
    nonce: Mapped[str | None] = mapped_column(Text(), nullable=True)


class OAuthAccessToken(Base):
    """SQLAlchemy model for OAuth access tokens."""

    __tablename__ = "oauth_access_tokens"

    token_hash: Mapped[str] = mapped_column(
        String(64), primary_key=True, nullable=False
    )
    client_id: Mapped[str] = mapped_column(
        ForeignKey("oauth_clients.client_id"), nullable=False
    )
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    scope: Mapped[str] = mapped_column(Text(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(), nullable=True)


class OAuthRefreshToken(Base):
    """SQLAlchemy model for OAuth refresh tokens."""

    __tablename__ = "oauth_refresh_tokens"

    token_hash: Mapped[str] = mapped_column(
        String(64), primary_key=True, nullable=False
    )
    client_id: Mapped[str] = mapped_column(
        ForeignKey("oauth_clients.client_id"), nullable=False
    )
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    scope: Mapped[str] = mapped_column(Text(), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(), nullable=True)
    access_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


__all__ = [
    "OAuthAccessToken",
    "OAuthAuthorizationCode",
    "OAuthClient",
    "OAuthGrant",
    "OAuthRefreshToken",
]
