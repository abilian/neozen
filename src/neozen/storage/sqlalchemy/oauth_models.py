"""SQLAlchemy OAuth models for NeoZen."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from neozen.core.oauth.types import CodeChallengeMethod
from neozen.storage.sqlalchemy import Base


class OAuthClient(Base):
    """SQLAlchemy model for OAuth clients."""

    __tablename__ = "oauth_clients"

    client_id: Mapped[str] = mapped_column(
        String(128), primary_key=True, unique=True, nullable=False
    )


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
    code_challenge: Mapped[str] = mapped_column(String(128), nullable=False)
    code_challenge_method: Mapped[CodeChallengeMethod] = mapped_column(
        String(128), nullable=False
    )


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
