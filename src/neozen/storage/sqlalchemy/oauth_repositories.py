"""Advanced-Alchemy repositories for NeoZen OAuth models."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from neozen.storage.sqlalchemy.oauth_models import (
    OAuthAccessToken,
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthGrant,
    OAuthRefreshToken,
)
from neozen.storage.sqlalchemy.repositories import NeoZenRepository


class OAuthClientRepository(NeoZenRepository[OAuthClient]):
    """Repository for OAuthClient model."""

    model_type = OAuthClient
    id_attribute = "client_id"


class OAuthGrantRepository(NeoZenRepository[OAuthGrant]):
    """Repository for OAuthGrant model."""

    model_type = OAuthGrant


class OAuthAuthorizationCodeRepository(NeoZenRepository[OAuthAuthorizationCode]):
    """Repository for OAuthAuthorizationCode model."""

    model_type = OAuthAuthorizationCode
    id_attribute = "code"


class OAuthAccessTokenRepository(NeoZenRepository[OAuthAccessToken]):
    """Repository for OAuthAccessToken model."""

    model_type = OAuthAccessToken
    id_attribute = "token_hash"


class OAuthRefreshTokenRepository(NeoZenRepository[OAuthRefreshToken]):
    """Repository for OAuthRefreshToken model."""

    model_type = OAuthRefreshToken
    id_attribute = "token_hash"


def get_oauth_client_repository(session: AsyncSession) -> OAuthClientRepository:
    """Factory function for OAuthClientRepository."""
    return OAuthClientRepository(session=session)


def get_oauth_grant_repository(session: AsyncSession) -> OAuthGrantRepository:
    """Factory function for OAuthGrantRepository."""
    return OAuthGrantRepository(session=session)


def get_oauth_authorization_code_repository(
    session: AsyncSession,
) -> OAuthAuthorizationCodeRepository:
    """Factory function for OAuthAuthorizationCodeRepository."""
    return OAuthAuthorizationCodeRepository(session=session)


def get_oauth_access_token_repository(
    session: AsyncSession,
) -> OAuthAccessTokenRepository:
    """Factory function for OAuthAccessTokenRepository."""
    return OAuthAccessTokenRepository(session=session)


def get_oauth_refresh_token_repository(
    session: AsyncSession,
) -> OAuthRefreshTokenRepository:
    """Factory function for OAuthRefreshTokenRepository."""
    return OAuthRefreshTokenRepository(session=session)


__all__ = [
    "OAuthAccessTokenRepository",
    "OAuthAuthorizationCodeRepository",
    "OAuthClientRepository",
    "OAuthGrantRepository",
    "OAuthRefreshTokenRepository",
    "get_oauth_access_token_repository",
    "get_oauth_authorization_code_repository",
    "get_oauth_client_repository",
    "get_oauth_grant_repository",
    "get_oauth_refresh_token_repository",
]
