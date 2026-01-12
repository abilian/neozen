"""Advanced-Alchemy repositories for NeoZen models."""

from __future__ import annotations

import typing

from advanced_alchemy.base import ModelProtocol
from advanced_alchemy.exceptions import NotFoundError
from advanced_alchemy.repository import SQLAlchemyAsyncRepository
from sqlalchemy.ext.asyncio import AsyncSession

from neozen.storage.base import DoesNotExist
from neozen.storage.sqlalchemy.models import (
    EmailVerificationToken,
    Session,
    Subject,
)


class NeoZenRepository[Model: ModelProtocol](SQLAlchemyAsyncRepository[Model]):
    """Base repository for NeoZen with our expected interface.

    Wraps Advanced-Alchemy's repository and provides the interface
    expected by NeoZen services.
    """

    async def get_one_by(self, **filters: typing.Any) -> Model:
        """Get one model by filters, raises DoesNotExist if not found."""
        try:
            return await self.get_one(**filters)
        except NotFoundError as e:
            raise DoesNotExist from e

    async def create(self, **data: typing.Any) -> Model:
        """Create a new model instance."""
        obj = self.model_type(**data)
        return await self.add(obj)

    async def update_obj(self, obj: Model, **data: typing.Any) -> Model:
        """Update an existing model instance."""
        for key, value in data.items():
            setattr(obj, key, value)
        return await self.update(obj)


class SubjectRepository(NeoZenRepository[Subject]):
    """Repository for Subject model."""

    model_type = Subject


class SessionRepository(NeoZenRepository[Session]):
    """Repository for Session model."""

    model_type = Session
    id_attribute = "token_hash"


class EmailVerificationTokenRepository(NeoZenRepository[EmailVerificationToken]):
    """Repository for EmailVerificationToken model."""

    model_type = EmailVerificationToken
    id_attribute = "token_hash"


def get_subject_repository(session: AsyncSession) -> SubjectRepository:
    """Factory function for SubjectRepository."""
    return SubjectRepository(session=session)


def get_session_repository(session: AsyncSession) -> SessionRepository:
    """Factory function for SessionRepository."""
    return SessionRepository(session=session)


def get_email_verification_token_repository(
    session: AsyncSession,
) -> EmailVerificationTokenRepository:
    """Factory function for EmailVerificationTokenRepository."""
    return EmailVerificationTokenRepository(session=session)


__all__ = [
    "EmailVerificationTokenRepository",
    "NeoZenRepository",
    "SessionRepository",
    "SubjectRepository",
    "get_email_verification_token_repository",
    "get_session_repository",
    "get_subject_repository",
]
