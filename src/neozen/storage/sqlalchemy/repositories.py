"""Advanced-Alchemy repositories for NeoZen models."""

from __future__ import annotations

import typing

from advanced_alchemy.base import ModelProtocol
from advanced_alchemy.exceptions import NotFoundError
from advanced_alchemy.filters import LimitOffset
from advanced_alchemy.repository import SQLAlchemyAsyncRepository
from sqlalchemy.ext.asyncio import AsyncSession

from neozen.storage.base import DoesNotExist
from neozen.storage.sqlalchemy.models import (
    BackupCode,
    EmailVerificationToken,
    Group,
    GroupMembership,
    GroupRoleAssignment,
    OAuthState,
    Organization,
    PasswordHistory,
    Role,
    RoleAssignment,
    Session,
    SocialAccount,
    Subject,
    WebAuthnChallenge,
    WebAuthnCredential,
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

    async def get_many_by(
        self,
        *,
        offset: int = 0,
        limit: int | None = None,
        **filters: typing.Any,
    ) -> list[Model]:
        """Get multiple models by filters; ``limit=None`` returns every match."""
        if limit is None:
            return list(await self.list(**filters))[offset:]
        pagination = LimitOffset(limit=limit, offset=offset)
        return list(await self.list(pagination, **filters))

    async def count(self, **filters: typing.Any) -> int:  # type: ignore[override]  # ty: ignore[invalid-method-override]
        """Count models matching the given filters."""
        # Advanced-Alchemy's count method accepts filters
        return await super().count(**filters)

    async def exists(self, **filters: typing.Any) -> bool:  # type: ignore[override]  # ty: ignore[invalid-method-override]
        """Check if any model exists matching the given filters."""
        # Advanced-Alchemy's exists method accepts filters
        return await super().exists(**filters)

    async def create(self, **data: typing.Any) -> Model:
        """Create a new model instance."""
        obj = self.model_type(**data)
        return await self.add(obj)

    async def update_obj(self, obj: Model, **data: typing.Any) -> Model:
        """Update an existing model instance."""
        for key, value in data.items():
            setattr(obj, key, value)
        return await self.update(obj)

    async def delete(self, obj: Model) -> None:  # type: ignore[override]  # ty: ignore[invalid-method-override]
        """Delete a model instance."""
        await super().delete(self.get_id_attribute_value(obj))


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


class RoleRepository(NeoZenRepository[Role]):
    """Repository for Role model."""

    model_type = Role


class RoleAssignmentRepository(NeoZenRepository[RoleAssignment]):
    """Repository for RoleAssignment model."""

    model_type = RoleAssignment


def get_role_repository(session: AsyncSession) -> RoleRepository:
    """Factory function for RoleRepository."""
    return RoleRepository(session=session)


def get_role_assignment_repository(session: AsyncSession) -> RoleAssignmentRepository:
    """Factory function for RoleAssignmentRepository."""
    return RoleAssignmentRepository(session=session)


class PasswordHistoryRepository(NeoZenRepository[PasswordHistory]):
    """Repository for PasswordHistory model."""

    model_type = PasswordHistory


def get_password_history_repository(session: AsyncSession) -> PasswordHistoryRepository:
    """Factory function for PasswordHistoryRepository."""
    return PasswordHistoryRepository(session=session)


class BackupCodeRepository(NeoZenRepository[BackupCode]):
    """Repository for BackupCode model."""

    model_type = BackupCode


def get_backup_code_repository(session: AsyncSession) -> BackupCodeRepository:
    """Factory function for BackupCodeRepository."""
    return BackupCodeRepository(session=session)


class SocialAccountRepository(NeoZenRepository[SocialAccount]):
    """Repository for SocialAccount model."""

    model_type = SocialAccount


def get_social_account_repository(session: AsyncSession) -> SocialAccountRepository:
    """Factory function for SocialAccountRepository."""
    return SocialAccountRepository(session=session)


class OAuthStateRepository(NeoZenRepository[OAuthState]):
    """Repository for OAuthState model."""

    model_type = OAuthState
    id_attribute = "state"


def get_oauth_state_repository(session: AsyncSession) -> OAuthStateRepository:
    """Factory function for OAuthStateRepository."""
    return OAuthStateRepository(session=session)


class WebAuthnCredentialRepository(NeoZenRepository[WebAuthnCredential]):
    """Repository for WebAuthnCredential model."""

    model_type = WebAuthnCredential


def get_webauthn_credential_repository(
    session: AsyncSession,
) -> WebAuthnCredentialRepository:
    """Factory function for WebAuthnCredentialRepository."""
    return WebAuthnCredentialRepository(session=session)


class WebAuthnChallengeRepository(NeoZenRepository[WebAuthnChallenge]):
    """Repository for WebAuthnChallenge model."""

    model_type = WebAuthnChallenge


def get_webauthn_challenge_repository(
    session: AsyncSession,
) -> WebAuthnChallengeRepository:
    """Factory function for WebAuthnChallengeRepository."""
    return WebAuthnChallengeRepository(session=session)


class GroupRepository(NeoZenRepository[Group]):
    """Repository for Group model."""

    model_type = Group


class GroupMembershipRepository(NeoZenRepository[GroupMembership]):
    """Repository for GroupMembership model."""

    model_type = GroupMembership


class GroupRoleAssignmentRepository(NeoZenRepository[GroupRoleAssignment]):
    """Repository for GroupRoleAssignment model."""

    model_type = GroupRoleAssignment


class OrganizationRepository(NeoZenRepository[Organization]):
    """Repository for Organization model."""

    model_type = Organization


def get_group_repository(session: AsyncSession) -> GroupRepository:
    """Factory function for GroupRepository."""
    return GroupRepository(session=session)


def get_group_membership_repository(
    session: AsyncSession,
) -> GroupMembershipRepository:
    """Factory function for GroupMembershipRepository."""
    return GroupMembershipRepository(session=session)


def get_group_role_assignment_repository(
    session: AsyncSession,
) -> GroupRoleAssignmentRepository:
    """Factory function for GroupRoleAssignmentRepository."""
    return GroupRoleAssignmentRepository(session=session)


def get_organization_repository(session: AsyncSession) -> OrganizationRepository:
    """Factory function for OrganizationRepository."""
    return OrganizationRepository(session=session)


__all__ = [
    "BackupCodeRepository",
    "EmailVerificationTokenRepository",
    "GroupMembershipRepository",
    "GroupRepository",
    "GroupRoleAssignmentRepository",
    "NeoZenRepository",
    "OAuthStateRepository",
    "OrganizationRepository",
    "PasswordHistoryRepository",
    "RoleAssignmentRepository",
    "RoleRepository",
    "SessionRepository",
    "SocialAccountRepository",
    "SubjectRepository",
    "WebAuthnChallengeRepository",
    "WebAuthnCredentialRepository",
    "get_backup_code_repository",
    "get_email_verification_token_repository",
    "get_group_membership_repository",
    "get_group_repository",
    "get_group_role_assignment_repository",
    "get_oauth_state_repository",
    "get_organization_repository",
    "get_password_history_repository",
    "get_role_assignment_repository",
    "get_role_repository",
    "get_session_repository",
    "get_social_account_repository",
    "get_subject_repository",
    "get_webauthn_challenge_repository",
    "get_webauthn_credential_repository",
]
