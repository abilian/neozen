"""Invitation system for group/role assignment.

Allows admins to send invitations to email addresses with pre-assigned
groups and roles. Invitations are token-based with expiration and can
be accepted or declined.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from neozen.core.crypto import generate_token_hash_pair, get_token_hash
from neozen.core.models import NeoZenModel
from neozen.core.utils import ensure_utc


class InvitationStatus(StrEnum):
    """Invitation status."""

    PENDING = "pending"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass(frozen=True)
class InvitationConfig:
    """Configuration for the invitation system.

    Attributes:
        token_lifetime: How long invitation tokens are valid.
        token_prefix: Prefix for invitation tokens.
        accept_url_template: URL template with {token} placeholder.
    """

    token_lifetime: timedelta = timedelta(days=7)
    token_prefix: str = "nz_inv_"
    accept_url_template: str = ""


class Invitation(NeoZenModel):
    """A pending invitation to join the system or a group.

    Attributes:
        id: Unique identifier
        token_hash: HMAC-SHA256 hash of the invitation token
        email: Recipient email address
        invited_by: Subject ID of the inviter
        group_ids_json: JSON array of group IDs to add the user to
        role_names_json: JSON array of role names to assign
        message: Optional personal message from the inviter
        status: Invitation status
        created_at: When the invitation was created
        expires_at: When the invitation expires
        accepted_at: When accepted (None if pending)
        accepted_by: Subject ID created/used on acceptance
    """

    id: str
    token_hash: str
    email: str
    invited_by: str | None
    group_ids_json: str
    role_names_json: str
    message: str
    status: str
    created_at: datetime
    expires_at: datetime
    accepted_at: datetime | None
    accepted_by: str | None


class InvitationRepository(Protocol):
    """Repository protocol for invitations."""

    async def create(self, **data: Any) -> Invitation: ...

    async def get_by_id(self, invitation_id: str) -> Invitation | None: ...

    async def get_by_hash(self, token_hash: str) -> Invitation | None: ...

    async def list_pending_for_email(self, email: str) -> list[Invitation]: ...

    async def list_pending(self) -> list[Invitation]: ...

    async def update_obj(self, obj: Invitation, **data: Any) -> Invitation: ...

    async def delete(self, obj: Invitation) -> None: ...


@dataclass(frozen=True)
class InvitationDetails:
    """Details extracted from a valid invitation."""

    invitation_id: str
    email: str
    group_ids: list[str]
    role_names: list[str]
    invited_by: str | None
    message: str
    expires_at: datetime


class InvitationError(Exception):
    """Base exception for invitation operations."""


class InvitationNotFoundError(InvitationError):
    """Raised when an invitation is not found."""


class InvitationExpiredError(InvitationError):
    """Raised when an invitation has expired."""


class InvitationAlreadyUsedError(InvitationError):
    """Raised when an invitation has already been accepted/declined."""


class InvitationService:
    """Service for invitation lifecycle.

    Handles:
    - Creating invitations with pre-assigned groups and roles
    - Token generation and validation
    - Acceptance and decline flows
    - Cleanup of expired invitations

    Application code is responsible for:
    - Sending the invitation email (via NotificationService or similar)
    - Actually creating the user / adding to groups / assigning roles
      after `accept_invitation()` returns details

    Example:
        service = InvitationService(
            config=InvitationConfig(
                accept_url_template="https://app.com/invite?token={token}",
            ),
            repository=invitation_repo,
            token_hash_key="secret",
        )

        # Create invitation
        invitation, token = await service.create_invitation(
            email="newuser@example.com",
            invited_by="admin_1",
            group_ids=["grp_engineering"],
            role_names=["user"],
        )
        # Send email with the URL: config.accept_url_template.format(token=token)

        # Accept invitation
        details = await service.accept_invitation(token, accepted_by="user_42")
    """

    def __init__(
        self,
        config: InvitationConfig,
        repository: InvitationRepository,
        token_hash_key: str,
    ) -> None:
        self.config = config
        self.repository = repository
        self.token_hash_key = token_hash_key

    @staticmethod
    def _new_id() -> str:
        return f"inv_{secrets.token_hex(8)}"

    async def create_invitation(
        self,
        email: str,
        *,
        invited_by: str | None = None,
        group_ids: list[str] | None = None,
        role_names: list[str] | None = None,
        message: str = "",
    ) -> tuple[Invitation, str]:
        """Create a new invitation.

        Returns the invitation record and the plain-text token to send
        in the email. Only the hash is stored.
        """
        token, token_hash = generate_token_hash_pair(
            self.token_hash_key,
            prefix=self.config.token_prefix,
        )

        now = datetime.now(UTC)
        invitation = await self.repository.create(
            id=self._new_id(),
            token_hash=token_hash,
            email=email.lower(),
            invited_by=invited_by,
            group_ids_json=json.dumps(group_ids or []),
            role_names_json=json.dumps(role_names or []),
            message=message,
            status=InvitationStatus.PENDING.value,
            created_at=now,
            expires_at=now + self.config.token_lifetime,
            accepted_at=None,
            accepted_by=None,
        )

        return invitation, token

    async def get_invitation_by_token(self, token: str) -> Invitation:
        """Look up an invitation by its plain-text token."""
        token_hash = get_token_hash(token, self.token_hash_key)
        invitation = await self.repository.get_by_hash(token_hash)
        if invitation is None:
            msg = "Invitation not found"
            raise InvitationNotFoundError(msg)
        return invitation

    async def validate_token(self, token: str) -> Invitation:
        """Check that an invitation token is valid and pending."""
        invitation = await self.get_invitation_by_token(token)

        if invitation.status != InvitationStatus.PENDING.value:
            msg = f"Invitation already {invitation.status}"
            raise InvitationAlreadyUsedError(msg)

        if datetime.now(UTC) > ensure_utc(invitation.expires_at):
            await self.repository.update_obj(
                invitation, status=InvitationStatus.EXPIRED.value
            )
            msg = "Invitation has expired"
            raise InvitationExpiredError(msg)

        return invitation

    async def accept_invitation(
        self,
        token: str,
        *,
        accepted_by: str,
    ) -> InvitationDetails:
        """Mark an invitation as accepted and return the details.

        The caller is responsible for actually creating the subject
        and applying the group memberships and role assignments.
        """
        invitation = await self.validate_token(token)

        await self.repository.update_obj(
            invitation,
            status=InvitationStatus.ACCEPTED.value,
            accepted_at=datetime.now(UTC),
            accepted_by=accepted_by,
        )

        return InvitationDetails(
            invitation_id=invitation.id,
            email=invitation.email,
            group_ids=json.loads(invitation.group_ids_json or "[]"),
            role_names=json.loads(invitation.role_names_json or "[]"),
            invited_by=invitation.invited_by,
            message=invitation.message,
            expires_at=invitation.expires_at,
        )

    async def decline_invitation(self, token: str) -> None:
        """Mark an invitation as declined."""
        invitation = await self.validate_token(token)
        await self.repository.update_obj(
            invitation,
            status=InvitationStatus.DECLINED.value,
        )

    async def revoke_invitation(self, invitation_id: str) -> None:
        """Revoke a pending invitation by its ID."""
        invitation = await self.repository.get_by_id(invitation_id)
        if invitation is None:
            msg = "Invitation not found"
            raise InvitationNotFoundError(msg)
        if invitation.status != InvitationStatus.PENDING.value:
            return  # Already used; nothing to do
        await self.repository.update_obj(
            invitation, status=InvitationStatus.REVOKED.value
        )

    async def list_pending_for_email(self, email: str) -> list[Invitation]:
        return await self.repository.list_pending_for_email(email.lower())

    async def list_pending(self) -> list[Invitation]:
        return await self.repository.list_pending()


__all__ = [
    "Invitation",
    "InvitationAlreadyUsedError",
    "InvitationConfig",
    "InvitationDetails",
    "InvitationError",
    "InvitationExpiredError",
    "InvitationNotFoundError",
    "InvitationRepository",
    "InvitationService",
    "InvitationStatus",
]
