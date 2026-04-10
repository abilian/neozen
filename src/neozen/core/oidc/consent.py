"""Consent management for OIDC.

Tracks which scopes a subject has granted to which OAuth client.
Enables UIs for "trusted applications" and consent revocation.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Any, Protocol

from neozen.core.models import NeoZenModel


class ConsentRecord(NeoZenModel):
    """A subject's consent for a client to access certain scopes.

    Attributes:
        id: Unique identifier
        subject_id: The subject who granted consent
        client_id: The OAuth client granted consent
        scopes: Space-separated granted scopes
        granted_at: When consent was first granted
        updated_at: When consent was last updated
        revoked_at: When consent was revoked (None if active)
    """

    id: str
    subject_id: str
    client_id: str
    scopes: str
    granted_at: datetime
    updated_at: datetime
    revoked_at: datetime | None


class ConsentRepository(Protocol):
    """Repository protocol for consent records."""

    async def create(self, **data: Any) -> ConsentRecord: ...

    async def get(self, subject_id: str, client_id: str) -> ConsentRecord | None:
        """Get the consent record for a subject/client pair (active or not)."""
        ...

    async def list_for_subject(
        self, subject_id: str, *, include_revoked: bool = False
    ) -> list[ConsentRecord]: ...

    async def update_obj(self, obj: ConsentRecord, **data: Any) -> ConsentRecord: ...

    async def delete(self, obj: ConsentRecord) -> None: ...


class ConsentService:
    """Service for OIDC consent management.

    Handles:
    - Granting consent (storing scopes per subject/client)
    - Listing trusted applications
    - Revoking and restoring consent
    - Checking if existing consent covers a new request

    Example:
        service = ConsentService(repository=consent_repo)

        # Check before authorization
        if not await service.has_consent("user_1", "client_1", "openid email"):
            # Show consent screen
            ...

        # Record consent
        await service.grant_consent("user_1", "client_1", "openid email")

        # User goes to trusted apps page
        records = await service.list_trusted_apps("user_1")

        # User revokes
        await service.revoke_consent("user_1", "client_1")
    """

    def __init__(self, repository: ConsentRepository) -> None:
        self.repository = repository

    @staticmethod
    def _new_id() -> str:
        return f"consent_{secrets.token_hex(8)}"

    async def grant_consent(
        self,
        subject_id: str,
        client_id: str,
        scopes: str,
    ) -> ConsentRecord:
        """Grant or update consent for a subject/client/scopes triple.

        If a record already exists (active or revoked), it is updated
        with the new scopes (union with existing) and reactivated.
        """
        now = datetime.now(UTC)
        existing = await self.repository.get(subject_id, client_id)

        if existing is not None:
            # Merge scopes: union of existing and new
            existing_set = set(existing.scopes.split())
            new_set = set(scopes.split())
            merged = " ".join(sorted(existing_set | new_set))
            return await self.repository.update_obj(
                existing,
                scopes=merged,
                updated_at=now,
                revoked_at=None,
            )

        return await self.repository.create(
            id=self._new_id(),
            subject_id=subject_id,
            client_id=client_id,
            scopes=scopes,
            granted_at=now,
            updated_at=now,
            revoked_at=None,
        )

    async def has_consent(
        self,
        subject_id: str,
        client_id: str,
        scopes: str,
    ) -> bool:
        """Check whether the requested scopes are already covered by consent.

        Returns True if there's an active consent record covering all
        the requested scopes.
        """
        record = await self.repository.get(subject_id, client_id)
        if record is None or record.revoked_at is not None:
            return False

        granted = set(record.scopes.split())
        requested = set(scopes.split())
        return requested.issubset(granted)

    async def get_consent(
        self,
        subject_id: str,
        client_id: str,
    ) -> ConsentRecord | None:
        """Get the active consent record for a subject/client pair."""
        record = await self.repository.get(subject_id, client_id)
        if record is None or record.revoked_at is not None:
            return None
        return record

    async def list_trusted_apps(
        self,
        subject_id: str,
        *,
        include_revoked: bool = False,
    ) -> list[ConsentRecord]:
        """List all clients the subject has granted consent to."""
        records = await self.repository.list_for_subject(
            subject_id, include_revoked=include_revoked
        )
        if not include_revoked:
            return [r for r in records if r.revoked_at is None]
        return records

    async def revoke_consent(
        self,
        subject_id: str,
        client_id: str,
    ) -> bool:
        """Revoke consent for a client.

        Returns True if a record was revoked, False if no record existed.
        """
        record = await self.repository.get(subject_id, client_id)
        if record is None or record.revoked_at is not None:
            return False

        await self.repository.update_obj(
            record,
            revoked_at=datetime.now(UTC),
        )
        return True

    async def restore_consent(
        self,
        subject_id: str,
        client_id: str,
    ) -> bool:
        """Restore previously revoked consent.

        Returns True if a revoked record was restored, False otherwise.
        """
        record = await self.repository.get(subject_id, client_id)
        if record is None or record.revoked_at is None:
            return False

        await self.repository.update_obj(
            record,
            revoked_at=None,
            updated_at=datetime.now(UTC),
        )
        return True


__all__ = [
    "ConsentRecord",
    "ConsentRepository",
    "ConsentService",
]
