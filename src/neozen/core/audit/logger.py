"""Audit logger service for NeoZen."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from neozen.core.audit.store import AuditLogStore
from neozen.core.audit.types import AuditLogEntry, AuditOutcome


class AuditLogger:
    """Central audit logging service.

    Provides a simple interface for logging security-relevant events.
    Can be integrated with the event system for automatic logging.

    Example:
        store = InMemoryAuditLogStore()
        logger = AuditLogger(store)

        await logger.log(
            event_type="auth",
            action=AuditActions.LOGIN,
            outcome=AuditOutcome.SUCCESS,
            subject_id="user123",
            ip_address="192.168.1.1",
        )

        # Query logs
        entries = await logger.query(subject_id="user123", limit=10)
    """

    def __init__(
        self,
        store: AuditLogStore,
        *,
        generate_id: bool = True,
    ) -> None:
        """Initialize audit logger.

        Args:
            store: Storage backend for audit logs.
            generate_id: Whether to auto-generate entry IDs.
        """
        self.store = store
        self.generate_id = generate_id

    async def log(
        self,
        event_type: str,
        action: str,
        outcome: str = AuditOutcome.SUCCESS,
        *,
        entry_id: str | None = None,
        subject_id: str | None = None,
        actor_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
        timestamp: datetime | None = None,
    ) -> AuditLogEntry:
        """Write an audit log entry.

        Args:
            event_type: Category of event (auth, oauth, admin, etc.).
            action: Specific action performed.
            outcome: Result of the action.
            entry_id: Optional entry ID (auto-generated if not provided).
            subject_id: Subject affected by the action.
            actor_id: Who performed the action.
            ip_address: Client IP address.
            user_agent: Client user agent.
            resource_type: Type of resource affected.
            resource_id: ID of resource affected.
            details: Additional event details.
            request_id: Request correlation ID.
            timestamp: Event timestamp (defaults to now).

        Returns:
            The created audit log entry.
        """
        if entry_id is None and self.generate_id:
            entry_id = str(uuid.uuid4())

        if entry_id is None:
            msg = "entry_id is required when generate_id is False"
            raise ValueError(msg)

        entry = AuditLogEntry(
            id=entry_id,
            timestamp=timestamp or datetime.now(UTC),
            event_type=event_type,
            action=action,
            outcome=outcome,
            subject_id=subject_id,
            actor_id=actor_id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            request_id=request_id,
        )

        await self.store.append(entry)
        return entry

    async def log_success(
        self,
        event_type: str,
        action: str,
        **kwargs: Any,
    ) -> AuditLogEntry:
        """Log a successful action."""
        return await self.log(event_type, action, AuditOutcome.SUCCESS, **kwargs)

    async def log_failure(
        self,
        event_type: str,
        action: str,
        **kwargs: Any,
    ) -> AuditLogEntry:
        """Log a failed action."""
        return await self.log(event_type, action, AuditOutcome.FAILURE, **kwargs)

    async def log_error(
        self,
        event_type: str,
        action: str,
        **kwargs: Any,
    ) -> AuditLogEntry:
        """Log an error."""
        return await self.log(event_type, action, AuditOutcome.ERROR, **kwargs)

    async def query(
        self,
        *,
        subject_id: str | None = None,
        actor_id: str | None = None,
        event_type: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        ip_address: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLogEntry]:
        """Query audit logs.

        Args:
            subject_id: Filter by subject.
            actor_id: Filter by actor.
            event_type: Filter by event type.
            action: Filter by action.
            outcome: Filter by outcome.
            start_time: Filter by start time.
            end_time: Filter by end time.
            ip_address: Filter by IP address.
            resource_type: Filter by resource type.
            resource_id: Filter by resource ID.
            limit: Maximum entries to return.
            offset: Number of entries to skip.

        Returns:
            List of matching audit log entries.
        """
        return await self.store.query(
            subject_id=subject_id,
            actor_id=actor_id,
            event_type=event_type,
            action=action,
            outcome=outcome,
            start_time=start_time,
            end_time=end_time,
            ip_address=ip_address,
            resource_type=resource_type,
            resource_id=resource_id,
            limit=limit,
            offset=offset,
        )

    async def count(
        self,
        *,
        subject_id: str | None = None,
        event_type: str | None = None,
        action: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """Count audit log entries."""
        return await self.store.count(
            subject_id=subject_id,
            event_type=event_type,
            action=action,
            start_time=start_time,
            end_time=end_time,
        )

    async def get_by_id(self, entry_id: str) -> AuditLogEntry | None:
        """Get a specific audit log entry."""
        return await self.store.get_by_id(entry_id)


__all__ = [
    "AuditLogger",
]
