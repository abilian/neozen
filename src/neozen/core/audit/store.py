"""Audit log storage backends for NeoZen."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from neozen.core.audit.types import AuditLogEntry


class AuditLogStore(Protocol):
    """Storage interface for audit logs."""

    async def append(self, entry: AuditLogEntry) -> None:
        """Append an audit log entry."""
        ...

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
        """Query audit logs with filters."""
        ...

    async def count(
        self,
        *,
        subject_id: str | None = None,
        event_type: str | None = None,
        action: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """Count audit log entries matching filters."""
        ...

    async def get_by_id(self, entry_id: str) -> AuditLogEntry | None:
        """Get a specific audit log entry by ID."""
        ...


class InMemoryAuditLogStore:
    """In-memory audit log store.

    Suitable for testing and development.
    For production, use a database-backed store.
    """

    def __init__(self, max_entries: int = 10000) -> None:
        """Initialize store with optional max entries limit."""
        self._entries: list[AuditLogEntry] = []
        self._max_entries = max_entries

    async def append(self, entry: AuditLogEntry) -> None:
        """Append an audit log entry."""
        self._entries.append(entry)
        # Trim if over limit
        if len(self._entries) > self._max_entries:
            self._entries = self._entries[-self._max_entries :]

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
        """Query audit logs with filters."""
        results = self._filter_entries(
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
        )
        # Sort by timestamp descending (most recent first)
        results.sort(key=lambda e: e.timestamp, reverse=True)
        return results[offset : offset + limit]

    async def count(
        self,
        *,
        subject_id: str | None = None,
        event_type: str | None = None,
        action: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """Count audit log entries matching filters."""
        results = self._filter_entries(
            subject_id=subject_id,
            event_type=event_type,
            action=action,
            start_time=start_time,
            end_time=end_time,
        )
        return len(results)

    async def get_by_id(self, entry_id: str) -> AuditLogEntry | None:
        """Get a specific audit log entry by ID."""
        for entry in self._entries:
            if entry.id == entry_id:
                return entry
        return None

    def _matches_filters(
        self,
        entry: AuditLogEntry,
        *,
        subject_id: str | None,
        actor_id: str | None,
        event_type: str | None,
        action: str | None,
        outcome: str | None,
        start_time: datetime | None,
        end_time: datetime | None,
        ip_address: str | None,
        resource_type: str | None,
        resource_id: str | None,
    ) -> bool:
        """Check if entry matches all filters."""
        if subject_id and entry.subject_id != subject_id:
            return False
        if actor_id and entry.actor_id != actor_id:
            return False
        if event_type and entry.event_type != event_type:
            return False
        if action and entry.action != action:
            return False
        if outcome and entry.outcome != outcome:
            return False
        if start_time and entry.timestamp < start_time:
            return False
        if end_time and entry.timestamp > end_time:
            return False
        if ip_address and entry.ip_address != ip_address:
            return False
        if resource_type and entry.resource_type != resource_type:
            return False
        return not (resource_id and entry.resource_id != resource_id)

    def _filter_entries(
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
    ) -> list[AuditLogEntry]:
        """Filter entries by criteria."""
        return [
            entry
            for entry in self._entries
            if self._matches_filters(
                entry,
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
            )
        ]


__all__ = [
    "AuditLogStore",
    "InMemoryAuditLogStore",
]
