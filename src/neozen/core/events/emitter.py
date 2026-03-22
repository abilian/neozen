"""Event emitter mixin for services."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .bus import EventBus
from .types import AuthEvent


class EventEmitterMixin:
    """Mixin for services that emit events.

    Add this mixin to any service that needs to emit authentication events.
    The event bus is optional - if not set, events are silently dropped.

    Example:
        class SessionService(EventEmitterMixin):
            async def create_session(self, subject_id: str) -> Session:
                session = await self._create_session_internal(subject_id)
                await self._emit(
                    EventTypes.SESSION_CREATED,
                    subject_id,
                    session_id=session.id,
                )
                return session

        # Set up event bus
        service = SessionService(...)
        service.set_event_bus(event_bus)
    """

    _event_bus: EventBus | None = None

    def set_event_bus(self, bus: EventBus) -> None:
        """Set the event bus for this service.

        Args:
            bus: The event bus to emit events to.
        """
        self._event_bus = bus

    @property
    def event_bus(self) -> EventBus | None:
        """Get the event bus, if set."""
        return self._event_bus

    async def _emit(
        self,
        event_type: str,
        subject_id: str | None = None,
        *,
        background: bool = False,
        **metadata: Any,
    ) -> None:
        """Emit an authentication event.

        If no event bus is configured, this is a no-op.

        Args:
            event_type: The type of event to emit.
            subject_id: The subject involved in the event.
            background: If True, emit in background task.
            **metadata: Additional event metadata.
        """
        if self._event_bus is None:
            return

        event = AuthEvent(
            event_type=event_type,
            timestamp=datetime.now(UTC),
            subject_id=subject_id,
            metadata=metadata,
        )

        if background:
            self._event_bus.emit_background(event)
        else:
            await self._event_bus.emit(event)

    def _emit_sync(
        self,
        event_type: str,
        subject_id: str | None = None,
        **metadata: Any,
    ) -> None:
        """Emit an authentication event synchronously.

        If no event bus is configured, this is a no-op.

        Args:
            event_type: The type of event to emit.
            subject_id: The subject involved in the event.
            **metadata: Additional event metadata.
        """
        if self._event_bus is None:
            return

        event = AuthEvent(
            event_type=event_type,
            timestamp=datetime.now(UTC),
            subject_id=subject_id,
            metadata=metadata,
        )

        self._event_bus.emit_sync(event)
