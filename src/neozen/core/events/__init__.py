"""NeoZen Event System.

The event system allows components to subscribe to and emit
authentication-related events. This enables features like:

- Audit logging
- Analytics
- Notifications
- Custom integrations

Example:
    from neozen.core.events import EventBus, AuthEvent, EventTypes

    # Create event bus
    bus = EventBus()

    # Subscribe to events
    async def log_login(event: AuthEvent) -> None:
        print(f"Login: {event.subject_id} at {event.timestamp}")

    bus.subscribe(EventTypes.LOGIN_SUCCESS, log_login)
    bus.subscribe("login.*", log_login)  # Wildcard

    # Emit events (typically done by services)
    await bus.emit(AuthEvent(
        event_type=EventTypes.LOGIN_SUCCESS,
        timestamp=datetime.now(UTC),
        subject_id="user123",
        metadata={"ip": "192.168.1.1"},
    ))

For services that emit events, use the EventEmitterMixin:

    from neozen.core.events import EventEmitterMixin, EventTypes

    class MyService(EventEmitterMixin):
        async def do_something(self, subject_id: str) -> None:
            # ... do work ...
            await self._emit(EventTypes.SUBJECT_UPDATED, subject_id)

    service = MyService()
    service.set_event_bus(bus)
"""

from __future__ import annotations

from .bus import AsyncEventHandler, EventBus, EventHandler, SyncEventHandler
from .emitter import EventEmitterMixin
from .types import AuthEvent, EventTypes

__all__ = [
    # Event types
    "AuthEvent",
    "EventTypes",
    # Event bus
    "EventBus",
    "EventHandler",
    "AsyncEventHandler",
    "SyncEventHandler",
    # Mixin
    "EventEmitterMixin",
]
