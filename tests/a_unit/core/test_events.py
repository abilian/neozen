# ruff: noqa: RUF029
"""Unit tests for the event system."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from neozen.core.events import (
    AuthEvent,
    EventBus,
    EventEmitterMixin,
    EventTypes,
)


class TestAuthEvent:
    """Tests for AuthEvent dataclass."""

    def test_create_event(self) -> None:
        event = AuthEvent(
            event_type=EventTypes.LOGIN_SUCCESS,
            timestamp=datetime.now(UTC),
            subject_id="user123",
            metadata={"ip": "192.168.1.1"},
        )

        assert event.event_type == EventTypes.LOGIN_SUCCESS
        assert event.subject_id == "user123"
        assert event.metadata["ip"] == "192.168.1.1"

    def test_with_metadata(self) -> None:
        event = AuthEvent(
            event_type=EventTypes.LOGIN_SUCCESS,
            timestamp=datetime.now(UTC),
            metadata={"ip": "192.168.1.1"},
        )

        new_event = event.with_metadata(user_agent="Chrome")

        # Original unchanged
        assert "user_agent" not in event.metadata

        # New event has both
        assert new_event.metadata["ip"] == "192.168.1.1"
        assert new_event.metadata["user_agent"] == "Chrome"

    def test_default_values(self) -> None:
        event = AuthEvent(
            event_type=EventTypes.LOGIN_SUCCESS,
            timestamp=datetime.now(UTC),
        )

        assert event.subject_id is None
        assert event.metadata == {}


class TestEventTypes:
    """Tests for EventTypes constants."""

    def test_login_events(self) -> None:
        assert EventTypes.LOGIN_SUCCESS == "login.success"
        assert EventTypes.LOGIN_FAILED == "login.failed"
        assert EventTypes.LOGOUT == "logout"

    def test_session_events(self) -> None:
        assert EventTypes.SESSION_CREATED == "session.created"
        assert EventTypes.SESSION_EXPIRED == "session.expired"
        assert EventTypes.SESSION_REVOKED == "session.revoked"

    def test_mfa_events(self) -> None:
        assert EventTypes.MFA_ENABLED == "mfa.enabled"
        assert EventTypes.MFA_DISABLED == "mfa.disabled"
        assert EventTypes.BACKUP_CODE_USED == "mfa.backup_code_used"


@pytest.mark.anyio
class TestEventBus:
    """Tests for EventBus."""

    async def test_subscribe_and_emit(self) -> None:
        bus = EventBus()
        received_events: list[AuthEvent] = []

        async def handler(event: AuthEvent) -> None:
            received_events.append(event)

        bus.subscribe(EventTypes.LOGIN_SUCCESS, handler)

        event = AuthEvent(
            event_type=EventTypes.LOGIN_SUCCESS,
            timestamp=datetime.now(UTC),
            subject_id="user123",
        )
        await bus.emit(event)

        assert len(received_events) == 1
        assert received_events[0].subject_id == "user123"

    async def test_multiple_handlers(self) -> None:
        bus = EventBus()
        calls: list[str] = []

        async def handler1(event: AuthEvent) -> None:
            calls.append("handler1")

        async def handler2(event: AuthEvent) -> None:
            calls.append("handler2")

        bus.subscribe(EventTypes.LOGIN_SUCCESS, handler1)
        bus.subscribe(EventTypes.LOGIN_SUCCESS, handler2)

        await bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
            )
        )

        assert calls == ["handler1", "handler2"]

    async def test_wildcard_pattern(self) -> None:
        bus = EventBus()
        received: list[str] = []

        async def handler(event: AuthEvent) -> None:
            received.append(event.event_type)

        bus.subscribe("login.*", handler)

        await bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
            )
        )
        await bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGIN_FAILED,
                timestamp=datetime.now(UTC),
            )
        )
        await bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGOUT,  # Does not match login.*
                timestamp=datetime.now(UTC),
            )
        )

        assert received == ["login.success", "login.failed"]

    async def test_catch_all_pattern(self) -> None:
        bus = EventBus()
        received: list[str] = []

        async def handler(event: AuthEvent) -> None:
            received.append(event.event_type)

        bus.subscribe("*", handler)

        await bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
            )
        )
        await bus.emit(
            AuthEvent(
                event_type=EventTypes.SESSION_CREATED,
                timestamp=datetime.now(UTC),
            )
        )

        assert len(received) == 2

    async def test_unsubscribe(self) -> None:
        bus = EventBus()
        calls = 0

        async def handler(event: AuthEvent) -> None:
            nonlocal calls
            calls += 1

        bus.subscribe(EventTypes.LOGIN_SUCCESS, handler)
        await bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
            )
        )

        assert calls == 1

        bus.unsubscribe(EventTypes.LOGIN_SUCCESS, handler)
        await bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
            )
        )

        assert calls == 1  # No additional calls

    async def test_unsubscribe_nonexistent(self) -> None:
        bus = EventBus()

        async def handler(event: AuthEvent) -> None:
            pass

        # Should not raise
        bus.unsubscribe(EventTypes.LOGIN_SUCCESS, handler)

    async def test_unsubscribe_all(self) -> None:
        bus = EventBus()

        async def handler1(event: AuthEvent) -> None:
            pass

        async def handler2(event: AuthEvent) -> None:
            pass

        bus.subscribe(EventTypes.LOGIN_SUCCESS, handler1)
        bus.subscribe(EventTypes.LOGIN_SUCCESS, handler2)

        assert bus.handler_count == 2

        bus.unsubscribe_all(EventTypes.LOGIN_SUCCESS)

        assert bus.handler_count == 0

    async def test_clear(self) -> None:
        bus = EventBus()

        async def handler(event: AuthEvent) -> None:
            pass

        bus.subscribe(EventTypes.LOGIN_SUCCESS, handler)
        bus.subscribe(EventTypes.LOGIN_FAILED, handler)

        assert bus.pattern_count == 2

        bus.clear()

        assert bus.handler_count == 0
        assert bus.pattern_count == 0

    async def test_sync_handler(self) -> None:
        bus = EventBus()
        received: list[AuthEvent] = []

        def sync_handler(event: AuthEvent) -> None:
            received.append(event)

        bus.subscribe(EventTypes.LOGIN_SUCCESS, sync_handler)

        await bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
            )
        )

        assert len(received) == 1

    def test_emit_sync(self) -> None:
        bus = EventBus()
        received: list[AuthEvent] = []

        def sync_handler(event: AuthEvent) -> None:
            received.append(event)

        bus.subscribe(EventTypes.LOGIN_SUCCESS, sync_handler)

        bus.emit_sync(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
            )
        )

        assert len(received) == 1

    async def test_handler_exception_doesnt_stop_others(self) -> None:
        bus = EventBus()
        calls: list[str] = []

        async def bad_handler(event: AuthEvent) -> None:
            msg = "Intentional error"
            raise RuntimeError(msg)

        async def good_handler(event: AuthEvent) -> None:
            calls.append("good")

        bus.subscribe(EventTypes.LOGIN_SUCCESS, bad_handler)
        bus.subscribe(EventTypes.LOGIN_SUCCESS, good_handler)

        # Should not raise, and good_handler should still be called
        await bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
            )
        )

        assert calls == ["good"]

    async def test_no_matching_handlers(self) -> None:
        bus = EventBus()

        async def handler(event: AuthEvent) -> None:
            pass

        bus.subscribe(EventTypes.LOGIN_SUCCESS, handler)

        # Should not raise even with no matching handlers
        await bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGOUT,
                timestamp=datetime.now(UTC),
            )
        )

    async def test_emit_background(self) -> None:
        bus = EventBus()
        received: list[AuthEvent] = []

        async def handler(event: AuthEvent) -> None:
            received.append(event)

        bus.subscribe(EventTypes.LOGIN_SUCCESS, handler)

        bus.emit_background(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
            )
        )

        # Wait for background task
        await bus.wait_for_background_tasks(max_wait=1.0)

        assert len(received) == 1


@pytest.mark.anyio
class TestEventEmitterMixin:
    """Tests for EventEmitterMixin."""

    async def test_emit_with_bus(self) -> None:
        bus = EventBus()
        received: list[AuthEvent] = []

        async def handler(event: AuthEvent) -> None:
            received.append(event)

        bus.subscribe(EventTypes.LOGIN_SUCCESS, handler)

        class TestService(EventEmitterMixin):
            async def do_login(self, subject_id: str) -> None:
                await self._emit(
                    EventTypes.LOGIN_SUCCESS,
                    subject_id,
                    method="password",
                )

        service = TestService()
        service.set_event_bus(bus)

        await service.do_login("user123")

        assert len(received) == 1
        assert received[0].subject_id == "user123"
        assert received[0].metadata["method"] == "password"

    async def test_emit_without_bus(self) -> None:
        class TestService(EventEmitterMixin):
            async def do_login(self, subject_id: str) -> None:
                await self._emit(EventTypes.LOGIN_SUCCESS, subject_id)

        service = TestService()

        # Should not raise even without event bus
        await service.do_login("user123")

    async def test_emit_sync(self) -> None:
        bus = EventBus()
        received: list[AuthEvent] = []

        def handler(event: AuthEvent) -> None:
            received.append(event)

        bus.subscribe(EventTypes.LOGIN_SUCCESS, handler)

        class TestService(EventEmitterMixin):
            def do_login_sync(self, subject_id: str) -> None:
                self._emit_sync(EventTypes.LOGIN_SUCCESS, subject_id)

        service = TestService()
        service.set_event_bus(bus)

        service.do_login_sync("user123")

        assert len(received) == 1

    async def test_emit_background(self) -> None:
        bus = EventBus()
        received: list[AuthEvent] = []

        async def handler(event: AuthEvent) -> None:
            received.append(event)

        bus.subscribe(EventTypes.LOGIN_SUCCESS, handler)

        class TestService(EventEmitterMixin):
            async def do_login(self, subject_id: str) -> None:
                await self._emit(
                    EventTypes.LOGIN_SUCCESS,
                    subject_id,
                    background=True,
                )

        service = TestService()
        service.set_event_bus(bus)

        await service.do_login("user123")
        await bus.wait_for_background_tasks(max_wait=1.0)

        assert len(received) == 1

    async def test_event_bus_property(self) -> None:
        bus = EventBus()

        class TestService(EventEmitterMixin):
            pass

        service = TestService()
        assert service.event_bus is None

        service.set_event_bus(bus)
        assert service.event_bus is bus
