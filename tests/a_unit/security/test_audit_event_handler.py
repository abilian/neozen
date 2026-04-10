"""Tests for the audit event handler."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from neozen.core.audit import (
    AuditEventHandler,
    AuditLogger,
    InMemoryAuditLogStore,
    create_audit_handler,
    setup_audit_logging,
)
from neozen.core.audit.types import AuditActions, AuditOutcome
from neozen.core.events import AuthEvent, EventBus, EventTypes


@pytest.fixture
def audit_store() -> InMemoryAuditLogStore:
    """Create an in-memory audit store."""
    return InMemoryAuditLogStore()


@pytest.fixture
def audit_logger(audit_store: InMemoryAuditLogStore) -> AuditLogger:
    """Create an audit logger."""
    return AuditLogger(audit_store)


@pytest.fixture
def event_bus() -> EventBus:
    """Create an event bus."""
    return EventBus()


@pytest.fixture
def audit_handler(audit_logger: AuditLogger) -> AuditEventHandler:
    """Create an audit event handler."""
    return AuditEventHandler(audit_logger)


class TestAuditEventHandler:
    """Tests for AuditEventHandler."""

    @pytest.mark.anyio
    async def test_handle_login_success(
        self,
        audit_handler: AuditEventHandler,
        audit_store: InMemoryAuditLogStore,
    ) -> None:
        """Test handling login success event."""
        event = AuthEvent(
            event_type=EventTypes.LOGIN_SUCCESS,
            timestamp=datetime.now(UTC),
            subject_id="user123",
            metadata={"ip_address": "192.168.1.1"},
        )

        await audit_handler.handle(event)

        entries = await audit_store.query(subject_id="user123")
        assert len(entries) == 1
        assert entries[0].action == AuditActions.LOGIN
        assert entries[0].outcome == AuditOutcome.SUCCESS
        assert entries[0].ip_address == "192.168.1.1"

    @pytest.mark.anyio
    async def test_handle_login_failed(
        self,
        audit_handler: AuditEventHandler,
        audit_store: InMemoryAuditLogStore,
    ) -> None:
        """Test handling login failed event."""
        event = AuthEvent(
            event_type=EventTypes.LOGIN_FAILED,
            timestamp=datetime.now(UTC),
            subject_id="user123",
        )

        await audit_handler.handle(event)

        entries = await audit_store.query(subject_id="user123")
        assert len(entries) == 1
        assert entries[0].action == AuditActions.LOGIN
        assert entries[0].outcome == AuditOutcome.FAILURE

    @pytest.mark.anyio
    async def test_handle_mfa_events(
        self,
        audit_handler: AuditEventHandler,
        audit_store: InMemoryAuditLogStore,
    ) -> None:
        """Test handling MFA events."""
        event = AuthEvent(
            event_type=EventTypes.MFA_ENABLED,
            timestamp=datetime.now(UTC),
            subject_id="user123",
        )

        await audit_handler.handle(event)

        entries = await audit_store.query(subject_id="user123")
        assert len(entries) == 1
        assert entries[0].action == AuditActions.MFA_ENABLE
        assert entries[0].outcome == AuditOutcome.SUCCESS

    @pytest.mark.anyio
    async def test_handle_oauth_events(
        self,
        audit_handler: AuditEventHandler,
        audit_store: InMemoryAuditLogStore,
    ) -> None:
        """Test handling OAuth events."""
        event = AuthEvent(
            event_type=EventTypes.TOKEN_ISSUED,
            timestamp=datetime.now(UTC),
            subject_id="user123",
            metadata={
                "resource_type": "oauth_token",
                "resource_id": "token123",
            },
        )

        await audit_handler.handle(event)

        entries = await audit_store.query(subject_id="user123")
        assert len(entries) == 1
        assert entries[0].action == AuditActions.TOKEN_ISSUE
        assert entries[0].resource_type == "oauth_token"
        assert entries[0].resource_id == "token123"

    @pytest.mark.anyio
    async def test_exclude_event_types(
        self,
        audit_logger: AuditLogger,
        audit_store: InMemoryAuditLogStore,
    ) -> None:
        """Test excluding specific event types."""
        handler = AuditEventHandler(
            audit_logger,
            exclude_types=[EventTypes.SESSION_VALIDATED],
        )

        # This should be logged
        await handler.handle(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
                subject_id="user123",
            )
        )

        # This should be excluded
        await handler.handle(
            AuthEvent(
                event_type=EventTypes.SESSION_VALIDATED,
                timestamp=datetime.now(UTC),
                subject_id="user123",
            )
        )

        entries = await audit_store.query(subject_id="user123")
        assert len(entries) == 1
        assert entries[0].action == AuditActions.LOGIN

    @pytest.mark.anyio
    async def test_filter_specific_event_types(
        self,
        audit_logger: AuditLogger,
        audit_store: InMemoryAuditLogStore,
    ) -> None:
        """Test filtering to specific event types."""
        handler = AuditEventHandler(
            audit_logger,
            event_types=[EventTypes.LOGIN_SUCCESS, EventTypes.LOGOUT],
        )

        # These should be logged
        await handler.handle(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
                subject_id="user123",
            )
        )
        await handler.handle(
            AuthEvent(
                event_type=EventTypes.LOGOUT,
                timestamp=datetime.now(UTC),
                subject_id="user123",
            )
        )

        # This should NOT be logged
        await handler.handle(
            AuthEvent(
                event_type=EventTypes.PASSWORD_CHANGED,
                timestamp=datetime.now(UTC),
                subject_id="user123",
            )
        )

        entries = await audit_store.query(subject_id="user123")
        assert len(entries) == 2

    @pytest.mark.anyio
    async def test_metadata_extraction(
        self,
        audit_handler: AuditEventHandler,
        audit_store: InMemoryAuditLogStore,
    ) -> None:
        """Test that metadata is properly extracted."""
        event = AuthEvent(
            event_type=EventTypes.LOGIN_SUCCESS,
            timestamp=datetime.now(UTC),
            subject_id="user123",
            metadata={
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0",
                "actor_id": "admin456",
                "request_id": "req-123",
                "custom_field": "custom_value",
            },
        )

        await audit_handler.handle(event)

        entries = await audit_store.query(subject_id="user123")
        assert len(entries) == 1
        entry = entries[0]
        assert entry.ip_address == "192.168.1.1"
        assert entry.user_agent == "Mozilla/5.0"
        assert entry.actor_id == "admin456"
        assert entry.request_id == "req-123"
        assert entry.details == {"custom_field": "custom_value"}


class TestEventBusIntegration:
    """Tests for event bus integration."""

    @pytest.mark.anyio
    async def test_subscribe_to_bus(
        self,
        event_bus: EventBus,
        audit_handler: AuditEventHandler,
        audit_store: InMemoryAuditLogStore,
    ) -> None:
        """Test subscribing to event bus."""
        audit_handler.subscribe(event_bus)

        await event_bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
                subject_id="user123",
            )
        )

        entries = await audit_store.query(subject_id="user123")
        assert len(entries) == 1

    @pytest.mark.anyio
    async def test_subscribe_to_specific_events(
        self,
        event_bus: EventBus,
        audit_handler: AuditEventHandler,
        audit_store: InMemoryAuditLogStore,
    ) -> None:
        """Test subscribing to specific events."""
        audit_handler.subscribe_to(
            event_bus,
            EventTypes.LOGIN_SUCCESS,
            EventTypes.LOGIN_FAILED,
        )

        # These should be logged
        await event_bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
                subject_id="user123",
            )
        )
        await event_bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGIN_FAILED,
                timestamp=datetime.now(UTC),
                subject_id="user456",
            )
        )

        # This should NOT be logged (not subscribed)
        await event_bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGOUT,
                timestamp=datetime.now(UTC),
                subject_id="user789",
            )
        )

        entries = await audit_store.query()
        assert len(entries) == 2


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_audit_handler(
        self,
        audit_logger: AuditLogger,
    ) -> None:
        """Test create_audit_handler function."""
        handler = create_audit_handler(audit_logger)
        assert isinstance(handler, AuditEventHandler)
        assert handler.logger is audit_logger

    def test_create_audit_handler_with_exclusions(
        self,
        audit_logger: AuditLogger,
    ) -> None:
        """Test create_audit_handler with exclusions."""
        handler = create_audit_handler(
            audit_logger,
            exclude_types=[EventTypes.SESSION_VALIDATED],
        )
        assert EventTypes.SESSION_VALIDATED in handler.exclude_types

    @pytest.mark.anyio
    async def test_setup_audit_logging(
        self,
        event_bus: EventBus,
        audit_logger: AuditLogger,
        audit_store: InMemoryAuditLogStore,
    ) -> None:
        """Test setup_audit_logging function."""
        handler = setup_audit_logging(event_bus, audit_logger)
        assert isinstance(handler, AuditEventHandler)

        # Emit an event and verify it's logged
        await event_bus.emit(
            AuthEvent(
                event_type=EventTypes.LOGIN_SUCCESS,
                timestamp=datetime.now(UTC),
                subject_id="user123",
            )
        )

        entries = await audit_store.query(subject_id="user123")
        assert len(entries) == 1


class TestEventMapping:
    """Tests for event type to action mapping."""

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("event_type", "expected_action"),
        [
            (EventTypes.LOGIN_SUCCESS, AuditActions.LOGIN),
            (EventTypes.LOGOUT, AuditActions.LOGOUT),
            (EventTypes.PASSWORD_CHANGED, AuditActions.PASSWORD_CHANGE),
            (EventTypes.MFA_ENABLED, AuditActions.MFA_ENABLE),
            (EventTypes.ROLE_ASSIGNED, AuditActions.ROLE_ASSIGN),
            (EventTypes.TOKEN_ISSUED, AuditActions.TOKEN_ISSUE),
        ],
    )
    async def test_event_action_mapping(
        self,
        audit_handler: AuditEventHandler,
        audit_store: InMemoryAuditLogStore,
        event_type: str,
        expected_action: str,
    ) -> None:
        """Test that events map to correct audit actions."""
        await audit_handler.handle(
            AuthEvent(
                event_type=event_type,
                timestamp=datetime.now(UTC),
                subject_id="user123",
            )
        )

        entries = await audit_store.query(subject_id="user123")
        assert len(entries) == 1
        assert entries[0].action == expected_action

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("event_type", "expected_outcome"),
        [
            (EventTypes.LOGIN_SUCCESS, AuditOutcome.SUCCESS),
            (EventTypes.LOGIN_FAILED, AuditOutcome.FAILURE),
            (EventTypes.MFA_CHALLENGE_SUCCESS, AuditOutcome.SUCCESS),
            (EventTypes.MFA_CHALLENGE_FAILED, AuditOutcome.FAILURE),
            (EventTypes.PERMISSION_GRANTED, AuditOutcome.SUCCESS),
            (EventTypes.PERMISSION_DENIED, AuditOutcome.FAILURE),
        ],
    )
    async def test_event_outcome_mapping(
        self,
        audit_handler: AuditEventHandler,
        audit_store: InMemoryAuditLogStore,
        event_type: str,
        expected_outcome: str,
    ) -> None:
        """Test that events map to correct outcomes."""
        await audit_handler.handle(
            AuthEvent(
                event_type=event_type,
                timestamp=datetime.now(UTC),
                subject_id="user123",
            )
        )

        entries = await audit_store.query(subject_id="user123")
        assert len(entries) == 1
        assert entries[0].outcome == expected_outcome
