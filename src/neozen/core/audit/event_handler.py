"""Audit event handler for automatic audit logging.

Integrates the event system with audit logging to automatically
record security-relevant events.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from neozen.core.audit.types import AuditActions, AuditOutcome
from neozen.core.events import AuthEvent, EventTypes

if TYPE_CHECKING:
    from neozen.core.audit.logger import AuditLogger
    from neozen.core.events import EventBus


# Mapping from event types to audit actions
EVENT_TO_AUDIT_ACTION: dict[str, str] = {
    # Subject lifecycle
    EventTypes.SUBJECT_CREATED: AuditActions.ACCOUNT_CREATE,
    EventTypes.SUBJECT_VERIFIED: AuditActions.EMAIL_VERIFIED,
    EventTypes.SUBJECT_DELETED: AuditActions.ACCOUNT_DELETE,
    EventTypes.SUBJECT_UPDATED: AuditActions.ACCOUNT_UPDATE,
    # Authentication
    EventTypes.LOGIN_SUCCESS: AuditActions.LOGIN,
    EventTypes.LOGIN_FAILED: AuditActions.LOGIN,
    EventTypes.LOGOUT: AuditActions.LOGOUT,
    # Session
    EventTypes.SESSION_CREATED: AuditActions.SESSION_CREATE,
    EventTypes.SESSION_EXPIRED: AuditActions.SESSION_EXPIRE,
    EventTypes.SESSION_REVOKED: AuditActions.SESSION_REVOKE,
    EventTypes.SESSION_REFRESHED: AuditActions.SESSION_REFRESH,
    # Password
    EventTypes.PASSWORD_CHANGED: AuditActions.PASSWORD_CHANGE,
    EventTypes.PASSWORD_VERIFIED: AuditActions.PASSWORD_VERIFY,
    EventTypes.PASSWORD_FAILED: AuditActions.PASSWORD_VERIFY,
    EventTypes.PASSWORD_RESET_REQUESTED: AuditActions.PASSWORD_RESET_REQUEST,
    EventTypes.PASSWORD_RESET_COMPLETED: AuditActions.PASSWORD_RESET_COMPLETE,
    # MFA
    EventTypes.MFA_ENABLED: AuditActions.MFA_ENABLE,
    EventTypes.MFA_DISABLED: AuditActions.MFA_DISABLE,
    EventTypes.MFA_ENROLLMENT_STARTED: AuditActions.MFA_ENROLL_START,
    EventTypes.MFA_ENROLLMENT_COMPLETED: AuditActions.MFA_ENROLL_COMPLETE,
    EventTypes.MFA_CHALLENGE_SUCCESS: AuditActions.MFA_CHALLENGE,
    EventTypes.MFA_CHALLENGE_FAILED: AuditActions.MFA_CHALLENGE,
    EventTypes.BACKUP_CODE_USED: AuditActions.BACKUP_CODE_USE,
    EventTypes.BACKUP_CODES_REGENERATED: AuditActions.BACKUP_CODE_REGENERATE,
    # Passkeys
    EventTypes.PASSKEY_REGISTRATION_STARTED: AuditActions.PASSKEY_REGISTER_START,
    EventTypes.PASSKEY_REGISTERED: AuditActions.PASSKEY_REGISTER,
    EventTypes.PASSKEY_REMOVED: AuditActions.PASSKEY_REMOVE,
    EventTypes.PASSKEY_AUTH_STARTED: AuditActions.PASSKEY_AUTH_START,
    EventTypes.PASSKEY_AUTH_SUCCESS: AuditActions.PASSKEY_AUTH,
    EventTypes.PASSKEY_AUTH_FAILED: AuditActions.PASSKEY_AUTH,
    # Social login
    EventTypes.SOCIAL_AUTH_STARTED: AuditActions.SOCIAL_AUTH_START,
    EventTypes.SOCIAL_AUTH_COMPLETED: AuditActions.SOCIAL_AUTH,
    EventTypes.SOCIAL_AUTH_FAILED: AuditActions.SOCIAL_AUTH,
    EventTypes.SOCIAL_ACCOUNT_LINKED: AuditActions.SOCIAL_LINK,
    EventTypes.SOCIAL_ACCOUNT_UNLINKED: AuditActions.SOCIAL_UNLINK,
    # RBAC
    EventTypes.ROLE_CREATED: AuditActions.ROLE_CREATE,
    EventTypes.ROLE_DELETED: AuditActions.ROLE_DELETE,
    EventTypes.ROLE_ASSIGNED: AuditActions.ROLE_ASSIGN,
    EventTypes.ROLE_REVOKED: AuditActions.ROLE_REVOKE,
    EventTypes.PERMISSION_DENIED: AuditActions.PERMISSION_CHECK,
    EventTypes.PERMISSION_GRANTED: AuditActions.PERMISSION_CHECK,
    # OAuth
    EventTypes.CLIENT_CREATED: AuditActions.CLIENT_CREATE,
    EventTypes.CLIENT_UPDATED: AuditActions.CLIENT_UPDATE,
    EventTypes.CLIENT_DEACTIVATED: AuditActions.CLIENT_DEACTIVATE,
    EventTypes.CLIENT_ACTIVATED: AuditActions.CLIENT_UPDATE,
    EventTypes.CLIENT_SECRET_ROTATED: AuditActions.CLIENT_SECRET_ROTATE,
    EventTypes.AUTHORIZATION_REQUESTED: AuditActions.AUTHORIZATION_REQUEST,
    EventTypes.AUTHORIZATION_GRANTED: AuditActions.AUTHORIZATION_GRANT,
    EventTypes.AUTHORIZATION_DENIED: AuditActions.AUTHORIZATION_DENY,
    EventTypes.TOKEN_ISSUED: AuditActions.TOKEN_ISSUE,
    EventTypes.TOKEN_REFRESHED: AuditActions.TOKEN_REFRESH,
    EventTypes.TOKEN_REVOKED: AuditActions.TOKEN_REVOKE,
    EventTypes.TOKEN_INTROSPECTED: AuditActions.TOKEN_INTROSPECT,
    # Verification
    EventTypes.VERIFICATION_SENT: AuditActions.VERIFICATION_SEND,
    EventTypes.VERIFICATION_COMPLETED: AuditActions.VERIFICATION_COMPLETE,
    EventTypes.VERIFICATION_FAILED: AuditActions.VERIFICATION_FAIL,
}

# Event types that indicate failure
FAILURE_EVENTS: set[str] = {
    EventTypes.LOGIN_FAILED,
    EventTypes.PASSWORD_FAILED,
    EventTypes.MFA_CHALLENGE_FAILED,
    EventTypes.PASSKEY_AUTH_FAILED,
    EventTypes.SOCIAL_AUTH_FAILED,
    EventTypes.PERMISSION_DENIED,
    EventTypes.AUTHORIZATION_DENIED,
    EventTypes.VERIFICATION_FAILED,
}


def _get_event_category(event_type: str) -> str:
    """Get audit event category from event type."""
    if "." in event_type:
        return event_type.split(".", 1)[0]
    return event_type


def _get_outcome(event_type: str) -> str:
    """Determine audit outcome from event type."""
    if event_type in FAILURE_EVENTS:
        return AuditOutcome.FAILURE
    return AuditOutcome.SUCCESS


class AuditEventHandler:
    """Event handler that logs events to audit log.

    Subscribes to the event bus and automatically logs
    authentication events to the audit system.

    Example:
        from neozen.core.events import EventBus
        from neozen.core.audit import AuditLogger, InMemoryAuditLogStore

        store = InMemoryAuditLogStore()
        logger = AuditLogger(store)
        bus = EventBus()

        handler = AuditEventHandler(logger)
        handler.subscribe(bus)

        # Now all events emitted to the bus will be logged
        await bus.emit(AuthEvent(
            event_type=EventTypes.LOGIN_SUCCESS,
            timestamp=datetime.now(UTC),
            subject_id="user123",
        ))

        # Check audit log
        entries = await logger.query(subject_id="user123")
    """

    def __init__(
        self,
        logger: AuditLogger,
        *,
        event_types: list[str] | None = None,
        exclude_types: list[str] | None = None,
    ) -> None:
        """Initialize audit event handler.

        Args:
            logger: The audit logger to use.
            event_types: Specific event types to handle. If None, handles all.
            exclude_types: Event types to exclude from logging.
        """
        self.logger = logger
        self.event_types = set(event_types) if event_types else None
        self.exclude_types = set(exclude_types or [])

    def _should_log(self, event_type: str) -> bool:
        """Check if event type should be logged."""
        if event_type in self.exclude_types:
            return False
        if self.event_types is None:
            return True
        return event_type in self.event_types

    async def handle(self, event: AuthEvent) -> None:
        """Handle an auth event by logging it.

        Args:
            event: The authentication event.
        """
        if not self._should_log(event.event_type):
            return

        # Get audit action from mapping, or use event type directly
        action = EVENT_TO_AUDIT_ACTION.get(event.event_type, event.event_type)
        event_category = _get_event_category(event.event_type)
        outcome = _get_outcome(event.event_type)

        # Extract common metadata
        metadata = event.metadata
        ip_address = metadata.get("ip_address") or metadata.get("ip")
        user_agent = metadata.get("user_agent")
        actor_id = metadata.get("actor_id")
        resource_type = metadata.get("resource_type")
        resource_id = metadata.get("resource_id")
        request_id = metadata.get("request_id")

        # Build details from remaining metadata
        excluded_keys = {
            "ip_address",
            "ip",
            "user_agent",
            "actor_id",
            "resource_type",
            "resource_id",
            "request_id",
        }
        details = {k: v for k, v in metadata.items() if k not in excluded_keys}

        await self.logger.log(
            event_type=event_category,
            action=action,
            outcome=outcome,
            subject_id=event.subject_id,
            actor_id=actor_id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or None,
            request_id=request_id,
            timestamp=event.timestamp,
        )

    def subscribe(self, bus: EventBus) -> None:
        """Subscribe to all events on the bus.

        Args:
            bus: The event bus to subscribe to.
        """
        # Subscribe to all events using wildcard
        bus.subscribe("*", self.handle)

    def subscribe_to(self, bus: EventBus, *event_types: str) -> None:
        """Subscribe to specific event types.

        Args:
            bus: The event bus to subscribe to.
            *event_types: Event types to subscribe to.
        """
        for event_type in event_types:
            bus.subscribe(event_type, self.handle)


def create_audit_handler(
    logger: AuditLogger,
    *,
    exclude_types: list[str] | None = None,
) -> AuditEventHandler:
    """Create an audit event handler with default configuration.

    Args:
        logger: The audit logger to use.
        exclude_types: Event types to exclude from logging.

    Returns:
        Configured AuditEventHandler.

    Example:
        handler = create_audit_handler(logger)
        handler.subscribe(bus)
    """
    return AuditEventHandler(logger, exclude_types=exclude_types)


def setup_audit_logging(
    bus: EventBus,
    logger: AuditLogger,
    *,
    exclude_types: list[str] | None = None,
) -> AuditEventHandler:
    """Set up automatic audit logging for an event bus.

    Convenience function that creates an audit handler and
    subscribes it to the event bus.

    Args:
        bus: The event bus to subscribe to.
        logger: The audit logger to use.
        exclude_types: Event types to exclude from logging.

    Returns:
        The created AuditEventHandler (for later unsubscription if needed).

    Example:
        from neozen.core.events import EventBus
        from neozen.core.audit import (
            AuditLogger,
            InMemoryAuditLogStore,
            setup_audit_logging,
        )

        bus = EventBus()
        store = InMemoryAuditLogStore()
        logger = AuditLogger(store)

        handler = setup_audit_logging(bus, logger)

        # All events now automatically logged to audit
    """
    handler = create_audit_handler(logger, exclude_types=exclude_types)
    handler.subscribe(bus)
    return handler


__all__ = [
    "EVENT_TO_AUDIT_ACTION",
    "FAILURE_EVENTS",
    "AuditEventHandler",
    "create_audit_handler",
    "setup_audit_logging",
]
