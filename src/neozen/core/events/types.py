"""Event types for the NeoZen authentication system."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class AuthEvent:
    """Base event for all authentication events.

    Events are immutable records of authentication-related occurrences.
    They can be subscribed to for logging, analytics, or triggering
    secondary actions.

    Attributes:
        event_type: The type of event (e.g., "login.success").
        timestamp: When the event occurred.
        subject_id: The subject involved, if any.
        metadata: Additional event-specific data.
    """

    event_type: str
    timestamp: datetime
    subject_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_metadata(self, **kwargs: Any) -> AuthEvent:
        """Create a new event with additional metadata."""
        new_metadata = {**self.metadata, **kwargs}
        return AuthEvent(
            event_type=self.event_type,
            timestamp=self.timestamp,
            subject_id=self.subject_id,
            metadata=new_metadata,
        )


class EventTypes:
    """Built-in event type constants.

    Event types follow the pattern: category.action

    Categories:
    - subject: Subject lifecycle events
    - login: Authentication events
    - session: Session management events
    - password: Password-related events
    - mfa: Multi-factor authentication events
    - passkey: WebAuthn/passkey events
    - social: Social login events
    - role: Authorization events
    - oauth: OAuth server events
    """

    # Subject lifecycle
    SUBJECT_CREATED = "subject.created"
    SUBJECT_VERIFIED = "subject.verified"
    SUBJECT_DELETED = "subject.deleted"
    SUBJECT_UPDATED = "subject.updated"

    # Authentication
    LOGIN_SUCCESS = "login.success"
    LOGIN_FAILED = "login.failed"
    LOGOUT = "logout"

    # Session management
    SESSION_CREATED = "session.created"
    SESSION_VALIDATED = "session.validated"
    SESSION_EXPIRED = "session.expired"
    SESSION_REVOKED = "session.revoked"
    SESSION_REFRESHED = "session.refreshed"

    # Password
    PASSWORD_CHANGED = "password.changed"
    PASSWORD_VERIFIED = "password.verified"
    PASSWORD_FAILED = "password.failed"
    PASSWORD_RESET_REQUESTED = "password.reset_requested"
    PASSWORD_RESET_COMPLETED = "password.reset_completed"

    # MFA (TOTP)
    MFA_ENABLED = "mfa.enabled"
    MFA_DISABLED = "mfa.disabled"
    MFA_ENROLLMENT_STARTED = "mfa.enrollment_started"
    MFA_ENROLLMENT_COMPLETED = "mfa.enrollment_completed"
    MFA_CHALLENGE_SUCCESS = "mfa.challenge_success"
    MFA_CHALLENGE_FAILED = "mfa.challenge_failed"
    BACKUP_CODE_USED = "mfa.backup_code_used"
    BACKUP_CODES_REGENERATED = "mfa.backup_codes_regenerated"

    # WebAuthn/Passkeys
    PASSKEY_REGISTRATION_STARTED = "passkey.registration_started"
    PASSKEY_REGISTERED = "passkey.registered"
    PASSKEY_REMOVED = "passkey.removed"
    PASSKEY_AUTH_STARTED = "passkey.auth_started"
    PASSKEY_AUTH_SUCCESS = "passkey.auth_success"
    PASSKEY_AUTH_FAILED = "passkey.auth_failed"

    # Social Login
    SOCIAL_AUTH_STARTED = "social.auth_started"
    SOCIAL_AUTH_COMPLETED = "social.auth_completed"
    SOCIAL_AUTH_FAILED = "social.auth_failed"
    SOCIAL_ACCOUNT_LINKED = "social.account_linked"
    SOCIAL_ACCOUNT_UNLINKED = "social.account_unlinked"

    # Authorization (RBAC)
    ROLE_CREATED = "role.created"
    ROLE_DELETED = "role.deleted"
    ROLE_ASSIGNED = "role.assigned"
    ROLE_REVOKED = "role.revoked"
    PERMISSION_DENIED = "permission.denied"
    PERMISSION_GRANTED = "permission.granted"

    # OAuth Server
    CLIENT_CREATED = "oauth.client_created"
    CLIENT_UPDATED = "oauth.client_updated"
    CLIENT_DEACTIVATED = "oauth.client_deactivated"
    CLIENT_ACTIVATED = "oauth.client_activated"
    CLIENT_SECRET_ROTATED = "oauth.client_secret_rotated"
    AUTHORIZATION_REQUESTED = "oauth.authorization_requested"
    AUTHORIZATION_GRANTED = "oauth.authorization_granted"
    AUTHORIZATION_DENIED = "oauth.authorization_denied"
    TOKEN_ISSUED = "oauth.token_issued"
    TOKEN_REFRESHED = "oauth.token_refreshed"
    TOKEN_REVOKED = "oauth.token_revoked"
    TOKEN_INTROSPECTED = "oauth.token_introspected"

    # Email verification
    VERIFICATION_SENT = "verification.sent"
    VERIFICATION_COMPLETED = "verification.completed"
    VERIFICATION_FAILED = "verification.failed"
