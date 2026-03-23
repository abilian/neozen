"""Audit logging types for NeoZen."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class AuditOutcome:
    """Standard audit outcomes."""

    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"
    DENIED = "denied"


class AuditActions:
    """Standard audit action names."""

    # Authentication
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"

    # Registration / Subject lifecycle
    REGISTER = "register"
    REGISTER_FAILED = "register_failed"
    ACCOUNT_CREATE = "account_create"
    ACCOUNT_UPDATE = "account_update"
    EMAIL_VERIFIED = "email_verified"

    # Password
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET_COMPLETE = "password_reset_complete"
    PASSWORD_RESET = "password_reset"
    PASSWORD_VERIFY = "password_verify"
    PASSWORD_VERIFY_FAILED = "password_verify_failed"

    # MFA
    MFA_ENABLE = "mfa_enable"
    MFA_DISABLE = "mfa_disable"
    MFA_ENROLL_START = "mfa_enroll_start"
    MFA_ENROLL_COMPLETE = "mfa_enroll_complete"
    MFA_CHALLENGE = "mfa_challenge"
    MFA_VERIFY = "mfa_verify"
    MFA_VERIFY_FAILED = "mfa_verify_failed"
    BACKUP_CODE_USE = "backup_code_use"
    BACKUP_CODE_USED = "backup_code_used"
    BACKUP_CODE_REGENERATE = "backup_code_regenerate"

    # Passkeys
    PASSKEY_REGISTER_START = "passkey_register_start"
    PASSKEY_REGISTER = "passkey_register"
    PASSKEY_REMOVE = "passkey_remove"
    PASSKEY_AUTH_START = "passkey_auth_start"
    PASSKEY_AUTH = "passkey_auth"
    PASSKEY_AUTH_FAILED = "passkey_auth_failed"

    # Sessions
    SESSION_CREATE = "session_create"
    SESSION_REVOKE = "session_revoke"
    SESSION_EXPIRE = "session_expire"
    SESSION_REFRESH = "session_refresh"
    SESSION_VALIDATE = "session_validate"

    # Roles & Permissions
    ROLE_CREATE = "role_create"
    ROLE_DELETE = "role_delete"
    ROLE_ASSIGN = "role_assign"
    ROLE_REVOKE = "role_revoke"
    PERMISSION_GRANT = "permission_grant"
    PERMISSION_REVOKE = "permission_revoke"
    PERMISSION_CHECK = "permission_check"

    # OAuth Client
    CLIENT_CREATE = "client_create"
    CLIENT_UPDATE = "client_update"
    CLIENT_DEACTIVATE = "client_deactivate"
    CLIENT_SECRET_ROTATE = "client_secret_rotate"
    OAUTH_CLIENT_CREATE = "oauth_client_create"
    OAUTH_CLIENT_UPDATE = "oauth_client_update"
    OAUTH_CLIENT_DELETE = "oauth_client_delete"

    # OAuth Token
    TOKEN_ISSUE = "token_issue"
    TOKEN_REFRESH = "token_refresh"
    TOKEN_REVOKE = "token_revoke"
    TOKEN_INTROSPECT = "token_introspect"

    # OAuth Authorization
    AUTHORIZATION_REQUEST = "authorization_request"
    AUTHORIZATION_GRANT = "authorization_grant"
    AUTHORIZATION_DENY = "authorization_deny"

    # Account management
    ACCOUNT_LOCK = "account_lock"
    ACCOUNT_UNLOCK = "account_unlock"
    ACCOUNT_DELETE = "account_delete"
    EMAIL_VERIFY = "email_verify"
    EMAIL_CHANGE = "email_change"

    # Verification
    VERIFICATION_SEND = "verification_send"
    VERIFICATION_COMPLETE = "verification_complete"
    VERIFICATION_FAIL = "verification_fail"

    # Data
    DATA_EXPORT = "data_export"

    # Social login
    SOCIAL_AUTH_START = "social_auth_start"
    SOCIAL_AUTH = "social_auth"
    SOCIAL_LINK = "social_link"
    SOCIAL_UNLINK = "social_unlink"
    SOCIAL_LOGIN = "social_login"

    # Admin actions
    ADMIN_IMPERSONATE = "admin_impersonate"
    ADMIN_IMPERSONATE_END = "admin_impersonate_end"


@dataclass
class AuditLogEntry:
    """Audit log entry for security events.

    Attributes:
        id: Unique identifier for the entry.
        timestamp: When the event occurred.
        event_type: Category of event (auth, oauth, admin, etc.).
        action: Specific action performed.
        outcome: Result of the action (success, failure, error).
        subject_id: Subject affected by the action.
        actor_id: Who performed the action (for admin actions).
        ip_address: Client IP address.
        user_agent: Client user agent string.
        resource_type: Type of resource affected.
        resource_id: ID of resource affected.
        details: Additional event-specific details.
        request_id: Request correlation ID for tracing.
    """

    id: str
    timestamp: datetime
    event_type: str
    action: str
    outcome: str
    subject_id: str | None = None
    actor_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    request_id: str | None = None


__all__ = [
    "AuditActions",
    "AuditLogEntry",
    "AuditOutcome",
]
