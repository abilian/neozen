"""Hook system types and constants."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class HookPoints:
    """Available hook points in the authentication flow.

    Hooks allow intercepting and modifying authentication flows.

    Pre-hooks:
    - Run before the operation
    - Can modify the context data
    - Can cancel the operation by setting cancelled=True

    Post-hooks:
    - Run after the operation
    - Cannot modify the operation (observe only)
    - Useful for logging, notifications, cleanup
    """

    # Subject lifecycle
    PRE_REGISTER = "pre_register"
    POST_REGISTER = "post_register"
    PRE_DELETE_SUBJECT = "pre_delete_subject"
    POST_DELETE_SUBJECT = "post_delete_subject"

    # Authentication
    PRE_LOGIN = "pre_login"
    POST_LOGIN = "post_login"
    PRE_LOGOUT = "pre_logout"
    POST_LOGOUT = "post_logout"

    # Session management
    PRE_SESSION_CREATE = "pre_session_create"
    POST_SESSION_CREATE = "post_session_create"
    PRE_SESSION_REVOKE = "pre_session_revoke"
    POST_SESSION_REVOKE = "post_session_revoke"

    # Password
    PRE_PASSWORD_CHANGE = "pre_password_change"
    POST_PASSWORD_CHANGE = "post_password_change"
    PRE_PASSWORD_VERIFY = "pre_password_verify"
    POST_PASSWORD_VERIFY = "post_password_verify"

    # MFA
    PRE_MFA_ENROLL = "pre_mfa_enroll"
    POST_MFA_ENROLL = "post_mfa_enroll"
    PRE_MFA_VERIFY = "pre_mfa_verify"
    POST_MFA_VERIFY = "post_mfa_verify"

    # OAuth Server
    PRE_TOKEN_ISSUE = "pre_token_issue"
    POST_TOKEN_ISSUE = "post_token_issue"
    PRE_TOKEN_REVOKE = "pre_token_revoke"
    POST_TOKEN_REVOKE = "post_token_revoke"
    PRE_AUTHORIZATION = "pre_authorization"
    POST_AUTHORIZATION = "post_authorization"


@dataclass
class HookContext:
    """Context passed to hook handlers.

    The context contains information about the operation being performed
    and can be modified by pre-hooks to alter behavior.

    Attributes:
        hook_point: The hook point being executed.
        subject_id: The subject involved in the operation, if any.
        data: Mutable dictionary with operation-specific data.
        cancelled: Set to True by pre-hooks to cancel the operation.
        cancel_reason: Human-readable reason for cancellation.
        results: Results from the operation (for post-hooks).
    """

    hook_point: str
    subject_id: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    cancelled: bool = False
    cancel_reason: str | None = None
    results: dict[str, Any] = field(default_factory=dict)

    def cancel(self, reason: str) -> None:
        """Cancel the operation with a reason.

        Args:
            reason: Human-readable reason for cancellation.
        """
        self.cancelled = True
        self.cancel_reason = reason


@dataclass(frozen=True)
class HookResult:
    """Result from a pre-hook execution.

    Pre-hooks can return this to modify the operation or cancel it.

    Attributes:
        proceed: Whether to continue with the operation.
        modified_data: Optional modified data to use instead.
        cancel_reason: Reason for cancellation if proceed=False.
    """

    proceed: bool = True
    modified_data: dict[str, Any] | None = None
    cancel_reason: str | None = None

    @classmethod
    def cancel(cls, reason: str) -> HookResult:
        """Create a result that cancels the operation.

        Args:
            reason: Human-readable reason for cancellation.

        Returns:
            HookResult with proceed=False.
        """
        return cls(proceed=False, cancel_reason=reason)

    @classmethod
    def modify(cls, **data: Any) -> HookResult:
        """Create a result that modifies the context data.

        Args:
            **data: Key-value pairs to update in context.data.

        Returns:
            HookResult with modified_data.
        """
        return cls(proceed=True, modified_data=data)

    @classmethod
    def allow(cls) -> HookResult:
        """Create a result that allows the operation to proceed.

        Returns:
            HookResult with proceed=True.
        """
        return cls(proceed=True)
