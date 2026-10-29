"""Base email sender protocol for NeoZen."""

from __future__ import annotations

import typing
from dataclasses import dataclass, field


@dataclass(frozen=True)
class EmailMessage:
    """Represents an email message.

    Attributes:
        to: Recipient email address(es).
        subject: Email subject line.
        body_text: Plain text body content.
        body_html: Optional HTML body content.
        from_addr: Sender email address (optional, may use default).
        reply_to: Reply-to address (optional).
        headers: Additional headers (optional).

    """

    to: str | list[str]
    subject: str
    body_text: str
    body_html: str | None = None
    from_addr: str | None = None
    reply_to: str | None = None
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def recipients(self) -> list[str]:
        """Return list of recipient addresses."""
        if isinstance(self.to, str):
            return [self.to]
        return list(self.to)


class EmailSenderProtocol(typing.Protocol):
    """Protocol for email sending implementations.

    Implementations should handle:
    - Sending single emails
    - Batching (if supported by backend)
    - Error handling and retries
    - Rate limiting (if needed)

    Example implementation:
        class MyEmailSender(EmailSenderProtocol):
            async def send(self, message: EmailMessage) -> None:
                # Send the email via your preferred method
                pass

    """

    async def send(self, message: EmailMessage) -> None:
        """Send an email message.

        Args:
            message: The email message to send.

        Raises:
            EmailSendError: If sending fails.

        """
        ...


class EmailSendError(Exception):
    """Raised when email sending fails."""

    def __init__(self, message: str, original_error: Exception | None = None) -> None:
        self.message = message
        self.original_error = original_error
        super().__init__(message)


__all__ = [
    "EmailMessage",
    "EmailSendError",
    "EmailSenderProtocol",
]
