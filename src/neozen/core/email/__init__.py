"""Email sending module for NeoZen."""

from __future__ import annotations

from neozen.core.email.base import EmailMessage, EmailSendError, EmailSenderProtocol
from neozen.core.email.console import ConsoleEmailSender
from neozen.core.email.smtp import SMTPEmailSender

__all__ = [
    "ConsoleEmailSender",
    "EmailMessage",
    "EmailSendError",
    "EmailSenderProtocol",
    "SMTPEmailSender",
]
