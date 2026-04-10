"""Email sending module for NeoZen."""

from __future__ import annotations

from neozen.core.email.base import EmailMessage, EmailSenderProtocol, EmailSendError
from neozen.core.email.console import ConsoleEmailSender
from neozen.core.email.notifications import NotificationService
from neozen.core.email.smtp import SMTPEmailSender
from neozen.core.email.templates import (
    account_lockout_email,
    compromised_password_email,
    email_otp_email,
    email_verification_email,
    password_reset_email,
)

__all__ = [
    "ConsoleEmailSender",
    "EmailMessage",
    "EmailSendError",
    "EmailSenderProtocol",
    "NotificationService",
    "SMTPEmailSender",
    "account_lockout_email",
    "compromised_password_email",
    "email_otp_email",
    "email_verification_email",
    "password_reset_email",
]
