"""Notification service that bridges domain-specific email protocols
to the generic `EmailSenderProtocol`.

Each domain (password reset, email verification, etc.) defines its own
narrow `EmailSender` protocol. This module provides adapter classes that
implement those narrow protocols by composing pre-built templates with
a single `EmailSenderProtocol` implementation.

This means application code only configures one email sender (SMTP,
console, custom) and gets all the notification types for free.
"""

from __future__ import annotations

from datetime import datetime

from neozen.core.email.base import EmailSenderProtocol
from neozen.core.email.templates import (
    account_lockout_email,
    compromised_password_email,
    email_otp_email,
    email_verification_email,
    password_reset_email,
)


class NotificationService:
    """Sends all NeoZen notification emails through one sender.

    Implements the narrow `EmailSender` protocols defined by
    `PasswordResetService` and other services, while delegating to
    a single `EmailSenderProtocol`.

    Example:
        sender = SMTPEmailSender(host="smtp.example.com", ...)
        notifications = NotificationService(
            sender=sender,
            app_name="My App",
            reset_url_template="https://app.example.com/reset?token={token}",
        )

        # Wire into PasswordResetService
        reset_service = PasswordResetService(
            ...,
            email_sender=notifications,
        )
    """

    def __init__(
        self,
        sender: EmailSenderProtocol,
        *,
        app_name: str = "NeoZen",
        reset_url_template: str = "",
        verify_url_template: str = "",
    ) -> None:
        """Initialize the notification service.

        Args:
            sender: Underlying email sender (SMTP, console, etc.).
            app_name: Application name shown in subject lines.
            reset_url_template: URL template with `{token}` placeholder
                for password reset links.
            verify_url_template: URL template with `{token}` placeholder
                for email verification links.
        """
        self.sender = sender
        self.app_name = app_name
        self.reset_url_template = reset_url_template
        self.verify_url_template = verify_url_template

    # ----- PasswordResetService.EmailSender -----

    async def send_reset_email(
        self,
        email: str,
        token: str,
        expires_at: datetime,
    ) -> bool:
        if not self.reset_url_template:
            msg = "reset_url_template not configured"
            raise ValueError(msg)
        url = self.reset_url_template.format(token=token)
        message = password_reset_email(
            to=email,
            reset_url=url,
            expires_at=expires_at,
            app_name=self.app_name,
        )
        await self.sender.send(message)
        return True

    # ----- Email verification -----

    async def send_verification_email(
        self,
        email: str,
        token: str,
        expires_at: datetime,
    ) -> bool:
        if not self.verify_url_template:
            msg = "verify_url_template not configured"
            raise ValueError(msg)
        url = self.verify_url_template.format(token=token)
        message = email_verification_email(
            to=email,
            verify_url=url,
            expires_at=expires_at,
            app_name=self.app_name,
        )
        await self.sender.send(message)
        return True

    # ----- Email OTP -----

    async def send_otp_email(
        self,
        email: str,
        code: str,
        lifetime_seconds: int,
    ) -> bool:
        message = email_otp_email(
            to=email,
            code=code,
            lifetime_seconds=lifetime_seconds,
            app_name=self.app_name,
        )
        await self.sender.send(message)
        return True

    # ----- Account lockout -----

    async def send_lockout_email(
        self,
        email: str,
        locked_until: datetime,
        failed_attempts: int,
        ip_address: str | None = None,
    ) -> bool:
        message = account_lockout_email(
            to=email,
            locked_until=locked_until,
            failed_attempts=failed_attempts,
            ip_address=ip_address,
            app_name=self.app_name,
        )
        await self.sender.send(message)
        return True

    # ----- Compromised password -----

    async def send_compromised_password_email(self, email: str) -> bool:
        message = compromised_password_email(to=email, app_name=self.app_name)
        await self.sender.send(message)
        return True


__all__ = ["NotificationService"]
