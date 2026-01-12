"""SMTP email sender for production."""

from __future__ import annotations

import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import anyio

from neozen.core.email.base import EmailMessage, EmailSendError


class SMTPEmailSender:
    """Email sender using SMTP for production use.

    This sender connects to an SMTP server to send emails.
    It supports:
    - TLS encryption (STARTTLS)
    - SSL/TLS connections
    - Authentication
    - Multipart messages (text + HTML)

    Example:
        sender = SMTPEmailSender(
            host="smtp.example.com",
            port=587,
            username="user@example.com",
            password="secret",
            use_tls=True,
        )
        await sender.send(EmailMessage(
            to="recipient@example.com",
            subject="Hello",
            body_text="Hello, World!",
        ))

    """

    def __init__(
        self,
        host: str,
        port: int = 587,
        *,
        username: str | None = None,
        password: str | None = None,
        use_tls: bool = True,
        use_ssl: bool = False,
        default_from: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        """Initialize the SMTP email sender.

        Args:
            host: SMTP server hostname.
            port: SMTP server port (default: 587 for TLS, 465 for SSL).
            username: Username for authentication (optional).
            password: Password for authentication (optional).
            use_tls: Use STARTTLS encryption (default: True).
            use_ssl: Use SSL/TLS connection (default: False).
            default_from: Default sender address if not specified in message.
            timeout: Connection timeout in seconds (default: 30).

        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.use_ssl = use_ssl
        self.default_from = default_from
        self.timeout = timeout

    async def send(self, message: EmailMessage) -> None:
        """Send an email via SMTP.

        Args:
            message: The email message to send.

        Raises:
            EmailSendError: If sending fails.

        """
        # Run SMTP operations in a thread to avoid blocking
        await anyio.to_thread.run_sync(self._send_sync, message)

    def _send_sync(self, message: EmailMessage) -> None:
        """Synchronous SMTP send operation.

        Args:
            message: The email message to send.

        Raises:
            EmailSendError: If sending fails.

        """
        from_addr = message.from_addr or self.default_from
        if not from_addr:
            raise EmailSendError("No sender address specified and no default set.")

        # Build the email
        if message.body_html:
            msg = MIMEMultipart("alternative")
            msg.attach(MIMEText(message.body_text, "plain"))
            msg.attach(MIMEText(message.body_html, "html"))
        else:
            msg = MIMEText(message.body_text, "plain")

        msg["Subject"] = message.subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(message.recipients)

        if message.reply_to:
            msg["Reply-To"] = message.reply_to

        for key, value in message.headers.items():
            msg[key] = value

        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(
                    self.host, self.port, timeout=self.timeout, context=context
                ) as server:
                    self._authenticate_and_send(server, from_addr, message, msg)
            else:
                with smtplib.SMTP(
                    self.host, self.port, timeout=self.timeout
                ) as server:
                    if self.use_tls:
                        context = ssl.create_default_context()
                        server.starttls(context=context)
                    self._authenticate_and_send(server, from_addr, message, msg)

        except smtplib.SMTPException as e:
            raise EmailSendError(f"SMTP error: {e}", original_error=e) from e
        except TimeoutError as e:
            raise EmailSendError("SMTP connection timeout", original_error=e) from e
        except OSError as e:
            raise EmailSendError(f"Network error: {e}", original_error=e) from e

    def _authenticate_and_send(
        self,
        server: smtplib.SMTP | smtplib.SMTP_SSL,
        from_addr: str,
        message: EmailMessage,
        msg: MIMEText | MIMEMultipart,
    ) -> None:
        """Authenticate and send the message.

        Args:
            server: The SMTP server connection.
            from_addr: Sender address.
            message: Original message (for recipients).
            msg: Built MIME message.

        """
        if self.username and self.password:
            server.login(self.username, self.password)

        server.sendmail(from_addr, message.recipients, msg.as_string())


__all__ = ["SMTPEmailSender"]
