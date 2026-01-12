"""Console email sender for development."""

from __future__ import annotations

import sys
from io import StringIO

from neozen.core.email.base import EmailMessage

SEPARATOR = "=" * 60


class ConsoleEmailSender:
    """Email sender that prints to console for development.

    This sender is useful during development and testing to see
    what emails would be sent without actually sending them.

    Example:
        sender = ConsoleEmailSender()
        await sender.send(EmailMessage(
            to="user@example.com",
            subject="Welcome!",
            body_text="Hello, welcome to our app!",
        ))

        # Output:
        # ============================================================
        # EMAIL
        # ============================================================
        # To: user@example.com
        # Subject: Welcome!
        # ------------------------------------------------------------
        # Hello, welcome to our app!
        # ============================================================

    """

    def __init__(
        self,
        *,
        output: StringIO | None = None,
        prefix: str = "EMAIL",
    ) -> None:
        """Initialize the console email sender.

        Args:
            output: Optional StringIO for capturing output (useful in tests).
                If None, prints to stdout.
            prefix: Label for the email block (default: "EMAIL").

        """
        self.output = output
        self.prefix = prefix
        self._sent_messages: list[EmailMessage] = []

    async def send(self, message: EmailMessage) -> None:
        """Print the email to console.

        Args:
            message: The email message to print.

        """
        self._sent_messages.append(message)

        lines = [
            SEPARATOR,
            self.prefix,
            SEPARATOR,
        ]

        if message.from_addr:
            lines.append(f"From: {message.from_addr}")

        lines.append(f"To: {', '.join(message.recipients)}")

        if message.reply_to:
            lines.append(f"Reply-To: {message.reply_to}")

        lines.append(f"Subject: {message.subject}")

        for key, value in message.headers.items():
            lines.append(f"{key}: {value}")

        lines.append("-" * 60)
        lines.append(message.body_text)

        if message.body_html:
            lines.append("-" * 60)
            lines.append("[HTML Version]")
            lines.append(message.body_html)

        lines.append(SEPARATOR)
        lines.append("")

        output_text = "\n".join(lines)

        if self.output is not None:
            self.output.write(output_text)
        else:
            print(output_text, file=sys.stdout)

    @property
    def sent_messages(self) -> list[EmailMessage]:
        """Return list of messages that were sent (for testing)."""
        return self._sent_messages

    def clear_sent_messages(self) -> None:
        """Clear the sent messages list."""
        self._sent_messages.clear()


__all__ = ["ConsoleEmailSender"]
