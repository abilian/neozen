"""Email-backed notifier for account lockouts.

Bridges `LockoutManager`'s notifier hook to NeoZen's
`NotificationService`. The bridge owns no state of its own; it
resolves a subject id to an email via a caller-provided async
callable, then delegates the actual send to `NotificationService`.

Example:
    notifier = LockoutEmailNotifier(
        notifications=notification_service,
        resolve_email=lambda sid: subject_repo.get_email(sid),
    )
    manager = LockoutManager(config, store, notifier=notifier)

The resolve_email callable returns `None` for subjects that have
no email — in that case, the notifier silently skips. This handles
LDAP-only or service-account subjects without raising.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from neozen.core.email.notifications import NotificationService

_log = logging.getLogger(__name__)


class LockoutEmailNotifier:
    """Notifier that sends an email on the locking transition.

    Implements `LockoutNotifierProtocol` from
    `neozen.core.security.lockout`.
    """

    def __init__(
        self,
        notifications: NotificationService,
        resolve_email: Callable[[str], Awaitable[str | None]],
    ) -> None:
        """
        Args:
            notifications: A configured `NotificationService` that
                will perform the actual email send.
            resolve_email: Async callable that maps a subject_id to
                an email address (or None if no email is on file).
        """
        self.notifications = notifications
        self.resolve_email = resolve_email

    async def on_lockout(
        self,
        subject_id: str,
        *,
        locked_until: datetime,
        failed_attempts: int,
        ip_address: str | None = None,
    ) -> None:
        """Send the lockout notification email.

        Failures from `resolve_email` or the underlying sender are
        logged and swallowed. The lockout itself never depends on
        successful notification.
        """
        try:
            email = await self.resolve_email(subject_id)
        except Exception:
            _log.exception(
                "lockout notifier: resolve_email failed for subject %s",
                subject_id,
            )
            return

        if not email:
            _log.info(
                "lockout notifier: no email for subject %s, skipping",
                subject_id,
            )
            return

        try:
            await self.notifications.send_lockout_email(
                email=email,
                locked_until=locked_until,
                failed_attempts=failed_attempts,
                ip_address=ip_address,
            )
        except Exception:
            _log.exception(
                "lockout notifier: send_lockout_email failed for %s",
                email,
            )


__all__ = ["LockoutEmailNotifier"]
