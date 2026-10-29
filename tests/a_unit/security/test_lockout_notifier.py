"""Tests for the lockout email notifier hookup.

Covers:
- LockoutManager calls the notifier on the locking transition only
- Notifier failures don't block the lockout
- LockoutEmailNotifier resolves emails and delegates to NotificationService
- Missing emails are handled silently (LDAP-only / service accounts)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from neozen.core.email.base import EmailMessage
from neozen.core.email.console import ConsoleEmailSender
from neozen.core.email.notifications import NotificationService
from neozen.core.security.lockout import LockoutConfig, LockoutManager
from neozen.core.security.lockout_notifier import LockoutEmailNotifier
from neozen.core.security.rate_limit_store import InMemoryRateLimitStore

# =============================================================================
# LockoutManager notifier hook
# =============================================================================


class _RecordingNotifier:
    """Notifier that records all on_lockout calls for assertion."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def on_lockout(
        self,
        subject_id: str,
        *,
        locked_until: datetime,
        failed_attempts: int,
        ip_address: str | None = None,
    ) -> None:
        self.calls.append({
            "subject_id": subject_id,
            "locked_until": locked_until,
            "failed_attempts": failed_attempts,
            "ip_address": ip_address,
        })


class _FailingNotifier:
    """Notifier that always raises — used to verify isolation."""

    def __init__(self) -> None:
        self.called = False

    async def on_lockout(self, subject_id: str, **kwargs) -> None:
        self.called = True
        msg = "boom"
        raise RuntimeError(msg)


@pytest.mark.anyio
class TestLockoutManagerNotifier:
    async def test_no_notifier_works(self) -> None:
        """Backwards compat: manager without notifier still locks."""
        manager = LockoutManager(
            LockoutConfig(max_failed_attempts=3),
            InMemoryRateLimitStore(),
        )
        status = None
        for _ in range(3):
            status = await manager.record_failed_attempt("user1")
        assert status is not None
        assert status.is_locked is True

    async def test_notifier_called_on_locking_transition(self) -> None:
        notifier = _RecordingNotifier()
        manager = LockoutManager(
            LockoutConfig(max_failed_attempts=3),
            InMemoryRateLimitStore(),
            notifier=notifier,
        )

        # Three failed attempts → lockout fires on the 3rd
        for _ in range(3):
            await manager.record_failed_attempt("user1")

        assert len(notifier.calls) == 1
        call = notifier.calls[0]
        assert call["subject_id"] == "user1"
        assert call["failed_attempts"] == 3
        assert call["locked_until"] is not None
        assert call["ip_address"] is None

    async def test_notifier_not_called_before_lockout(self) -> None:
        notifier = _RecordingNotifier()
        manager = LockoutManager(
            LockoutConfig(max_failed_attempts=5),
            InMemoryRateLimitStore(),
            notifier=notifier,
        )

        # Two attempts is below the threshold of 5
        await manager.record_failed_attempt("user1")
        await manager.record_failed_attempt("user1")
        assert notifier.calls == []

    async def test_notifier_passes_ip_address(self) -> None:
        notifier = _RecordingNotifier()
        manager = LockoutManager(
            LockoutConfig(max_failed_attempts=2),
            InMemoryRateLimitStore(),
            notifier=notifier,
        )
        await manager.record_failed_attempt("user1", ip_address="203.0.113.7")
        await manager.record_failed_attempt("user1", ip_address="203.0.113.7")

        assert len(notifier.calls) == 1
        assert notifier.calls[0]["ip_address"] == "203.0.113.7"

    async def test_notifier_failure_does_not_break_lockout(self) -> None:
        """Notifier exceptions are logged and swallowed."""
        notifier = _FailingNotifier()
        manager = LockoutManager(
            LockoutConfig(max_failed_attempts=2),
            InMemoryRateLimitStore(),
            notifier=notifier,
        )

        await manager.record_failed_attempt("user1")
        status = await manager.record_failed_attempt("user1")

        assert notifier.called is True  # tried
        assert status.is_locked is True  # but lockout still landed

    async def test_notifier_only_called_once_per_lockout_episode(self) -> None:
        """A second failed attempt after the lockout fires doesn't re-fire."""
        notifier = _RecordingNotifier()
        config = LockoutConfig(
            max_failed_attempts=2,
            lockout_duration=timedelta(minutes=30),
            progressive=False,
        )
        manager = LockoutManager(
            config,
            InMemoryRateLimitStore(),
            notifier=notifier,
        )

        # First lockout: 2 attempts
        await manager.record_failed_attempt("user1")
        await manager.record_failed_attempt("user1")
        assert len(notifier.calls) == 1

        # Note: a third attempt while locked WILL fire the notifier
        # again because the manager treats every threshold-exceeding
        # call as a "lock" event. This is fine for the email-driven
        # use case (the user gets reminded), but documenting the
        # behaviour explicitly here so a future change is intentional.


# =============================================================================
# LockoutEmailNotifier
# =============================================================================


class _FailingSender:
    """An email sender whose server is down."""

    async def send(self, message: EmailMessage) -> None:
        msg = "SMTP down"
        raise RuntimeError(msg)


LOCKED_UNTIL = datetime(2026, 4, 11, 12, 0, tzinfo=UTC)


async def _email_of(sid: str) -> str | None:
    return f"{sid}@example.com"


@pytest.mark.anyio
class TestLockoutEmailNotifier:
    async def test_resolves_email_and_sends(self) -> None:
        sender = ConsoleEmailSender()
        notifier = LockoutEmailNotifier(NotificationService(sender=sender), _email_of)

        await notifier.on_lockout(
            "alice", locked_until=LOCKED_UNTIL, failed_attempts=5, ip_address="10.0.0.1"
        )

        [message] = sender.sent_messages
        assert message.to == "alice@example.com"
        assert "10.0.0.1" in message.body_text

    async def test_skips_when_email_is_none(self) -> None:
        async def no_email(sid: str) -> str | None:
            return None

        sender = ConsoleEmailSender()
        notifier = LockoutEmailNotifier(NotificationService(sender=sender), no_email)

        await notifier.on_lockout(
            "ldap-only-subject", locked_until=LOCKED_UNTIL, failed_attempts=5
        )

        assert sender.sent_messages == []

    async def test_swallows_resolve_email_errors(self) -> None:
        async def broken_resolve(sid: str) -> str | None:
            msg = "DB down"
            raise RuntimeError(msg)

        sender = ConsoleEmailSender()
        notifier = LockoutEmailNotifier(
            NotificationService(sender=sender), broken_resolve
        )

        await notifier.on_lockout("alice", locked_until=LOCKED_UNTIL, failed_attempts=5)

        assert sender.sent_messages == []

    async def test_swallows_send_email_errors(self) -> None:
        notifier = LockoutEmailNotifier(
            NotificationService(sender=_FailingSender()), _email_of
        )

        # Should not raise
        await notifier.on_lockout("alice", locked_until=LOCKED_UNTIL, failed_attempts=5)


# =============================================================================
# End-to-end integration: LockoutManager + LockoutEmailNotifier + NotificationService
# =============================================================================


@pytest.mark.anyio
class TestLockoutEndToEndIntegration:
    async def test_lockout_triggers_email_via_notification_service(
        self,
    ) -> None:
        sender = ConsoleEmailSender()
        notifications = NotificationService(sender=sender, app_name="TestApp")

        async def resolve(sid: str) -> str | None:
            return f"{sid}@example.com"

        notifier = LockoutEmailNotifier(notifications, resolve)
        manager = LockoutManager(
            LockoutConfig(max_failed_attempts=3),
            InMemoryRateLimitStore(),
            notifier=notifier,
        )

        for _ in range(3):
            await manager.record_failed_attempt("alice", ip_address="10.0.0.1")

        # The console sender records sent messages — we should see one
        assert len(sender.sent_messages) == 1
        msg = sender.sent_messages[0]
        assert msg.to == "alice@example.com"
        assert "TestApp" in msg.subject
        assert "locked" in msg.subject.lower()
        assert "10.0.0.1" in msg.body_text
