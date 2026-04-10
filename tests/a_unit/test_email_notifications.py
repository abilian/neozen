"""Tests for email templates, NotificationService, and EmailOTPFactor."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from neozen.core.email.base import EmailMessage
from neozen.core.email.notifications import NotificationService
from neozen.core.email.templates import (
    account_lockout_email,
    compromised_password_email,
    email_otp_email,
    email_verification_email,
    password_reset_email,
)
from neozen.core.factors.email_otp import EmailOTPConfig, EmailOTPFactor

# =============================================================================
# Email Templates
# =============================================================================


class TestEmailTemplates:
    def test_password_reset_email(self) -> None:
        msg = password_reset_email(
            to="alice@example.com",
            reset_url="https://app.example.com/reset?token=abc",
            expires_at=datetime(2026, 4, 10, 12, 0, tzinfo=UTC),
            app_name="My App",
        )
        assert isinstance(msg, EmailMessage)
        assert msg.to == "alice@example.com"
        assert "My App" in msg.subject
        assert "abc" in msg.body_text
        assert "abc" in msg.body_html

    def test_email_verification_email(self) -> None:
        msg = email_verification_email(
            to="bob@example.com",
            verify_url="https://app.example.com/verify?token=xyz",
            expires_at=datetime(2026, 4, 10, 12, 0, tzinfo=UTC),
        )
        assert "Verify" in msg.subject
        assert "xyz" in msg.body_text

    def test_email_otp_email(self) -> None:
        msg = email_otp_email(
            to="carol@example.com",
            code="123456",
            lifetime_seconds=600,
        )
        assert "123456" in msg.subject
        assert "123456" in msg.body_text
        assert "10 minutes" in msg.body_text

    def test_email_otp_email_singular_minute(self) -> None:
        msg = email_otp_email(
            to="d@example.com",
            code="999999",
            lifetime_seconds=60,
        )
        assert "1 minute" in msg.body_text
        assert "1 minutes" not in msg.body_text

    def test_account_lockout_email(self) -> None:
        msg = account_lockout_email(
            to="user@example.com",
            locked_until=datetime(2026, 4, 10, 13, 0, tzinfo=UTC),
            failed_attempts=5,
            ip_address="1.2.3.4",
        )
        assert "5" in msg.body_text
        assert "1.2.3.4" in msg.body_text

    def test_compromised_password_email(self) -> None:
        msg = compromised_password_email(to="user@example.com")
        assert "breach" in msg.body_text.lower()
        assert msg.body_html is not None


# =============================================================================
# NotificationService
# =============================================================================


@dataclass
class MockEmailSender:
    sent: list[EmailMessage] = field(default_factory=list)

    async def send(self, message: EmailMessage) -> None:
        self.sent.append(message)


class TestNotificationService:
    @pytest.mark.anyio
    async def test_send_reset_email(self) -> None:
        sender = MockEmailSender()
        service = NotificationService(
            sender=sender,
            app_name="Test",
            reset_url_template="https://app.test/reset?token={token}",
        )

        result = await service.send_reset_email(
            "u@e.com",
            "abc123",
            datetime(2026, 4, 10, 12, 0, tzinfo=UTC),
        )

        assert result is True
        assert len(sender.sent) == 1
        assert "abc123" in sender.sent[0].body_text

    @pytest.mark.anyio
    async def test_send_reset_email_no_template_raises(self) -> None:
        sender = MockEmailSender()
        service = NotificationService(sender=sender)

        with pytest.raises(ValueError, match="reset_url_template"):
            await service.send_reset_email(
                "u@e.com",
                "abc",
                datetime.now(UTC),
            )

    @pytest.mark.anyio
    async def test_send_verification_email(self) -> None:
        sender = MockEmailSender()
        service = NotificationService(
            sender=sender,
            verify_url_template="https://app.test/verify?token={token}",
        )

        await service.send_verification_email(
            "u@e.com",
            "tok123",
            datetime.now(UTC),
        )
        assert "tok123" in sender.sent[0].body_text

    @pytest.mark.anyio
    async def test_send_otp_email(self) -> None:
        sender = MockEmailSender()
        service = NotificationService(sender=sender)

        await service.send_otp_email("u@e.com", "999999", 600)
        assert "999999" in sender.sent[0].body_text

    @pytest.mark.anyio
    async def test_send_lockout_email(self) -> None:
        sender = MockEmailSender()
        service = NotificationService(sender=sender)

        await service.send_lockout_email(
            "u@e.com",
            locked_until=datetime.now(UTC) + timedelta(minutes=15),
            failed_attempts=10,
            ip_address="1.1.1.1",
        )
        assert "10" in sender.sent[0].body_text
        assert "1.1.1.1" in sender.sent[0].body_text

    @pytest.mark.anyio
    async def test_send_compromised_password_email(self) -> None:
        sender = MockEmailSender()
        service = NotificationService(sender=sender)

        await service.send_compromised_password_email("u@e.com")
        assert len(sender.sent) == 1


# =============================================================================
# EmailOTPFactor
# =============================================================================


@dataclass
class MockOTPCode:
    id: str
    subject_id: str
    code_hash: str
    email: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None = None
    attempts: int = 0


class MockOTPCodeRepository:
    def __init__(self) -> None:
        self._codes: list[MockOTPCode] = []
        self._counter = 0

    async def create(self, **kwargs: Any) -> MockOTPCode:
        self._counter += 1
        code = MockOTPCode(id=f"otp_{self._counter}", **kwargs)
        self._codes.append(code)
        return code

    async def get_latest_pending(
        self, subject_id: str, now: datetime
    ) -> MockOTPCode | None:
        candidates = [
            c
            for c in self._codes
            if c.subject_id == subject_id and c.used_at is None and c.expires_at > now
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda c: c.created_at)

    async def mark_used(self, code_id: str, used_at: datetime) -> None:
        for c in self._codes:
            if c.id == code_id:
                c.used_at = used_at
                return

    async def increment_attempts(self, code_id: str) -> int:
        for c in self._codes:
            if c.id == code_id:
                c.attempts += 1
                return c.attempts
        return 0

    async def count_pending(self, subject_id: str, since: datetime) -> int:
        now = datetime.now(UTC)
        return sum(
            1
            for c in self._codes
            if c.subject_id == subject_id
            and c.created_at >= since
            and c.used_at is None
            and c.expires_at > now
        )

    async def invalidate_all(self, subject_id: str) -> int:
        now = datetime.now(UTC)
        count = 0
        for c in self._codes:
            if c.subject_id == subject_id and c.used_at is None:
                c.used_at = now
                count += 1
        return count


class MockSubjectLookup:
    def __init__(self, subjects: dict[str, str] | None = None) -> None:
        self._subjects = subjects or {}

    async def get_email(self, subject_id: str) -> str | None:
        return self._subjects.get(subject_id)

    async def subject_exists(self, subject_id: str) -> bool:
        return subject_id in self._subjects


@pytest.fixture
def factor() -> EmailOTPFactor:
    return EmailOTPFactor(
        config=EmailOTPConfig(),
        code_repository=MockOTPCodeRepository(),
        subject_email_lookup=MockSubjectLookup({
            "u1": "u1@example.com",
            "u2": "u2@example.com",
        }),
        email_sender=MockEmailSender(),
        code_hash_key="test-secret",
    )


class TestEmailOTPFactorProperties:
    def test_factor_id(self, factor: EmailOTPFactor) -> None:
        assert factor.factor_id == "email_otp"

    def test_display_name(self, factor: EmailOTPFactor) -> None:
        assert factor.display_name == "Email OTP"

    def test_factor_type(self, factor: EmailOTPFactor) -> None:
        assert factor.factor_type == "possession"

    @pytest.mark.anyio
    async def test_is_enrolled_with_email(self, factor: EmailOTPFactor) -> None:
        assert await factor.is_enrolled("u1") is True

    @pytest.mark.anyio
    async def test_is_enrolled_without_email(self, factor: EmailOTPFactor) -> None:
        assert await factor.is_enrolled("nobody") is False


class TestBeginAuthentication:
    @pytest.mark.anyio
    async def test_sends_email(self, factor: EmailOTPFactor) -> None:
        result = await factor.begin_authentication("u1")
        assert result["status"] == "sent"
        sender = factor.email_sender  # type: ignore[has-type]
        assert len(sender.sent) == 1
        assert sender.sent[0].to == "u1@example.com"

    @pytest.mark.anyio
    async def test_email_contains_code(self, factor: EmailOTPFactor) -> None:
        await factor.begin_authentication("u1")
        sender = factor.email_sender  # type: ignore[has-type]
        body = sender.sent[0].body_text
        # Body should contain a 6-digit code
        import re

        assert re.search(r"\b\d{6}\b", body) is not None

    @pytest.mark.anyio
    async def test_nonexistent_subject_no_email(self, factor: EmailOTPFactor) -> None:
        result = await factor.begin_authentication("nobody")
        assert result["status"] == "sent"
        sender = factor.email_sender  # type: ignore[has-type]
        assert len(sender.sent) == 0

    @pytest.mark.anyio
    async def test_rate_limiting(self, factor: EmailOTPFactor) -> None:
        for _ in range(3):
            await factor.begin_authentication("u1")

        sender = factor.email_sender  # type: ignore[has-type]
        assert len(sender.sent) == 3

        # Fourth should be rate limited
        result = await factor.begin_authentication("u1")
        assert result.get("rate_limited") is True
        assert len(sender.sent) == 3  # no new email


class TestCompleteAuthentication:
    @pytest.mark.anyio
    async def test_valid_code(self, factor: EmailOTPFactor) -> None:
        await factor.begin_authentication("u1")
        sender = factor.email_sender  # type: ignore[has-type]
        # Extract code from email body
        import re

        match = re.search(r"\b(\d{6})\b", sender.sent[0].body_text)
        assert match is not None
        code = match.group(1)

        result = await factor.complete_authentication("u1", response=code)
        assert result is True

    @pytest.mark.anyio
    async def test_invalid_code(self, factor: EmailOTPFactor) -> None:
        await factor.begin_authentication("u1")
        result = await factor.complete_authentication("u1", response="000000")
        assert result is False

    @pytest.mark.anyio
    async def test_no_code(self, factor: EmailOTPFactor) -> None:
        result = await factor.complete_authentication("u1", response=None)
        assert result is False

    @pytest.mark.anyio
    async def test_no_pending_code(self, factor: EmailOTPFactor) -> None:
        result = await factor.complete_authentication("u1", response="123456")
        assert result is False

    @pytest.mark.anyio
    async def test_single_use(self, factor: EmailOTPFactor) -> None:
        await factor.begin_authentication("u1")
        sender = factor.email_sender  # type: ignore[has-type]
        import re

        code = re.search(r"\b(\d{6})\b", sender.sent[0].body_text).group(1)  # type: ignore[union-attr]

        # First use succeeds
        assert await factor.complete_authentication("u1", response=code) is True
        # Second use fails
        assert await factor.complete_authentication("u1", response=code) is False

    @pytest.mark.anyio
    async def test_max_attempts(self, factor: EmailOTPFactor) -> None:
        await factor.begin_authentication("u1")

        # Try wrong code 5 times (max_attempts default is 5)
        for _ in range(5):
            await factor.complete_authentication("u1", response="000000")

        # 6th attempt should fail because the code is now invalidated
        result = await factor.complete_authentication("u1", response="000000")
        assert result is False
