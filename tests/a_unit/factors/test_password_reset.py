"""Unit tests for password reset service."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from neozen.core.recovery.password_reset import (
    PasswordResetConfig,
    PasswordResetService,
)


@dataclass
class MockSubject:
    """Mock subject for testing."""

    id: str
    email: str


@dataclass
class MockPasswordResetToken:
    """Mock password reset token for testing."""

    id: str
    subject_id: str
    token_hash: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None = None
    ip_address: str | None = None


class MockTokenRepository:
    """Mock token repository for testing."""

    def __init__(self) -> None:
        self._tokens: dict[str, MockPasswordResetToken] = {}
        self._by_hash: dict[str, str] = {}
        self._counter = 0

    async def create(self, **kwargs: Any) -> MockPasswordResetToken:
        """Create a new token."""
        self._counter += 1
        token_id = f"token_{self._counter}"
        token = MockPasswordResetToken(
            id=token_id,
            subject_id=kwargs["subject_id"],
            token_hash=kwargs["token_hash"],
            created_at=kwargs["created_at"],
            expires_at=kwargs["expires_at"],
            used_at=kwargs.get("used_at"),
            ip_address=kwargs.get("ip_address"),
        )
        self._tokens[token_id] = token
        self._by_hash[kwargs["token_hash"]] = token_id
        return token

    async def get_by_hash(self, token_hash: str) -> MockPasswordResetToken | None:
        """Get token by hash."""
        token_id = self._by_hash.get(token_hash)
        if token_id:
            return self._tokens.get(token_id)
        return None

    async def mark_used(self, token_id: str, used_at: datetime) -> None:
        """Mark token as used."""
        if token_id in self._tokens:
            token = self._tokens[token_id]
            self._tokens[token_id] = MockPasswordResetToken(
                id=token.id,
                subject_id=token.subject_id,
                token_hash=token.token_hash,
                created_at=token.created_at,
                expires_at=token.expires_at,
                used_at=used_at,
                ip_address=token.ip_address,
            )

    async def count_pending(self, subject_id: str, since: datetime) -> int:
        """Count pending tokens."""
        count = 0
        now = datetime.now(UTC)
        for token in self._tokens.values():
            if (
                token.subject_id == subject_id
                and token.created_at >= since
                and token.used_at is None
                and token.expires_at > now
            ):
                count += 1
        return count

    async def invalidate_all(self, subject_id: str) -> int:
        """Invalidate all pending tokens for subject."""
        now = datetime.now(UTC)
        count = 0
        for token_id, token in list(self._tokens.items()):
            if token.subject_id == subject_id and token.used_at is None:
                self._tokens[token_id] = MockPasswordResetToken(
                    id=token.id,
                    subject_id=token.subject_id,
                    token_hash=token.token_hash,
                    created_at=token.created_at,
                    expires_at=token.expires_at,
                    used_at=now,
                    ip_address=token.ip_address,
                )
                count += 1
        return count


class MockSubjectLookup:
    """Mock subject lookup for testing."""

    def __init__(self, subjects: dict[str, MockSubject] | None = None) -> None:
        self._subjects = subjects or {}

    async def get_by_email(self, email: str) -> MockSubject | None:
        """Get subject by email."""
        return self._subjects.get(email)

    def add_subject(self, subject: MockSubject) -> None:
        """Add a subject."""
        self._subjects[subject.email] = subject


class MockPasswordChanger:
    """Mock password changer for testing."""

    def __init__(self) -> None:
        self.passwords: dict[str, str] = {}
        self.fail_for: set[str] = set()

    async def change_password(self, subject_id: str, new_password: str) -> bool:
        """Change password."""
        if subject_id in self.fail_for:
            return False
        self.passwords[subject_id] = new_password
        return True


@dataclass
class MockEmailSender:
    """Mock email sender for testing."""

    sent_emails: list[dict[str, Any]] = field(default_factory=list)

    async def send_reset_email(
        self,
        email: str,
        token: str,
        expires_at: datetime,
    ) -> bool:
        """Send reset email."""
        self.sent_emails.append({
            "email": email,
            "token": token,
            "expires_at": expires_at,
        })
        return True


@pytest.fixture
def config() -> PasswordResetConfig:
    """Create password reset config."""
    return PasswordResetConfig(
        token_lifetime=timedelta(hours=1),
        max_pending_requests=3,
        rate_limit_window=timedelta(hours=24),
    )


@pytest.fixture
def token_repo() -> MockTokenRepository:
    """Create mock token repository."""
    return MockTokenRepository()


@pytest.fixture
def subject_lookup() -> MockSubjectLookup:
    """Create mock subject lookup."""
    lookup = MockSubjectLookup()
    lookup.add_subject(MockSubject(id="user1", email="user@example.com"))
    return lookup


@pytest.fixture
def password_changer() -> MockPasswordChanger:
    """Create mock password changer."""
    return MockPasswordChanger()


@pytest.fixture
def email_sender() -> MockEmailSender:
    """Create mock email sender."""
    return MockEmailSender()


@pytest.fixture
def service(
    config: PasswordResetConfig,
    token_repo: MockTokenRepository,
    subject_lookup: MockSubjectLookup,
    password_changer: MockPasswordChanger,
    email_sender: MockEmailSender,
) -> PasswordResetService:
    """Create password reset service."""
    return PasswordResetService(
        config=config,
        token_repository=token_repo,
        subject_lookup=subject_lookup,
        password_changer=password_changer,
        token_hash_key="test_secret_key",
        email_sender=email_sender,
    )


class TestPasswordResetConfig:
    """Tests for PasswordResetConfig."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = PasswordResetConfig()

        assert config.token_lifetime == timedelta(hours=1)
        assert config.max_pending_requests == 3
        assert config.rate_limit_window == timedelta(hours=24)
        assert config.token_prefix == "nz_pr_"


class TestPasswordResetService:
    """Tests for PasswordResetService."""

    @pytest.mark.anyio
    async def test_request_reset_existing_user(
        self,
        service: PasswordResetService,
        email_sender: MockEmailSender,
    ) -> None:
        """Test requesting reset for existing user."""
        result = await service.request_reset("user@example.com")

        assert result.success is True
        assert result.token_sent is True
        assert len(email_sender.sent_emails) == 1

    @pytest.mark.anyio
    async def test_request_reset_nonexistent_user(
        self,
        service: PasswordResetService,
        email_sender: MockEmailSender,
    ) -> None:
        """Test requesting reset for nonexistent user."""
        result = await service.request_reset("nonexistent@example.com")

        # Should still return success to prevent enumeration
        assert result.success is True
        assert result.token_sent is True
        # But no email should be sent
        assert len(email_sender.sent_emails) == 0

    @pytest.mark.anyio
    async def test_request_reset_rate_limit(
        self,
        service: PasswordResetService,
    ) -> None:
        """Test rate limiting of reset requests."""
        # Make max_pending_requests
        for _ in range(3):
            await service.request_reset("user@example.com")

        # Fourth request should still return success (but not send email)
        result = await service.request_reset("user@example.com")
        assert result.success is True

    @pytest.mark.anyio
    async def test_validate_token_valid(
        self,
        service: PasswordResetService,
        email_sender: MockEmailSender,
    ) -> None:
        """Test validating a valid token."""
        await service.request_reset("user@example.com")

        token = email_sender.sent_emails[0]["token"]
        is_valid = await service.validate_token(token)

        assert is_valid is True

    @pytest.mark.anyio
    async def test_validate_token_invalid(
        self,
        service: PasswordResetService,
    ) -> None:
        """Test validating an invalid token."""
        is_valid = await service.validate_token("invalid_token")
        assert is_valid is False

    @pytest.mark.anyio
    async def test_reset_password_success(
        self,
        service: PasswordResetService,
        email_sender: MockEmailSender,
        password_changer: MockPasswordChanger,
    ) -> None:
        """Test successful password reset."""
        await service.request_reset("user@example.com")
        token = email_sender.sent_emails[0]["token"]

        result = await service.reset_password(token, "new_password123")

        assert result.success is True
        assert password_changer.passwords.get("user1") == "new_password123"

    @pytest.mark.anyio
    async def test_reset_password_invalid_token(
        self,
        service: PasswordResetService,
    ) -> None:
        """Test reset with invalid token."""
        result = await service.reset_password("invalid_token", "new_password")

        assert result.success is False
        assert result.error_code == "invalid_token"

    @pytest.mark.anyio
    async def test_reset_password_used_token(
        self,
        service: PasswordResetService,
        email_sender: MockEmailSender,
    ) -> None:
        """Test reset with already used token."""
        await service.request_reset("user@example.com")
        token = email_sender.sent_emails[0]["token"]

        # First reset should succeed
        result1 = await service.reset_password(token, "new_password1")
        assert result1.success is True

        # Second reset should fail
        result2 = await service.reset_password(token, "new_password2")
        assert result2.success is False
        assert result2.error_code == "token_used"

    @pytest.mark.anyio
    async def test_reset_password_expired_token(
        self,
        token_repo: MockTokenRepository,
        subject_lookup: MockSubjectLookup,
        password_changer: MockPasswordChanger,
    ) -> None:
        """Test reset with expired token."""
        config = PasswordResetConfig(token_lifetime=timedelta(seconds=-1))
        service = PasswordResetService(
            config=config,
            token_repository=token_repo,
            subject_lookup=subject_lookup,
            password_changer=password_changer,
            token_hash_key="test_secret",
        )

        # Create an already-expired token
        await service.request_reset("user@example.com")

        # Try to find the token and reset (should fail)
        result = await service.reset_password("any_token", "new_password")
        assert result.success is False

    @pytest.mark.anyio
    async def test_reset_password_change_fails(
        self,
        service: PasswordResetService,
        email_sender: MockEmailSender,
        password_changer: MockPasswordChanger,
    ) -> None:
        """Test reset when password change fails."""
        password_changer.fail_for.add("user1")

        await service.request_reset("user@example.com")
        token = email_sender.sent_emails[0]["token"]

        result = await service.reset_password(token, "new_password")

        assert result.success is False
        assert result.error_code == "change_failed"

    @pytest.mark.anyio
    async def test_get_token_subject_id(
        self,
        service: PasswordResetService,
        email_sender: MockEmailSender,
    ) -> None:
        """Test getting subject ID from token."""
        await service.request_reset("user@example.com")
        token = email_sender.sent_emails[0]["token"]

        subject_id = await service.get_token_subject_id(token)

        assert subject_id == "user1"

    @pytest.mark.anyio
    async def test_get_token_subject_id_invalid(
        self,
        service: PasswordResetService,
    ) -> None:
        """Test getting subject ID from invalid token."""
        subject_id = await service.get_token_subject_id("invalid_token")
        assert subject_id is None

    @pytest.mark.anyio
    async def test_reset_invalidates_other_tokens(
        self,
        service: PasswordResetService,
        email_sender: MockEmailSender,
    ) -> None:
        """Test that reset invalidates other pending tokens."""
        # Create multiple tokens
        await service.request_reset("user@example.com")
        await service.request_reset("user@example.com")
        token1 = email_sender.sent_emails[0]["token"]
        token2 = email_sender.sent_emails[1]["token"]

        # Reset with first token
        await service.reset_password(token1, "new_password")

        # Second token should now be invalid
        is_valid = await service.validate_token(token2)
        assert is_valid is False

    @pytest.mark.anyio
    async def test_request_with_ip_address(
        self,
        service: PasswordResetService,
        token_repo: MockTokenRepository,
    ) -> None:
        """Test that IP address is recorded."""
        await service.request_reset("user@example.com", ip_address="192.168.1.1")

        # Check token was created with IP
        tokens = list(token_repo._tokens.values())
        assert len(tokens) == 1
        assert tokens[0].ip_address == "192.168.1.1"
