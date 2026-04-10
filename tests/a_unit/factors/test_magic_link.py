"""Unit tests for magic link authentication factor."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from neozen.core.factors.magic_link import (
    MagicLinkConfig,
    MagicLinkFactor,
)


@dataclass
class MockMagicLinkToken:
    """Mock magic link token for testing."""

    id: str
    subject_id: str
    token_hash: str
    email: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None = None
    ip_address: str | None = None


class MockMagicLinkTokenRepository:
    """Mock token repository for testing."""

    def __init__(self) -> None:
        self._tokens: dict[str, MockMagicLinkToken] = {}
        self._by_hash: dict[str, str] = {}
        self._counter = 0

    async def create(self, **kwargs: Any) -> MockMagicLinkToken:
        self._counter += 1
        token_id = f"mlt_{self._counter}"
        token = MockMagicLinkToken(
            id=token_id,
            subject_id=kwargs["subject_id"],
            token_hash=kwargs["token_hash"],
            email=kwargs["email"],
            created_at=kwargs["created_at"],
            expires_at=kwargs["expires_at"],
            used_at=kwargs.get("used_at"),
            ip_address=kwargs.get("ip_address"),
        )
        self._tokens[token_id] = token
        self._by_hash[kwargs["token_hash"]] = token_id
        return token

    async def get_by_hash(self, token_hash: str) -> MockMagicLinkToken | None:
        token_id = self._by_hash.get(token_hash)
        if token_id:
            return self._tokens.get(token_id)
        return None

    async def mark_used(self, token_id: str, used_at: datetime) -> None:
        if token_id in self._tokens:
            token = self._tokens[token_id]
            self._tokens[token_id] = MockMagicLinkToken(
                id=token.id,
                subject_id=token.subject_id,
                token_hash=token.token_hash,
                email=token.email,
                created_at=token.created_at,
                expires_at=token.expires_at,
                used_at=used_at,
                ip_address=token.ip_address,
            )

    async def count_pending(self, subject_id: str, since: datetime) -> int:
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
        now = datetime.now(UTC)
        count = 0
        for token_id, token in list(self._tokens.items()):
            if token.subject_id == subject_id and token.used_at is None:
                self._tokens[token_id] = MockMagicLinkToken(
                    id=token.id,
                    subject_id=token.subject_id,
                    token_hash=token.token_hash,
                    email=token.email,
                    created_at=token.created_at,
                    expires_at=token.expires_at,
                    used_at=now,
                    ip_address=token.ip_address,
                )
                count += 1
        return count


class MockSubjectEmailLookup:
    """Mock subject email lookup for testing."""

    def __init__(self, subjects: dict[str, str] | None = None) -> None:
        # subject_id -> email
        self._subjects = subjects or {}

    async def get_email(self, subject_id: str) -> str | None:
        return self._subjects.get(subject_id)

    async def subject_exists(self, subject_id: str) -> bool:
        return subject_id in self._subjects

    def add_subject(self, subject_id: str, email: str) -> None:
        self._subjects[subject_id] = email


@dataclass
class MockEmailSender:
    """Mock email sender for testing."""

    sent_messages: list[dict[str, Any]] = field(default_factory=list)

    async def send(self, message: Any) -> None:
        self.sent_messages.append({
            "to": message.to,
            "subject": message.subject,
            "body_text": message.body_text,
            "body_html": message.body_html,
        })


@pytest.fixture
def config() -> MagicLinkConfig:
    return MagicLinkConfig(
        token_lifetime=timedelta(minutes=15),
        max_pending_per_subject=3,
        rate_limit_window=timedelta(hours=1),
        link_base_url="https://app.example.com/magic-login",
    )


@pytest.fixture
def token_repo() -> MockMagicLinkTokenRepository:
    return MockMagicLinkTokenRepository()


@pytest.fixture
def subject_lookup() -> MockSubjectEmailLookup:
    lookup = MockSubjectEmailLookup()
    lookup.add_subject("user1", "user@example.com")
    lookup.add_subject("user2", "other@example.com")
    return lookup


@pytest.fixture
def email_sender() -> MockEmailSender:
    return MockEmailSender()


@pytest.fixture
def factor(
    config: MagicLinkConfig,
    token_repo: MockMagicLinkTokenRepository,
    subject_lookup: MockSubjectEmailLookup,
    email_sender: MockEmailSender,
) -> MagicLinkFactor:
    return MagicLinkFactor(
        config=config,
        token_repository=token_repo,
        subject_email_lookup=subject_lookup,
        email_sender=email_sender,
        token_hash_key="test_secret_key",
    )


class TestMagicLinkConfig:
    """Tests for MagicLinkConfig."""

    def test_default_values(self) -> None:
        config = MagicLinkConfig()

        assert config.token_lifetime == timedelta(minutes=15)
        assert config.max_pending_per_subject == 3
        assert config.rate_limit_window == timedelta(hours=1)
        assert config.token_prefix == "nz_ml_"
        assert config.link_base_url == ""

    def test_custom_values(self) -> None:
        config = MagicLinkConfig(
            token_lifetime=timedelta(minutes=30),
            max_pending_per_subject=5,
            link_base_url="https://example.com/login",
        )

        assert config.token_lifetime == timedelta(minutes=30)
        assert config.max_pending_per_subject == 5
        assert config.link_base_url == "https://example.com/login"

    def test_frozen(self) -> None:
        config = MagicLinkConfig()
        with pytest.raises(AttributeError):
            config.token_lifetime = timedelta(hours=1)  # type: ignore[misc]


class TestMagicLinkFactorProperties:
    """Tests for MagicLinkFactor properties."""

    def test_factor_id(self, factor: MagicLinkFactor) -> None:
        assert factor.factor_id == "magic_link"

    def test_display_name(self, factor: MagicLinkFactor) -> None:
        assert factor.display_name == "Email Magic Link"

    def test_factor_type(self, factor: MagicLinkFactor) -> None:
        assert factor.factor_type == "possession"

    @pytest.mark.anyio
    async def test_is_enrolled_with_email(self, factor: MagicLinkFactor) -> None:
        assert await factor.is_enrolled("user1") is True

    @pytest.mark.anyio
    async def test_is_enrolled_without_email(self, factor: MagicLinkFactor) -> None:
        assert await factor.is_enrolled("nonexistent") is False

    @pytest.mark.anyio
    async def test_supports_subject(self, factor: MagicLinkFactor) -> None:
        assert await factor.supports_subject("user1") is True
        assert await factor.supports_subject("nonexistent") is False


class TestMagicLinkBeginAuthentication:
    """Tests for begin_authentication."""

    @pytest.mark.anyio
    async def test_sends_email(
        self,
        factor: MagicLinkFactor,
        email_sender: MockEmailSender,
    ) -> None:
        result = await factor.begin_authentication("user1")

        assert result["status"] == "sent"
        assert len(email_sender.sent_messages) == 1
        assert email_sender.sent_messages[0]["to"] == "user@example.com"

    @pytest.mark.anyio
    async def test_email_contains_magic_link(
        self,
        factor: MagicLinkFactor,
        email_sender: MockEmailSender,
    ) -> None:
        await factor.begin_authentication("user1")

        body = email_sender.sent_messages[0]["body_text"]
        assert "https://app.example.com/magic-login?token=" in body

    @pytest.mark.anyio
    async def test_email_has_html_body(
        self,
        factor: MagicLinkFactor,
        email_sender: MockEmailSender,
    ) -> None:
        await factor.begin_authentication("user1")

        html = email_sender.sent_messages[0]["body_html"]
        assert html is not None
        assert "Sign in" in html

    @pytest.mark.anyio
    async def test_returns_expiry(
        self,
        factor: MagicLinkFactor,
    ) -> None:
        result = await factor.begin_authentication("user1")

        assert "expires_at" in result

    @pytest.mark.anyio
    async def test_stores_token_hash(
        self,
        factor: MagicLinkFactor,
        token_repo: MockMagicLinkTokenRepository,
    ) -> None:
        await factor.begin_authentication("user1")

        assert len(token_repo._tokens) == 1
        token = next(iter(token_repo._tokens.values()))
        assert token.subject_id == "user1"
        assert token.email == "user@example.com"
        assert token.used_at is None

    @pytest.mark.anyio
    async def test_nonexistent_subject_returns_success(
        self,
        factor: MagicLinkFactor,
        email_sender: MockEmailSender,
    ) -> None:
        """Should not reveal that the subject doesn't exist."""
        result = await factor.begin_authentication("nonexistent")

        assert result["status"] == "sent"
        assert len(email_sender.sent_messages) == 0

    @pytest.mark.anyio
    async def test_records_ip_address(
        self,
        factor: MagicLinkFactor,
        token_repo: MockMagicLinkTokenRepository,
    ) -> None:
        await factor.begin_authentication("user1", ip_address="10.0.0.1")

        token = next(iter(token_repo._tokens.values()))
        assert token.ip_address == "10.0.0.1"

    @pytest.mark.anyio
    async def test_rate_limiting(
        self,
        factor: MagicLinkFactor,
        email_sender: MockEmailSender,
    ) -> None:
        """Should stop sending after max_pending_per_subject."""
        for _ in range(3):
            await factor.begin_authentication("user1")

        assert len(email_sender.sent_messages) == 3

        # Fourth request should be rate limited
        result = await factor.begin_authentication("user1")
        assert result["status"] == "sent"  # still looks like success
        assert len(email_sender.sent_messages) == 3  # no new email


class TestMagicLinkCompleteAuthentication:
    """Tests for complete_authentication."""

    @pytest.mark.anyio
    async def test_valid_token(
        self,
        factor: MagicLinkFactor,
        email_sender: MockEmailSender,
    ) -> None:
        await factor.begin_authentication("user1")

        # Extract token from email body
        body = email_sender.sent_messages[0]["body_text"]
        token = body.split("token=")[1].split("\n")[0]

        result = await factor.complete_authentication("user1", response=token)
        assert result is True

    @pytest.mark.anyio
    async def test_invalid_token(self, factor: MagicLinkFactor) -> None:
        result = await factor.complete_authentication("user1", response="bad_token")
        assert result is False

    @pytest.mark.anyio
    async def test_no_token(self, factor: MagicLinkFactor) -> None:
        result = await factor.complete_authentication("user1", response=None)
        assert result is False

    @pytest.mark.anyio
    async def test_non_string_token(self, factor: MagicLinkFactor) -> None:
        result = await factor.complete_authentication("user1", response=12345)
        assert result is False

    @pytest.mark.anyio
    async def test_token_via_kwarg(
        self,
        factor: MagicLinkFactor,
        email_sender: MockEmailSender,
    ) -> None:
        await factor.begin_authentication("user1")

        body = email_sender.sent_messages[0]["body_text"]
        token = body.split("token=")[1].split("\n")[0]

        result = await factor.complete_authentication("user1", token=token)
        assert result is True

    @pytest.mark.anyio
    async def test_token_single_use(
        self,
        factor: MagicLinkFactor,
        email_sender: MockEmailSender,
    ) -> None:
        await factor.begin_authentication("user1")

        body = email_sender.sent_messages[0]["body_text"]
        token = body.split("token=")[1].split("\n")[0]

        # First use should succeed
        assert await factor.complete_authentication("user1", response=token) is True

        # Second use should fail
        assert await factor.complete_authentication("user1", response=token) is False

    @pytest.mark.anyio
    async def test_wrong_subject(
        self,
        factor: MagicLinkFactor,
        email_sender: MockEmailSender,
    ) -> None:
        """Token should only work for the correct subject."""
        await factor.begin_authentication("user1")

        body = email_sender.sent_messages[0]["body_text"]
        token = body.split("token=")[1].split("\n")[0]

        # Different subject should fail
        result = await factor.complete_authentication("user2", response=token)
        assert result is False

    @pytest.mark.anyio
    async def test_expired_token(
        self,
        token_repo: MockMagicLinkTokenRepository,
        subject_lookup: MockSubjectEmailLookup,
        email_sender: MockEmailSender,
    ) -> None:
        """Expired tokens should be rejected."""
        config = MagicLinkConfig(
            token_lifetime=timedelta(seconds=-1),
            link_base_url="https://app.example.com/magic-login",
        )
        factor = MagicLinkFactor(
            config=config,
            token_repository=token_repo,
            subject_email_lookup=subject_lookup,
            email_sender=email_sender,
            token_hash_key="test_secret_key",
        )

        await factor.begin_authentication("user1")

        body = email_sender.sent_messages[0]["body_text"]
        token = body.split("token=")[1].split("\n")[0]

        result = await factor.complete_authentication("user1", response=token)
        assert result is False

    @pytest.mark.anyio
    async def test_invalidates_other_tokens(
        self,
        factor: MagicLinkFactor,
        email_sender: MockEmailSender,
    ) -> None:
        """Using one token should invalidate other pending tokens."""
        await factor.begin_authentication("user1")
        await factor.begin_authentication("user1")

        body1 = email_sender.sent_messages[0]["body_text"]
        token1 = body1.split("token=")[1].split("\n")[0]

        body2 = email_sender.sent_messages[1]["body_text"]
        token2 = body2.split("token=")[1].split("\n")[0]

        # Use first token
        assert await factor.complete_authentication("user1", response=token1) is True

        # Second token should now be invalid
        assert await factor.complete_authentication("user1", response=token2) is False
