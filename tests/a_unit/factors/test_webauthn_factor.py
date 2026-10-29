"""Tests for WebAuthn authentication factor."""

from __future__ import annotations

import dataclasses
import sys
from datetime import UTC, datetime, timedelta

import pytest

from neozen.core.factors.webauthn import (
    WebAuthnChallengeExpiredError,
    WebAuthnConfig,
    WebAuthnCredentialNotFoundError,
    WebAuthnError,
    WebAuthnFactor,
)
from neozen.core.subject import Subject
from tests.conftest import MockStorage


@dataclasses.dataclass
class MockSubject(Subject):
    id: str
    email: str


@dataclasses.dataclass
class MockWebAuthnCredential:
    id: str
    subject_id: str
    credential_id: str
    public_key: str
    sign_count: int
    transports: str
    device_type: str
    backed_up: bool
    name: str
    created_at: datetime
    last_used_at: datetime | None


@dataclasses.dataclass
class MockWebAuthnChallenge:
    id: str
    challenge: str
    subject_id: str | None
    operation: str
    expires_at: datetime


@pytest.fixture
def credential_storage() -> MockStorage[MockWebAuthnCredential]:
    return MockStorage(MockWebAuthnCredential, [])


@pytest.fixture
def challenge_storage() -> MockStorage[MockWebAuthnChallenge]:
    return MockStorage(MockWebAuthnChallenge, [])


@pytest.fixture
def webauthn_config() -> WebAuthnConfig:
    return WebAuthnConfig(
        rp_id="example.com",
        rp_name="Example App",
        origin="https://example.com",
        challenge_timeout_seconds=300,
    )


@pytest.fixture
def webauthn_factor(
    credential_storage: MockStorage[MockWebAuthnCredential],
    challenge_storage: MockStorage[MockWebAuthnChallenge],
    webauthn_config: WebAuthnConfig,
) -> WebAuthnFactor[MockSubject]:
    factor = WebAuthnFactor(
        config=webauthn_config,
        credential_repository=credential_storage,
        challenge_repository=challenge_storage,
    )
    return factor


@pytest.mark.anyio
class TestWebAuthnConfig:
    """Tests for WebAuthn configuration."""

    def test_config_defaults(self) -> None:
        config = WebAuthnConfig(
            rp_id="example.com",
            rp_name="Example App",
            origin="https://example.com",
        )

        assert config.rp_id == "example.com"
        assert config.rp_name == "Example App"
        assert config.origin == "https://example.com"
        assert config.challenge_timeout_seconds == 300
        assert config.user_verification == "preferred"


@pytest.mark.anyio
class TestCredentialManagement:
    """Tests for credential management operations."""

    async def test_list_credentials_empty(
        self,
        webauthn_factor: WebAuthnFactor[MockSubject],
    ) -> None:
        subject = MockSubject(id="user1", email="user@example.com")

        credentials = await webauthn_factor.list_credentials(subject)

        assert credentials == []

    async def test_list_credentials(
        self,
        webauthn_factor: WebAuthnFactor[MockSubject],
        credential_storage: MockStorage[MockWebAuthnCredential],
    ) -> None:
        subject = MockSubject(id="user1", email="user@example.com")

        # Create some credentials
        await credential_storage.create(
            id="cred1",
            subject_id="user1",
            credential_id="cred_id_1",
            public_key="pk1",
            sign_count=0,
            transports="internal",
            device_type="platform",
            backed_up=True,
            name="MacBook Pro",
            created_at=datetime.now(UTC),
            last_used_at=None,
        )
        await credential_storage.create(
            id="cred2",
            subject_id="user1",
            credential_id="cred_id_2",
            public_key="pk2",
            sign_count=5,
            transports="usb",
            device_type="cross-platform",
            backed_up=False,
            name="Security Key",
            created_at=datetime.now(UTC),
            last_used_at=datetime.now(UTC),
        )

        credentials = await webauthn_factor.list_credentials(subject)

        assert len(credentials) == 2
        names = {c.name for c in credentials}
        assert names == {"MacBook Pro", "Security Key"}

    async def test_delete_credential(
        self,
        webauthn_factor: WebAuthnFactor[MockSubject],
        credential_storage: MockStorage[MockWebAuthnCredential],
    ) -> None:
        subject = MockSubject(id="user1", email="user@example.com")

        await credential_storage.create(
            id="cred1",
            subject_id="user1",
            credential_id="cred_id_1",
            public_key="pk1",
            sign_count=0,
            transports="internal",
            device_type="platform",
            backed_up=True,
            name="MacBook Pro",
            created_at=datetime.now(UTC),
            last_used_at=None,
        )

        await webauthn_factor.delete_credential(subject, "cred_id_1")

        credentials = await webauthn_factor.list_credentials(subject)
        assert len(credentials) == 0

    async def test_delete_credential_not_found(
        self,
        webauthn_factor: WebAuthnFactor[MockSubject],
    ) -> None:
        subject = MockSubject(id="user1", email="user@example.com")

        with pytest.raises(WebAuthnCredentialNotFoundError):
            await webauthn_factor.delete_credential(subject, "nonexistent")

    async def test_delete_credential_wrong_user(
        self,
        webauthn_factor: WebAuthnFactor[MockSubject],
        credential_storage: MockStorage[MockWebAuthnCredential],
    ) -> None:
        # Create credential for user1
        await credential_storage.create(
            id="cred1",
            subject_id="user1",
            credential_id="cred_id_1",
            public_key="pk1",
            sign_count=0,
            transports="internal",
            device_type="platform",
            backed_up=True,
            name="MacBook Pro",
            created_at=datetime.now(UTC),
            last_used_at=None,
        )

        # Try to delete as user2
        subject = MockSubject(id="user2", email="user2@example.com")

        with pytest.raises(WebAuthnCredentialNotFoundError):
            await webauthn_factor.delete_credential(subject, "cred_id_1")

    async def test_rename_credential(
        self,
        webauthn_factor: WebAuthnFactor[MockSubject],
        credential_storage: MockStorage[MockWebAuthnCredential],
    ) -> None:
        subject = MockSubject(id="user1", email="user@example.com")

        await credential_storage.create(
            id="cred1",
            subject_id="user1",
            credential_id="cred_id_1",
            public_key="pk1",
            sign_count=0,
            transports="internal",
            device_type="platform",
            backed_up=True,
            name="Old Name",
            created_at=datetime.now(UTC),
            last_used_at=None,
        )

        updated = await webauthn_factor.rename_credential(
            subject, "cred_id_1", "New Name"
        )

        assert updated.name == "New Name"

    async def test_rename_credential_not_found(
        self,
        webauthn_factor: WebAuthnFactor[MockSubject],
    ) -> None:
        subject = MockSubject(id="user1", email="user@example.com")

        with pytest.raises(WebAuthnCredentialNotFoundError):
            await webauthn_factor.rename_credential(subject, "nonexistent", "New Name")


@pytest.mark.anyio
class TestChallengeHandling:
    """Tests for challenge storage and validation."""

    async def test_challenge_storage(
        self,
        challenge_storage: MockStorage[MockWebAuthnChallenge],
    ) -> None:
        """Test that challenges can be stored and retrieved."""
        expires_at = datetime.now(UTC) + timedelta(minutes=5)

        await challenge_storage.create(
            id="ch1",
            challenge="test_challenge",
            subject_id="user1",
            operation="registration",
            expires_at=expires_at,
        )

        challenge = await challenge_storage.get_one_by(challenge="test_challenge")

        assert challenge.subject_id == "user1"
        assert challenge.operation == "registration"
        assert challenge.expires_at == expires_at

    async def test_challenge_cleanup_on_expiry(
        self,
        challenge_storage: MockStorage[MockWebAuthnChallenge],
    ) -> None:
        """Test that expired challenges can be identified."""
        expired = datetime.now(UTC) - timedelta(hours=1)

        await challenge_storage.create(
            id="ch1",
            challenge="expired_challenge",
            subject_id="user1",
            operation="registration",
            expires_at=expired,
        )

        challenge = await challenge_storage.get_one_by(challenge="expired_challenge")

        # Check if expired
        assert datetime.now(UTC) > challenge.expires_at


@pytest.mark.anyio
class TestWebAuthnErrorHandling:
    """Tests for error handling."""

    def test_webauthn_error_message(self) -> None:
        error = WebAuthnError("Test error")
        assert error.message == "Test error"

    def test_credential_not_found_error(self) -> None:
        error = WebAuthnCredentialNotFoundError("cred123")
        assert "cred123" in error.message

    def test_credential_not_found_error_no_id(self) -> None:
        error = WebAuthnCredentialNotFoundError()
        assert "not found" in error.message

    def test_challenge_expired_error(self) -> None:
        error = WebAuthnChallengeExpiredError()
        assert "expired" in error.message


def test_factor_needs_the_webauthn_package(
    monkeypatch: pytest.MonkeyPatch,
    credential_storage: MockStorage[MockWebAuthnCredential],
    challenge_storage: MockStorage[MockWebAuthnChallenge],
    webauthn_config: WebAuthnConfig,
) -> None:
    monkeypatch.setitem(sys.modules, "webauthn", None)  # import fails

    with pytest.raises(WebAuthnError, match="webauthn package is required"):
        WebAuthnFactor(
            config=webauthn_config,
            credential_repository=credential_storage,
            challenge_repository=challenge_storage,
        )
