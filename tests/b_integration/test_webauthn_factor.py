"""Integration tests for WebAuthn factor with SQLAlchemy storage.

Tests the WebAuthnFactor with real database storage for credentials and challenges.
Note: Full WebAuthn flows require browser interaction, so we primarily test
storage operations and challenge management.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from neozen.core.factors.webauthn import (
    WebAuthnConfig,
    WebAuthnCredentialNotFoundError,
    WebAuthnFactor,
)
from neozen.core.repository import DoesNotExist
from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.models import (
    Subject,
)
from neozen.storage.sqlalchemy.repositories import (
    SubjectRepository,
    WebAuthnChallengeRepository,
    WebAuthnCredentialRepository,
)

# Skip if webauthn is not installed
pytest.importorskip("webauthn")


@pytest.fixture
async def async_engine():
    """Create async SQLite engine for tests."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest.fixture
async def session(async_engine):
    """Create async session for tests."""
    session_maker = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with session_maker() as session:
        yield session


@pytest.fixture
def subject_repo(session: AsyncSession) -> SubjectRepository:
    """Create subject repository."""
    return SubjectRepository(session=session)


@pytest.fixture
def credential_repo(session: AsyncSession) -> WebAuthnCredentialRepository:
    """Create credential repository."""
    return WebAuthnCredentialRepository(session=session)


@pytest.fixture
def challenge_repo(session: AsyncSession) -> WebAuthnChallengeRepository:
    """Create challenge repository."""
    return WebAuthnChallengeRepository(session=session)


@pytest.fixture
def webauthn_config() -> WebAuthnConfig:
    """Create WebAuthn configuration."""
    return WebAuthnConfig(
        rp_id="localhost",
        rp_name="Test App",
        origin="http://localhost:8000",
        challenge_timeout_seconds=300,
    )


@pytest.fixture
def webauthn_factor(
    webauthn_config: WebAuthnConfig,
    credential_repo: WebAuthnCredentialRepository,
    challenge_repo: WebAuthnChallengeRepository,
) -> WebAuthnFactor:
    """Create WebAuthn factor."""
    return WebAuthnFactor(
        config=webauthn_config,
        credential_repository=credential_repo,
        challenge_repository=challenge_repo,
        id_generator=lambda: secrets.token_hex(16),
    )


@pytest.fixture
async def subject(subject_repo: SubjectRepository) -> Subject:
    """Create a test subject."""
    return await subject_repo.create(
        id=secrets.token_hex(16),
        email="test@example.com",
        hashed_password=None,
        is_active=True,
        is_verified=False,
    )


@pytest.mark.anyio
class TestWebAuthnRegistrationChallenge:
    """Tests for WebAuthn registration challenge generation."""

    async def test_begin_registration_returns_options(
        self, webauthn_factor: WebAuthnFactor, subject: Subject
    ) -> None:
        """Test that begin_registration returns options."""
        options = await webauthn_factor.begin_registration(subject)

        assert options is not None
        assert options.challenge is not None
        assert "rp" in options.options_json
        assert options.options_json["rp"]["id"] == "localhost"
        assert options.options_json["rp"]["name"] == "Test App"

    async def test_begin_registration_stores_challenge(
        self,
        webauthn_factor: WebAuthnFactor,
        challenge_repo: WebAuthnChallengeRepository,
        subject: Subject,
    ) -> None:
        """Test that registration challenge is stored in database."""
        await webauthn_factor.begin_registration(subject)

        challenges = await challenge_repo.get_many_by(subject_id=subject.id)
        assert len(challenges) == 1
        assert challenges[0].operation == "registration"

    async def test_begin_registration_excludes_existing_credentials(
        self,
        webauthn_factor: WebAuthnFactor,
        credential_repo: WebAuthnCredentialRepository,
        subject: Subject,
    ) -> None:
        """Test that existing credentials are excluded from registration."""
        # Create existing credential
        await credential_repo.create(
            id=secrets.token_hex(16),
            subject_id=subject.id,
            credential_id="ZXhpc3RpbmctY3JlZC1pZA",  # base64url encoded
            public_key="public-key-data",
            sign_count=0,
            transports="internal",
            device_type="platform",
            backed_up=False,
            name="Existing Key",
        )

        options = await webauthn_factor.begin_registration(subject)

        assert "excludeCredentials" in options.options_json
        assert len(options.options_json["excludeCredentials"]) == 1


@pytest.mark.anyio
class TestWebAuthnAuthenticationChallenge:
    """Tests for WebAuthn authentication challenge generation."""

    async def test_begin_authentication_returns_options(
        self,
        webauthn_factor: WebAuthnFactor,
        credential_repo: WebAuthnCredentialRepository,
        subject: Subject,
    ) -> None:
        """Test that begin_authentication returns options."""
        # Create a credential first
        await credential_repo.create(
            id=secrets.token_hex(16),
            subject_id=subject.id,
            credential_id="Y3JlZC1pZC0xMjM",  # base64url encoded
            public_key="public-key-data",
            sign_count=0,
            transports="internal",
            device_type="platform",
            backed_up=False,
            name="Test Key",
        )

        options = await webauthn_factor.begin_authentication(subject)

        assert options is not None
        assert options.challenge is not None
        assert "allowCredentials" in options.options_json

    async def test_begin_authentication_stores_challenge(
        self,
        webauthn_factor: WebAuthnFactor,
        challenge_repo: WebAuthnChallengeRepository,
        credential_repo: WebAuthnCredentialRepository,
        subject: Subject,
    ) -> None:
        """Test that authentication challenge is stored in database."""
        # Create a credential
        await credential_repo.create(
            id=secrets.token_hex(16),
            subject_id=subject.id,
            credential_id="Y3JlZC1pZC0xMjM",
            public_key="public-key-data",
            sign_count=0,
            transports="internal",
            device_type="platform",
            backed_up=False,
            name="Test Key",
        )

        await webauthn_factor.begin_authentication(subject)

        challenges = await challenge_repo.get_many_by(subject_id=subject.id)
        assert len(challenges) == 1
        assert challenges[0].operation == "authentication"

    async def test_begin_authentication_includes_allowed_credentials(
        self,
        webauthn_factor: WebAuthnFactor,
        credential_repo: WebAuthnCredentialRepository,
        subject: Subject,
    ) -> None:
        """Test that allowed credentials are included in options."""
        # Create multiple credentials
        for i in range(3):
            await credential_repo.create(
                id=secrets.token_hex(16),
                subject_id=subject.id,
                credential_id=f"Y3JlZC1pZC17aX0{i}",  # base64url-like
                public_key="public-key-data",
                sign_count=0,
                transports="internal,usb",
                device_type="platform",
                backed_up=False,
                name=f"Key {i}",
            )

        options = await webauthn_factor.begin_authentication(subject)

        assert len(options.options_json["allowCredentials"]) == 3


@pytest.mark.anyio
class TestWebAuthnCredentialManagement:
    """Tests for credential CRUD operations."""

    async def test_list_credentials(
        self,
        webauthn_factor: WebAuthnFactor,
        credential_repo: WebAuthnCredentialRepository,
        subject: Subject,
    ) -> None:
        """Test listing credentials for a subject."""
        # Create credentials
        for i in range(2):
            await credential_repo.create(
                id=secrets.token_hex(16),
                subject_id=subject.id,
                credential_id=f"Y3JlZC17aX0{i}",
                public_key="public-key",
                sign_count=0,
                transports="internal",
                device_type="platform",
                backed_up=False,
                name=f"Key {i}",
            )

        credentials = await webauthn_factor.list_credentials(subject)
        assert len(credentials) == 2

    async def test_delete_credential(
        self,
        webauthn_factor: WebAuthnFactor,
        credential_repo: WebAuthnCredentialRepository,
        subject: Subject,
    ) -> None:
        """Test deleting a credential."""
        await credential_repo.create(
            id=secrets.token_hex(16),
            subject_id=subject.id,
            credential_id="dG8tZGVsZXRl",
            public_key="public-key",
            sign_count=0,
            transports="internal",
            device_type="platform",
            backed_up=False,
            name="To Delete",
        )

        await webauthn_factor.delete_credential(subject, "dG8tZGVsZXRl")

        credentials = await credential_repo.get_many_by(subject_id=subject.id)
        assert len(credentials) == 0

    async def test_delete_nonexistent_credential_raises(
        self, webauthn_factor: WebAuthnFactor, subject: Subject
    ) -> None:
        """Test deleting nonexistent credential raises error."""
        with pytest.raises(WebAuthnCredentialNotFoundError):
            await webauthn_factor.delete_credential(subject, "nonexistent")

    async def test_delete_credential_wrong_subject_raises(
        self,
        webauthn_factor: WebAuthnFactor,
        credential_repo: WebAuthnCredentialRepository,
        subject_repo: SubjectRepository,
        subject: Subject,
    ) -> None:
        """Test deleting another subject's credential raises error."""
        # Create another subject
        other_subject = await subject_repo.create(
            id=secrets.token_hex(16),
            email="other@example.com",
            hashed_password=None,
            is_active=True,
            is_verified=False,
        )

        # Create credential for first subject
        await credential_repo.create(
            id=secrets.token_hex(16),
            subject_id=subject.id,
            credential_id="b3duZWQtY3JlZA",
            public_key="public-key",
            sign_count=0,
            transports="internal",
            device_type="platform",
            backed_up=False,
            name="Owned",
        )

        # Try to delete with different subject
        with pytest.raises(WebAuthnCredentialNotFoundError):
            await webauthn_factor.delete_credential(other_subject, "b3duZWQtY3JlZA")


@pytest.mark.anyio
class TestWebAuthnRenameCredential:
    """Tests for renaming credentials."""

    async def test_rename_credential(
        self,
        webauthn_factor: WebAuthnFactor,
        credential_repo: WebAuthnCredentialRepository,
        subject: Subject,
    ) -> None:
        """Test renaming a credential."""
        await credential_repo.create(
            id=secrets.token_hex(16),
            subject_id=subject.id,
            credential_id="cmVuYW1lLWNyZWQ",
            public_key="public-key",
            sign_count=0,
            transports="internal",
            device_type="platform",
            backed_up=False,
            name="Old Name",
        )

        await webauthn_factor.rename_credential(subject, "cmVuYW1lLWNyZWQ", "New Name")

        cred = await credential_repo.get_one_by(credential_id="cmVuYW1lLWNyZWQ")
        assert cred.name == "New Name"

    async def test_rename_nonexistent_credential_raises(
        self, webauthn_factor: WebAuthnFactor, subject: Subject
    ) -> None:
        """Test renaming nonexistent credential raises error."""
        with pytest.raises(WebAuthnCredentialNotFoundError):
            await webauthn_factor.rename_credential(subject, "nonexistent", "New Name")


@pytest.mark.anyio
class TestWebAuthnIsolation:
    """Tests for credential isolation between subjects."""

    async def test_credentials_isolated_by_subject(
        self,
        webauthn_factor: WebAuthnFactor,
        credential_repo: WebAuthnCredentialRepository,
        subject_repo: SubjectRepository,
        subject: Subject,
    ) -> None:
        """Test that credentials are isolated per subject."""
        # Create another subject
        other_subject = await subject_repo.create(
            id=secrets.token_hex(16),
            email="other@example.com",
            hashed_password=None,
            is_active=True,
            is_verified=False,
        )

        # Create credentials for both
        await credential_repo.create(
            id=secrets.token_hex(16),
            subject_id=subject.id,
            credential_id="Y3JlZC0x",
            public_key="key-1",
            sign_count=0,
            transports="internal",
            device_type="platform",
            backed_up=False,
            name="Key 1",
        )

        await credential_repo.create(
            id=secrets.token_hex(16),
            subject_id=other_subject.id,
            credential_id="Y3JlZC0y",
            public_key="key-2",
            sign_count=0,
            transports="internal",
            device_type="platform",
            backed_up=False,
            name="Key 2",
        )

        # Each subject should only see their own
        creds1 = await webauthn_factor.list_credentials(subject)
        creds2 = await webauthn_factor.list_credentials(other_subject)

        assert len(creds1) == 1
        assert creds1[0].credential_id == "Y3JlZC0x"

        assert len(creds2) == 1
        assert creds2[0].credential_id == "Y3JlZC0y"


@pytest.mark.anyio
class TestWebAuthnChallengeRepository:
    """Tests for challenge repository operations."""

    async def test_challenge_stored_with_expiration(
        self,
        challenge_repo: WebAuthnChallengeRepository,
        subject: Subject,
    ) -> None:
        """Test that challenge is stored with expiration time."""
        expires_at = datetime.now(UTC) + timedelta(minutes=5)

        challenge = await challenge_repo.create(
            id=secrets.token_hex(16),
            challenge="test-challenge-value",
            subject_id=subject.id,
            operation="registration",
            expires_at=expires_at,
        )

        assert challenge.expires_at is not None
        stored = await challenge_repo.get_one_by(challenge="test-challenge-value")
        assert stored.operation == "registration"

    async def test_challenge_deleted(
        self,
        challenge_repo: WebAuthnChallengeRepository,
        subject: Subject,
    ) -> None:
        """Test that challenge can be deleted."""
        challenge = await challenge_repo.create(
            id=secrets.token_hex(16),
            challenge="to-delete",
            subject_id=subject.id,
            operation="authentication",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )

        await challenge_repo.delete(challenge)

        with pytest.raises(DoesNotExist):
            await challenge_repo.get_one_by(challenge="to-delete")
