"""Tests for the account recovery service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from neozen.core.recovery import (
    AccountRecoveryConfig,
    AccountRecoveryService,
    RecoveryMethod,
    RecoveryOption,
)


@dataclass
class FakeSubject:
    """Fake subject for testing."""

    id: str
    email: str
    totp_enabled: bool = False


@dataclass
class FakeRecoveryKey:
    """Fake recovery key for testing."""

    id: str
    subject_id: str
    key_hash: str
    created_at: datetime
    used_at: datetime | None = None


@dataclass
class FakeRecoverySession:
    """Fake recovery session for testing."""

    id: str
    subject_id: str
    method: str
    created_at: datetime
    expires_at: datetime
    verified_at: datetime | None = None
    completed_at: datetime | None = None
    ip_address: str | None = None


class FakeSubjectLookup:
    """Fake subject lookup for testing."""

    def __init__(self) -> None:
        self.subjects: dict[str, FakeSubject] = {}

    def add(self, subject: FakeSubject) -> None:
        self.subjects[subject.email] = subject

    async def get_by_email(self, email: str) -> FakeSubject | None:
        return self.subjects.get(email)

    async def get_by_id(self, subject_id: str) -> FakeSubject | None:
        for subject in self.subjects.values():
            if subject.id == subject_id:
                return subject
        return None


class FakeRecoveryKeyRepository:
    """Fake recovery key repository for testing."""

    def __init__(self) -> None:
        self.keys: dict[str, FakeRecoveryKey] = {}
        self._counter = 0

    async def create(self, **kwargs: Any) -> FakeRecoveryKey:
        self._counter += 1
        key = FakeRecoveryKey(id=f"key-{self._counter}", **kwargs)
        self.keys[key.id] = key
        return key

    async def get_by_hash(self, key_hash: str) -> FakeRecoveryKey | None:
        for key in self.keys.values():
            if key.key_hash == key_hash:
                return key
        return None

    async def mark_used(self, key_id: str, used_at: datetime) -> None:
        if key_id in self.keys:
            key = self.keys[key_id]
            self.keys[key_id] = FakeRecoveryKey(
                id=key.id,
                subject_id=key.subject_id,
                key_hash=key.key_hash,
                created_at=key.created_at,
                used_at=used_at,
            )

    async def get_for_subject(self, subject_id: str) -> FakeRecoveryKey | None:
        for key in self.keys.values():
            if key.subject_id == subject_id and key.used_at is None:
                return key
        return None

    async def delete_for_subject(self, subject_id: str) -> int:
        to_delete = [k for k, v in self.keys.items() if v.subject_id == subject_id]
        for k in to_delete:
            del self.keys[k]
        return len(to_delete)


class FakeRecoverySessionRepository:
    """Fake recovery session repository for testing."""

    def __init__(self) -> None:
        self.sessions: dict[str, FakeRecoverySession] = {}
        self._counter = 0

    async def create(self, **kwargs: Any) -> FakeRecoverySession:
        self._counter += 1
        session_id = f"session-{self._counter}"
        session = FakeRecoverySession(id=session_id, **kwargs)
        self.sessions[session_id] = session
        return session

    async def get_by_id(self, session_id: str) -> FakeRecoverySession | None:
        return self.sessions.get(session_id)

    async def update(self, session_id: str, **kwargs: Any) -> None:
        if session_id in self.sessions:
            session = self.sessions[session_id]
            for key, value in kwargs.items():
                setattr(session, key, value)


class FakePasswordChanger:
    """Fake password changer for testing."""

    def __init__(self) -> None:
        self.passwords: dict[str, str] = {}

    async def change_password(self, subject_id: str, new_password: str) -> bool:
        self.passwords[subject_id] = new_password
        return True


class FakeBackupCodeChecker:
    """Fake backup code checker for testing."""

    def __init__(self) -> None:
        self.codes: dict[str, set[str]] = {}

    def add_code(self, subject_id: str, code: str) -> None:
        if subject_id not in self.codes:
            self.codes[subject_id] = set()
        self.codes[subject_id].add(code)

    async def verify_backup_code(self, subject_id: str, code: str) -> bool:
        if subject_id not in self.codes:
            return False
        if code in self.codes[subject_id]:
            self.codes[subject_id].remove(code)
            return True
        return False


@pytest.fixture
def subject_lookup() -> FakeSubjectLookup:
    """Create a subject lookup."""
    lookup = FakeSubjectLookup()
    lookup.add(FakeSubject(id="user-1", email="user@example.com"))
    lookup.add(FakeSubject(id="user-2", email="totp@example.com", totp_enabled=True))
    return lookup


@pytest.fixture
def key_repository() -> FakeRecoveryKeyRepository:
    """Create a recovery key repository."""
    return FakeRecoveryKeyRepository()


@pytest.fixture
def session_repository() -> FakeRecoverySessionRepository:
    """Create a recovery session repository."""
    return FakeRecoverySessionRepository()


@pytest.fixture
def password_changer() -> FakePasswordChanger:
    """Create a password changer."""
    return FakePasswordChanger()


@pytest.fixture
def backup_code_checker() -> FakeBackupCodeChecker:
    """Create a backup code checker."""
    checker = FakeBackupCodeChecker()
    checker.add_code("user-2", "12345678")
    return checker


@pytest.fixture
def recovery_service(
    subject_lookup: FakeSubjectLookup,
    key_repository: FakeRecoveryKeyRepository,
    session_repository: FakeRecoverySessionRepository,
    password_changer: FakePasswordChanger,
    backup_code_checker: FakeBackupCodeChecker,
) -> AccountRecoveryService:
    """Create an account recovery service."""
    return AccountRecoveryService(
        config=AccountRecoveryConfig(),
        subject_lookup=subject_lookup,
        session_repository=session_repository,
        recovery_key_repository=key_repository,
        password_changer=password_changer,
        token_hash_key="test-secret",
        backup_code_checker=backup_code_checker,
    )


class TestAccountRecoveryConfig:
    """Tests for AccountRecoveryConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = AccountRecoveryConfig()
        assert config.session_lifetime == timedelta(hours=1)
        assert config.email_code_length == 6
        assert config.recovery_key_prefix == "nz_rk_"
        assert config.require_verification is True

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = AccountRecoveryConfig(
            session_lifetime=timedelta(minutes=30),
            email_code_length=8,
            require_verification=False,
        )
        assert config.session_lifetime == timedelta(minutes=30)
        assert config.email_code_length == 8
        assert config.require_verification is False


class TestRecoveryOption:
    """Tests for RecoveryOption."""

    def test_recovery_option(self) -> None:
        """Test creating a recovery option."""
        option = RecoveryOption(
            method=RecoveryMethod.EMAIL,
            identifier="u***r@example.com",
            available=True,
            hint="Check your email",
        )
        assert option.method == RecoveryMethod.EMAIL
        assert option.identifier == "u***r@example.com"
        assert option.available is True
        assert option.hint == "Check your email"


class TestGetRecoveryOptions:
    """Tests for get_recovery_options."""

    @pytest.mark.anyio
    async def test_get_options_for_existing_user(
        self,
        recovery_service: AccountRecoveryService,
    ) -> None:
        """Test getting recovery options for existing user."""
        options = await recovery_service.get_recovery_options("user@example.com")

        assert len(options) >= 1
        assert any(o.method == RecoveryMethod.EMAIL for o in options)

    @pytest.mark.anyio
    async def test_get_options_for_nonexistent_user(
        self,
        recovery_service: AccountRecoveryService,
    ) -> None:
        """Test getting recovery options for nonexistent user."""
        # Should return fake options to prevent enumeration
        options = await recovery_service.get_recovery_options("nonexistent@example.com")

        assert len(options) >= 1
        # Should return masked email to prevent enumeration
        assert options[0].method == RecoveryMethod.EMAIL
        assert "*" in options[0].identifier

    @pytest.mark.anyio
    async def test_backup_codes_shown_for_totp_user(
        self,
        recovery_service: AccountRecoveryService,
    ) -> None:
        """Test that backup codes option is shown for TOTP users."""
        options = await recovery_service.get_recovery_options("totp@example.com")

        assert any(o.method == RecoveryMethod.BACKUP_CODES for o in options)

    @pytest.mark.anyio
    async def test_recovery_key_shown_when_exists(
        self,
        recovery_service: AccountRecoveryService,
        key_repository: FakeRecoveryKeyRepository,
    ) -> None:
        """Test that recovery key option is shown when key exists."""
        # Create a recovery key for the user
        await key_repository.create(
            subject_id="user-1",
            key_hash="test-hash",
            created_at=datetime.now(UTC),
            used_at=None,
        )

        options = await recovery_service.get_recovery_options("user@example.com")

        assert any(o.method == RecoveryMethod.RECOVERY_KEY for o in options)


class TestInitiateRecovery:
    """Tests for initiate_recovery."""

    @pytest.mark.anyio
    async def test_initiate_email_recovery(
        self,
        recovery_service: AccountRecoveryService,
    ) -> None:
        """Test initiating email recovery."""
        result = await recovery_service.initiate_recovery(
            identifier="user@example.com",
            method=RecoveryMethod.EMAIL,
        )

        assert result.session_id is not None
        assert result.method == RecoveryMethod.EMAIL
        assert result.expires_at > datetime.now(UTC)
        assert result.verification_required is True

    @pytest.mark.anyio
    async def test_initiate_backup_code_recovery(
        self,
        recovery_service: AccountRecoveryService,
    ) -> None:
        """Test initiating backup code recovery."""
        result = await recovery_service.initiate_recovery(
            identifier="totp@example.com",
            method=RecoveryMethod.BACKUP_CODES,
        )

        assert result.session_id is not None
        assert result.method == RecoveryMethod.BACKUP_CODES
        assert "backup" in result.hint.lower()

    @pytest.mark.anyio
    async def test_initiate_recovery_for_nonexistent_user(
        self,
        recovery_service: AccountRecoveryService,
    ) -> None:
        """Test initiating recovery for nonexistent user (enumeration prevention)."""
        result = await recovery_service.initiate_recovery(
            identifier="nonexistent@example.com",
            method=RecoveryMethod.EMAIL,
        )

        # Should return a fake session to prevent enumeration
        assert result.session_id is not None
        assert result.expires_at > datetime.now(UTC)


class TestVerifyRecovery:
    """Tests for verify_recovery."""

    @pytest.mark.anyio
    async def test_verify_with_backup_code(
        self,
        recovery_service: AccountRecoveryService,
    ) -> None:
        """Test verifying with backup code."""
        # Initiate recovery
        initiation = await recovery_service.initiate_recovery(
            identifier="totp@example.com",
            method=RecoveryMethod.BACKUP_CODES,
        )

        # Verify with backup code
        verification = await recovery_service.verify_recovery(
            session_id=initiation.session_id,
            code="12345678",
        )

        assert verification.verified is True
        assert verification.session_id == initiation.session_id
        assert verification.error is None

    @pytest.mark.anyio
    async def test_verify_with_invalid_code(
        self,
        recovery_service: AccountRecoveryService,
    ) -> None:
        """Test verifying with invalid code."""
        initiation = await recovery_service.initiate_recovery(
            identifier="totp@example.com",
            method=RecoveryMethod.BACKUP_CODES,
        )

        verification = await recovery_service.verify_recovery(
            session_id=initiation.session_id,
            code="invalid",
        )

        assert verification.verified is False
        assert verification.error is not None

    @pytest.mark.anyio
    async def test_verify_invalid_session(
        self,
        recovery_service: AccountRecoveryService,
    ) -> None:
        """Test verifying with invalid session."""
        verification = await recovery_service.verify_recovery(
            session_id="invalid-session",
            code="123456",
        )

        assert verification.verified is False
        assert (
            "invalid" in verification.error.lower()
            or "expired" in verification.error.lower()
        )

    @pytest.mark.anyio
    async def test_verify_expired_session(
        self,
        recovery_service: AccountRecoveryService,
        session_repository: FakeRecoverySessionRepository,
    ) -> None:
        """Test verifying expired session."""
        # Create an expired session
        expired_session = await session_repository.create(
            subject_id="user-2",
            method=RecoveryMethod.BACKUP_CODES.value,
            created_at=datetime.now(UTC) - timedelta(hours=2),
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )

        verification = await recovery_service.verify_recovery(
            session_id=expired_session.id,
            code="12345678",
        )

        assert verification.verified is False
        assert "expired" in verification.error.lower()


class TestCompleteRecovery:
    """Tests for complete_recovery."""

    @pytest.mark.anyio
    async def test_complete_recovery_success(
        self,
        recovery_service: AccountRecoveryService,
        session_repository: FakeRecoverySessionRepository,
        password_changer: FakePasswordChanger,
    ) -> None:
        """Test completing recovery successfully."""
        # Create a verified session
        now = datetime.now(UTC)
        session = await session_repository.create(
            subject_id="user-1",
            method=RecoveryMethod.EMAIL.value,
            created_at=now,
            expires_at=now + timedelta(hours=1),
            verified_at=now,
        )

        result = await recovery_service.complete_recovery(
            session_id=session.id,
            new_password="new-secure-password",
        )

        assert result is True
        assert password_changer.passwords.get("user-1") == "new-secure-password"

    @pytest.mark.anyio
    async def test_complete_recovery_unverified(
        self,
        recovery_service: AccountRecoveryService,
        session_repository: FakeRecoverySessionRepository,
    ) -> None:
        """Test completing recovery without verification."""
        # Create an unverified session
        now = datetime.now(UTC)
        session = await session_repository.create(
            subject_id="user-1",
            method=RecoveryMethod.EMAIL.value,
            created_at=now,
            expires_at=now + timedelta(hours=1),
            verified_at=None,  # Not verified
        )

        result = await recovery_service.complete_recovery(
            session_id=session.id,
            new_password="new-password",
        )

        assert result is False

    @pytest.mark.anyio
    async def test_complete_recovery_invalid_session(
        self,
        recovery_service: AccountRecoveryService,
    ) -> None:
        """Test completing recovery with invalid session."""
        result = await recovery_service.complete_recovery(
            session_id="invalid-session",
            new_password="new-password",
        )

        assert result is False


class TestGenerateRecoveryKey:
    """Tests for generate_recovery_key."""

    @pytest.mark.anyio
    async def test_generate_recovery_key(
        self,
        recovery_service: AccountRecoveryService,
        key_repository: FakeRecoveryKeyRepository,
    ) -> None:
        """Test generating a recovery key."""
        key = await recovery_service.generate_recovery_key("user-1")

        assert key is not None
        assert key.startswith("nz_rk_")
        assert len(key_repository.keys) == 1

    @pytest.mark.anyio
    async def test_generate_recovery_key_replaces_existing(
        self,
        recovery_service: AccountRecoveryService,
        key_repository: FakeRecoveryKeyRepository,
    ) -> None:
        """Test that generating a new key invalidates the old one."""
        # Generate first key
        key1 = await recovery_service.generate_recovery_key("user-1")

        # Generate second key
        key2 = await recovery_service.generate_recovery_key("user-1")

        assert key1 != key2
        # Old key should be deleted
        assert len(key_repository.keys) == 1


class TestEmailMasking:
    """Tests for email masking."""

    @pytest.mark.anyio
    async def test_email_masking(
        self,
        recovery_service: AccountRecoveryService,
    ) -> None:
        """Test that email addresses are properly masked."""
        options = await recovery_service.get_recovery_options("user@example.com")

        email_option = next(
            (o for o in options if o.method == RecoveryMethod.EMAIL), None
        )
        assert email_option is not None
        # Should be masked like "u***r@example.com"
        assert "@example.com" in email_option.identifier
        assert "***" in email_option.identifier or "*" in email_option.identifier
