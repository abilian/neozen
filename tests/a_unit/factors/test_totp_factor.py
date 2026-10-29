"""Tests for TOTP authentication factor."""

from __future__ import annotations

import dataclasses
import sys
from datetime import UTC, datetime

import pyotp
import pytest

from neozen.core.factors.totp import (
    BackupCodeModel,
    InvalidBackupCodeError,
    InvalidTOTPCodeError,
    TOTPAlreadyEnabledError,
    TOTPConfig,
    TOTPError,
    TOTPFactor,
    TOTPNotEnabledError,
    TOTPSubjectModel,
)
from tests.conftest import MockStorage


@dataclasses.dataclass
class MockTOTPSubject(TOTPSubjectModel):
    id: str
    email: str
    totp_secret: str | None = None
    totp_enabled: bool = False
    totp_confirmed_at: datetime | None = None


@dataclasses.dataclass
class MockBackupCode(BackupCodeModel):
    id: str
    subject_id: str
    code_hash: str
    used_at: datetime | None
    created_at: datetime


class MockHasher:
    """Simple mock hasher that uses plaintext for testing."""

    def verify_and_update(
        self, password: str | bytes, hash: str | bytes
    ) -> tuple[bool, str | None]:
        password_str = password if isinstance(password, str) else password.decode()
        hash_str = hash if isinstance(hash, str) else hash.decode()
        return password_str == hash_str, None

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        return password if isinstance(password, str) else password.decode()


@pytest.fixture
def subject_storage() -> MockStorage[MockTOTPSubject]:
    return MockStorage(MockTOTPSubject, [])


@pytest.fixture
def backup_code_storage() -> MockStorage[MockBackupCode]:
    return MockStorage(MockBackupCode, [])


@pytest.fixture
def hasher() -> MockHasher:
    return MockHasher()


@pytest.fixture
def totp_config() -> TOTPConfig:
    return TOTPConfig(issuer="TestApp", backup_code_count=5, backup_code_length=8)


@pytest.fixture
def totp_factor(
    subject_storage: MockStorage[MockTOTPSubject],
    backup_code_storage: MockStorage[MockBackupCode],
    hasher: MockHasher,
    totp_config: TOTPConfig,
) -> TOTPFactor[MockTOTPSubject]:
    return TOTPFactor(
        config=totp_config,
        subject_repository=subject_storage,
        backup_code_repository=backup_code_storage,
        hasher=hasher,
    )


@pytest.mark.anyio
class TestBeginEnrollment:
    """Tests for TOTP enrollment initiation."""

    async def test_begin_enrollment_success(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret=None,
            totp_enabled=False,
            totp_confirmed_at=None,
        )

        result = await totp_factor.begin_enrollment(subject)

        assert result.secret is not None
        assert len(result.secret) > 0
        assert result.provisioning_uri.startswith("otpauth://totp/")
        assert "TestApp" in result.provisioning_uri
        # Subject should have secret but not be enabled yet
        assert subject.totp_secret is not None
        assert subject.totp_enabled is False

    async def test_begin_enrollment_already_enabled(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret="JBSWY3DPEHPK3PXP",
            totp_enabled=True,
            totp_confirmed_at=datetime.now(UTC),
        )

        with pytest.raises(TOTPAlreadyEnabledError):
            await totp_factor.begin_enrollment(subject)


@pytest.mark.anyio
class TestConfirmEnrollment:
    """Tests for TOTP enrollment confirmation."""

    async def test_confirm_enrollment_success(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret=None,
            totp_enabled=False,
            totp_confirmed_at=None,
        )

        # Begin enrollment
        result = await totp_factor.begin_enrollment(subject)

        # Generate valid code
        totp = pyotp.TOTP(result.secret)
        valid_code = totp.now()

        # Confirm enrollment
        updated_subject, backup_codes = await totp_factor.confirm_enrollment(
            subject, valid_code
        )

        assert updated_subject.totp_enabled is True
        assert updated_subject.totp_confirmed_at is not None
        assert len(backup_codes) == 5  # config.backup_code_count

    async def test_confirm_enrollment_invalid_code(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret=None,
            totp_enabled=False,
            totp_confirmed_at=None,
        )

        # Begin enrollment
        await totp_factor.begin_enrollment(subject)

        # Try with invalid code
        with pytest.raises(InvalidTOTPCodeError):
            await totp_factor.confirm_enrollment(subject, "000000")

    async def test_confirm_enrollment_already_enabled(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret="JBSWY3DPEHPK3PXP",
            totp_enabled=True,
            totp_confirmed_at=datetime.now(UTC),
        )

        totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")
        valid_code = totp.now()

        with pytest.raises(TOTPAlreadyEnabledError):
            await totp_factor.confirm_enrollment(subject, valid_code)


@pytest.mark.anyio
class TestAuthenticate:
    """Tests for TOTP authentication."""

    async def test_authenticate_success(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        secret = pyotp.random_base32()
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret=secret,
            totp_enabled=True,
            totp_confirmed_at=datetime.now(UTC),
        )

        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        result = await totp_factor.authenticate(subject, valid_code)
        assert result is True

    async def test_authenticate_invalid_code(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        secret = pyotp.random_base32()
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret=secret,
            totp_enabled=True,
            totp_confirmed_at=datetime.now(UTC),
        )

        with pytest.raises(InvalidTOTPCodeError):
            await totp_factor.authenticate(subject, "000000")

    async def test_authenticate_not_enabled(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret=None,
            totp_enabled=False,
            totp_confirmed_at=None,
        )

        with pytest.raises(TOTPNotEnabledError):
            await totp_factor.authenticate(subject, "123456")


@pytest.mark.anyio
class TestBackupCodes:
    """Tests for backup code functionality."""

    async def test_use_backup_code_success(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        backup_code_storage: MockStorage[MockBackupCode],
        hasher: MockHasher,
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        secret = pyotp.random_base32()
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret=secret,
            totp_enabled=True,
            totp_confirmed_at=datetime.now(UTC),
        )

        # Create a backup code
        code = "ABCD1234"
        await backup_code_storage.create(
            id="code1",
            subject_id="user1",
            code_hash=hasher.hash(code),
            used_at=None,
            created_at=datetime.now(UTC),
        )

        result = await totp_factor.use_backup_code(subject, code)
        assert result is True

        # Code should be marked as used
        codes = await backup_code_storage.get_many_by(subject_id="user1")
        assert codes[0].used_at is not None

    async def test_use_backup_code_with_dashes(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        backup_code_storage: MockStorage[MockBackupCode],
        hasher: MockHasher,
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        secret = pyotp.random_base32()
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret=secret,
            totp_enabled=True,
            totp_confirmed_at=datetime.now(UTC),
        )

        # Create a backup code (stored without dashes)
        code = "ABCD1234"
        await backup_code_storage.create(
            id="code1",
            subject_id="user1",
            code_hash=hasher.hash(code),
            used_at=None,
            created_at=datetime.now(UTC),
        )

        # Use code with dashes (should still work)
        result = await totp_factor.use_backup_code(subject, "ABCD-1234")
        assert result is True

    async def test_use_backup_code_already_used(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        backup_code_storage: MockStorage[MockBackupCode],
        hasher: MockHasher,
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        secret = pyotp.random_base32()
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret=secret,
            totp_enabled=True,
            totp_confirmed_at=datetime.now(UTC),
        )

        # Create an already used backup code
        await backup_code_storage.create(
            id="code1",
            subject_id="user1",
            code_hash=hasher.hash("ABCD1234"),
            used_at=datetime.now(UTC),
            created_at=datetime.now(UTC),
        )

        with pytest.raises(InvalidBackupCodeError):
            await totp_factor.use_backup_code(subject, "ABCD1234")

    async def test_use_backup_code_invalid(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        backup_code_storage: MockStorage[MockBackupCode],
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        secret = pyotp.random_base32()
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret=secret,
            totp_enabled=True,
            totp_confirmed_at=datetime.now(UTC),
        )

        with pytest.raises(InvalidBackupCodeError):
            await totp_factor.use_backup_code(subject, "INVALID")

    async def test_regenerate_backup_codes(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        backup_code_storage: MockStorage[MockBackupCode],
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        secret = pyotp.random_base32()
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret=secret,
            totp_enabled=True,
            totp_confirmed_at=datetime.now(UTC),
        )

        # Generate codes
        codes = await totp_factor.regenerate_backup_codes(subject)
        assert len(codes) == 5

        # Check they're stored
        stored = await backup_code_storage.get_many_by(subject_id="user1")
        assert len(stored) == 5


@pytest.mark.anyio
class TestDisable:
    """Tests for disabling TOTP."""

    async def test_disable_totp(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        backup_code_storage: MockStorage[MockBackupCode],
        hasher: MockHasher,
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        secret = pyotp.random_base32()
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret=secret,
            totp_enabled=True,
            totp_confirmed_at=datetime.now(UTC),
        )

        # Create a backup code
        await backup_code_storage.create(
            id="code1",
            subject_id="user1",
            code_hash=hasher.hash("ABCD1234"),
            used_at=None,
            created_at=datetime.now(UTC),
        )

        updated = await totp_factor.disable(subject)

        assert updated.totp_enabled is False
        assert updated.totp_secret is None
        assert updated.totp_confirmed_at is None

        # Backup codes should be deleted
        codes = await backup_code_storage.get_many_by(subject_id="user1")
        assert len(codes) == 0


@pytest.mark.anyio
class TestRemainingBackupCodes:
    """Tests for getting remaining backup codes count."""

    async def test_get_remaining_count(
        self,
        subject_storage: MockStorage[MockTOTPSubject],
        backup_code_storage: MockStorage[MockBackupCode],
        hasher: MockHasher,
        totp_factor: TOTPFactor[MockTOTPSubject],
    ) -> None:
        subject = await subject_storage.create(
            id="user1",
            email="user@example.com",
            totp_secret=pyotp.random_base32(),
            totp_enabled=True,
            totp_confirmed_at=datetime.now(UTC),
        )

        # Create some backup codes, some used
        await backup_code_storage.create(
            id="code1",
            subject_id="user1",
            code_hash=hasher.hash("CODE1"),
            used_at=None,
            created_at=datetime.now(UTC),
        )
        await backup_code_storage.create(
            id="code2",
            subject_id="user1",
            code_hash=hasher.hash("CODE2"),
            used_at=datetime.now(UTC),  # Used
            created_at=datetime.now(UTC),
        )
        await backup_code_storage.create(
            id="code3",
            subject_id="user1",
            code_hash=hasher.hash("CODE3"),
            used_at=None,
            created_at=datetime.now(UTC),
        )

        count = await totp_factor.get_remaining_backup_codes_count(subject)
        assert count == 2  # Only unused codes


def test_factor_needs_pyotp(
    monkeypatch: pytest.MonkeyPatch, subject_storage: MockStorage[MockTOTPSubject]
) -> None:
    monkeypatch.setitem(sys.modules, "pyotp", None)  # import fails

    with pytest.raises(TOTPError, match="pyotp is required"):
        TOTPFactor(config=TOTPConfig(), subject_repository=subject_storage)
