"""Integration tests for TOTP factor with SQLAlchemy storage.

Tests the TOTPFactor with real database storage for backup codes.
"""

from __future__ import annotations

import secrets

import pytest
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from neozen.core.factors.totp import (
    InvalidBackupCodeError,
    InvalidTOTPCodeError,
    TOTPAlreadyEnabledError,
    TOTPConfig,
    TOTPFactor,
    TOTPNotEnabledError,
)
from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.models import Subject
from neozen.storage.sqlalchemy.repositories import (
    BackupCodeRepository,
    SubjectRepository,
)

# Skip tests if pyotp is not installed
pytest.importorskip("pyotp")


@pytest.fixture
async def async_engine():
    """Create async SQLite engine for tests."""
    from sqlalchemy.pool import StaticPool

    # Use StaticPool for in-memory SQLite to maintain single connection
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
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
def backup_code_repo(session: AsyncSession) -> BackupCodeRepository:
    """Create backup code repository."""
    return BackupCodeRepository(session=session)


@pytest.fixture
def hasher() -> PasswordHash:
    """Create password hasher for backup codes."""
    return PasswordHash((Argon2Hasher(),))


@pytest.fixture
def totp_config() -> TOTPConfig:
    """Create TOTP configuration."""
    return TOTPConfig(
        issuer="TestApp",
        digits=6,
        interval=30,
        backup_code_count=5,
        backup_code_length=8,
    )


@pytest.fixture
def totp_factor(
    totp_config: TOTPConfig,
    subject_repo: SubjectRepository,
    backup_code_repo: BackupCodeRepository,
    hasher: PasswordHash,
) -> TOTPFactor:
    """Create TOTP factor."""
    return TOTPFactor(
        config=totp_config,
        subject_repository=subject_repo,
        backup_code_repository=backup_code_repo,
        hasher=hasher,
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
        totp_secret=None,
        totp_enabled=False,
        totp_confirmed_at=None,
    )


def get_current_totp_code(secret: str) -> str:
    """Generate current TOTP code for testing."""
    import pyotp

    totp = pyotp.TOTP(secret)
    return totp.now()


@pytest.mark.anyio
class TestTOTPEnrollment:
    """Tests for TOTP enrollment flow."""

    async def test_begin_enrollment_returns_secret(
        self, totp_factor: TOTPFactor, subject: Subject
    ) -> None:
        """Test that beginning enrollment returns a secret."""
        result = await totp_factor.begin_enrollment(subject)

        assert result.secret is not None
        assert len(result.secret) > 0
        assert result.provisioning_uri is not None
        assert "otpauth://" in result.provisioning_uri

    async def test_begin_enrollment_stores_secret(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
    ) -> None:
        """Test that enrollment stores secret in subject."""
        result = await totp_factor.begin_enrollment(subject)

        updated = await subject_repo.get_one_by(id=subject.id)
        assert updated.totp_secret == result.secret
        assert updated.totp_enabled is False

    async def test_begin_enrollment_already_enabled_raises(
        self, totp_factor: TOTPFactor, subject_repo: SubjectRepository, subject: Subject
    ) -> None:
        """Test that enrolling when already enabled raises."""
        # Enable TOTP
        await subject_repo.update_obj(subject, totp_enabled=True, totp_secret="secret")
        updated = await subject_repo.get_one_by(id=subject.id)

        with pytest.raises(TOTPAlreadyEnabledError):
            await totp_factor.begin_enrollment(updated)

    async def test_confirm_enrollment_with_valid_code(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
    ) -> None:
        """Test confirming enrollment with valid TOTP code."""
        result = await totp_factor.begin_enrollment(subject)

        # Get valid code
        code = get_current_totp_code(result.secret)

        # Refresh subject to get updated state
        refreshed = await subject_repo.get_one_by(id=subject.id)
        updated, backup_codes = await totp_factor.confirm_enrollment(refreshed, code)

        assert updated.totp_enabled is True
        assert updated.totp_confirmed_at is not None
        assert len(backup_codes) == 5  # backup_code_count

    async def test_confirm_enrollment_with_invalid_code_raises(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
    ) -> None:
        """Test confirming enrollment with invalid code raises."""
        await totp_factor.begin_enrollment(subject)
        refreshed = await subject_repo.get_one_by(id=subject.id)

        with pytest.raises(InvalidTOTPCodeError):
            await totp_factor.confirm_enrollment(refreshed, "000000")


@pytest.mark.anyio
class TestTOTPAuthentication:
    """Tests for TOTP authentication."""

    async def test_authenticate_with_valid_code(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
    ) -> None:
        """Test authentication with valid TOTP code."""
        # Enroll and confirm
        result = await totp_factor.begin_enrollment(subject)
        code = get_current_totp_code(result.secret)
        refreshed = await subject_repo.get_one_by(id=subject.id)
        await totp_factor.confirm_enrollment(refreshed, code)

        # Authenticate with new code
        enabled_subject = await subject_repo.get_one_by(id=subject.id)
        new_code = get_current_totp_code(result.secret)
        authenticated = await totp_factor.authenticate(enabled_subject, new_code)
        assert authenticated is True

    async def test_authenticate_with_invalid_code_raises(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
    ) -> None:
        """Test authentication with invalid code raises."""
        # Enroll and confirm
        result = await totp_factor.begin_enrollment(subject)
        code = get_current_totp_code(result.secret)
        refreshed = await subject_repo.get_one_by(id=subject.id)
        await totp_factor.confirm_enrollment(refreshed, code)

        enabled_subject = await subject_repo.get_one_by(id=subject.id)
        with pytest.raises(InvalidTOTPCodeError):
            await totp_factor.authenticate(enabled_subject, "999999")

    async def test_authenticate_when_not_enabled_raises(
        self, totp_factor: TOTPFactor, subject: Subject
    ) -> None:
        """Test authentication when TOTP not enabled raises."""
        with pytest.raises(TOTPNotEnabledError):
            await totp_factor.authenticate(subject, "123456")


@pytest.mark.anyio
class TestBackupCodes:
    """Tests for backup code functionality."""

    async def test_backup_codes_stored_in_database(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
        backup_code_repo: BackupCodeRepository,
    ) -> None:
        """Test that backup codes are stored in database."""
        result = await totp_factor.begin_enrollment(subject)
        code = get_current_totp_code(result.secret)
        refreshed = await subject_repo.get_one_by(id=subject.id)
        await totp_factor.confirm_enrollment(refreshed, code)

        stored_codes = await backup_code_repo.get_many_by(subject_id=subject.id)
        assert len(stored_codes) == 5

    async def test_use_backup_code_authenticates(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
    ) -> None:
        """Test that backup code can be used for authentication."""
        # Enroll and confirm
        result = await totp_factor.begin_enrollment(subject)
        code = get_current_totp_code(result.secret)
        refreshed = await subject_repo.get_one_by(id=subject.id)
        _, backup_codes = await totp_factor.confirm_enrollment(refreshed, code)

        # Use backup code
        enabled_subject = await subject_repo.get_one_by(id=subject.id)
        authenticated = await totp_factor.use_backup_code(
            enabled_subject, backup_codes[0]
        )
        assert authenticated is True

    async def test_backup_code_marked_as_used(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
        backup_code_repo: BackupCodeRepository,
    ) -> None:
        """Test that used backup code is marked."""
        # Enroll and confirm
        result = await totp_factor.begin_enrollment(subject)
        code = get_current_totp_code(result.secret)
        refreshed = await subject_repo.get_one_by(id=subject.id)
        _, backup_codes = await totp_factor.confirm_enrollment(refreshed, code)

        # Use backup code
        enabled_subject = await subject_repo.get_one_by(id=subject.id)
        await totp_factor.use_backup_code(enabled_subject, backup_codes[0])

        # Check remaining count
        remaining = await totp_factor.get_remaining_backup_codes_count(enabled_subject)
        assert remaining == 4

    async def test_used_backup_code_rejected(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
    ) -> None:
        """Test that used backup code cannot be reused."""
        # Enroll and confirm
        result = await totp_factor.begin_enrollment(subject)
        code = get_current_totp_code(result.secret)
        refreshed = await subject_repo.get_one_by(id=subject.id)
        _, backup_codes = await totp_factor.confirm_enrollment(refreshed, code)

        # Use backup code twice
        enabled_subject = await subject_repo.get_one_by(id=subject.id)
        await totp_factor.use_backup_code(enabled_subject, backup_codes[0])

        with pytest.raises(InvalidBackupCodeError):
            await totp_factor.use_backup_code(enabled_subject, backup_codes[0])

    async def test_invalid_backup_code_rejected(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
    ) -> None:
        """Test that invalid backup code is rejected."""
        # Enroll and confirm
        result = await totp_factor.begin_enrollment(subject)
        code = get_current_totp_code(result.secret)
        refreshed = await subject_repo.get_one_by(id=subject.id)
        await totp_factor.confirm_enrollment(refreshed, code)

        enabled_subject = await subject_repo.get_one_by(id=subject.id)
        with pytest.raises(InvalidBackupCodeError):
            await totp_factor.use_backup_code(enabled_subject, "INVALID-CODE")


@pytest.mark.anyio
class TestTOTPDisable:
    """Tests for disabling TOTP."""

    async def test_disable_clears_totp_fields(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
    ) -> None:
        """Test that disabling TOTP clears subject fields."""
        # Enroll and confirm
        result = await totp_factor.begin_enrollment(subject)
        code = get_current_totp_code(result.secret)
        refreshed = await subject_repo.get_one_by(id=subject.id)
        await totp_factor.confirm_enrollment(refreshed, code)

        # Disable
        enabled_subject = await subject_repo.get_one_by(id=subject.id)
        disabled = await totp_factor.disable(enabled_subject)

        assert disabled.totp_enabled is False
        assert disabled.totp_secret is None
        assert disabled.totp_confirmed_at is None

    async def test_disable_removes_backup_codes(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
        backup_code_repo: BackupCodeRepository,
    ) -> None:
        """Test that disabling TOTP removes backup codes."""
        # Enroll and confirm
        result = await totp_factor.begin_enrollment(subject)
        code = get_current_totp_code(result.secret)
        refreshed = await subject_repo.get_one_by(id=subject.id)
        await totp_factor.confirm_enrollment(refreshed, code)

        # Verify codes exist
        codes_before = await backup_code_repo.get_many_by(subject_id=subject.id)
        assert len(codes_before) == 5

        # Disable
        enabled_subject = await subject_repo.get_one_by(id=subject.id)
        await totp_factor.disable(enabled_subject)

        # Verify codes removed
        codes_after = await backup_code_repo.get_many_by(subject_id=subject.id)
        assert len(codes_after) == 0


@pytest.mark.anyio
class TestRegenerateBackupCodes:
    """Tests for regenerating backup codes."""

    async def test_regenerate_creates_new_codes(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
    ) -> None:
        """Test that regenerating creates new codes."""
        # Enroll and confirm
        result = await totp_factor.begin_enrollment(subject)
        code = get_current_totp_code(result.secret)
        refreshed = await subject_repo.get_one_by(id=subject.id)
        _, original_codes = await totp_factor.confirm_enrollment(refreshed, code)

        # Regenerate
        enabled_subject = await subject_repo.get_one_by(id=subject.id)
        new_codes = await totp_factor.regenerate_backup_codes(enabled_subject)

        assert len(new_codes) == 5
        assert set(new_codes) != set(original_codes)

    async def test_regenerate_invalidates_old_codes(
        self,
        totp_factor: TOTPFactor,
        subject: Subject,
        subject_repo: SubjectRepository,
    ) -> None:
        """Test that regenerating invalidates old codes."""
        # Enroll and confirm
        result = await totp_factor.begin_enrollment(subject)
        code = get_current_totp_code(result.secret)
        refreshed = await subject_repo.get_one_by(id=subject.id)
        _, original_codes = await totp_factor.confirm_enrollment(refreshed, code)

        # Regenerate
        enabled_subject = await subject_repo.get_one_by(id=subject.id)
        await totp_factor.regenerate_backup_codes(enabled_subject)

        # Try to use old code
        with pytest.raises(InvalidBackupCodeError):
            await totp_factor.use_backup_code(enabled_subject, original_codes[0])

    async def test_regenerate_when_not_enabled_raises(
        self, totp_factor: TOTPFactor, subject: Subject
    ) -> None:
        """Test regenerating when TOTP not enabled raises."""
        with pytest.raises(TOTPNotEnabledError):
            await totp_factor.regenerate_backup_codes(subject)
