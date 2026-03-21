"""Integration tests for password policy with SQLAlchemy storage.

Tests the PasswordPolicyValidator with real database storage for password history.
"""

from __future__ import annotations

import secrets

import pytest
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from neozen.core.factors.password_policy import (
    PasswordPolicy,
    PasswordPolicyValidator,
    PasswordPolicyViolation,
)
from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.models import Subject
from neozen.storage.sqlalchemy.repositories import (
    PasswordHistoryRepository,
    SubjectRepository,
)


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
def history_repo(session: AsyncSession) -> PasswordHistoryRepository:
    """Create password history repository."""
    return PasswordHistoryRepository(session=session)


@pytest.fixture
def hasher() -> PasswordHash:
    """Create password hasher."""
    return PasswordHash((Argon2Hasher(),))


@pytest.fixture
def policy() -> PasswordPolicy:
    """Create a password policy with history checking."""
    return PasswordPolicy(
        min_length=8,
        max_length=128,
        require_uppercase=True,
        require_lowercase=True,
        require_digit=True,
        require_special=False,
        check_hibp=False,
        password_history_count=3,
    )


@pytest.fixture
def validator(
    policy: PasswordPolicy,
    hasher: PasswordHash,
    history_repo: PasswordHistoryRepository,
) -> PasswordPolicyValidator:
    """Create password policy validator."""
    return PasswordPolicyValidator(
        policy=policy,
        hasher=hasher,
        history_repository=history_repo,
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
class TestPasswordPolicyValidation:
    """Tests for password policy complexity validation."""

    async def test_valid_password_passes(
        self, validator: PasswordPolicyValidator
    ) -> None:
        """Test that a valid password passes validation."""
        await validator.validate("ValidPass123")

    async def test_too_short_password_fails(
        self, validator: PasswordPolicyValidator
    ) -> None:
        """Test that a short password fails."""
        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("Short1A")

        assert "at least 8 characters" in exc_info.value.violations[0]

    async def test_missing_uppercase_fails(
        self, validator: PasswordPolicyValidator
    ) -> None:
        """Test that missing uppercase fails."""
        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("lowercase123")

        assert "uppercase" in exc_info.value.violations[0].lower()

    async def test_missing_lowercase_fails(
        self, validator: PasswordPolicyValidator
    ) -> None:
        """Test that missing lowercase fails."""
        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("UPPERCASE123")

        assert "lowercase" in exc_info.value.violations[0].lower()

    async def test_missing_digit_fails(
        self, validator: PasswordPolicyValidator
    ) -> None:
        """Test that missing digit fails."""
        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("NoDigitsHere")

        assert "digit" in exc_info.value.violations[0].lower()

    async def test_multiple_violations_reported(
        self, validator: PasswordPolicyValidator
    ) -> None:
        """Test that multiple violations are all reported."""
        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("bad")

        assert len(exc_info.value.violations) > 1


@pytest.mark.anyio
class TestPasswordHistoryIntegration:
    """Tests for password history checking with real database."""

    async def test_record_password_stores_hash(
        self,
        validator: PasswordPolicyValidator,
        hasher: PasswordHash,
        history_repo: PasswordHistoryRepository,
        subject: Subject,
    ) -> None:
        """Test that recording a password stores it in history."""
        hashed = hasher.hash("ValidPass123")
        await validator.record_password(subject.id, hashed)

        history = await history_repo.get_many_by(subject_id=subject.id)
        assert len(history) == 1

    async def test_reused_password_rejected(
        self,
        validator: PasswordPolicyValidator,
        hasher: PasswordHash,
        subject: Subject,
    ) -> None:
        """Test that a recently used password is rejected."""
        password = "ValidPass123"
        hashed = hasher.hash(password)
        await validator.record_password(subject.id, hashed)

        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate(password, subject_id=subject.id)

        assert "recently" in exc_info.value.violations[0].lower()

    async def test_old_password_accepted_after_rotation(
        self,
        validator: PasswordPolicyValidator,
        hasher: PasswordHash,
        subject: Subject,
    ) -> None:
        """Test that an old password is accepted after enough rotations."""
        old_password = "OldPass123"
        old_hashed = hasher.hash(old_password)
        await validator.record_password(subject.id, old_hashed)

        # Record 3 more passwords (history_count = 3)
        for i in range(3):
            new_hashed = hasher.hash(f"NewPass{i}Abc")
            await validator.record_password(subject.id, new_hashed)

        # Old password should now be accepted
        await validator.validate(old_password, subject_id=subject.id)

    async def test_history_limit_enforced(
        self,
        validator: PasswordPolicyValidator,
        hasher: PasswordHash,
        history_repo: PasswordHistoryRepository,
        subject: Subject,
    ) -> None:
        """Test that history limit is enforced (old entries deleted)."""
        # Record more than history_count passwords
        for i in range(5):
            hashed = hasher.hash(f"Password{i}A")
            await validator.record_password(subject.id, hashed)

        history = await history_repo.get_many_by(subject_id=subject.id)
        assert len(history) == 3  # Only last 3 kept

    async def test_different_users_have_separate_history(
        self,
        validator: PasswordPolicyValidator,
        hasher: PasswordHash,
        subject_repo: SubjectRepository,
        subject: Subject,
    ) -> None:
        """Test that password history is per-user."""
        # Create second user
        subject2 = await subject_repo.create(
            id=secrets.token_hex(16),
            email="other@example.com",
            hashed_password=None,
            is_active=True,
            is_verified=False,
        )

        password = "SharedPass123"
        hashed = hasher.hash(password)
        await validator.record_password(subject.id, hashed)

        # Same password should be allowed for different user
        await validator.validate(password, subject_id=subject2.id)


@pytest.mark.anyio
class TestPasswordPolicySpecialCharacters:
    """Tests for special character requirements."""

    async def test_special_character_required_when_enabled(
        self,
        hasher: PasswordHash,
        history_repo: PasswordHistoryRepository,
    ) -> None:
        """Test special character requirement when enabled."""
        policy = PasswordPolicy(
            min_length=8,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True,
        )
        validator = PasswordPolicyValidator(
            policy=policy,
            hasher=hasher,
            history_repository=history_repo,
        )

        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("NoSpecial123")

        assert "special" in exc_info.value.violations[0].lower()

        # With special character should pass
        await validator.validate("HasSpecial@123")


@pytest.mark.anyio
class TestPasswordPolicyEdgeCases:
    """Tests for edge cases in password policy validation."""

    async def test_exact_min_length_accepted(
        self, validator: PasswordPolicyValidator
    ) -> None:
        """Test that password at exact min length is accepted."""
        await validator.validate("Exact8Ab")  # 8 characters

    async def test_max_length_enforced(
        self,
        hasher: PasswordHash,
        history_repo: PasswordHistoryRepository,
    ) -> None:
        """Test that passwords over max length are rejected."""
        policy = PasswordPolicy(min_length=8, max_length=16)
        validator = PasswordPolicyValidator(
            policy=policy,
            hasher=hasher,
            history_repository=history_repo,
        )

        long_password = "A" * 17 + "a1"

        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate(long_password)

        assert "at most 16 characters" in exc_info.value.violations[0]

    async def test_validation_without_subject_id(
        self, validator: PasswordPolicyValidator
    ) -> None:
        """Test validation works without subject_id (no history check)."""
        await validator.validate("ValidPass123")

    async def test_validation_with_nonexistent_subject(
        self, validator: PasswordPolicyValidator
    ) -> None:
        """Test validation with subject_id that has no history."""
        await validator.validate("ValidPass123", subject_id="nonexistent")
