"""Tests for password policy validation."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from neozen.core.factors.password_policy import (
    HIBPCheckerProtocol,
    PasswordHasherProtocol,
    PasswordHistoryModel,
    PasswordPolicy,
    PasswordPolicyValidator,
    PasswordPolicyViolation,
)
from tests.conftest import MockStorage


@dataclasses.dataclass
class MockPasswordHistory(PasswordHistoryModel):
    id: str
    subject_id: str
    hashed_password: str
    created_at: datetime


class MockHasher(PasswordHasherProtocol):
    """Simple mock hasher that uses plaintext for testing."""

    def verify_and_update(
        self, password: str | bytes, hash: str | bytes
    ) -> tuple[bool, str | None]:
        password_str = password if isinstance(password, str) else password.decode()
        hash_str = hash if isinstance(hash, str) else hash.decode()
        return password_str == hash_str, None

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        return password if isinstance(password, str) else password.decode()


class MockHIBPChecker(HIBPCheckerProtocol):
    """Mock HIBP checker for testing."""

    def __init__(self, compromised_passwords: set[str] | None = None) -> None:
        self.compromised_passwords = compromised_passwords or set()

    async def is_compromised(self, password: str) -> bool:
        return password in self.compromised_passwords


@pytest.fixture
def history_storage() -> MockStorage[MockPasswordHistory]:
    return MockStorage(MockPasswordHistory, [])


@pytest.fixture
def hasher() -> MockHasher:
    return MockHasher()


@pytest.mark.anyio
class TestPasswordPolicyValidation:
    """Tests for basic password policy validation."""

    async def test_default_policy_valid_password(self) -> None:
        policy = PasswordPolicy()
        validator = PasswordPolicyValidator(policy)

        # Should not raise
        await validator.validate("SecurePassword123")

    async def test_min_length_violation(self) -> None:
        policy = PasswordPolicy(min_length=12)
        validator = PasswordPolicyValidator(policy)

        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("Short1Aa")

        assert "at least 12 characters" in exc_info.value.message

    async def test_max_length_violation(self) -> None:
        policy = PasswordPolicy(max_length=20)
        validator = PasswordPolicyValidator(policy)

        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("A" * 21 + "a1")

        assert "at most 20 characters" in exc_info.value.message

    async def test_uppercase_required(self) -> None:
        policy = PasswordPolicy(require_uppercase=True)
        validator = PasswordPolicyValidator(policy)

        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("lowercase123")

        assert "uppercase letter" in exc_info.value.message

    async def test_lowercase_required(self) -> None:
        policy = PasswordPolicy(require_lowercase=True)
        validator = PasswordPolicyValidator(policy)

        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("UPPERCASE123")

        assert "lowercase letter" in exc_info.value.message

    async def test_digit_required(self) -> None:
        policy = PasswordPolicy(require_digit=True)
        validator = PasswordPolicyValidator(policy)

        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("NoDigitsHere")

        assert "digit" in exc_info.value.message

    async def test_special_required(self) -> None:
        policy = PasswordPolicy(require_special=True)
        validator = PasswordPolicyValidator(policy)

        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("NoSpecial123")

        assert "special character" in exc_info.value.message

    async def test_special_character_valid(self) -> None:
        policy = PasswordPolicy(require_special=True)
        validator = PasswordPolicyValidator(policy)

        # Should not raise
        await validator.validate("HasSpecial123!")

    async def test_multiple_violations(self) -> None:
        policy = PasswordPolicy(
            min_length=12,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True,
        )
        validator = PasswordPolicyValidator(policy)

        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("short")

        # Should have multiple violations
        assert len(exc_info.value.violations) > 1

    async def test_no_requirements(self) -> None:
        policy = PasswordPolicy(
            min_length=1,
            require_uppercase=False,
            require_lowercase=False,
            require_digit=False,
            require_special=False,
        )
        validator = PasswordPolicyValidator(policy)

        # Any password should work
        await validator.validate("x")


@pytest.mark.anyio
class TestHIBPCheck:
    """Tests for Have I Been Pwned integration."""

    async def test_hibp_disabled(self) -> None:
        policy = PasswordPolicy(check_hibp=False)
        hibp_checker = MockHIBPChecker({"password123"})
        validator = PasswordPolicyValidator(policy, hibp_checker=hibp_checker)

        # Should not check HIBP when disabled
        await validator.validate("Password123")

    async def test_hibp_compromised_password(self) -> None:
        policy = PasswordPolicy(
            check_hibp=True,
            require_uppercase=False,
            require_lowercase=False,
            require_digit=False,
        )
        hibp_checker = MockHIBPChecker({"compromised"})
        validator = PasswordPolicyValidator(policy, hibp_checker=hibp_checker)

        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("compromised")

        assert "data breach" in exc_info.value.message

    async def test_hibp_safe_password(self) -> None:
        policy = PasswordPolicy(check_hibp=True)
        hibp_checker = MockHIBPChecker({"compromised"})
        validator = PasswordPolicyValidator(policy, hibp_checker=hibp_checker)

        await validator.validate("SafePassword123")


@pytest.mark.anyio
class TestPasswordHistory:
    """Tests for password history/reuse prevention."""

    async def test_history_disabled(
        self,
        history_storage: MockStorage[MockPasswordHistory],
        hasher: MockHasher,
    ) -> None:
        policy = PasswordPolicy(password_history_count=0)
        validator = PasswordPolicyValidator(
            policy, hasher=hasher, history_repository=history_storage
        )

        # Add a password to history manually
        await history_storage.create(
            id="1",
            subject_id="user1",
            hashed_password="OldPassword123",
            created_at=datetime.now(UTC),
        )

        # Should not check history when count is 0
        await validator.validate("OldPassword123", subject_id="user1")

    async def test_history_reuse_blocked(
        self,
        history_storage: MockStorage[MockPasswordHistory],
        hasher: MockHasher,
    ) -> None:
        policy = PasswordPolicy(password_history_count=3)
        validator = PasswordPolicyValidator(
            policy, hasher=hasher, history_repository=history_storage
        )

        # Add password to history
        await history_storage.create(
            id="1",
            subject_id="user1",
            hashed_password="OldPassword123",
            created_at=datetime.now(UTC),
        )

        with pytest.raises(PasswordPolicyViolation) as exc_info:
            await validator.validate("OldPassword123", subject_id="user1")

        assert "used recently" in exc_info.value.message

    async def test_history_different_user(
        self,
        history_storage: MockStorage[MockPasswordHistory],
        hasher: MockHasher,
    ) -> None:
        policy = PasswordPolicy(password_history_count=3)
        validator = PasswordPolicyValidator(
            policy, hasher=hasher, history_repository=history_storage
        )

        # Add password to history for user1
        await history_storage.create(
            id="1",
            subject_id="user1",
            hashed_password="OldPassword123",
            created_at=datetime.now(UTC),
        )

        # Should be allowed for user2
        await validator.validate("OldPassword123", subject_id="user2")

    async def test_history_no_subject_id(
        self,
        history_storage: MockStorage[MockPasswordHistory],
        hasher: MockHasher,
    ) -> None:
        policy = PasswordPolicy(password_history_count=3)
        validator = PasswordPolicyValidator(
            policy, hasher=hasher, history_repository=history_storage
        )

        # Should not check history without subject_id
        await validator.validate("AnyPassword123")


@pytest.mark.anyio
class TestRecordPassword:
    """Tests for recording passwords in history."""

    async def test_record_password(
        self,
        history_storage: MockStorage[MockPasswordHistory],
    ) -> None:
        policy = PasswordPolicy(password_history_count=3)
        validator = PasswordPolicyValidator(policy, history_repository=history_storage)

        await validator.record_password("user1", "hashed_password_1")

        records = await history_storage.get_many_by(subject_id="user1")
        assert len(records) == 1
        assert records[0].hashed_password == "hashed_password_1"

    async def test_record_password_disabled(
        self,
        history_storage: MockStorage[MockPasswordHistory],
    ) -> None:
        policy = PasswordPolicy(password_history_count=0)
        validator = PasswordPolicyValidator(policy, history_repository=history_storage)

        await validator.record_password("user1", "hashed_password_1")

        # Should not record when history is disabled
        records = await history_storage.get_many_by(subject_id="user1")
        assert len(records) == 0

    async def test_record_password_cleanup(
        self,
        history_storage: MockStorage[MockPasswordHistory],
    ) -> None:
        policy = PasswordPolicy(password_history_count=2)
        validator = PasswordPolicyValidator(
            policy,
            history_repository=history_storage,
            id_generator=lambda: f"id_{len(history_storage._data) + 1}",
        )

        # Record 3 passwords, should keep only 2
        for i in range(3):
            await history_storage.create(
                id=f"old_{i}",
                subject_id="user1",
                hashed_password=f"old_password_{i}",
                created_at=datetime(2020, 1, i + 1, tzinfo=UTC),
            )

        # Record a new password (cleanup should happen)
        await validator.record_password("user1", "new_password")

        records = await history_storage.get_many_by(subject_id="user1")
        # Should have 2 records (the 2 most recent)
        assert len(records) == 2
