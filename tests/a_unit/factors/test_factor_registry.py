"""Unit tests for factor registry."""

from __future__ import annotations

import pytest

from neozen.core.factors import (
    FactorAlreadyRegisteredError,
    FactorNotFoundError,
    FactorRegistry,
)
from neozen.core.factors.protocol import (
    AuthenticatingFactorProtocol,
    EnrollableFactorProtocol,
    FactorProtocol,
)


class MockFactor:
    """Mock factor for testing."""

    def __init__(
        self,
        factor_id: str = "mock",
        display_name: str = "Mock Factor",
        factor_type: str = "knowledge",
        enrolled_subjects: set[str] | None = None,
    ) -> None:
        self._factor_id = factor_id
        self._display_name = display_name
        self._factor_type = factor_type
        self._enrolled: set[str] = enrolled_subjects or set()

    @property
    def factor_id(self) -> str:
        return self._factor_id

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def factor_type(self) -> str:
        return self._factor_type

    async def is_enrolled(self, subject_id: str) -> bool:
        return subject_id in self._enrolled

    async def supports_subject(self, subject_id: str) -> bool:
        return True


class BrokenFactor(MockFactor):
    """Factor whose storage is unavailable."""

    async def is_enrolled(self, subject_id: str) -> bool:
        msg = "storage down"
        raise ConnectionError(msg)


class MockAuthenticatingFactor(MockFactor):
    """Mock factor that supports authentication."""

    async def authenticate(
        self,
        subject_id: str,
        credential: str,
        **kwargs,
    ) -> bool:
        return credential == "valid"


class MockEnrollableFactor(MockFactor):
    """Mock factor that supports enrollment."""

    async def begin_enrollment(self, subject_id: str, **kwargs) -> dict:
        return {"setup": "data"}

    async def complete_enrollment(
        self,
        subject_id: str,
        verification: str,
        **kwargs,
    ) -> bool:
        if verification == "valid":
            self._enrolled.add(subject_id)
            return True
        return False

    async def unenroll(self, subject_id: str) -> None:
        self._enrolled.discard(subject_id)


class TestFactorRegistry:
    """Tests for FactorRegistry."""

    def test_register(self) -> None:
        registry = FactorRegistry()
        factor = MockFactor("test")

        registry.register(factor)

        assert registry.has("test")
        assert registry.factor_count == 1

    def test_register_duplicate(self) -> None:
        registry = FactorRegistry()
        factor1 = MockFactor("test")
        factor2 = MockFactor("test")

        registry.register(factor1)

        with pytest.raises(FactorAlreadyRegisteredError) as exc_info:
            registry.register(factor2)

        assert exc_info.value.factor_id == "test"

    def test_register_replace(self) -> None:
        registry = FactorRegistry()
        factor1 = MockFactor("test", display_name="First")
        factor2 = MockFactor("test", display_name="Second")

        registry.register(factor1)
        registry.register(factor2, replace=True)

        assert registry.get("test").display_name == "Second"

    def test_unregister(self) -> None:
        registry = FactorRegistry()
        factor = MockFactor("test")

        registry.register(factor)
        assert registry.has("test")

        registry.unregister("test")
        assert not registry.has("test")

    def test_unregister_nonexistent(self) -> None:
        registry = FactorRegistry()

        # Should not raise
        registry.unregister("nonexistent")

    def test_get(self) -> None:
        registry = FactorRegistry()
        factor = MockFactor("test")

        registry.register(factor)

        result = registry.get("test")
        assert result is factor

    def test_get_not_found(self) -> None:
        registry = FactorRegistry()

        with pytest.raises(FactorNotFoundError) as exc_info:
            registry.get("nonexistent")

        assert exc_info.value.factor_id == "nonexistent"

    def test_get_or_none(self) -> None:
        registry = FactorRegistry()
        factor = MockFactor("test")

        assert registry.get_or_none("test") is None

        registry.register(factor)

        assert registry.get_or_none("test") is factor

    def test_has(self) -> None:
        registry = FactorRegistry()
        factor = MockFactor("test")

        assert registry.has("test") is False

        registry.register(factor)

        assert registry.has("test") is True

    def test_list_all(self) -> None:
        registry = FactorRegistry()
        factor1 = MockFactor("test1")
        factor2 = MockFactor("test2")

        registry.register(factor1)
        registry.register(factor2)

        factors = registry.list_all()

        assert len(factors) == 2
        assert factor1 in factors
        assert factor2 in factors

    def test_list_by_type(self) -> None:
        registry = FactorRegistry()
        knowledge = MockFactor("password", factor_type="knowledge")
        possession = MockFactor("totp", factor_type="possession")

        registry.register(knowledge)
        registry.register(possession)

        knowledge_factors = registry.list_by_type("knowledge")
        possession_factors = registry.list_by_type("possession")

        assert len(knowledge_factors) == 1
        assert knowledge_factors[0].factor_id == "password"
        assert len(possession_factors) == 1
        assert possession_factors[0].factor_id == "totp"

    def test_clear(self) -> None:
        registry = FactorRegistry()
        registry.register(MockFactor("test1"))
        registry.register(MockFactor("test2"))

        assert registry.factor_count == 2

        registry.clear()

        assert registry.factor_count == 0

    def test_register_many(self) -> None:
        registry = FactorRegistry()
        factors = [MockFactor("test1"), MockFactor("test2"), MockFactor("test3")]

        registry.register_many(factors)

        assert registry.factor_count == 3

    def test_factor_ids(self) -> None:
        registry = FactorRegistry()
        registry.register(MockFactor("alpha"))
        registry.register(MockFactor("beta"))

        ids = registry.factor_ids

        assert "alpha" in ids
        assert "beta" in ids

    def test_get_factor_info(self) -> None:
        registry = FactorRegistry()
        registry.register(
            MockFactor("test", display_name="Test Factor", factor_type="knowledge")
        )

        info = registry.get_factor_info()

        assert len(info) == 1
        assert info[0]["factor_id"] == "test"
        assert info[0]["display_name"] == "Test Factor"
        assert info[0]["factor_type"] == "knowledge"


@pytest.mark.anyio
class TestFactorRegistryAsync:
    """Async tests for FactorRegistry."""

    async def test_enrollment_errors_propagate(self) -> None:
        # A storage failure must not look like "not enrolled", or a second
        # factor could be skipped.
        registry = FactorRegistry()
        registry.register(BrokenFactor("totp"))

        with pytest.raises(ConnectionError):
            await registry.list_enrolled("user1")
        with pytest.raises(ConnectionError):
            await registry.get_enrolled_factors("user1")
        with pytest.raises(ConnectionError):
            await registry.list_available("user1")

    async def test_list_enrolled(self) -> None:
        registry = FactorRegistry()
        factor1 = MockFactor("password", enrolled_subjects={"user1", "user2"})
        factor2 = MockFactor("totp", enrolled_subjects={"user1"})
        factor3 = MockFactor("webauthn", enrolled_subjects=set())

        registry.register(factor1)
        registry.register(factor2)
        registry.register(factor3)

        user1_enrolled = await registry.list_enrolled("user1")
        user2_enrolled = await registry.list_enrolled("user2")
        user3_enrolled = await registry.list_enrolled("user3")

        assert set(user1_enrolled) == {"password", "totp"}
        assert set(user2_enrolled) == {"password"}
        assert user3_enrolled == []

    async def test_list_available(self) -> None:
        registry = FactorRegistry()
        factor1 = MockFactor("password", enrolled_subjects={"user1"})
        factor2 = MockFactor("totp", enrolled_subjects=set())
        factor3 = MockFactor("webauthn", enrolled_subjects=set())

        registry.register(factor1)
        registry.register(factor2)
        registry.register(factor3)

        available = await registry.list_available("user1")
        available_ids = [f.factor_id for f in available]

        assert "password" not in available_ids
        assert "totp" in available_ids
        assert "webauthn" in available_ids

    async def test_get_enrolled_factors(self) -> None:
        registry = FactorRegistry()
        factor1 = MockFactor("password", enrolled_subjects={"user1"})
        factor2 = MockFactor("totp", enrolled_subjects={"user1"})
        factor3 = MockFactor("webauthn", enrolled_subjects=set())

        registry.register(factor1)
        registry.register(factor2)
        registry.register(factor3)

        enrolled = await registry.get_enrolled_factors("user1")
        enrolled_ids = [f.factor_id for f in enrolled]

        assert "password" in enrolled_ids
        assert "totp" in enrolled_ids
        assert "webauthn" not in enrolled_ids


class TestFactorRegistryTypedGetters:
    """Tests for typed factor getters."""

    def test_get_authenticating_factor(self) -> None:
        registry = FactorRegistry()
        factor = MockAuthenticatingFactor("password")
        registry.register(factor)

        result = registry.get_authenticating_factor("password")

        assert isinstance(result, AuthenticatingFactorProtocol)

    def test_get_authenticating_factor_wrong_type(self) -> None:
        registry = FactorRegistry()
        factor = MockFactor("test")  # Does not implement authenticate
        registry.register(factor)

        with pytest.raises(TypeError, match="does not support authentication"):
            registry.get_authenticating_factor("test")

    def test_get_enrollable_factor(self) -> None:
        registry = FactorRegistry()
        factor = MockEnrollableFactor("totp")
        registry.register(factor)

        result = registry.get_enrollable_factor("totp")

        assert isinstance(result, EnrollableFactorProtocol)

    def test_get_enrollable_factor_wrong_type(self) -> None:
        registry = FactorRegistry()
        factor = MockFactor("test")  # Does not implement enrollment
        registry.register(factor)

        with pytest.raises(TypeError, match="does not support enrollment"):
            registry.get_enrollable_factor("test")

    def test_protocol_conformance(self) -> None:
        """Verify mock factors conform to protocols."""
        mock = MockFactor("test")
        auth = MockAuthenticatingFactor("auth")
        enrollable = MockEnrollableFactor("enroll")

        assert isinstance(mock, FactorProtocol)
        assert isinstance(auth, FactorProtocol)
        assert isinstance(auth, AuthenticatingFactorProtocol)
        assert isinstance(enrollable, FactorProtocol)
        assert isinstance(enrollable, EnrollableFactorProtocol)
