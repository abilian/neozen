"""Tests for identifier lookup service."""

from __future__ import annotations

import dataclasses

import pytest

from neozen.core.identifiers.email import EmailIdentifier, EmailSubjectModel
from neozen.core.identifiers.lookup import IdentifierLookupService
from neozen.core.identifiers.username import UsernameIdentifier, UsernameSubjectModel
from neozen.core.storage import DoesNotExist
from tests.conftest import MockStorage


@dataclasses.dataclass
class MockMultiSubject(EmailSubjectModel, UsernameSubjectModel):
    id: str
    email: str
    username: str


@pytest.fixture
def storage() -> MockStorage[MockMultiSubject]:
    return MockStorage(MockMultiSubject, [])


@pytest.fixture
def email_identifier(
    storage: MockStorage[MockMultiSubject],
) -> EmailIdentifier[MockMultiSubject]:
    return EmailIdentifier(storage)


@pytest.fixture
def username_identifier(
    storage: MockStorage[MockMultiSubject],
) -> UsernameIdentifier[MockMultiSubject]:
    return UsernameIdentifier(storage)


@pytest.fixture
def lookup_service(
    email_identifier: EmailIdentifier[MockMultiSubject],
    username_identifier: UsernameIdentifier[MockMultiSubject],
) -> IdentifierLookupService[MockMultiSubject]:
    service: IdentifierLookupService[MockMultiSubject] = IdentifierLookupService()
    service.register("email", email_identifier)
    service.register("username", username_identifier)
    return service


@pytest.mark.anyio
class TestIdentifierLookupService:
    async def test_register_and_get_identifier(
        self, lookup_service: IdentifierLookupService[MockMultiSubject]
    ) -> None:
        assert "email" in lookup_service.registered_types
        assert "username" in lookup_service.registered_types
        assert lookup_service.get_identifier("email") is not None

    async def test_unregister(
        self, lookup_service: IdentifierLookupService[MockMultiSubject]
    ) -> None:
        lookup_service.unregister("email")
        assert "email" not in lookup_service.registered_types

    async def test_detect_type_email(
        self, lookup_service: IdentifierLookupService[MockMultiSubject]
    ) -> None:
        assert lookup_service.detect_type("user@example.com") == "email"

    async def test_detect_type_username(
        self, lookup_service: IdentifierLookupService[MockMultiSubject]
    ) -> None:
        assert lookup_service.detect_type("john_doe") == "username"

    async def test_lookup_by_type_email(
        self,
        storage: MockStorage[MockMultiSubject],
        lookup_service: IdentifierLookupService[MockMultiSubject],
    ) -> None:
        await storage.create(id="1", email="user@example.com", username="user")
        result = await lookup_service.lookup_by_type("email", "user@example.com")
        assert result.id == "1"

    async def test_lookup_by_type_username(
        self,
        storage: MockStorage[MockMultiSubject],
        lookup_service: IdentifierLookupService[MockMultiSubject],
    ) -> None:
        await storage.create(id="1", email="user@example.com", username="john_doe")
        result = await lookup_service.lookup_by_type("username", "john_doe")
        assert result.id == "1"

    async def test_lookup_by_type_not_found(
        self, lookup_service: IdentifierLookupService[MockMultiSubject]
    ) -> None:
        with pytest.raises(DoesNotExist):
            await lookup_service.lookup_by_type("email", "nonexistent@example.com")

    async def test_lookup_auto_detect_email(
        self,
        storage: MockStorage[MockMultiSubject],
        lookup_service: IdentifierLookupService[MockMultiSubject],
    ) -> None:
        await storage.create(id="1", email="user@example.com", username="user")
        result = await lookup_service.lookup("user@example.com")
        assert result.id == "1"

    async def test_lookup_auto_detect_username(
        self,
        storage: MockStorage[MockMultiSubject],
        lookup_service: IdentifierLookupService[MockMultiSubject],
    ) -> None:
        await storage.create(id="1", email="user@example.com", username="john_doe")
        result = await lookup_service.lookup("john_doe")
        assert result.id == "1"

    async def test_lookup_any_tries_all_types(
        self,
        storage: MockStorage[MockMultiSubject],
        lookup_service: IdentifierLookupService[MockMultiSubject],
    ) -> None:
        await storage.create(id="1", email="user@example.com", username="myuser")
        # This looks like a username but won't match email, should try username
        result = await lookup_service.lookup_any("myuser")
        assert result.id == "1"

    async def test_lookup_not_found(
        self, lookup_service: IdentifierLookupService[MockMultiSubject]
    ) -> None:
        with pytest.raises(DoesNotExist):
            await lookup_service.lookup("nonexistent")

    async def test_verify_and_normalize_email(
        self, lookup_service: IdentifierLookupService[MockMultiSubject]
    ) -> None:
        result = await lookup_service.verify_and_normalize("email", "USER@EXAMPLE.COM")
        # Domain should be lowercase
        assert result == "USER@example.com"

    async def test_verify_and_normalize_username(
        self, lookup_service: IdentifierLookupService[MockMultiSubject]
    ) -> None:
        result = await lookup_service.verify_and_normalize("username", "John_Doe")
        assert result == "john_doe"


@pytest.mark.anyio
class TestIdentifierLookupServiceDetection:
    def test_detect_type_with_dots_in_email(
        self, lookup_service: IdentifierLookupService[MockMultiSubject]
    ) -> None:
        assert lookup_service.detect_type("first.last@example.com") == "email"

    def test_detect_type_with_plus_in_email(
        self, lookup_service: IdentifierLookupService[MockMultiSubject]
    ) -> None:
        assert lookup_service.detect_type("user+tag@example.com") == "email"

    def test_detect_type_username_with_underscore(
        self, lookup_service: IdentifierLookupService[MockMultiSubject]
    ) -> None:
        assert lookup_service.detect_type("user_name") == "username"

    def test_detect_type_username_with_hyphen(
        self, lookup_service: IdentifierLookupService[MockMultiSubject]
    ) -> None:
        assert lookup_service.detect_type("user-name") == "username"

    def test_detect_type_non_string_returns_none(
        self, lookup_service: IdentifierLookupService[MockMultiSubject]
    ) -> None:
        assert lookup_service.detect_type(12345) is None  # type: ignore[arg-type]


@pytest.mark.anyio
class TestIdentifierLookupServicePriority:
    async def test_detection_priority(
        self, storage: MockStorage[MockMultiSubject]
    ) -> None:
        service: IdentifierLookupService[MockMultiSubject] = IdentifierLookupService()
        email_id = EmailIdentifier(storage)
        username_id = UsernameIdentifier(storage)

        # Register username first
        service.register("username", username_id, detection_priority=0)
        service.register("email", email_id, detection_priority=1)

        assert service.registered_types == ["username", "email"]
