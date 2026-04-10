"""Integration tests for admin bulk import/export."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from neozen.admin.bulk import (
    EXPORT_COLUMNS,
    REQUIRED_COLUMNS,
    BulkRowStatus,
    export_subjects_to_csv,
    import_subjects_from_csv,
    validate_row,
)
from neozen.admin.services import AdminService
from neozen.storage.sqlalchemy.base import Base


@pytest.fixture
async def session() -> AsyncGenerator[AsyncSession, None]:
    """Create a fresh in-memory SQLite database with all tables."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with session_factory() as s:
        yield s

    await engine.dispose()


@pytest.fixture
def admin_service(session: AsyncSession) -> AdminService:
    return AdminService(session)


# =============================================================================
# Row validation
# =============================================================================


class TestValidateRow:
    def test_valid_minimal(self) -> None:
        email, fields = validate_row({"email": "alice@example.com"})
        assert email == "alice@example.com"
        assert fields["email"] == "alice@example.com"
        assert fields["username"] is None
        assert fields["is_active"] is True
        assert fields["is_verified"] is False

    def test_valid_full(self) -> None:
        email, fields = validate_row({
            "email": "Alice@Example.com",
            "username": "alice",
            "is_active": "true",
            "is_verified": "yes",
        })
        assert email == "alice@example.com"  # lowercased
        assert fields["username"] == "alice"
        assert fields["is_active"] is True
        assert fields["is_verified"] is True

    def test_missing_email_raises(self) -> None:
        with pytest.raises(ValueError, match="email is required"):
            validate_row({"username": "alice"})

    def test_invalid_email_raises(self) -> None:
        with pytest.raises(ValueError, match="invalid email"):
            validate_row({"email": "not-an-email"})

    def test_invalid_username_raises(self) -> None:
        with pytest.raises(ValueError, match="invalid username"):
            validate_row({
                "email": "alice@example.com",
                "username": "has spaces",
            })

    def test_boolean_variants(self) -> None:
        for value, expected in [
            ("true", True),
            ("True", True),
            ("yes", True),
            ("y", True),
            ("1", True),
            ("false", False),
            ("False", False),
            ("no", False),
            ("0", False),
            ("", True),  # default for is_active
        ]:
            _, fields = validate_row({
                "email": "a@b.com",
                "is_active": value,
            })
            assert fields["is_active"] is expected, (
                f"value={value!r} expected={expected}"
            )

    def test_invalid_boolean_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid boolean"):
            validate_row({"email": "a@b.com", "is_active": "maybe"})


# =============================================================================
# Export
# =============================================================================


@pytest.mark.anyio
class TestExport:
    async def test_export_empty(self, admin_service: AdminService) -> None:
        csv_text = await export_subjects_to_csv(admin_service)
        # Header only
        lines = csv_text.strip().split("\n")
        assert len(lines) == 1
        for col in EXPORT_COLUMNS:
            assert col in lines[0]

    async def test_export_with_subjects(self, admin_service: AdminService) -> None:
        await admin_service.create_subject(
            email="alice@example.com",
            username="alice",
            is_verified=True,
        )
        await admin_service.create_subject(
            email="bob@example.com",
            username="bob",
            is_active=False,
        )

        csv_text = await export_subjects_to_csv(admin_service)
        assert "alice@example.com" in csv_text
        assert "bob@example.com" in csv_text
        assert "alice" in csv_text
        assert "bob" in csv_text

    async def test_export_round_trip(self, admin_service: AdminService) -> None:
        """Export → import on a fresh service should produce the same users."""
        for i in range(3):
            await admin_service.create_subject(
                email=f"user{i}@example.com",
                username=f"user{i}",
            )

        csv_text = await export_subjects_to_csv(admin_service)
        # Count data rows (excluding header)
        data_lines = [line for line in csv_text.strip().split("\n")[1:] if line]
        assert len(data_lines) == 3


# =============================================================================
# Import
# =============================================================================


@pytest.mark.anyio
class TestImport:
    async def test_import_basic(self, admin_service: AdminService) -> None:
        csv_text = "email,username\nalice@example.com,alice\nbob@example.com,bob\n"
        result = await import_subjects_from_csv(admin_service, csv_text)

        assert result.total_rows == 2
        assert result.created == 2
        assert result.failed == 0
        assert not result.has_failures

    async def test_import_creates_users(self, admin_service: AdminService) -> None:
        csv_text = "email\nalice@example.com\n"
        await import_subjects_from_csv(admin_service, csv_text)

        # Verify the user actually exists
        from neozen.storage.base import DoesNotExist  # noqa: PLC0415

        try:
            user = await admin_service.subject_repo.get_one_by(
                email="alice@example.com"
            )
            assert user.email == "alice@example.com"
        except DoesNotExist:
            pytest.fail("User was not created")

    async def test_import_dry_run_does_not_persist(
        self, admin_service: AdminService
    ) -> None:
        csv_text = "email\nalice@example.com\n"
        result = await import_subjects_from_csv(admin_service, csv_text, dry_run=True)

        assert result.created == 1
        assert result.dry_run is True

        # Should not actually exist
        from neozen.storage.base import DoesNotExist  # noqa: PLC0415

        with pytest.raises(DoesNotExist):
            await admin_service.subject_repo.get_one_by(email="alice@example.com")

    async def test_import_skips_existing(self, admin_service: AdminService) -> None:
        await admin_service.create_subject(email="alice@example.com")

        csv_text = (
            "email\n"
            "alice@example.com\n"  # already exists
            "bob@example.com\n"  # new
        )
        result = await import_subjects_from_csv(admin_service, csv_text)

        assert result.total_rows == 2
        assert result.created == 1
        assert result.skipped == 1

    async def test_import_updates_existing_when_enabled(
        self, admin_service: AdminService
    ) -> None:
        await admin_service.create_subject(
            email="alice@example.com",
            username="old_username",
        )

        csv_text = "email,username\nalice@example.com,new_username\n"
        result = await import_subjects_from_csv(
            admin_service, csv_text, update_existing=True
        )

        assert result.updated == 1
        # Verify the username actually changed
        user = await admin_service.subject_repo.get_one_by(email="alice@example.com")
        assert user.username == "new_username"

    async def test_import_validation_failures(
        self, admin_service: AdminService
    ) -> None:
        csv_text = (
            "email,username\n"
            "alice@example.com,alice\n"
            "not-an-email,bob\n"  # bad email
            ",carol\n"  # missing email
            "dave@example.com,has spaces\n"  # bad username
        )
        result = await import_subjects_from_csv(admin_service, csv_text)

        assert result.total_rows == 4
        assert result.created == 1  # only alice
        assert result.failed == 3
        assert result.has_failures

        # Check error messages
        failed_rows = [r for r in result.rows if r.status == BulkRowStatus.FAILED]
        assert any("invalid email" in (r.error or "") for r in failed_rows)
        assert any("email is required" in (r.error or "") for r in failed_rows)
        assert any("invalid username" in (r.error or "") for r in failed_rows)

    async def test_import_missing_required_column(
        self, admin_service: AdminService
    ) -> None:
        csv_text = "username\nalice\n"
        result = await import_subjects_from_csv(admin_service, csv_text)

        assert result.failed == 1
        assert "missing required column" in (result.rows[0].error or "")

    async def test_import_empty_csv(self, admin_service: AdminService) -> None:
        csv_text = "email,username\n"
        result = await import_subjects_from_csv(admin_service, csv_text)
        assert result.total_rows == 0

    async def test_import_extra_columns_ignored(
        self, admin_service: AdminService
    ) -> None:
        csv_text = (
            "email,username,department,phone\nalice@example.com,alice,eng,555-0100\n"
        )
        result = await import_subjects_from_csv(admin_service, csv_text)
        assert result.created == 1

    async def test_import_with_active_and_verified_flags(
        self, admin_service: AdminService
    ) -> None:
        csv_text = (
            "email,is_active,is_verified\n"
            "alice@example.com,true,true\n"
            "bob@example.com,false,false\n"
        )
        result = await import_subjects_from_csv(admin_service, csv_text)
        assert result.created == 2

        alice = await admin_service.subject_repo.get_one_by(email="alice@example.com")
        bob = await admin_service.subject_repo.get_one_by(email="bob@example.com")
        assert alice.is_active is True
        assert alice.is_verified is True
        assert bob.is_active is False
        assert bob.is_verified is False


# =============================================================================
# Result reporting
# =============================================================================


class TestBulkImportResultDict:
    def test_to_dict_format(self) -> None:
        from neozen.admin.bulk import BulkImportResult, BulkRowResult

        result = BulkImportResult()
        result.add(
            BulkRowResult(
                row_number=1,
                status=BulkRowStatus.CREATED,
                email="alice@example.com",
                subject_id="user_1",
            )
        )
        result.add(
            BulkRowResult(
                row_number=2,
                status=BulkRowStatus.FAILED,
                email="bad",
                error="invalid email",
            )
        )

        d = result.to_dict()
        assert d["total_rows"] == 2
        assert d["created"] == 1
        assert d["failed"] == 1
        assert d["has_failures"] is True
        assert len(d["rows"]) == 2
        assert d["rows"][0]["status"] == "created"
        assert d["rows"][1]["error"] == "invalid email"


# =============================================================================
# Round trip
# =============================================================================


@pytest.mark.anyio
class TestRoundTrip:
    async def test_export_then_import_to_fresh_service(
        self,
        admin_service: AdminService,
    ) -> None:
        """Export from one service, import into another, verify match."""
        # Populate the first service
        for i in range(5):
            await admin_service.create_subject(
                email=f"user{i}@example.com",
                username=f"user{i}",
                is_verified=(i % 2 == 0),
            )

        csv_text = await export_subjects_to_csv(admin_service)

        # Create a fresh second service and import
        engine2 = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            echo=False,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine2.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory2 = async_sessionmaker(
            engine2, class_=AsyncSession, expire_on_commit=False
        )
        async with factory2() as session2:
            service2 = AdminService(session2)
            result = await import_subjects_from_csv(service2, csv_text)

            assert result.created == 5
            assert result.failed == 0

            # Verify the second DB has all the users
            users = await service2.list_subjects()
            emails = sorted(u.email for u in users)
            assert emails == [f"user{i}@example.com" for i in range(5)]

        await engine2.dispose()


# =============================================================================
# Constants
# =============================================================================


class TestConstants:
    def test_required_columns(self) -> None:
        assert "email" in REQUIRED_COLUMNS

    def test_export_columns(self) -> None:
        assert "id" in EXPORT_COLUMNS
        assert "email" in EXPORT_COLUMNS
        assert "created_at" in EXPORT_COLUMNS
