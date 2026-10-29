"""Bulk import/export operations for the admin console.

Supports CSV-based bulk subject operations:
- Export: serialize all subjects to CSV
- Import: parse a CSV, validate each row, optionally dry-run, then create
- Detailed result reporting (per-row status, errors, summary counts)

The operations are framework-agnostic — they work on file-like objects
and dict iterables, so they can be wired into any web framework's
upload/download flow.
"""

from __future__ import annotations

import contextlib
import csv
import io
import re
import typing
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from advanced_alchemy.exceptions import RepositoryError
from sqlalchemy.exc import SQLAlchemyError

from neozen.storage.base import DoesNotExist

if TYPE_CHECKING:
    from neozen.admin.services import AdminService


# =============================================================================
# Result types
# =============================================================================


class BulkRowStatus(StrEnum):
    """Status of a single row in a bulk operation."""

    CREATED = "created"
    UPDATED = "updated"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True)
class BulkRowResult:
    """Result of processing a single row."""

    row_number: int  # 1-based, header is row 0
    status: BulkRowStatus
    email: str | None = None
    subject_id: str | None = None
    error: str | None = None


@dataclass
class BulkImportResult:
    """Aggregate result of a bulk import."""

    total_rows: int = 0
    created: int = 0
    updated: int = 0
    skipped: int = 0
    failed: int = 0
    rows: list[BulkRowResult] = field(default_factory=list)
    dry_run: bool = False

    def add(self, result: BulkRowResult) -> None:
        self.rows.append(result)
        self.total_rows += 1
        if result.status == BulkRowStatus.CREATED:
            self.created += 1
        elif result.status == BulkRowStatus.UPDATED:
            self.updated += 1
        elif result.status == BulkRowStatus.SKIPPED:
            self.skipped += 1
        elif result.status == BulkRowStatus.FAILED:
            self.failed += 1

    @property
    def has_failures(self) -> bool:
        return self.failed > 0

    def to_dict(self) -> dict[str, object]:
        return {
            "total_rows": self.total_rows,
            "created": self.created,
            "updated": self.updated,
            "skipped": self.skipped,
            "failed": self.failed,
            "dry_run": self.dry_run,
            "has_failures": self.has_failures,
            "rows": [
                {
                    "row_number": r.row_number,
                    "status": r.status.value,
                    "email": r.email,
                    "subject_id": r.subject_id,
                    "error": r.error,
                }
                for r in self.rows
            ],
        }


# =============================================================================
# CSV format
# =============================================================================


# Required columns for import
REQUIRED_COLUMNS = ("email",)
# Optional columns recognized on import (others are ignored)
OPTIONAL_COLUMNS = ("username", "is_active", "is_verified")
# Columns produced by export
EXPORT_COLUMNS = (
    "id",
    "email",
    "username",
    "is_active",
    "is_verified",
    "created_at",
)


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")


def _parse_bool(value: str | bool | None, *, default: bool) -> bool:  # noqa: FBT001
    """Parse a CSV cell as a boolean."""
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    lowered = str(value).strip().lower()
    if lowered in {"true", "yes", "y", "1", "t"}:
        return True
    if lowered in {"false", "no", "n", "0", "f"}:
        return False
    msg = f"Invalid boolean value: {value!r}"
    raise ValueError(msg)


def validate_row(row: dict[str, str]) -> tuple[str, dict[str, typing.Any]]:
    """Validate a CSV row and return (email, normalized fields).

    Raises ValueError with a descriptive message on validation failure.
    """
    email = (row.get("email") or "").strip().lower()
    if not email:
        msg = "email is required"
        raise ValueError(msg)
    if not _EMAIL_RE.match(email):
        msg = f"invalid email: {email!r}"
        raise ValueError(msg)

    username_raw = (row.get("username") or "").strip()
    username: str | None = username_raw or None
    if username and not _USERNAME_RE.match(username):
        msg = f"invalid username: {username!r}"
        raise ValueError(msg)

    fields: dict[str, typing.Any] = {
        "email": email,
        "username": username,
        "is_active": _parse_bool(row.get("is_active"), default=True),
        "is_verified": _parse_bool(row.get("is_verified"), default=False),
    }
    return email, fields


# =============================================================================
# Export
# =============================================================================


def _cell(value: str) -> str:
    """A value a spreadsheet won't run as a formula (CSV injection)."""
    return f"'{value}" if value.startswith(("=", "+", "-", "@", "\t", "\r")) else value


async def export_subjects_to_csv(
    service: AdminService,
    output: io.TextIOBase | None = None,
) -> str:
    """Export all subjects to CSV format.

    Args:
        service: The admin service.
        output: Optional file-like object to write to. If None,
            returns the CSV as a string.

    Returns:
        The CSV string (also written to `output` if provided).
    """
    buffer = output if output is not None else io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(EXPORT_COLUMNS))
    writer.writeheader()

    subjects = await service.list_subjects(limit=None)
    for subject in subjects:
        writer.writerow({
            "id": subject.id,
            "email": _cell(subject.email),
            "username": _cell(subject.username or ""),
            "is_active": "true" if subject.is_active else "false",
            "is_verified": "true" if subject.is_verified else "false",
            "created_at": (
                subject.created_at.isoformat() if subject.created_at else ""
            ),
        })

    if isinstance(buffer, io.StringIO):
        return buffer.getvalue()
    return ""


# =============================================================================
# Import
# =============================================================================


async def import_subjects_from_csv(
    service: AdminService,
    csv_text: str | io.TextIOBase,
    *,
    dry_run: bool = False,
    update_existing: bool = False,
) -> BulkImportResult:
    """Import subjects from CSV.

    Args:
        service: The admin service.
        csv_text: CSV content (string or file-like).
        dry_run: If True, validate everything but don't actually create.
        update_existing: If True, update existing subjects (matched by
            email). If False, existing subjects are reported as SKIPPED.

    Returns:
        A `BulkImportResult` with per-row status and counts.
    """
    if isinstance(csv_text, str):
        reader = csv.DictReader(io.StringIO(csv_text))
    else:
        reader = csv.DictReader(csv_text)

    result = BulkImportResult(dry_run=dry_run)

    # Validate headers
    if reader.fieldnames is None:
        return result
    field_set = {f.strip().lower() for f in reader.fieldnames}
    for col in REQUIRED_COLUMNS:
        if col not in field_set:
            row_result = BulkRowResult(
                row_number=0,
                status=BulkRowStatus.FAILED,
                error=f"missing required column: {col}",
            )
            result.add(row_result)
            return result

    # Process rows
    for row_index, raw_row in enumerate(reader, start=1):
        row = {(k or "").strip().lower(): v for k, v in raw_row.items()}
        await _process_row(
            service, row, row_index, result, update_existing=update_existing
        )

    return result


async def _process_row(
    service: AdminService,
    row: dict[str, str],
    row_index: int,
    result: BulkImportResult,
    *,
    update_existing: bool,
) -> None:
    """Validate and apply a single import row, recording its outcome."""
    result.add(
        await _row_outcome(
            service,
            row,
            row_index,
            update_existing=update_existing,
            dry_run=result.dry_run,
        )
    )


async def _row_outcome(
    service: AdminService,
    row: dict[str, str],
    row_index: int,
    *,
    update_existing: bool,
    dry_run: bool,
) -> BulkRowResult:
    try:
        email, fields = validate_row(row)
    except ValueError as e:
        return BulkRowResult(
            row_number=row_index,
            status=BulkRowStatus.FAILED,
            email=row.get("email"),
            error=str(e),
        )

    def outcome(
        status: BulkRowStatus, subject_id: str | None = None, error: str | None = None
    ) -> BulkRowResult:
        return BulkRowResult(
            row_number=row_index,
            status=status,
            email=email,
            subject_id=subject_id,
            error=error,
        )

    existing = None
    with contextlib.suppress(DoesNotExist):
        existing = await service.subject_repo.get_one_by(email=email)

    if existing is not None and not update_existing:
        return outcome(BulkRowStatus.SKIPPED, existing.id, "subject already exists")
    status = BulkRowStatus.UPDATED if existing else BulkRowStatus.CREATED
    if dry_run:
        return outcome(status, existing.id if existing else None)

    try:
        # A savepoint per row: a failed one leaves the session usable.
        async with service.session.begin_nested():
            if existing is not None:
                subject = await service.update_subject(existing.id, **fields)
            else:
                subject = await service.create_subject(**fields)
    except (RepositoryError, SQLAlchemyError) as e:
        verb = "update" if existing else "create"
        return outcome(BulkRowStatus.FAILED, error=f"{verb} failed: {e}")
    return outcome(status, subject.id)


__all__ = [
    "EXPORT_COLUMNS",
    "OPTIONAL_COLUMNS",
    "REQUIRED_COLUMNS",
    "BulkImportResult",
    "BulkRowResult",
    "BulkRowStatus",
    "export_subjects_to_csv",
    "import_subjects_from_csv",
    "validate_row",
]
