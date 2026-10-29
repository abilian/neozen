"""Endpoint smoke tests for the admin bulk import/export UI.

Covers the new /users/import (GET + POST in dry-run and apply modes)
and /users/export routes added during the 1.0 admin bulk-ops UI work.

These tests use Litestar's TestClient and exercise the route layer
end-to-end against a SQLite database. They are intentionally
narrow: the heavy lifting is already covered by tests in
test_admin_bulk.py (which test the bulk module directly). What we
verify here is the wiring: form submission → bulk module → response.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from litestar.testing import TestClient

from neozen.admin.app import create_admin_app
from neozen.admin.config import AdminConfig

from .conftest import superadmin_client


@pytest.fixture
def admin_client(tmp_path: Path) -> TestClient:
    # A file: the tests restart the app, which disposes the engine, and an
    # in-memory database would go with it.
    config = AdminConfig(
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'admin.db'}",
        secret_key="test-secret-key",
    )
    return superadmin_client(create_admin_app(config))


class TestImportFormGet:
    def test_returns_200_with_form(self, admin_client: TestClient) -> None:
        with admin_client as client:
            response = client.get("/users/import")
        assert response.status_code == 200
        body = response.text
        assert "Upload CSV File" in body
        assert "Dry run" in body
        assert "Apply import" in body
        # No result block on initial GET
        assert "Dry run preview" not in body
        assert "Import results" not in body


class TestImportPostDryRun:
    def test_dry_run_shows_preview_without_persisting(
        self, admin_client: TestClient
    ) -> None:
        csv_content = "email,username\nalice@example.com,alice\nbob@example.com,bob\n"
        files = {
            "csv_file": ("users.csv", io.BytesIO(csv_content.encode()), "text/csv")
        }
        with admin_client as client:
            response = client.post(
                "/users/import",
                files=files,
                data={"action": "dry_run"},
            )
        assert response.status_code == 200
        body = response.text
        assert "Dry run preview" in body
        assert "Not yet applied" in body
        assert "alice@example.com" in body
        assert "bob@example.com" in body

        # Verify nothing was persisted by hitting export
        with admin_client as client:
            export = client.get("/users/export")
        assert export.status_code == 200
        assert "alice@example.com" not in export.text
        assert "bob@example.com" not in export.text

    def test_dry_run_reports_validation_failures(
        self, admin_client: TestClient
    ) -> None:
        csv_content = "email,username\nnot-an-email,bob\n,carol\n"
        files = {"csv_file": ("bad.csv", io.BytesIO(csv_content.encode()), "text/csv")}
        with admin_client as client:
            response = client.post(
                "/users/import",
                files=files,
                data={"action": "dry_run"},
            )
        assert response.status_code == 200
        body = response.text
        assert "failed" in body.lower()
        assert "invalid email" in body
        assert "email is required" in body


class TestImportPostApply:
    def test_apply_creates_users_and_returns_results(
        self, admin_client: TestClient
    ) -> None:
        csv_content = "email\nalice@example.com\nbob@example.com\n"
        files = {
            "csv_file": ("users.csv", io.BytesIO(csv_content.encode()), "text/csv")
        }
        with admin_client as client:
            response = client.post(
                "/users/import",
                files=files,
                data={"action": "apply"},
            )
        assert response.status_code == 200
        body = response.text
        assert "Import results" in body
        assert "Committed" in body
        assert "alice@example.com" in body

        # Verify they actually exist via export
        with admin_client as client:
            export = client.get("/users/export")
        assert export.status_code == 200
        assert "alice@example.com" in export.text
        assert "bob@example.com" in export.text


class TestImportRejectsBadInput:
    def test_missing_file_redirects(self, admin_client: TestClient) -> None:
        with admin_client as client:
            response = client.post(
                "/users/import",
                data={"action": "dry_run"},
                follow_redirects=False,
            )
        assert response.status_code == 303
        assert response.headers["location"] == "/users/import"

    def test_non_utf8_file_redirects(self, admin_client: TestClient) -> None:
        # Latin-1 byte that isn't valid UTF-8 mid-stream
        bad_bytes = b"email\nfoo\xc3\x28@example.com\n"
        files = {"csv_file": ("bad.csv", io.BytesIO(bad_bytes), "text/csv")}
        with admin_client as client:
            response = client.post(
                "/users/import",
                files=files,
                data={"action": "dry_run"},
                follow_redirects=False,
            )
        assert response.status_code == 303
        assert response.headers["location"] == "/users/import"


class TestExport:
    def test_export_returns_csv_with_correct_headers(
        self, admin_client: TestClient
    ) -> None:
        with admin_client as client:
            response = client.get("/users/export")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        assert "attachment" in response.headers["content-disposition"]
        assert 'filename="neozen-users.csv"' in response.headers["content-disposition"]
        # Header row present
        first_line = response.text.split("\n", 1)[0]
        for col in ("id", "email", "username", "is_active"):
            assert col in first_line
