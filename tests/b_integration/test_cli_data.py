"""Integration tests for CLI data commands (dump, restore, populate)."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import pytest

from neozen.cli.commands import data


@pytest.fixture
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Set up an isolated SQLite database for the test."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("NEOZEN_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    return db_path


def make_args(**kwargs: object) -> argparse.Namespace:
    """Build an argparse-like namespace."""
    return argparse.Namespace(**kwargs)


class TestPopulate:
    def test_populate_default_count(
        self, isolated_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = data.populate(make_args(count=10))
        assert result == 0
        captured = capsys.readouterr()
        assert "Created 10 test users" in captured.out

    def test_populate_custom_count(
        self, isolated_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = data.populate(make_args(count=5))
        assert result == 0
        captured = capsys.readouterr()
        assert "Created 5 test users" in captured.out


class TestDump:
    def test_dump_empty_database(self, isolated_db: Path, tmp_path: Path) -> None:
        output_file = tmp_path / "dump.json"
        result = data.dump(make_args(output=str(output_file)))
        assert result == 0
        assert output_file.exists()

        dump_data = json.loads(output_file.read_text())
        assert dump_data["version"] == 1
        assert "exported_at" in dump_data
        assert dump_data["subjects"] == []
        assert dump_data["roles"] == []
        assert dump_data["role_assignments"] == []

    def test_dump_with_subjects(self, isolated_db: Path, tmp_path: Path) -> None:
        # Populate first
        data.populate(make_args(count=3))

        output_file = tmp_path / "dump.json"
        result = data.dump(make_args(output=str(output_file)))
        assert result == 0

        dump_data = json.loads(output_file.read_text())
        assert len(dump_data["subjects"]) == 3
        assert all("email" in s for s in dump_data["subjects"])
        assert all("hashed_password" in s for s in dump_data["subjects"])

    def test_dump_to_stdout(
        self, isolated_db: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = data.dump(make_args(output=None))
        assert result == 0
        captured = capsys.readouterr()
        dump_data = json.loads(captured.out)
        assert dump_data["version"] == 1


class TestRestore:
    def test_restore_missing_file(self, isolated_db: Path, tmp_path: Path) -> None:
        result = data.restore(make_args(input=str(tmp_path / "nope.json")))
        assert result == 1

    def test_restore_invalid_json(self, isolated_db: Path, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json")
        result = data.restore(make_args(input=str(bad_file)))
        assert result == 1

    def test_restore_unsupported_version(
        self, isolated_db: Path, tmp_path: Path
    ) -> None:
        bad_file = tmp_path / "v999.json"
        bad_file.write_text(json.dumps({"version": 999, "subjects": []}))
        result = data.restore(make_args(input=str(bad_file)))
        assert result == 1

    def test_restore_round_trip(self, isolated_db: Path, tmp_path: Path) -> None:
        """Populate, dump, wipe DB, restore, dump again — should match."""
        # Populate and dump
        data.populate(make_args(count=5))

        dump_file = tmp_path / "dump.json"
        data.dump(make_args(output=str(dump_file)))

        original = json.loads(dump_file.read_text())
        original_emails = sorted(s["email"] for s in original["subjects"])

        # Switch to fresh DB
        new_db = tmp_path / "fresh.db"
        os.environ["NEOZEN_DATABASE_URL"] = f"sqlite+aiosqlite:///{new_db}"

        # Restore
        result = data.restore(make_args(input=str(dump_file)))
        assert result == 0

        # Verify
        restored_dump = tmp_path / "restored.json"
        data.dump(make_args(output=str(restored_dump)))
        restored = json.loads(restored_dump.read_text())
        restored_emails = sorted(s["email"] for s in restored["subjects"])

        assert restored_emails == original_emails

    def test_restore_skips_existing(self, isolated_db: Path, tmp_path: Path) -> None:
        """Restoring the same dump twice should not create duplicates."""
        data.populate(make_args(count=3))
        dump_file = tmp_path / "dump.json"
        data.dump(make_args(output=str(dump_file)))

        # Restore once (no-op since records exist)
        result = data.restore(make_args(input=str(dump_file)))
        assert result == 0

        # Verify count unchanged
        verify_dump = tmp_path / "verify.json"
        data.dump(make_args(output=str(verify_dump)))
        verify = json.loads(verify_dump.read_text())
        assert len(verify["subjects"]) == 3
