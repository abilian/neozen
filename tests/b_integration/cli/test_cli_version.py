"""`neozen --version` reports the version declared in pyproject.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from neozen.cli.main import main

PYPROJECT = Path(__file__).parents[3] / "pyproject.toml"


def test_version_matches_pyproject(capsys: pytest.CaptureFixture[str]) -> None:
    expected = tomllib.loads(PYPROJECT.read_text())["project"]["version"]

    with pytest.raises(SystemExit):
        main(["--version"])

    assert capsys.readouterr().out.strip() == f"neozen {expected}"
