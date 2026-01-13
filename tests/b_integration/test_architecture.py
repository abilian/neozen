"""
Ref/tuto:

- https://github.com/jwbargsten/pytest-archon
- https://xebia.com/blog/how-to-tame-your-python-codebase/
"""

from __future__ import annotations

from pytest_archon import archrule


def test_core_should_not_import_sqlalchemy() -> None:
    (
        archrule("core should not import sqlalchemy")
        .match("neozen.core.*")
        .should_not_import("sqlalchemy")
        .check("neozen")
    )


def test_core_should_not_import_web() -> None:
    (
        archrule("core should not import web")
        .match("neozen.core.*")
        .should_not_import("neozen.web")
        .check("neozen")
    )


def test_core_should_not_import_storage() -> None:
    (
        archrule("core should not import storage")
        .match("neozen.core.*")
        .should_not_import("neozen.storage")
        .check("neozen")
    )


def test_core_should_not_import_cli() -> None:
    (
        archrule("core should not import cli")
        .match("neozen.core.*")
        .should_not_import("neozen.cli")
        .check("neozen")
    )
