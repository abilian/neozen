"""NeoZen Command-Line Interface.

A CLI for managing NeoZen authentication services.
Uses stdlib argparse only (no Click/Typer dependencies).
"""

from __future__ import annotations

from neozen.cli.main import main

__all__ = ["main"]
