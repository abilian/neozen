"""Entry point for python -m neozen.cli."""

from __future__ import annotations

import sys

from neozen.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
