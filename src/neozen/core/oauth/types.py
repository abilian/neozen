"""OAuth type definitions for NeoZen."""

from __future__ import annotations

import typing

type CodeChallengeMethod = typing.Literal["plain", "S256"]

__all__ = ["CodeChallengeMethod"]
