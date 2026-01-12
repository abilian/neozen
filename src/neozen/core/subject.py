"""Subject model for NeoZen."""

from __future__ import annotations

import typing

from neozen.core.models import NeoZenModel


class Subject(NeoZenModel):
    """Base class for authenticated subjects (users, services, etc.)."""

    id: typing.Any


__all__ = ["Subject"]
