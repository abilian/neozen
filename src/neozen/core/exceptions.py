"""Base exceptions for NeoZen."""

from __future__ import annotations

import typing

from pydantic import ValidationError
from pydantic_core import ErrorDetails


class NeoZenException(Exception):
    """Base exception for all NeoZen exceptions."""

    message: str

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class InvalidRequestError(NeoZenException):
    """Exception raised for invalid requests."""

    def __init__(self, errors: list[ErrorDetails]) -> None:
        message = "Invalid request"
        self.errors = errors
        super().__init__(message)

    @classmethod
    def from_validation_error(cls, error: ValidationError) -> typing.Self:
        return cls(errors=error.errors())


__all__ = ["InvalidRequestError", "NeoZenException"]
