"""Unified identifier lookup service for NeoZen."""

from __future__ import annotations

import re
import typing

from neozen.core.identifiers.base import (
    IdentifierProtocol,
    InvalidIdentifierFormat,
)
from neozen.core.repository import DoesNotExist
from neozen.core.subject import Subject

# Pattern to detect email addresses
EMAIL_PATTERN = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

# Pattern to detect phone numbers (starts with + or digits)
PHONE_PATTERN = re.compile(r"^\+?[0-9\s\-()]+$")


class IdentifierType(typing.NamedTuple):
    """Represents an identifier type with its handler."""

    name: str
    identifier: IdentifierProtocol[typing.Any]


class IdentifierLookupService[S: Subject]:
    """Service for looking up subjects by any identifier type.

    This service manages multiple identifier types and can:
    - Auto-detect the type of an identifier
    - Look up subjects by any registered identifier
    - Register and unregister identifier handlers

    Example:
        lookup = IdentifierLookupService()
        lookup.register("email", email_identifier)
        lookup.register("username", username_identifier)

        # Auto-detect and lookup
        subject = await lookup.lookup("user@example.com")  # Uses email
        subject = await lookup.lookup("john_doe")  # Uses username

        # Explicit lookup
        subject = await lookup.lookup_by_type("email", "user@example.com")

    """

    def __init__(self) -> None:
        self._identifiers: dict[str, IdentifierProtocol[S]] = {}
        self._detection_order: list[str] = []

    def register(
        self,
        name: str,
        identifier: IdentifierProtocol[S],
        *,
        detection_priority: int | None = None,
    ) -> None:
        """Register an identifier handler.

        Args:
            name: The name of the identifier type (e.g., "email", "username").
            identifier: The identifier protocol implementation.
            detection_priority: Position in auto-detection order (lower = first).
                If None, appends to the end.

        """
        self._identifiers[name] = identifier
        if name not in self._detection_order:
            if detection_priority is not None:
                self._detection_order.insert(detection_priority, name)
            else:
                self._detection_order.append(name)

    def unregister(self, name: str) -> None:
        """Unregister an identifier handler."""
        self._identifiers.pop(name, None)
        if name in self._detection_order:
            self._detection_order.remove(name)

    def get_identifier(self, name: str) -> IdentifierProtocol[S]:
        """Get an identifier handler by name.

        Raises:
            KeyError: If the identifier type is not registered.

        """
        return self._identifiers[name]

    @property
    def registered_types(self) -> list[str]:
        """Return list of registered identifier type names."""
        return list(self._detection_order)

    def detect_type(self, identifier: str) -> str | None:
        """Detect the type of an identifier.

        Uses heuristics to determine the most likely identifier type:
        - Contains @ and . → email
        - Starts with + or contains only digits → phone
        - Otherwise → username (fallback)

        Returns:
            The detected identifier type name, or None if no match.

        """
        if not isinstance(identifier, str):
            return None

        # Check for email pattern
        if "email" in self._identifiers and EMAIL_PATTERN.match(identifier):
            return "email"

        # Check for phone pattern
        if "phone" in self._identifiers and PHONE_PATTERN.match(identifier):
            # Additional check: must have enough digits
            digits = re.sub(r"\D", "", identifier)
            if len(digits) >= 7:  # Minimum phone number length
                return "phone"

        # Default to username if registered
        if "username" in self._identifiers:
            return "username"

        # Return first available identifier type
        return self._detection_order[0] if self._detection_order else None

    async def lookup(self, identifier: str) -> S:
        """Look up a subject by auto-detecting identifier type.

        Args:
            identifier: The identifier value to look up.

        Returns:
            The subject matching the identifier.

        Raises:
            DoesNotExist: If no subject matches any identifier type.
            InvalidIdentifierFormat: If identifier format is invalid.

        """
        detected_type = self.detect_type(identifier)
        if detected_type:
            try:
                return await self.lookup_by_type(detected_type, identifier)
            except DoesNotExist:
                pass  # Try other types

        # Fall back to trying all types
        return await self.lookup_any(identifier)

    async def lookup_by_type(self, type_name: str, identifier: str) -> S:
        """Look up a subject by a specific identifier type.

        Args:
            type_name: The identifier type name (e.g., "email").
            identifier: The identifier value to look up.

        Returns:
            The subject matching the identifier.

        Raises:
            KeyError: If the identifier type is not registered.
            DoesNotExist: If no subject matches.
            InvalidIdentifierFormat: If identifier format is invalid.

        """
        handler = self._identifiers[type_name]
        parsed = await handler.parse_identifier(identifier)
        return await handler.get_by_identifier(parsed)

    async def lookup_any(self, identifier: str) -> S:
        """Try to look up a subject using all registered identifier types.

        Tries each identifier type in detection order until one succeeds.

        Args:
            identifier: The identifier value to look up.

        Returns:
            The subject matching the identifier.

        Raises:
            DoesNotExist: If no subject matches any identifier type.

        """
        last_error: Exception | None = None

        for type_name in self._detection_order:
            handler = self._identifiers[type_name]
            try:
                parsed = await handler.parse_identifier(identifier)
                return await handler.get_by_identifier(parsed)
            except (DoesNotExist, InvalidIdentifierFormat) as e:
                last_error = e
                continue

        if last_error:
            raise DoesNotExist from last_error
        raise DoesNotExist

    async def verify_and_normalize(self, type_name: str, identifier: str) -> str:
        """Verify and normalize an identifier.

        Args:
            type_name: The identifier type name.
            identifier: The identifier value to verify.

        Returns:
            The verified and normalized identifier.

        Raises:
            KeyError: If the identifier type is not registered.
            IdentifierVerificationError: If verification fails.

        """
        handler = self._identifiers[type_name]
        parsed = await handler.parse_identifier(identifier)
        return await handler.verify_identifier(parsed)


__all__ = [
    "IdentifierLookupService",
    "IdentifierType",
]
