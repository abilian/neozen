"""Factor registry for managing authentication factors."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from .protocol import (
    AuthenticatingFactorProtocol,
    ChallengingFactorProtocol,
    EnrollableFactorProtocol,
    FactorProtocol,
)

logger = logging.getLogger(__name__)


class FactorNotFoundError(Exception):
    """Raised when a requested factor is not found in the registry."""

    def __init__(self, factor_id: str) -> None:
        super().__init__(f"Factor not found: {factor_id}")
        self.factor_id = factor_id


class FactorAlreadyRegisteredError(Exception):
    """Raised when trying to register a factor that already exists."""

    def __init__(self, factor_id: str) -> None:
        super().__init__(f"Factor already registered: {factor_id}")
        self.factor_id = factor_id


class FactorRegistry:
    """Registry for authentication factors.

    The factor registry manages available authentication factors and
    provides methods to query factor availability and enrollment status.

    Example:
        registry = FactorRegistry()

        # Register factors
        registry.register(password_factor)
        registry.register(totp_factor)
        registry.register(webauthn_factor)

        # Get available factors
        all_factors = registry.list_all()

        # Get specific factor
        factor = registry.get("totp")

        # Check enrollment
        enrolled = await registry.list_enrolled("user123")
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._factors: dict[str, FactorProtocol] = {}

    def register(
        self,
        factor: FactorProtocol,
        *,
        replace: bool = False,
    ) -> None:
        """Register a factor.

        Args:
            factor: The factor to register.
            replace: If True, replace existing factor with same ID.

        Raises:
            FactorAlreadyRegisteredError: If factor ID exists and replace=False.
        """
        factor_id = factor.factor_id

        if factor_id in self._factors and not replace:
            raise FactorAlreadyRegisteredError(factor_id)

        self._factors[factor_id] = factor
        logger.debug("Registered factor: %s", factor_id)

    def unregister(self, factor_id: str) -> None:
        """Remove a factor from the registry.

        Args:
            factor_id: ID of the factor to remove.

        Note:
            Does not raise if factor doesn't exist.
        """
        if factor_id in self._factors:
            del self._factors[factor_id]
            logger.debug("Unregistered factor: %s", factor_id)

    def get(self, factor_id: str) -> FactorProtocol:
        """Get a factor by ID.

        Args:
            factor_id: The factor ID to look up.

        Returns:
            The registered factor.

        Raises:
            FactorNotFoundError: If factor is not registered.
        """
        if factor_id not in self._factors:
            raise FactorNotFoundError(factor_id)
        return self._factors[factor_id]

    def get_or_none(self, factor_id: str) -> FactorProtocol | None:
        """Get a factor by ID, or None if not found.

        Args:
            factor_id: The factor ID to look up.

        Returns:
            The registered factor, or None.
        """
        return self._factors.get(factor_id)

    def has(self, factor_id: str) -> bool:
        """Check if a factor is registered.

        Args:
            factor_id: The factor ID to check.

        Returns:
            True if the factor is registered.
        """
        return factor_id in self._factors

    def list_all(self) -> list[FactorProtocol]:
        """List all registered factors.

        Returns:
            List of all registered factors.
        """
        return list(self._factors.values())

    def list_by_type(self, factor_type: str) -> list[FactorProtocol]:
        """List factors by type.

        Args:
            factor_type: The type to filter by ("knowledge", "possession", etc.)

        Returns:
            List of factors matching the type.
        """
        return [f for f in self._factors.values() if f.factor_type == factor_type]

    async def list_enrolled(self, subject_id: str) -> list[str]:
        """List factor IDs enrolled for a subject.

        Args:
            subject_id: The subject to check.

        Returns:
            List of factor IDs the subject has enrolled.
        """
        return [
            factor_id
            for factor_id, factor in self._factors.items()
            if await factor.is_enrolled(subject_id)
        ]

    async def list_available(self, subject_id: str) -> list[FactorProtocol]:
        """List factors available but not enrolled for a subject.

        Args:
            subject_id: The subject to check.

        Returns:
            List of factors the subject can enroll in.
        """
        return [
            factor
            for factor in self._factors.values()
            if not await factor.is_enrolled(subject_id)
            and await factor.supports_subject(subject_id)
        ]

    async def get_enrolled_factors(
        self,
        subject_id: str,
    ) -> list[FactorProtocol]:
        """Get enrolled factor objects for a subject.

        Args:
            subject_id: The subject to check.

        Returns:
            List of factor objects the subject has enrolled.
        """
        return [
            factor
            for factor in self._factors.values()
            if await factor.is_enrolled(subject_id)
        ]

    def get_authenticating_factor(
        self,
        factor_id: str,
    ) -> AuthenticatingFactorProtocol:
        """Get a factor that supports authentication.

        Args:
            factor_id: The factor ID to look up.

        Returns:
            The factor (with authentication support).

        Raises:
            FactorNotFoundError: If factor not found.
            TypeError: If factor doesn't support authentication.
        """
        factor = self.get(factor_id)
        if not isinstance(factor, AuthenticatingFactorProtocol):
            msg = f"Factor {factor_id} does not support authentication"
            raise TypeError(msg)
        return factor

    def get_enrollable_factor(
        self,
        factor_id: str,
    ) -> EnrollableFactorProtocol:
        """Get a factor that supports enrollment.

        Args:
            factor_id: The factor ID to look up.

        Returns:
            The factor (with enrollment support).

        Raises:
            FactorNotFoundError: If factor not found.
            TypeError: If factor doesn't support enrollment.
        """
        factor = self.get(factor_id)
        if not isinstance(factor, EnrollableFactorProtocol):
            msg = f"Factor {factor_id} does not support enrollment"
            raise TypeError(msg)
        return factor

    def get_challenging_factor(
        self,
        factor_id: str,
    ) -> ChallengingFactorProtocol:
        """Get a factor that uses challenge-response.

        Args:
            factor_id: The factor ID to look up.

        Returns:
            The factor (with challenge support).

        Raises:
            FactorNotFoundError: If factor not found.
            TypeError: If factor doesn't support challenges.
        """
        factor = self.get(factor_id)
        if not isinstance(factor, ChallengingFactorProtocol):
            msg = f"Factor {factor_id} does not support challenges"
            raise TypeError(msg)
        return factor

    def clear(self) -> None:
        """Remove all registered factors."""
        self._factors.clear()

    def register_many(
        self,
        factors: Iterable[FactorProtocol],
        *,
        replace: bool = False,
    ) -> None:
        """Register multiple factors at once.

        Args:
            factors: Factors to register.
            replace: If True, replace existing factors.
        """
        for factor in factors:
            self.register(factor, replace=replace)

    @property
    def factor_count(self) -> int:
        """Number of registered factors."""
        return len(self._factors)

    @property
    def factor_ids(self) -> list[str]:
        """List of registered factor IDs."""
        return list(self._factors.keys())

    def get_factor_info(self) -> list[dict[str, Any]]:
        """Get summary information about all factors.

        Returns:
            List of factor info dicts with id, name, type.
        """
        return [
            {
                "factor_id": f.factor_id,
                "display_name": f.display_name,
                "factor_type": f.factor_type,
            }
            for f in self._factors.values()
        ]
