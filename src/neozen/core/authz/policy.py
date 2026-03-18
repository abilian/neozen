"""Policy system for flexible authorization.

Policies provide code-based authorization logic for cases where
simple RBAC is insufficient. Policies can:
- Explicitly allow an action
- Explicitly deny an action
- Abstain (let other policies decide)
"""

from __future__ import annotations

import typing
from dataclasses import dataclass
from enum import Enum

if typing.TYPE_CHECKING:
    from neozen.core.authz.models import Role


class PolicyResult(Enum):
    """Result of a policy evaluation."""

    ALLOW = "allow"  # Explicitly allow the action
    DENY = "deny"  # Explicitly deny the action
    ABSTAIN = "abstain"  # No opinion, let other policies decide


@typing.runtime_checkable
class Policy(typing.Protocol):
    """Protocol for authorization policies.

    Policies are evaluated in order. The first policy to return
    ALLOW or DENY wins. If all policies return ABSTAIN, the
    default behavior is DENY.
    """

    def evaluate(
        self,
        subject_id: str,
        action: str,
        resource: typing.Any | None = None,
        context: dict[str, typing.Any] | None = None,
    ) -> PolicyResult:
        """Evaluate whether the action is allowed.

        Args:
            subject_id: The subject attempting the action
            action: The action being attempted (permission string)
            resource: The resource being accessed (if applicable)
            context: Additional context for the decision

        Returns:
            PolicyResult indicating whether to allow, deny, or abstain
        """
        ...


@dataclass
class PolicyChain:
    """Evaluates a chain of policies in order.

    The first policy to return ALLOW or DENY wins.
    If all policies return ABSTAIN, returns DENY by default.
    """

    policies: list[Policy]
    default_deny: bool = True

    def evaluate(
        self,
        subject_id: str,
        action: str,
        resource: typing.Any | None = None,
        context: dict[str, typing.Any] | None = None,
    ) -> PolicyResult:
        """Evaluate all policies in order.

        Args:
            subject_id: The subject attempting the action
            action: The action being attempted
            resource: The resource being accessed
            context: Additional context for the decision

        Returns:
            ALLOW if any policy allows, DENY if any denies or default
        """
        for policy in self.policies:
            result = policy.evaluate(subject_id, action, resource, context)
            if result != PolicyResult.ABSTAIN:
                return result

        return PolicyResult.DENY if self.default_deny else PolicyResult.ALLOW

    def add_policy(self, policy: Policy) -> None:
        """Add a policy to the chain."""
        self.policies.append(policy)


class OwnerPolicy:
    """Policy that allows actions on resources owned by the subject.

    This policy checks if the resource has an `owner_id` attribute
    that matches the subject_id.
    """

    def __init__(
        self,
        *,
        owner_attribute: str = "owner_id",
        allowed_actions: set[str] | None = None,
    ) -> None:
        """Initialize the owner policy.

        Args:
            owner_attribute: The attribute name for the owner ID
            allowed_actions: Actions to allow for owners (None = all)
        """
        self.owner_attribute = owner_attribute
        self.allowed_actions = allowed_actions

    def evaluate(
        self,
        subject_id: str,
        action: str,
        resource: typing.Any | None = None,
        context: dict[str, typing.Any] | None = None,
    ) -> PolicyResult:
        """Check if the subject owns the resource."""
        if resource is None:
            return PolicyResult.ABSTAIN

        # Check if we should handle this action
        if self.allowed_actions is not None and action not in self.allowed_actions:
            return PolicyResult.ABSTAIN

        # Check ownership
        owner_id = getattr(resource, self.owner_attribute, None)
        if owner_id is None:
            return PolicyResult.ABSTAIN

        if owner_id == subject_id:
            return PolicyResult.ALLOW

        return PolicyResult.ABSTAIN


class RolePolicy:
    """Policy that checks role-based permissions.

    This policy requires access to the subject's roles and checks
    if any role grants the required permission.
    """

    def __init__(
        self,
        get_roles: typing.Callable[[str], typing.Awaitable[list[Role]]]
        | typing.Callable[[str], list[Role]],
    ) -> None:
        """Initialize the role policy.

        Args:
            get_roles: Function to get roles for a subject ID
                      (can be sync or async)
        """
        self._get_roles = get_roles
        self._roles_cache: dict[str, list[Role]] = {}

    def set_roles(self, subject_id: str, roles: list[Role]) -> None:
        """Pre-set roles for a subject (for sync evaluation)."""
        self._roles_cache[subject_id] = roles

    def evaluate(
        self,
        subject_id: str,
        action: str,
        resource: typing.Any | None = None,
        context: dict[str, typing.Any] | None = None,
    ) -> PolicyResult:
        """Check if any of the subject's roles grant the permission."""
        # Get roles from cache (must be pre-populated for sync evaluation)
        roles = self._roles_cache.get(subject_id, [])

        for role in roles:
            if role.has_permission(action):
                return PolicyResult.ALLOW

        return PolicyResult.ABSTAIN
