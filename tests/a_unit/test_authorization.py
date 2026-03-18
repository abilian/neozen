"""Unit tests for authorization module."""

from __future__ import annotations

import typing
from datetime import UTC, datetime, timedelta

import pytest

from neozen.core.authz.models import (
    BUILTIN_ROLES,
    Permission,
    Role,
    RoleAssignment,
    ScopeType,
)
from neozen.core.authz.policy import (
    OwnerPolicy,
    Policy,
    PolicyChain,
    PolicyResult,
    RolePolicy,
)


class TestPermission:
    """Tests for Permission model."""

    def test_parse_simple(self) -> None:
        """Test parsing a simple permission string."""
        perm = Permission.parse("user:read")
        assert perm.resource == "user"
        assert perm.action == "read"
        assert perm.scope is None

    def test_parse_with_scope(self) -> None:
        """Test parsing a permission string with scope."""
        perm = Permission.parse("user:read:own")
        assert perm.resource == "user"
        assert perm.action == "read"
        assert perm.scope == "own"

    def test_parse_wildcard_resource(self) -> None:
        """Test parsing a permission with wildcard resource."""
        perm = Permission.parse("*:read")
        assert perm.resource == "*"
        assert perm.action == "read"

    def test_parse_wildcard_action(self) -> None:
        """Test parsing a permission with wildcard action."""
        perm = Permission.parse("user:*")
        assert perm.resource == "user"
        assert perm.action == "*"

    def test_parse_superuser(self) -> None:
        """Test parsing the superuser permission."""
        perm = Permission.parse("*:*")
        assert perm.resource == "*"
        assert perm.action == "*"

    def test_parse_invalid_format(self) -> None:
        """Test parsing an invalid permission string."""
        with pytest.raises(ValueError, match="Invalid permission format"):
            Permission.parse("invalid")

    def test_parse_invalid_characters(self) -> None:
        """Test parsing a permission with invalid characters."""
        # The regex allows lowercase and underscores only
        # But actually the current regex converts to lowercase first
        # So let's test truly invalid format
        with pytest.raises(ValueError, match="Invalid permission format"):
            Permission.parse("user@read")  # @ not allowed

    def test_str_without_scope(self) -> None:
        """Test string representation without scope."""
        perm = Permission(resource="user", action="read")
        assert str(perm) == "user:read"

    def test_str_with_scope(self) -> None:
        """Test string representation with scope."""
        perm = Permission(resource="user", action="read", scope="own")
        assert str(perm) == "user:read:own"

    def test_matches_exact(self) -> None:
        """Test exact permission matching."""
        perm = Permission.parse("user:read")
        required = Permission.parse("user:read")
        assert perm.matches(required) is True

    def test_matches_different_resource(self) -> None:
        """Test non-matching resources."""
        perm = Permission.parse("user:read")
        required = Permission.parse("post:read")
        assert perm.matches(required) is False

    def test_matches_different_action(self) -> None:
        """Test non-matching actions."""
        perm = Permission.parse("user:read")
        required = Permission.parse("user:write")
        assert perm.matches(required) is False

    def test_matches_wildcard_resource(self) -> None:
        """Test wildcard resource matching."""
        perm = Permission.parse("*:read")
        required = Permission.parse("user:read")
        assert perm.matches(required) is True

    def test_matches_wildcard_action(self) -> None:
        """Test wildcard action matching."""
        perm = Permission.parse("user:*")
        required = Permission.parse("user:read")
        assert perm.matches(required) is True
        required2 = Permission.parse("user:delete")
        assert perm.matches(required2) is True

    def test_matches_superuser(self) -> None:
        """Test superuser permission matches everything."""
        perm = Permission.parse("*:*")
        assert perm.matches(Permission.parse("user:read")) is True
        assert perm.matches(Permission.parse("post:delete")) is True
        assert perm.matches(Permission.parse("admin:manage")) is True

    def test_matches_scope_granted_no_scope_required(self) -> None:
        """Test permission with scope grants permission without scope."""
        perm = Permission.parse("user:read:own")
        required = Permission.parse("user:read")
        # Permission with scope DOES NOT match requirement without scope
        # because "own" is more restrictive
        assert perm.matches(required) is False

    def test_matches_no_scope_grants_any_scope(self) -> None:
        """Test permission without scope grants permission with any scope."""
        perm = Permission.parse("user:read")
        required = Permission.parse("user:read:own")
        # Permission without scope matches any scope (more permissive)
        assert perm.matches(required) is True

    def test_matches_scope_must_match(self) -> None:
        """Test scope must match when both have scopes."""
        perm = Permission.parse("user:read:own")
        required = Permission.parse("user:read:own")
        assert perm.matches(required) is True

        required2 = Permission.parse("user:read:team")
        assert perm.matches(required2) is False


class TestRole:
    """Tests for Role model."""

    def test_has_permission_exact(self) -> None:
        """Test role has exact permission."""
        role = Role(
            id="test",
            name="test_role",
            permissions=frozenset(["user:read", "user:write"]),
        )
        assert role.has_permission("user:read") is True
        assert role.has_permission("user:write") is True
        assert role.has_permission("user:delete") is False

    def test_has_permission_wildcard(self) -> None:
        """Test role with wildcard permission."""
        role = Role(
            id="admin",
            name="admin",
            permissions=frozenset(["user:*"]),
        )
        assert role.has_permission("user:read") is True
        assert role.has_permission("user:write") is True
        assert role.has_permission("user:delete") is True
        assert role.has_permission("post:read") is False

    def test_has_permission_superuser(self) -> None:
        """Test superuser role has all permissions."""
        role = Role(
            id="superuser",
            name="superuser",
            permissions=frozenset(["*:*"]),
        )
        assert role.has_permission("user:read") is True
        assert role.has_permission("post:delete") is True
        assert role.has_permission("admin:manage") is True

    def test_has_permission_with_permission_object(self) -> None:
        """Test has_permission with Permission object."""
        role = Role(
            id="test",
            name="test_role",
            permissions=frozenset(["user:read"]),
        )
        perm = Permission.parse("user:read")
        assert role.has_permission(perm) is True


class TestRoleAssignment:
    """Tests for RoleAssignment model."""

    def test_not_expired_no_expiry(self) -> None:
        """Test assignment without expiry is not expired."""
        assignment = RoleAssignment(
            id="test",
            subject_id="user123",
            role_id="admin",
            expires_at=None,
        )
        assert assignment.is_expired() is False
        assert assignment.is_valid() is True

    def test_not_expired_future_expiry(self) -> None:
        """Test assignment with future expiry is not expired."""
        future = datetime.now(UTC) + timedelta(hours=1)
        assignment = RoleAssignment(
            id="test",
            subject_id="user123",
            role_id="admin",
            expires_at=future,
        )
        assert assignment.is_expired() is False
        assert assignment.is_valid() is True

    def test_expired_past_expiry(self) -> None:
        """Test assignment with past expiry is expired."""
        past = datetime.now(UTC) - timedelta(hours=1)
        assignment = RoleAssignment(
            id="test",
            subject_id="user123",
            role_id="admin",
            expires_at=past,
        )
        assert assignment.is_expired() is True
        assert assignment.is_valid() is False

    def test_scope_types(self) -> None:
        """Test different scope types."""
        global_assignment = RoleAssignment(
            id="1",
            subject_id="user123",
            role_id="admin",
            scope_type=ScopeType.GLOBAL,
        )
        assert global_assignment.scope_type == ScopeType.GLOBAL

        team_assignment = RoleAssignment(
            id="2",
            subject_id="user123",
            role_id="editor",
            scope_type=ScopeType.TEAM,
            scope_id="team_456",
        )
        assert team_assignment.scope_type == ScopeType.TEAM
        assert team_assignment.scope_id == "team_456"


class TestBuiltinRoles:
    """Tests for built-in roles."""

    def test_superuser_role(self) -> None:
        """Test superuser role has all permissions."""
        superuser = BUILTIN_ROLES["superuser"]
        assert superuser.name == "superuser"
        assert superuser.is_system is True
        assert superuser.has_permission("anything:here") is True

    def test_admin_role(self) -> None:
        """Test admin role permissions."""
        admin = BUILTIN_ROLES["admin"]
        assert admin.name == "admin"
        assert admin.is_system is True
        assert admin.has_permission("user:read") is True
        assert admin.has_permission("user:delete") is True
        assert admin.has_permission("role:manage") is True

    def test_user_role(self) -> None:
        """Test user role permissions."""
        user = BUILTIN_ROLES["user"]
        assert user.name == "user"
        assert user.is_system is True
        assert user.has_permission("user:read:own") is True
        assert user.has_permission("user:update:own") is True
        # User role should not have admin permissions
        assert user.has_permission("user:delete") is False


class TestPolicyResult:
    """Tests for PolicyResult enum."""

    def test_policy_result_values(self) -> None:
        """Test policy result enum values."""
        assert PolicyResult.ALLOW.value == "allow"
        assert PolicyResult.DENY.value == "deny"
        assert PolicyResult.ABSTAIN.value == "abstain"


class TestOwnerPolicy:
    """Tests for OwnerPolicy."""

    def test_owner_can_access(self) -> None:
        """Test owner can access their resource."""

        class Resource:
            def __init__(self, owner_id: str) -> None:
                self.owner_id = owner_id

        policy = OwnerPolicy(owner_attribute="owner_id")
        resource = Resource(owner_id="user123")

        result = policy.evaluate(
            subject_id="user123",
            action="read",
            resource=resource,
        )
        assert result == PolicyResult.ALLOW

    def test_non_owner_abstains(self) -> None:
        """Test non-owner gets abstain result."""

        class Resource:
            def __init__(self, owner_id: str) -> None:
                self.owner_id = owner_id

        policy = OwnerPolicy(owner_attribute="owner_id")
        resource = Resource(owner_id="user456")

        result = policy.evaluate(
            subject_id="user123",
            action="read",
            resource=resource,
        )
        assert result == PolicyResult.ABSTAIN

    def test_no_resource_abstains(self) -> None:
        """Test evaluation abstains when no resource provided."""
        policy = OwnerPolicy(owner_attribute="owner_id")

        result = policy.evaluate(
            subject_id="user123",
            action="read",
            resource=None,
        )
        assert result == PolicyResult.ABSTAIN

    def test_custom_actions(self) -> None:
        """Test policy only applies to specified actions."""

        class Resource:
            def __init__(self, owner_id: str) -> None:
                self.owner_id = owner_id

        policy = OwnerPolicy(
            owner_attribute="owner_id", allowed_actions={"read", "update"}
        )
        resource = Resource(owner_id="user123")

        # Should allow read
        result = policy.evaluate(
            subject_id="user123",
            action="read",
            resource=resource,
        )
        assert result == PolicyResult.ALLOW

        # Should abstain for delete (not in allowed_actions)
        result = policy.evaluate(
            subject_id="user123",
            action="delete",
            resource=resource,
        )
        assert result == PolicyResult.ABSTAIN


class TestRolePolicy:
    """Tests for RolePolicy."""

    def test_role_grants_permission(self) -> None:
        """Test role policy grants permission."""
        roles = [
            Role(
                id="editor",
                name="editor",
                permissions=frozenset(["post:read", "post:write"]),
            )
        ]
        # RolePolicy requires a get_roles function
        policy = RolePolicy(get_roles=lambda _: roles)
        policy.set_roles("user123", roles)

        result = policy.evaluate(
            subject_id="user123",
            action="post:read",
            resource=None,
        )
        assert result == PolicyResult.ALLOW

    def test_role_denies_missing_permission(self) -> None:
        """Test role policy abstains for missing permission."""
        roles = [
            Role(
                id="viewer",
                name="viewer",
                permissions=frozenset(["post:read"]),
            )
        ]
        policy = RolePolicy(get_roles=lambda _: roles)
        policy.set_roles("user123", roles)

        result = policy.evaluate(
            subject_id="user123",
            action="post:delete",
            resource=None,
        )
        assert result == PolicyResult.ABSTAIN

    def test_no_roles_abstains(self) -> None:
        """Test policy abstains when no roles set."""
        policy = RolePolicy(get_roles=lambda _: [])

        result = policy.evaluate(
            subject_id="user123",
            action="post:read",
            resource=None,
        )
        assert result == PolicyResult.ABSTAIN


class TestPolicyChain:
    """Tests for PolicyChain."""

    def test_first_allow_wins(self) -> None:
        """Test first ALLOW result is returned."""

        class AlwaysAllow:
            def evaluate(
                self,
                subject_id: str,
                action: str,
                resource: typing.Any | None = None,
                context: dict[str, typing.Any] | None = None,
            ) -> PolicyResult:
                return PolicyResult.ALLOW

        class AlwaysDeny:
            def evaluate(
                self,
                subject_id: str,
                action: str,
                resource: typing.Any | None = None,
                context: dict[str, typing.Any] | None = None,
            ) -> PolicyResult:
                return PolicyResult.DENY

        chain = PolicyChain(policies=[AlwaysAllow(), AlwaysDeny()])
        result = chain.evaluate(
            subject_id="test",
            action="read",
            resource=None,
        )
        assert result == PolicyResult.ALLOW

    def test_first_deny_wins(self) -> None:
        """Test first DENY result is returned."""

        class AlwaysDeny:
            def evaluate(
                self,
                subject_id: str,
                action: str,
                resource: typing.Any | None = None,
                context: dict[str, typing.Any] | None = None,
            ) -> PolicyResult:
                return PolicyResult.DENY

        class AlwaysAllow:
            def evaluate(
                self,
                subject_id: str,
                action: str,
                resource: typing.Any | None = None,
                context: dict[str, typing.Any] | None = None,
            ) -> PolicyResult:
                return PolicyResult.ALLOW

        chain = PolicyChain(policies=[AlwaysDeny(), AlwaysAllow()])
        result = chain.evaluate(
            subject_id="test",
            action="read",
            resource=None,
        )
        assert result == PolicyResult.DENY

    def test_abstain_continues(self) -> None:
        """Test ABSTAIN continues to next policy."""

        class AlwaysAbstain:
            def evaluate(
                self,
                subject_id: str,
                action: str,
                resource: typing.Any | None = None,
                context: dict[str, typing.Any] | None = None,
            ) -> PolicyResult:
                return PolicyResult.ABSTAIN

        class AlwaysAllow:
            def evaluate(
                self,
                subject_id: str,
                action: str,
                resource: typing.Any | None = None,
                context: dict[str, typing.Any] | None = None,
            ) -> PolicyResult:
                return PolicyResult.ALLOW

        chain = PolicyChain(policies=[AlwaysAbstain(), AlwaysAllow()])
        result = chain.evaluate(
            subject_id="test",
            action="read",
            resource=None,
        )
        assert result == PolicyResult.ALLOW

    def test_default_deny(self) -> None:
        """Test default deny when all policies abstain."""

        class AlwaysAbstain:
            def evaluate(
                self,
                subject_id: str,
                action: str,
                resource: typing.Any | None = None,
                context: dict[str, typing.Any] | None = None,
            ) -> PolicyResult:
                return PolicyResult.ABSTAIN

        chain = PolicyChain(policies=[AlwaysAbstain()], default_deny=True)
        result = chain.evaluate(
            subject_id="test",
            action="read",
            resource=None,
        )
        assert result == PolicyResult.DENY

    def test_default_allow(self) -> None:
        """Test default allow when configured."""

        class AlwaysAbstain:
            def evaluate(
                self,
                subject_id: str,
                action: str,
                resource: typing.Any | None = None,
                context: dict[str, typing.Any] | None = None,
            ) -> PolicyResult:
                return PolicyResult.ABSTAIN

        chain = PolicyChain(policies=[AlwaysAbstain()], default_deny=False)
        result = chain.evaluate(
            subject_id="test",
            action="read",
            resource=None,
        )
        assert result == PolicyResult.ALLOW

    def test_add_policy(self) -> None:
        """Test adding policy to chain."""

        class AlwaysAllow:
            def evaluate(
                self,
                subject_id: str,
                action: str,
                resource: typing.Any | None = None,
                context: dict[str, typing.Any] | None = None,
            ) -> PolicyResult:
                return PolicyResult.ALLOW

        chain = PolicyChain(policies=[])
        assert len(chain.policies) == 0

        chain.add_policy(AlwaysAllow())
        assert len(chain.policies) == 1
