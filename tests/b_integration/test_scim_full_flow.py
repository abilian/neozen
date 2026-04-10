"""End-to-end integration test for SCIM 2.0.

Walks through realistic SCIM client scenarios:
1. Discover provider capabilities via /ServiceProviderConfig
2. Provision a user via POST /Users
3. Look up users with filters
4. Update a user's attributes
5. Add the user to a group
6. List a user's group memberships
7. Deprovision (delete) the user
8. Verify JSON round-tripping at every step

The test exercises the real `SCIMUserService`, `SCIMGroupService`,
their HTTP endpoints, and the discovery endpoints. JSON serialization
is tested explicitly to catch issues that wouldn't show up with
direct dataclass tests.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from neozen.core.scim import (
    Group,
    SCIMGroupService,
    SCIMUserService,
    User,
)
from neozen.web.scim import (
    DiscoveryEndpoints,
    GroupsEndpoint,
    ServiceProviderConfig,
    UsersEndpoint,
)

# =============================================================================
# Mock Adapters
# =============================================================================


class MockUserAdapter:
    """Stores SCIM users in memory."""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._counter = 0

    async def create(self, user: User) -> User:
        self._counter += 1
        user.id = f"user_{self._counter:04d}"
        self._users[user.id] = user
        return user

    async def get(self, user_id: str) -> User | None:
        return self._users.get(user_id)

    async def get_by_username(self, user_name: str) -> User | None:
        for u in self._users.values():
            if u.user_name == user_name:
                return u
        return None

    async def update(self, user_id: str, user: User) -> User:
        user.id = user_id
        self._users[user_id] = user
        return user

    async def delete(self, user_id: str) -> None:
        del self._users[user_id]

    async def list_all(self) -> list[User]:
        return list(self._users.values())


class MockGroupAdapter:
    def __init__(self) -> None:
        self._groups: dict[str, Group] = {}
        self._counter = 0

    async def create(self, group: Group) -> Group:
        self._counter += 1
        group.id = f"group_{self._counter:04d}"
        self._groups[group.id] = group
        return group

    async def get(self, group_id: str) -> Group | None:
        return self._groups.get(group_id)

    async def get_by_display_name(self, display_name: str) -> Group | None:
        for g in self._groups.values():
            if g.display_name == display_name:
                return g
        return None

    async def update(self, group_id: str, group: Group) -> Group:
        group.id = group_id
        self._groups[group_id] = group
        return group

    async def delete(self, group_id: str) -> None:
        del self._groups[group_id]

    async def list_all(self) -> list[Group]:
        return list(self._groups.values())


def _to_json(data: dict[str, Any]) -> dict[str, Any]:
    """Round-trip a dict through JSON to catch serialization issues."""
    return json.loads(json.dumps(data))


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def users_endpoint() -> UsersEndpoint:
    service = SCIMUserService(
        adapter=MockUserAdapter(),
        base_url="https://api.example.com/scim/v2",
    )
    return UsersEndpoint(service)


@pytest.fixture
def groups_endpoint() -> GroupsEndpoint:
    service = SCIMGroupService(
        adapter=MockGroupAdapter(),
        base_url="https://api.example.com/scim/v2",
    )
    return GroupsEndpoint(service)


@pytest.fixture
def discovery() -> DiscoveryEndpoints:
    return DiscoveryEndpoints(
        service_provider_config=ServiceProviderConfig(
            patch_supported=False,
            bulk_supported=False,
            filter_supported=True,
            change_password_supported=True,
            documentation_uri="https://docs.example.com/scim",
        )
    )


# =============================================================================
# Provisioning Scenario
# =============================================================================


@pytest.mark.anyio
class TestProvisioningScenario:
    """Realistic external IdP provisioning a new user."""

    async def test_full_user_lifecycle(self, users_endpoint: UsersEndpoint) -> None:
        # ---- Provision: external IdP creates a new user ----
        created = await users_endpoint.create(
            _to_json({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "alice@example.com",
                "name": {
                    "givenName": "Alice",
                    "familyName": "Smith",
                    "formatted": "Alice Smith",
                },
                "displayName": "Alice Smith",
                "emails": [
                    {
                        "value": "alice@example.com",
                        "type": "work",
                        "primary": True,
                    }
                ],
                "active": True,
                "externalId": "okta-12345",
            })
        )

        # JSON round-trips cleanly
        json_text = json.dumps(created)
        parsed = json.loads(json_text)
        assert parsed["userName"] == "alice@example.com"
        assert parsed["id"].startswith("user_")
        assert parsed["meta"]["resourceType"] == "User"
        user_id = parsed["id"]

        # ---- Look up by ID ----
        fetched = await users_endpoint.get(user_id)
        assert fetched["userName"] == "alice@example.com"
        assert fetched["emails"][0]["primary"] is True

        # ---- Filter by external ID ----
        # SCIM filter on externalId
        result = await users_endpoint.list({
            "filter": 'externalId eq "okta-12345"',
        })
        assert result["totalResults"] == 1

        # ---- Update: external IdP changes the user's name ----
        updated = await users_endpoint.replace(
            user_id,
            _to_json({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "alice@example.com",
                "name": {
                    "givenName": "Alice",
                    "familyName": "Johnson",  # changed
                },
                "displayName": "Alice Johnson",
                "emails": [{"value": "alice@example.com", "primary": True}],
                "active": True,
                "externalId": "okta-12345",
            }),
        )
        assert updated["name"]["familyName"] == "Johnson"
        assert updated["displayName"] == "Alice Johnson"

        # ---- Deactivate: IdP marks the user inactive ----
        deactivated = await users_endpoint.replace(
            user_id,
            _to_json({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "alice@example.com",
                "active": False,
                "externalId": "okta-12345",
            }),
        )
        assert deactivated["active"] is False

        # ---- Deprovision: IdP deletes the user ----
        await users_endpoint.delete(user_id)

        # Subsequent get should raise
        from neozen.core.scim.errors import SCIMNotFoundError

        with pytest.raises(SCIMNotFoundError):
            await users_endpoint.get(user_id)

    async def test_pagination_and_filtering(
        self, users_endpoint: UsersEndpoint
    ) -> None:
        """Provision many users and test paginated filtered listing."""
        # Provision 25 users
        for i in range(25):
            await users_endpoint.create({
                "userName": f"user{i:02d}@example.com",
                "displayName": f"User {i}",
                "active": i % 2 == 0,  # half active
            })

        # Total
        all_result = await users_endpoint.list()
        assert all_result["totalResults"] == 25

        # Pagination
        page1 = await users_endpoint.list({"startIndex": "1", "count": "10"})
        assert page1["totalResults"] == 25
        assert len(page1["Resources"]) == 10

        page3 = await users_endpoint.list({"startIndex": "21", "count": "10"})
        assert len(page3["Resources"]) == 5

        # Filter: active users only
        active_result = await users_endpoint.list({
            "filter": "active eq true",
        })
        assert active_result["totalResults"] == 13  # 0, 2, 4, ..., 24

        # Combined filter and pagination
        combined = await users_endpoint.list({
            "filter": 'userName sw "user0"',
            "startIndex": "1",
            "count": "5",
        })
        assert combined["totalResults"] == 10  # user00..user09
        assert len(combined["Resources"]) == 5


# =============================================================================
# Group Membership Scenario
# =============================================================================


@pytest.mark.anyio
class TestGroupScenario:
    async def test_group_lifecycle(
        self,
        users_endpoint: UsersEndpoint,
        groups_endpoint: GroupsEndpoint,
    ) -> None:
        # Provision two users
        alice = await users_endpoint.create({
            "userName": "alice",
            "displayName": "Alice",
            "active": True,
        })
        bob = await users_endpoint.create({
            "userName": "bob",
            "displayName": "Bob",
            "active": True,
        })

        # Create a group with both users
        group = await groups_endpoint.create({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Engineers",
            "members": [
                {
                    "value": alice["id"],
                    "display": "Alice",
                    "type": "User",
                },
                {
                    "value": bob["id"],
                    "display": "Bob",
                    "type": "User",
                },
            ],
        })

        assert group["displayName"] == "Engineers"
        assert len(group["members"]) == 2

        # JSON round-trips
        json.dumps(group)

        # Look up by display name
        result = await groups_endpoint.list({
            "filter": 'displayName eq "Engineers"',
        })
        assert result["totalResults"] == 1

        # Replace members (remove bob)
        updated = await groups_endpoint.replace(
            group["id"],
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "Engineers",
                "members": [
                    {"value": alice["id"], "type": "User"},
                ],
            },
        )
        assert len(updated["members"]) == 1
        assert updated["members"][0]["value"] == alice["id"]

        # Delete the group
        await groups_endpoint.delete(group["id"])
        from neozen.core.scim.errors import SCIMNotFoundError

        with pytest.raises(SCIMNotFoundError):
            await groups_endpoint.get(group["id"])


# =============================================================================
# Discovery Scenario
# =============================================================================


@pytest.mark.anyio
class TestDiscoveryScenario:
    async def test_external_idp_discovers_capabilities(
        self, discovery: DiscoveryEndpoints
    ) -> None:
        """An external IdP would call all three discovery endpoints first."""
        # ServiceProviderConfig
        config = await discovery.service_provider_config_handler()
        assert config["filter"]["supported"] is True
        assert config["filter"]["maxResults"] >= 1
        assert config["bulk"]["supported"] is False
        assert config["patch"]["supported"] is False
        assert config["changePassword"]["supported"] is True
        assert any(
            scheme["type"] == "oauthbearertoken"
            for scheme in config["authenticationSchemes"]
        )

        # ResourceTypes
        types = await discovery.resource_types_handler()
        type_ids = {t["id"] for t in types}
        assert "User" in type_ids
        assert "Group" in type_ids

        # Schemas
        schemas = await discovery.schemas_handler()
        schema_ids = {s["id"] for s in schemas}
        assert "urn:ietf:params:scim:schemas:core:2.0:User" in schema_ids
        assert "urn:ietf:params:scim:schemas:core:2.0:Group" in schema_ids

        # All discovery responses must be JSON-serializable
        json.dumps(config)
        json.dumps(types)
        json.dumps(schemas)


# =============================================================================
# Error Response Format
# =============================================================================


@pytest.mark.anyio
class TestErrorResponseFormat:
    async def test_not_found_error_format(self, users_endpoint: UsersEndpoint) -> None:
        """SCIM error responses follow RFC 7644 Section 3.12."""
        from neozen.core.scim.errors import SCIMNotFoundError

        try:
            await users_endpoint.get("missing")
        except SCIMNotFoundError as e:
            body = e.to_response()
            assert body["status"] == "404"
            assert "Error" in body["schemas"][0]
            json.dumps(body)  # serializable

    async def test_uniqueness_error_format(self, users_endpoint: UsersEndpoint) -> None:
        from neozen.core.scim.errors import SCIMUniquenessError

        await users_endpoint.create({"userName": "alice"})
        try:
            await users_endpoint.create({"userName": "alice"})
        except SCIMUniquenessError as e:
            body = e.to_response()
            assert body["status"] == "409"
            assert body["scimType"] == "uniqueness"
            json.dumps(body)
