"""Tests for SCIM HTTP endpoints."""

from __future__ import annotations

import pytest

from neozen.core.scim.errors import (
    SCIMNotFoundError,
    SCIMValidationError,
)
from neozen.core.scim.models import Group, User
from neozen.core.scim.service import (
    SCIMGroupService,
    SCIMUserService,
)
from neozen.web.scim import (
    DiscoveryEndpoints,
    GroupsEndpoint,
    ServiceProviderConfig,
    UsersEndpoint,
)


# Re-use mock adapters from test_scim
class MockUserAdapter:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._counter = 0

    async def create(self, user: User) -> User:
        self._counter += 1
        user.id = f"user_{self._counter}"
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
        group.id = f"group_{self._counter}"
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


@pytest.mark.anyio
class TestUsersEndpoint:
    async def test_create_user(self, users_endpoint: UsersEndpoint) -> None:
        result = await users_endpoint.create({"userName": "alice"})
        assert result["userName"] == "alice"
        assert "id" in result
        assert result["id"].startswith("user_")
        assert "meta" in result

    async def test_create_with_emails(self, users_endpoint: UsersEndpoint) -> None:
        result = await users_endpoint.create({
            "userName": "alice",
            "emails": [{"value": "alice@work.com", "type": "work", "primary": True}],
        })
        assert len(result["emails"]) == 1

    async def test_create_invalid_payload(self, users_endpoint: UsersEndpoint) -> None:
        with pytest.raises(SCIMValidationError):
            await users_endpoint.create("not a dict")  # type: ignore[arg-type]

    async def test_get_user(self, users_endpoint: UsersEndpoint) -> None:
        created = await users_endpoint.create({"userName": "alice"})
        result = await users_endpoint.get(created["id"])
        assert result["userName"] == "alice"

    async def test_get_unknown_user(self, users_endpoint: UsersEndpoint) -> None:
        with pytest.raises(SCIMNotFoundError):
            await users_endpoint.get("nope")

    async def test_replace_user(self, users_endpoint: UsersEndpoint) -> None:
        created = await users_endpoint.create({"userName": "alice"})
        result = await users_endpoint.replace(
            created["id"],
            {"userName": "alice", "displayName": "Alice Smith"},
        )
        assert result["displayName"] == "Alice Smith"

    async def test_delete_user(self, users_endpoint: UsersEndpoint) -> None:
        created = await users_endpoint.create({"userName": "alice"})
        await users_endpoint.delete(created["id"])
        with pytest.raises(SCIMNotFoundError):
            await users_endpoint.get(created["id"])

    async def test_list_users(self, users_endpoint: UsersEndpoint) -> None:
        await users_endpoint.create({"userName": "alice"})
        await users_endpoint.create({"userName": "bob"})

        result = await users_endpoint.list()
        assert result["totalResults"] == 2
        assert len(result["Resources"]) == 2

    async def test_list_with_filter(self, users_endpoint: UsersEndpoint) -> None:
        await users_endpoint.create({"userName": "alice"})
        await users_endpoint.create({"userName": "bob"})

        result = await users_endpoint.list({
            "filter": 'userName eq "alice"',
        })
        assert result["totalResults"] == 1
        assert result["Resources"][0]["userName"] == "alice"

    async def test_list_with_pagination(self, users_endpoint: UsersEndpoint) -> None:
        for i in range(10):
            await users_endpoint.create({"userName": f"user{i}"})

        result = await users_endpoint.list({
            "startIndex": "1",
            "count": "3",
        })
        assert result["totalResults"] == 10
        assert len(result["Resources"]) == 3
        assert result["startIndex"] == 1
        assert result["itemsPerPage"] == 3

    async def test_list_invalid_pagination_params(
        self, users_endpoint: UsersEndpoint
    ) -> None:
        await users_endpoint.create({"userName": "alice"})
        # Invalid count -> defaults to 100
        result = await users_endpoint.list({"count": "abc"})
        assert result["totalResults"] == 1

    async def test_list_invalid_start_index(
        self, users_endpoint: UsersEndpoint
    ) -> None:
        await users_endpoint.create({"userName": "alice"})
        # Invalid startIndex -> defaults to 1
        result = await users_endpoint.list({"startIndex": "xyz"})
        assert result["startIndex"] == 1

    async def test_replace_invalid_payload(self, users_endpoint: UsersEndpoint) -> None:
        created = await users_endpoint.create({"userName": "alice"})
        with pytest.raises(SCIMValidationError):
            await users_endpoint.replace(created["id"], "not a dict")  # type: ignore[arg-type]

    async def test_create_with_malformed_email(
        self, users_endpoint: UsersEndpoint
    ) -> None:
        # Email object missing required 'value' key
        with pytest.raises(SCIMValidationError):
            await users_endpoint.create({
                "userName": "alice",
                "emails": [{"type": "work"}],  # No 'value'
            })

    async def test_replace_with_malformed_email(
        self, users_endpoint: UsersEndpoint
    ) -> None:
        created = await users_endpoint.create({"userName": "alice"})
        with pytest.raises(SCIMValidationError):
            await users_endpoint.replace(
                created["id"],
                {
                    "userName": "alice",
                    "emails": [{"type": "work"}],
                },
            )

    async def test_create_with_complex_user(
        self, users_endpoint: UsersEndpoint
    ) -> None:
        result = await users_endpoint.create({
            "userName": "alice",
            "displayName": "Alice Smith",
            "name": {"givenName": "Alice", "familyName": "Smith"},
            "phoneNumbers": [{"value": "+1-555-0100", "type": "work"}],
            "active": False,
        })
        assert result["displayName"] == "Alice Smith"
        assert result["name"]["givenName"] == "Alice"
        assert result["active"] is False
        assert len(result["phoneNumbers"]) == 1


@pytest.mark.anyio
class TestGroupsEndpoint:
    async def test_create_group(self, groups_endpoint: GroupsEndpoint) -> None:
        result = await groups_endpoint.create({"displayName": "Engineers"})
        assert result["displayName"] == "Engineers"
        assert "id" in result

    async def test_create_with_members(self, groups_endpoint: GroupsEndpoint) -> None:
        result = await groups_endpoint.create({
            "displayName": "Engineers",
            "members": [
                {"value": "user_1", "display": "Alice", "type": "User"},
            ],
        })
        assert len(result["members"]) == 1

    async def test_get_group(self, groups_endpoint: GroupsEndpoint) -> None:
        created = await groups_endpoint.create({"displayName": "Engineers"})
        result = await groups_endpoint.get(created["id"])
        assert result["displayName"] == "Engineers"

    async def test_replace_adds_members(self, groups_endpoint: GroupsEndpoint) -> None:
        created = await groups_endpoint.create({"displayName": "Engineers"})
        result = await groups_endpoint.replace(
            created["id"],
            {
                "displayName": "Engineers",
                "members": [
                    {"value": "user_1", "type": "User"},
                    {"value": "user_2", "type": "User"},
                ],
            },
        )
        assert len(result["members"]) == 2

    async def test_delete_group(self, groups_endpoint: GroupsEndpoint) -> None:
        created = await groups_endpoint.create({"displayName": "Engineers"})
        await groups_endpoint.delete(created["id"])
        with pytest.raises(SCIMNotFoundError):
            await groups_endpoint.get(created["id"])

    async def test_list_groups(self, groups_endpoint: GroupsEndpoint) -> None:
        await groups_endpoint.create({"displayName": "Engineers"})
        await groups_endpoint.create({"displayName": "Designers"})
        result = await groups_endpoint.list()
        assert result["totalResults"] == 2

    async def test_list_groups_with_filter(
        self, groups_endpoint: GroupsEndpoint
    ) -> None:
        await groups_endpoint.create({"displayName": "Engineers"})
        await groups_endpoint.create({"displayName": "Designers"})
        result = await groups_endpoint.list({"filter": 'displayName eq "Engineers"'})
        assert result["totalResults"] == 1

    async def test_list_groups_pagination(
        self, groups_endpoint: GroupsEndpoint
    ) -> None:
        for i in range(5):
            await groups_endpoint.create({"displayName": f"Group{i}"})
        result = await groups_endpoint.list({
            "startIndex": "1",
            "count": "2",
        })
        assert result["totalResults"] == 5
        assert len(result["Resources"]) == 2

    async def test_list_groups_invalid_params(
        self, groups_endpoint: GroupsEndpoint
    ) -> None:
        await groups_endpoint.create({"displayName": "Engineers"})
        result = await groups_endpoint.list({
            "startIndex": "bad",
            "count": "bad",
        })
        assert result["totalResults"] == 1

    async def test_create_invalid_payload(
        self, groups_endpoint: GroupsEndpoint
    ) -> None:
        with pytest.raises(SCIMValidationError):
            await groups_endpoint.create("not a dict")  # type: ignore[arg-type]

    async def test_replace_invalid_payload(
        self, groups_endpoint: GroupsEndpoint
    ) -> None:
        created = await groups_endpoint.create({"displayName": "Engineers"})
        with pytest.raises(SCIMValidationError):
            await groups_endpoint.replace(created["id"], "not a dict")  # type: ignore[arg-type]

    async def test_get_unknown_group(self, groups_endpoint: GroupsEndpoint) -> None:
        with pytest.raises(SCIMNotFoundError):
            await groups_endpoint.get("nope")

    async def test_create_with_malformed_member(
        self, groups_endpoint: GroupsEndpoint
    ) -> None:
        with pytest.raises(SCIMValidationError):
            await groups_endpoint.create({
                "displayName": "Engineers",
                "members": [{"type": "User"}],  # Missing 'value'
            })

    async def test_replace_with_malformed_member(
        self, groups_endpoint: GroupsEndpoint
    ) -> None:
        created = await groups_endpoint.create({"displayName": "Engineers"})
        with pytest.raises(SCIMValidationError):
            await groups_endpoint.replace(
                created["id"],
                {
                    "displayName": "Engineers",
                    "members": [{"type": "User"}],
                },
            )


# =============================================================================
# Discovery
# =============================================================================


@pytest.mark.anyio
class TestDiscoveryEndpoints:
    async def test_service_provider_config(self) -> None:
        endpoints = DiscoveryEndpoints()
        config = await endpoints.service_provider_config_handler()
        assert "schemas" in config
        assert config["filter"]["supported"] is True
        assert config["bulk"]["supported"] is False

    async def test_resource_types(self) -> None:
        endpoints = DiscoveryEndpoints()
        types = await endpoints.resource_types_handler()
        assert len(types) >= 2
        type_ids = [t["id"] for t in types]
        assert "User" in type_ids
        assert "Group" in type_ids

    async def test_schemas(self) -> None:
        endpoints = DiscoveryEndpoints()
        schemas = await endpoints.schemas_handler()
        assert len(schemas) >= 2
        # User schema should have userName attribute
        user_schema = next(s for s in schemas if "User" in s["id"])
        attrs = [a["name"] for a in user_schema["attributes"]]
        assert "userName" in attrs

    async def test_custom_config(self) -> None:
        config = ServiceProviderConfig(
            patch_supported=True,
            etag_supported=True,
            documentation_uri="https://docs.example.com/scim",
        )
        endpoints = DiscoveryEndpoints(service_provider_config=config)
        result = await endpoints.service_provider_config_handler()
        assert result["patch"]["supported"] is True
        assert result["etag"]["supported"] is True
        assert result["documentationUri"] == "https://docs.example.com/scim"


# =============================================================================
# Error responses
# =============================================================================


class TestSCIMErrors:
    def test_to_response(self) -> None:
        from neozen.core.scim.errors import SCIMNotFoundError

        err = SCIMNotFoundError("User missing")
        body = err.to_response()
        assert body["status"] == "404"
        assert body["detail"] == "User missing"
        assert "Error" in body["schemas"][0]

    def test_uniqueness_error(self) -> None:
        from neozen.core.scim.errors import SCIMUniquenessError

        err = SCIMUniquenessError("Duplicate")
        body = err.to_response()
        assert body["status"] == "409"
        assert body["scimType"] == "uniqueness"

    def test_filter_error(self) -> None:
        from neozen.core.scim.errors import SCIMFilterError

        err = SCIMFilterError("Bad filter")
        body = err.to_response()
        assert body["status"] == "400"
        assert body["scimType"] == "invalidFilter"
