"""Tests for SCIM 2.0: models, filter parser, service layer."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from neozen.core.scim.errors import (
    SCIMFilterError,
    SCIMNotFoundError,
    SCIMUniquenessError,
    SCIMValidationError,
)
from neozen.core.scim.filter_parser import (
    Conjunction,
    FilterOp,
    Negation,
    SimpleExpression,
    parse_filter,
)
from neozen.core.scim.models import (
    Email,
    Group,
    GroupMember,
    ListResponse,
    Meta,
    Name,
    SchemaUri,
    User,
)
from neozen.core.scim.service import (
    MAX_RESULTS,
    SCIMGroupService,
    SCIMUserService,
)

# =============================================================================
# Models
# =============================================================================


class TestUserModel:
    def test_to_dict_minimal(self) -> None:
        user = User(user_name="alice", id="user_1")
        d = user.to_dict()
        assert d["userName"] == "alice"
        assert d["id"] == "user_1"
        assert d["schemas"] == [SchemaUri.USER.value]

    def test_to_dict_with_emails(self) -> None:
        user = User(
            user_name="alice",
            emails=[
                Email(value="alice@work.com", type="work", primary=True),
                Email(value="alice@home.com", type="home"),
            ],
        )
        d = user.to_dict()
        assert len(d["emails"]) == 2
        assert d["emails"][0]["primary"] is True

    def test_omits_none_fields(self) -> None:
        user = User(user_name="alice")
        d = user.to_dict()
        assert "displayName" not in d
        assert "title" not in d

    def test_from_dict(self) -> None:
        data = {
            "userName": "alice",
            "displayName": "Alice",
            "name": {"givenName": "Alice", "familyName": "Smith"},
            "emails": [{"value": "alice@e.com", "primary": True}],
        }
        user = User.from_dict(data)
        assert user.user_name == "alice"
        assert user.display_name == "Alice"
        assert user.name is not None
        assert user.name.given_name == "Alice"
        assert len(user.emails) == 1

    def test_primary_email(self) -> None:
        user = User(
            user_name="alice",
            emails=[
                Email(value="alice@home.com"),
                Email(value="alice@work.com", primary=True),
            ],
        )
        assert user.primary_email() == "alice@work.com"

    def test_primary_email_fallback_to_first(self) -> None:
        user = User(
            user_name="alice",
            emails=[Email(value="alice@e.com")],
        )
        assert user.primary_email() == "alice@e.com"

    def test_primary_email_none(self) -> None:
        user = User(user_name="alice")
        assert user.primary_email() is None


class TestGroupModel:
    def test_to_dict(self) -> None:
        group = Group(
            display_name="Engineers",
            id="grp_1",
            members=[GroupMember(value="user_1", display="Alice", type="User")],
        )
        d = group.to_dict()
        assert d["displayName"] == "Engineers"
        assert d["id"] == "grp_1"
        assert len(d["members"]) == 1

    def test_from_dict(self) -> None:
        data = {
            "displayName": "Engineers",
            "members": [{"value": "user_1", "display": "Alice"}],
        }
        group = Group.from_dict(data)
        assert group.display_name == "Engineers"
        assert len(group.members) == 1


class TestMetaModel:
    def test_to_dict(self) -> None:
        meta = Meta(
            resource_type="User",
            created=datetime(2026, 4, 10, tzinfo=UTC),
            location="https://api/Users/123",
        )
        d = meta.to_dict()
        assert d["resourceType"] == "User"
        assert d["location"] == "https://api/Users/123"
        assert "lastModified" not in d  # None is omitted


class TestListResponse:
    def test_to_dict(self) -> None:
        users = [User(user_name="alice", id="1"), User(user_name="bob", id="2")]
        response = ListResponse(
            resources=users,
            total_results=2,
            start_index=1,
        )
        d = response.to_dict()
        assert d["totalResults"] == 2
        assert d["startIndex"] == 1
        assert len(d["Resources"]) == 2
        assert SchemaUri.LIST_RESPONSE.value in d["schemas"]


# =============================================================================
# Filter Parser
# =============================================================================


class TestFilterTokenizer:
    def test_simple_equality(self) -> None:
        expr = parse_filter('userName eq "alice"')
        assert isinstance(expr, SimpleExpression)
        assert expr.attribute == "userName"
        assert expr.op == FilterOp.EQ
        assert expr.value == "alice"

    def test_present(self) -> None:
        expr = parse_filter("emails pr")
        assert isinstance(expr, SimpleExpression)
        assert expr.op == FilterOp.PR
        assert expr.value is None

    def test_number_value(self) -> None:
        expr = parse_filter("age gt 18")
        assert isinstance(expr, SimpleExpression)
        assert expr.value == 18

    def test_boolean_value(self) -> None:
        expr = parse_filter("active eq true")
        assert isinstance(expr, SimpleExpression)
        assert expr.value is True

    def test_and(self) -> None:
        expr = parse_filter('userName eq "alice" and active eq true')
        assert isinstance(expr, Conjunction)
        assert expr.op == "and"

    def test_or(self) -> None:
        expr = parse_filter('userName eq "alice" or userName eq "bob"')
        assert isinstance(expr, Conjunction)
        assert expr.op == "or"

    def test_not(self) -> None:
        expr = parse_filter('not (userName eq "alice")')
        assert isinstance(expr, Negation)

    def test_parentheses(self) -> None:
        expr = parse_filter(
            '(userName eq "alice" or userName eq "bob") and active eq true'
        )
        assert isinstance(expr, Conjunction)
        assert expr.op == "and"

    def test_string_with_spaces(self) -> None:
        expr = parse_filter('displayName eq "Alice Smith"')
        assert isinstance(expr, SimpleExpression)
        assert expr.value == "Alice Smith"

    def test_invalid_filter(self) -> None:
        with pytest.raises(SCIMFilterError):
            parse_filter("nonsense")

    def test_empty_filter(self) -> None:
        with pytest.raises(SCIMFilterError):
            parse_filter("")

    def test_unknown_operator(self) -> None:
        with pytest.raises(SCIMFilterError):
            parse_filter('userName xyz "alice"')

    def test_missing_paren(self) -> None:
        with pytest.raises(SCIMFilterError):
            parse_filter('(userName eq "alice"')

    def test_rejects_deeply_nested_filter(self) -> None:
        """DoS defense: reject filters nested past the hard depth cap.

        Without a depth limit, a deeply nested filter like
        ``(((...(a eq "b")...)))`` exhausts the Python recursion stack
        and raises RecursionError. We want a structured SCIMFilterError
        well before that.
        """
        depth = 500  # well past the 100-level cap
        nested = "(" * depth + 'userName eq "alice"' + ")" * depth
        with pytest.raises(SCIMFilterError, match="nesting depth"):
            parse_filter(nested)

    def test_accepts_reasonably_nested_filter(self) -> None:
        """Legitimate filters with a few levels of grouping still parse."""
        # 5 levels of nesting, well under the 100-level cap.
        nested = '(((((userName eq "alice")))))'
        expr = parse_filter(nested)
        assert expr is not None


class TestFilterMatching:
    @pytest.mark.parametrize(
        ("filter_text", "expected"),
        [
            ('emails.value ew "corp.com"', True),
            ('emails ew "corp.com"', True),  # stands for emails.value
            ('emails.value eq "nobody@x.org"', False),
            ("emails pr", True),
            ("name pr", True),
            ('name.familyName eq "Doe"', True),
        ],
    )
    def test_multi_valued_and_complex_attributes(
        self, filter_text: str, expected: bool
    ) -> None:
        user = User(
            user_name="alice",
            emails=[Email(value="a@x.org"), Email(value="alice@corp.com")],
            name=Name(family_name="Doe"),
        )
        assert parse_filter(filter_text).matches(user) is expected

    def test_eq_string_case_insensitive(self) -> None:
        expr = parse_filter('userName eq "ALICE"')
        user = User(user_name="alice")
        assert expr.matches(user)  # type: ignore[union-attr]

    def test_eq_no_match(self) -> None:
        expr = parse_filter('userName eq "bob"')
        user = User(user_name="alice")
        assert not expr.matches(user)  # type: ignore[union-attr]

    def test_sw(self) -> None:
        expr = parse_filter('userName sw "ali"')
        user = User(user_name="alice")
        assert expr.matches(user)  # type: ignore[union-attr]

    def test_co(self) -> None:
        expr = parse_filter('userName co "lic"')
        user = User(user_name="alice")
        assert expr.matches(user)  # type: ignore[union-attr]

    def test_ew(self) -> None:
        expr = parse_filter('userName ew "ice"')
        user = User(user_name="alice")
        assert expr.matches(user)  # type: ignore[union-attr]

    def test_pr(self) -> None:
        expr = parse_filter("displayName pr")
        user_with = User(user_name="alice", display_name="Alice")
        user_without = User(user_name="bob")
        assert expr.matches(user_with)  # type: ignore[union-attr]
        assert not expr.matches(user_without)  # type: ignore[union-attr]

    def test_ne(self) -> None:
        expr = parse_filter('userName ne "alice"')
        assert not expr.matches(User(user_name="alice"))  # type: ignore[union-attr]
        assert expr.matches(User(user_name="bob"))  # type: ignore[union-attr]

    def test_and(self) -> None:
        expr = parse_filter('userName eq "alice" and active eq true')
        assert expr.matches(User(user_name="alice", active=True))  # type: ignore[union-attr]
        assert not expr.matches(User(user_name="alice", active=False))  # type: ignore[union-attr]
        assert not expr.matches(User(user_name="bob", active=True))  # type: ignore[union-attr]

    def test_or(self) -> None:
        expr = parse_filter('userName eq "alice" or userName eq "bob"')
        assert expr.matches(User(user_name="alice"))  # type: ignore[union-attr]
        assert expr.matches(User(user_name="bob"))  # type: ignore[union-attr]
        assert not expr.matches(User(user_name="carol"))  # type: ignore[union-attr]

    def test_not(self) -> None:
        expr = parse_filter('not (userName eq "alice")')
        assert not expr.matches(User(user_name="alice"))  # type: ignore[union-attr]
        assert expr.matches(User(user_name="bob"))  # type: ignore[union-attr]

    def test_camelcase_to_snake_case(self) -> None:
        # SCIM uses camelCase; our model uses snake_case
        expr = parse_filter('displayName eq "Alice"')
        user = User(user_name="alice", display_name="Alice")
        assert expr.matches(user)  # type: ignore[union-attr]

    def test_dict_target(self) -> None:
        expr = parse_filter('userName eq "alice"')
        assert expr.matches({"userName": "alice"})  # type: ignore[union-attr]

    def test_gt_ge_lt_le(self) -> None:
        expr = parse_filter("count gt 5")
        assert expr.matches({"count": 10})  # type: ignore[union-attr]
        assert not expr.matches({"count": 3})  # type: ignore[union-attr]

        expr = parse_filter("count ge 5")
        assert expr.matches({"count": 5})  # type: ignore[union-attr]
        assert not expr.matches({"count": 4})  # type: ignore[union-attr]

        expr = parse_filter("count lt 5")
        assert expr.matches({"count": 3})  # type: ignore[union-attr]
        assert not expr.matches({"count": 5})  # type: ignore[union-attr]

        expr = parse_filter("count le 5")
        assert expr.matches({"count": 5})  # type: ignore[union-attr]
        assert not expr.matches({"count": 6})  # type: ignore[union-attr]

    def test_null_value(self) -> None:
        expr = parse_filter("title eq null")
        assert isinstance(expr, SimpleExpression)
        assert expr.value is None

    def test_float_value(self) -> None:
        expr = parse_filter("score gt 2.5")
        assert isinstance(expr, SimpleExpression)
        assert expr.value == pytest.approx(2.5)

    def test_pr_with_empty_string(self) -> None:
        expr = parse_filter("displayName pr")
        assert not expr.matches({"displayName": ""})  # type: ignore[union-attr]
        assert not expr.matches({"displayName": []})  # type: ignore[union-attr]
        assert expr.matches({"displayName": "Alice"})  # type: ignore[union-attr]

    def test_pr_on_missing_attribute(self) -> None:
        expr = parse_filter("missing pr")
        assert not expr.matches({"userName": "alice"})  # type: ignore[union-attr]

    def test_op_on_none_returns_false(self) -> None:
        expr = parse_filter('missing eq "value"')
        assert not expr.matches({"userName": "alice"})  # type: ignore[union-attr]


class TestFilterParserErrors:
    def test_unexpected_character(self) -> None:
        with pytest.raises(SCIMFilterError):
            parse_filter("@@@")

    def test_missing_value(self) -> None:
        with pytest.raises(SCIMFilterError):
            parse_filter("userName eq")

    def test_missing_operator(self) -> None:
        with pytest.raises(SCIMFilterError):
            parse_filter("userName")

    def test_bareword_value(self) -> None:
        with pytest.raises(SCIMFilterError):
            parse_filter("userName eq alice")

    def test_unexpected_token_at_top_level(self) -> None:
        with pytest.raises(SCIMFilterError):
            parse_filter('userName eq "a" "extra"')


# =============================================================================
# Service Layer
# =============================================================================


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


@pytest.fixture
def user_service() -> SCIMUserService:
    return SCIMUserService(
        adapter=MockUserAdapter(),
        base_url="https://api.example.com/scim/v2",
    )


@pytest.mark.anyio
class TestSCIMUserService:
    async def test_create_user(self, user_service: SCIMUserService) -> None:
        user = await user_service.create_user(User(user_name="alice"))
        assert user.id is not None
        assert user.meta is not None
        assert user.meta.resource_type == "User"
        assert "Users/" in (user.meta.location or "")

    async def test_create_user_no_username(self, user_service: SCIMUserService) -> None:
        with pytest.raises(SCIMValidationError):
            await user_service.create_user(User(user_name=""))

    async def test_create_duplicate_username(
        self, user_service: SCIMUserService
    ) -> None:
        await user_service.create_user(User(user_name="alice"))
        with pytest.raises(SCIMUniquenessError):
            await user_service.create_user(User(user_name="alice"))

    async def test_get_user(self, user_service: SCIMUserService) -> None:
        created = await user_service.create_user(User(user_name="alice"))
        fetched = await user_service.get_user(created.id)  # type: ignore[arg-type]
        assert fetched.user_name == "alice"

    async def test_get_unknown_user(self, user_service: SCIMUserService) -> None:
        with pytest.raises(SCIMNotFoundError):
            await user_service.get_user("nope")

    async def test_update_user(self, user_service: SCIMUserService) -> None:
        created = await user_service.create_user(User(user_name="alice"))
        updated = await user_service.update_user(
            created.id,  # type: ignore[arg-type]
            User(user_name="alice", display_name="Alice Smith"),
        )
        assert updated.display_name == "Alice Smith"

    async def test_update_username_collision(
        self, user_service: SCIMUserService
    ) -> None:
        await user_service.create_user(User(user_name="alice"))
        u2 = await user_service.create_user(User(user_name="bob"))

        with pytest.raises(SCIMUniquenessError):
            await user_service.update_user(
                u2.id,  # type: ignore[arg-type]
                User(user_name="alice"),
            )

    async def test_delete_user(self, user_service: SCIMUserService) -> None:
        created = await user_service.create_user(User(user_name="alice"))
        await user_service.delete_user(created.id)  # type: ignore[arg-type]
        with pytest.raises(SCIMNotFoundError):
            await user_service.get_user(created.id)  # type: ignore[arg-type]

    async def test_delete_unknown(self, user_service: SCIMUserService) -> None:
        with pytest.raises(SCIMNotFoundError):
            await user_service.delete_user("nope")

    async def test_list_no_filter(self, user_service: SCIMUserService) -> None:
        await user_service.create_user(User(user_name="alice"))
        await user_service.create_user(User(user_name="bob"))
        await user_service.create_user(User(user_name="carol"))

        result = await user_service.list_users()
        assert result.total_results == 3
        assert len(result.resources) == 3

    async def test_list_with_filter(self, user_service: SCIMUserService) -> None:
        await user_service.create_user(User(user_name="alice"))
        await user_service.create_user(User(user_name="bob"))
        await user_service.create_user(User(user_name="carol"))

        result = await user_service.list_users(filter_expr='userName sw "a"')
        assert result.total_results == 1
        assert result.resources[0].user_name == "alice"  # type: ignore[union-attr]

    async def test_list_pagination(self, user_service: SCIMUserService) -> None:
        for i in range(10):
            await user_service.create_user(User(user_name=f"user{i}"))

        page1 = await user_service.list_users(start_index=1, count=3)
        assert len(page1.resources) == 3
        assert page1.total_results == 10

        page2 = await user_service.list_users(start_index=4, count=3)
        assert len(page2.resources) == 3
        # Different items
        assert page1.resources[0].id != page2.resources[0].id  # type: ignore[union-attr]

    async def test_count_zero_returns_only_the_total(
        self, user_service: SCIMUserService
    ) -> None:
        for i in range(3):
            await user_service.create_user(User(user_name=f"user{i}"))

        result = await user_service.list_users(count=0)

        assert result.resources == []
        assert result.total_results == 3

    async def test_count_is_capped_at_max_results(
        self, user_service: SCIMUserService
    ) -> None:
        for i in range(MAX_RESULTS + 1):
            await user_service.create_user(User(user_name=f"user{i}"))

        result = await user_service.list_users(count=MAX_RESULTS + 1)

        assert len(result.resources) == MAX_RESULTS
        assert result.total_results == MAX_RESULTS + 1


# =============================================================================
# SCIM Group Service
# =============================================================================


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
def group_service() -> SCIMGroupService:
    return SCIMGroupService(
        adapter=MockGroupAdapter(),
        base_url="https://api.example.com/scim/v2",
    )


@pytest.mark.anyio
class TestSCIMGroupService:
    async def test_create_group(self, group_service: SCIMGroupService) -> None:
        group = await group_service.create_group(Group(display_name="Engineers"))
        assert group.id is not None
        assert group.meta is not None

    async def test_create_no_display_name(
        self, group_service: SCIMGroupService
    ) -> None:
        with pytest.raises(SCIMValidationError):
            await group_service.create_group(Group(display_name=""))

    async def test_create_duplicate(self, group_service: SCIMGroupService) -> None:
        await group_service.create_group(Group(display_name="Engineers"))
        with pytest.raises(SCIMUniquenessError):
            await group_service.create_group(Group(display_name="Engineers"))

    async def test_update_group(self, group_service: SCIMGroupService) -> None:
        created = await group_service.create_group(Group(display_name="Engineers"))
        updated = await group_service.update_group(
            created.id,  # type: ignore[arg-type]
            Group(
                display_name="Engineers",
                members=[GroupMember(value="user_1", type="User")],
            ),
        )
        assert len(updated.members) == 1

    async def test_list_groups(self, group_service: SCIMGroupService) -> None:
        await group_service.create_group(Group(display_name="Engineers"))
        await group_service.create_group(Group(display_name="Designers"))
        result = await group_service.list_groups()
        assert result.total_results == 2

    async def test_list_groups_filter(self, group_service: SCIMGroupService) -> None:
        await group_service.create_group(Group(display_name="Engineers"))
        await group_service.create_group(Group(display_name="Designers"))
        result = await group_service.list_groups(
            filter_expr='displayName eq "Engineers"'
        )
        assert result.total_results == 1
